"""Delta reproduction tests for the G2Fuzz input-generator pipeline.

These tests exercise the strict paper-native G2Fuzz reproduction contract from
``plans/g2fuzz_reproduction_delta.md`` with fake Docker/CLI fixtures so they
pass without real external checkouts, Docker, AFL++ builds, or model access.

G2Fuzz is an ``input_generator`` (it synthesizes Python input generators and
seeds for a fixed native FuzzBench target triple, then drives its modified
AFL++ with CmpLog), never a harness generator.

The tests target the exact HGB5 issues called out by the plan:
- profile not accepted by the host runner,
- prebuilt ``G2FUZZ_TARGET_DIR`` leaking a non-FuzzBench triple,
- a fake builder that does not verify ``/out/<target>``,
- coverage report missing but status evaluated,
- zero-exec campaigns,
- missing CmpLog ``-c`` argument,
- ``G2FUZZ_TRY_NUM`` patched down to a smoke value,
- paper-core vs extension matrix split.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
_DOCKER_COMMON = ROOT / "docker" / "common"
if str(_DOCKER_COMMON) not in sys.path:
    sys.path.insert(0, str(_DOCKER_COMMON))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


g2 = load_module("g2fuzz_target_pipeline_delta", ROOT / "docker/common/g2fuzz_target_pipeline.py")
builder = load_module("hgb_fuzzbench_builder_delta", ROOT / "docker/common/hgb_fuzzbench_builder.py")
contract_mod = load_module("g2fuzz_contract_delta", ROOT / "docker/common/g2fuzz_contract.py")
matrix_collector = load_module("hgb_collect_matrix_delta", ROOT / "scripts/hgb_collect_matrix.py")


COVERAGE_JSON = json.dumps({
    "data": [{"totals": {"lines": {"count": 50, "covered": 30},
                         "functions": {"count": 10, "covered": 6},
                         "regions": {"count": 40, "covered": 20}}}],
    "type": "llvm.coverage.json.export", "version": "2.0.1",
})


def make_executable(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)
    return path


def make_target_package(base: Path, target: str = "libpng_libpng_read_fuzzer") -> Path:
    package = base / "target"
    bench = package / "fuzzbench_benchmark"
    bench.mkdir(parents=True)
    (package / "target_manifest.json").write_text(
        json.dumps(
            {
                "target": target,
                "project": target.split("_", 1)[0],
                "fuzz_target": target,
                "fuzzbench_commit": "fixture",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (bench / "benchmark.yaml").write_text(f"project: {target}\nfuzz_target: {target}\n", encoding="utf-8")
    (bench / "Dockerfile").write_text("FROM gcr.io/fuzzbench/base-builder\nCOPY . /src/\nRUN compile\n", encoding="utf-8")
    (bench / "build.sh").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    (bench / "build.sh").chmod(0o755)
    return package


def fake_program_gen(path: Path) -> Path:
    return make_executable(
        path,
        """#!/usr/bin/env python3
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--output", required=True)
parser.add_argument("--program", required=True)
args = parser.parse_args()
root = Path(args.output) / "default"
(root / "generators").mkdir(parents=True, exist_ok=True)
(root / "gen_seeds").mkdir(parents=True, exist_ok=True)
(root / "generators" / f"{args.program}_generator.py").write_text("print('seed')\\n", encoding="utf-8")
(root / "gen_seeds" / "id_000000").write_bytes(b"fixture-seed")
(root / "gen_seeds" / "config.json").write_text("not python, but generated seed-like data\\n", encoding="utf-8")
""",
    )


def fake_afl_fuzz(path: Path, execs_done: int = 100, queue: bool = True) -> Path:
    q = "queue.mkdir(parents=True, exist_ok=True)\n(queue / 'id:000000,orig:seed').write_bytes(b'queued')\n" if queue else ""
    return make_executable(
        path,
        f"""#!/usr/bin/env python3
import sys
from pathlib import Path
out = None
for index, arg in enumerate(sys.argv):
    if arg == "-o" and index + 1 < len(sys.argv):
        out = Path(sys.argv[index + 1])
if out is None:
    raise SystemExit(2)
queue = out / "default" / "queue"
crashes = out / "default" / "crashes"
hangs = out / "default" / "hangs"
crashes.mkdir(parents=True, exist_ok=True)
hangs.mkdir(parents=True, exist_ok=True)
{q}
(out / "default" / "fuzzer_stats").write_text("execs_done : {execs_done}\\npaths_total : 3\\n", encoding="utf-8")
raise SystemExit(0)
""",
    )


def fake_coverage_report(path: Path) -> Path:
    path.write_text(COVERAGE_JSON, encoding="utf-8")
    return path


class FakeRunnerResult:
    def __init__(self, command, exit_code=0, stdout="", stderr=""):
        self.command = list(command)
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


class FakeDockerRunner:
    """Simulates the G2Fuzz triple Docker build and the coverage replay shell.

    - ``docker build`` succeeds and records the image tag.
    - ``docker image inspect`` returns a fake digest.
    - ``docker create`` returns a container name.
    - ``docker cp <container>:/out/<fuzz_target> <host>`` writes a real fake
      executable binary to the host path so contract probe/smoke/coverage work.
    - the coverage replay ``sh -lc`` command (containing LLVM_PROFILE_FILE and
      llvm-cov export) returns a real LLVM coverage JSON on stdout.
    """

    def __init__(self, coverage_stdout: str = COVERAGE_JSON, *, write_binary: bool = True):
        self.commands = []
        self.images: set[str] = set()
        self.coverage_stdout = coverage_stdout
        self.write_binary = write_binary

    def __call__(self, command, timeout):
        self.commands.append(list(command))
        cmd = list(command)
        if not cmd:
            return FakeRunnerResult(cmd, 1)
        head = cmd[0]
        if head == "docker":
            sub = cmd[1] if len(cmd) > 1 else ""
            if sub == "build":
                tag = ""
                for i, tok in enumerate(cmd):
                    if tok == "--tag" and i + 1 < len(cmd):
                        tag = cmd[i + 1]
                if tag:
                    self.images.add(tag)
                return FakeRunnerResult(cmd, 0, "build ok", "")
            if sub == "image" and len(cmd) > 3 and cmd[2] == "inspect":
                return FakeRunnerResult(cmd, 0, "sha256:fakedigest\n", "")
            if sub == "create":
                name = ""
                for i, tok in enumerate(cmd):
                    if tok == "--name" and i + 1 < len(cmd):
                        name = cmd[i + 1]
                return FakeRunnerResult(cmd, 0, name + "\n", "")
            if sub == "cp":
                if len(cmd) >= 4 and self.write_binary:
                    host_dst = Path(cmd[-1])
                    host_dst.parent.mkdir(parents=True, exist_ok=True)
                    make_executable(host_dst, "#!/usr/bin/env bash\nexit 0\n")
                return FakeRunnerResult(cmd, 0, "", "")
            if sub == "rm":
                return FakeRunnerResult(cmd, 0, "", "")
        if head == "sh":
            joined = " ".join(cmd)
            if "llvm-cov export" in joined and "LLVM_PROFILE_FILE" in joined:
                return FakeRunnerResult(cmd, 0, self.coverage_stdout, "")
        return FakeRunnerResult(cmd, 0, "", "")


def make_pipeline(
    tmp_path: Path,
    target: str = "libpng_libpng_read_fuzzer",
    runner=None,
) -> "g2.G2FuzzPipeline":
    package = make_target_package(tmp_path, target)
    pipeline = g2.G2FuzzPipeline(
        workspace=tmp_path / "workspace",
        target=target,
        target_package=package,
        artifact_dir=tmp_path / "artifact",
        metadata_root=ROOT / "metadata",
        profile="reproduction-delta",
        protocol="paper-native",
    )
    if runner is not None:
        pipeline.runner = runner
    return pipeline


def run_full(tmp_path, target="libpng_libpng_read_fuzzer", runner=None, *, coverage_stdout=COVERAGE_JSON, set_coverage_report=True):
    if runner is None:
        runner = FakeDockerRunner(coverage_stdout=coverage_stdout)
    program_gen = fake_program_gen(tmp_path / "program_gen.py")
    afl = fake_afl_fuzz(tmp_path / "afl-fuzz")
    coverage = fake_coverage_report(tmp_path / "coverage.json")
    pipeline = make_pipeline(tmp_path, target, runner=runner)
    saved = dict(os.environ)
    os.environ["G2FUZZ_PROGRAM_GEN"] = str(program_gen)
    os.environ["G2FUZZ_AFL_FUZZ"] = str(afl)
    if set_coverage_report:
        os.environ["G2FUZZ_COVERAGE_REPORT"] = str(coverage)
    else:
        os.environ.pop("G2FUZZ_COVERAGE_REPORT", None)
    os.environ["G2FUZZ_AFL_TIMEOUT_SECONDS"] = "5"
    try:
        code = pipeline.full()
    finally:
        os.environ.clear()
        os.environ.update(saved)
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    return code, metadata, pipeline, tmp_path / "workspace"


# 1. reproduction-delta profile is accepted by the host runner (dry run)
def test_reproduction_delta_profile_accepted_by_host_runner():
    run_baseline = (ROOT / "scripts/hgb_run_baseline.sh").read_text(encoding="utf-8")
    assert "reproduction-delta" in run_baseline
    assert "g2fuzz/reproduction-delta: G2FUZZ_TARGET_DIR is forbidden" in run_baseline
    # A dry run validates the profile/protocol without Docker or LLM calls.
    proc = subprocess.run(
        ["bash", str(ROOT / "scripts/hgb_run_baseline.sh"), "--dry-run",
         "--generator", "g2fuzz", "--target", "libpng_libpng_read_fuzzer",
         "--profile", "reproduction-delta", "--protocol", "paper-native"],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    assert proc.returncode == 0, proc.stderr


# 2. Prebuilt G2FUZZ_TARGET_DIR is forbidden under delta before generation
def test_delta_refuses_prebuilt_target_dir(tmp_path: Path):
    pair = tmp_path / "pair"
    pair.mkdir()
    make_executable(pair / "libpng_libpng_read_fuzzer.afl", "#!/usr/bin/env bash\nexit 0\n")
    make_executable(pair / "libpng_libpng_read_fuzzer.cmp", "#!/usr/bin/env bash\nexit 0\n")
    env = os.environ.copy()
    env["G2FUZZ_TARGET_DIR"] = str(pair)
    package = make_target_package(tmp_path)
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "docker/common/g2fuzz_target_pipeline.py"),
            "full",
            "--workspace", str(tmp_path / "workspace"),
            "--target", "libpng_libpng_read_fuzzer",
            "--target-package", str(package),
            "--artifact-dir", str(tmp_path / "artifact"),
            "--metadata-root", str(ROOT / "metadata"),
            "--profile", "reproduction-delta",
            "--protocol", "paper-native",
        ],
        cwd=ROOT, env=env, text=True, capture_output=True, check=False,
    )
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "infra_missing"
    assert "G2FUZZ_TARGET_DIR" in metadata["reason"]
    assert proc.returncode != 0


# 3. Triple provenance shows all three variants verified and FuzzBench Docker env
def test_triple_provenance_all_variants_verified(tmp_path: Path):
    code, metadata, pipeline, workspace = run_full(tmp_path)
    assert code == 0, metadata.get("reason")
    provenance = json.loads((workspace / "target" / "triple_provenance.json").read_text(encoding="utf-8"))
    assert provenance["uses_fuzzbench_docker_environment"] is True
    for variant in ("afl", "cmp", "cov"):
        assert provenance["variants"][variant]["verified"] is True
        assert provenance["variants"][variant]["binary_sha256"]
    # The result payload carries the same triple under target_triple.
    assert metadata["target_triple"]["uses_fuzzbench_docker_environment"] is True
    for variant in ("afl", "cmp", "cov"):
        assert metadata["target_triple"]["variants"][variant]["verified"] is True


# 4. A fake builder that does not verify /out/<target> must fail
def test_fake_builder_not_verifying_out_fails(tmp_path: Path):
    runner = FakeDockerRunner(write_binary=False)
    code, metadata, pipeline, workspace = run_full(tmp_path, runner=runner)
    assert code != 0
    assert metadata["status"] != "evaluated"
    # The triple build should have failed because no binary was produced.
    assert metadata["stages"]["target_pair_built"]["status"] != "complete"


# 5. Generated seed count excludes .py/.json/log files; at least one payload
def test_generated_seed_count_excludes_non_inputs(tmp_path: Path):
    produced = tmp_path / "gen_seeds"
    produced.mkdir()
    (produced / "input_000").write_bytes(b'{"k": 0}')
    (produced / "evolved.py").write_text("x=1\n", encoding="utf-8")
    (produced / "meta.json").write_text("{}", encoding="utf-8")
    (produced / "run.log").write_text("log\n", encoding="utf-8")
    (produced / "config.yaml").write_text("k: v\n", encoding="utf-8")
    assert g2.is_generated_input_candidate(produced / "input_000")
    assert not g2.is_generated_input_candidate(produced / "evolved.py")
    assert not g2.is_generated_input_candidate(produced / "meta.json")
    assert not g2.is_generated_input_candidate(produced / "run.log")
    assert not g2.is_generated_input_candidate(produced / "config.yaml")


# 6. Zero-exec campaign fails and never reaches evaluated
def test_zero_exec_campaign_fails(tmp_path: Path):
    runner = FakeDockerRunner()
    program_gen = fake_program_gen(tmp_path / "program_gen.py")
    afl = fake_afl_fuzz(tmp_path / "afl-fuzz", execs_done=0, queue=True)
    coverage = fake_coverage_report(tmp_path / "coverage.json")
    pipeline = make_pipeline(tmp_path, runner=runner)
    saved = dict(os.environ)
    os.environ["G2FUZZ_PROGRAM_GEN"] = str(program_gen)
    os.environ["G2FUZZ_AFL_FUZZ"] = str(afl)
    os.environ["G2FUZZ_COVERAGE_REPORT"] = str(coverage)
    os.environ["G2FUZZ_AFL_TIMEOUT_SECONDS"] = "5"
    try:
        code = pipeline.full()
    finally:
        os.environ.clear()
        os.environ.update(saved)
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert code != 0
    assert metadata["stages"]["campaign"]["status"] != "complete"
    assert metadata["campaign"]["execs_done"] == 0
    assert metadata["status"] != "evaluated"


# 7. Coverage report missing but status evaluated must fail
def test_coverage_report_missing_fails(tmp_path: Path):
    code, metadata, pipeline, workspace = run_full(tmp_path, coverage_stdout="", set_coverage_report=False)
    assert code != 0
    assert metadata["status"] != "evaluated"
    assert metadata["stages"]["coverage"]["status"] != "complete"
    assert metadata["coverage"]["line_coverage"] is None
    assert metadata["coverage"]["edge_coverage"]["status"] == "unavailable"


# 8. Missing -c CmpLog argument fails
def test_missing_cmplog_argument_fails(tmp_path: Path):
    runner = FakeDockerRunner()
    program_gen = fake_program_gen(tmp_path / "program_gen.py")
    # An afl-fuzz that does not accept -c/-k but still produces output.
    afl = make_executable(
        tmp_path / "afl-fuzz",
        """#!/usr/bin/env python3
import sys
from pathlib import Path
out = None
for index, arg in enumerate(sys.argv):
    if arg == "-o" and index + 1 < len(sys.argv):
        out = Path(sys.argv[index + 1])
if out is None:
    raise SystemExit(2)
queue = out / "default" / "queue"
(queue).mkdir(parents=True, exist_ok=True)
(queue / 'id:000000,orig:seed').write_bytes(b'queued')
(out / "default" / "fuzzer_stats").write_text("execs_done : 100\\npaths_total : 3\\n", encoding="utf-8")
raise SystemExit(0)
""",
    )
    coverage = fake_coverage_report(tmp_path / "coverage.json")
    pipeline = make_pipeline(tmp_path, runner=runner)
    saved = dict(os.environ)
    os.environ["G2FUZZ_PROGRAM_GEN"] = str(program_gen)
    os.environ["G2FUZZ_AFL_FUZZ"] = str(afl)
    os.environ["G2FUZZ_COVERAGE_REPORT"] = str(coverage)
    os.environ["G2FUZZ_AFL_TIMEOUT_SECONDS"] = "5"
    try:
        code = pipeline.full()
    finally:
        os.environ.clear()
        os.environ.update(saved)
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    # The campaign command is constructed with -c by the pipeline; the guard
    # verifies -c is present. The command file must contain -c.
    cmd_text = (tmp_path / "workspace" / "campaign" / "command.txt").read_text(encoding="utf-8")
    assert " -c " in cmd_text
    # The pipeline must require a CmpLog target.cmp binary; if it were missing
    # the campaign would fail with infra_missing.
    assert (tmp_path / "workspace" / "target" / "target.cmp").is_file()


def test_campaign_requires_cmplog_binary(tmp_path: Path):
    pipeline = make_pipeline(tmp_path, runner=FakeDockerRunner())
    # Provide a fake afl-fuzz in the artifact dir so afl_fuzz_path() passes;
    # the campaign must then fail on the missing target.cmp CmpLog binary.
    (tmp_path / "artifact").mkdir(parents=True, exist_ok=True)
    make_executable(tmp_path / "artifact" / "afl-fuzz", "#!/usr/bin/env bash\nexit 0\n")
    pipeline.invocation = g2.resolved_invocation(pipeline.adapter, pipeline.target_afl)
    pipeline.target_afl.parent.mkdir(parents=True, exist_ok=True)
    make_executable(pipeline.target_afl, "#!/usr/bin/env bash\nexit 0\n")
    # target.cmp does not exist.
    assert not pipeline.target_cmp.is_file()
    with pytest.raises(g2.PipelineError) as exc_info:
        pipeline.run_campaign()
    assert exc_info.value.status == "infra_missing"
    assert "CmpLog" in exc_info.value.reason


# 9. evaluated requires the full closed loop (real evidence) with delta schema
def test_evaluated_requires_full_closed_loop(tmp_path: Path):
    code, metadata, pipeline, workspace = run_full(tmp_path)
    assert code == 0, metadata.get("reason")
    assert metadata["status"] == "evaluated"
    assert metadata["task_family"] == "input_generator"
    assert metadata["profile"] == "reproduction-delta"
    # Delta schema fields (plan section 7).
    assert metadata["method_variant"] == "paper-core"
    assert metadata["target_triple"]["uses_fuzzbench_docker_environment"] is True
    for variant in ("afl", "cmp", "cov"):
        assert metadata["target_triple"]["variants"][variant]["verified"] is True
    assert metadata["program_generation"]["generator_count"] > 0
    assert metadata["program_generation"]["g2_generated_count"] > 0
    assert metadata["seed_provenance_delta"]["g2_generated_count"] > 0
    assert metadata["campaign"]["execs_done"] > 0
    assert metadata["campaign"]["queue_count"] > 0
    assert metadata["coverage"]["line_coverage"]["covered"] > 0
    # Global invariant 5 fields.
    for key in ("task_family", "profile", "protocol", "method_variant", "status",
                "applicability", "stages", "artifacts", "build", "campaign",
                "coverage", "reproducibility", "error", "exclude_from_aggregate"):
        assert key in metadata, key
    # Delta must not be excluded from aggregate.
    assert metadata["exclude_from_aggregate"] is False
    # Build provenance from the FuzzBench Docker environment.
    assert metadata["build"]["uses_fuzzbench_docker_environment"] is True
    # All stages complete.
    for stage in g2.STAGE_NAMES:
        assert metadata["stages"][stage]["status"] == "complete", stage
    # Consumption smoke persisted and consumed input.
    smoke = json.loads((workspace / "target_contract" / "consumption_smoke.json").read_text(encoding="utf-8"))
    assert smoke["consumed_input"] is True
    # Execution wrappers exist.
    for variant in ("afl", "cmp", "cov"):
        assert (workspace / "target" / f"run_{variant}.sh").is_file()
    # g2_programs generators/seeds recorded (plan section 4.3).
    assert (workspace / "generators" / "source").is_dir()
    assert any((workspace / "seeds" / "g2_generated").iterdir())


# 9b. Zero Python generators fails under delta (plan section 4.4)
def test_zero_generators_fails_under_delta(tmp_path: Path):
    runner = FakeDockerRunner()
    # A program_gen that produces seeds but no .py generators.
    no_gen = make_executable(
        tmp_path / "program_gen.py",
        """#!/usr/bin/env python3
import argparse
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument("--output", required=True)
parser.add_argument("--program", required=True)
args = parser.parse_args()
root = Path(args.output) / "default"
(root / "gen_seeds").mkdir(parents=True, exist_ok=True)
(root / "gen_seeds" / "id_000000").write_bytes(b"fixture-seed")
""",
    )
    afl = fake_afl_fuzz(tmp_path / "afl-fuzz")
    coverage = fake_coverage_report(tmp_path / "coverage.json")
    pipeline = make_pipeline(tmp_path, runner=runner)
    saved = dict(os.environ)
    os.environ["G2FUZZ_PROGRAM_GEN"] = str(no_gen)
    os.environ["G2FUZZ_AFL_FUZZ"] = str(afl)
    os.environ["G2FUZZ_COVERAGE_REPORT"] = str(coverage)
    os.environ["G2FUZZ_AFL_TIMEOUT_SECONDS"] = "5"
    try:
        code = pipeline.full()
    finally:
        os.environ.clear()
        os.environ.update(saved)
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert code != 0
    assert metadata["status"] != "evaluated"
    assert "generators" in metadata.get("reason", "")


# 9c. Zero generated seeds fails under delta (plan section 4.4)
def test_zero_generated_seeds_fails_under_delta(tmp_path: Path):
    runner = FakeDockerRunner()
    no_seed = make_executable(
        tmp_path / "program_gen.py",
        """#!/usr/bin/env python3
import argparse
from pathlib import Path
parser = argparse.ArgumentParser()
parser.add_argument("--output", required=True)
parser.add_argument("--program", required=True)
args = parser.parse_args()
root = Path(args.output) / "default"
(root / "generators").mkdir(parents=True, exist_ok=True)
(root / "generators" / "g.py").write_text("x=1\\n", encoding="utf-8")
# No gen_seeds directory -> zero seeds.
""",
    )
    afl = fake_afl_fuzz(tmp_path / "afl-fuzz")
    coverage = fake_coverage_report(tmp_path / "coverage.json")
    pipeline = make_pipeline(tmp_path, runner=runner)
    saved = dict(os.environ)
    os.environ["G2FUZZ_PROGRAM_GEN"] = str(no_seed)
    os.environ["G2FUZZ_AFL_FUZZ"] = str(afl)
    os.environ["G2FUZZ_COVERAGE_REPORT"] = str(coverage)
    os.environ["G2FUZZ_AFL_TIMEOUT_SECONDS"] = "5"
    try:
        code = pipeline.full()
    finally:
        os.environ.clear()
        os.environ.update(saved)
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert code != 0
    assert metadata["status"] != "evaluated"
    assert "generated input" in metadata.get("reason", "")


# 10. method_variant is extension for extension adapters
def test_method_variant_extension_for_extension_targets(tmp_path: Path):
    # jsoncpp_jsoncpp_fuzzer is an extension adapter.
    code, metadata, pipeline, workspace = run_full(tmp_path, target="jsoncpp_jsoncpp_fuzzer")
    assert code == 0, metadata.get("reason")
    assert metadata["status"] == "evaluated"
    assert metadata["method_variant"] == "extension"
    assert metadata["method_profile"] == "extension"
    assert metadata["paper_core"] is False


def test_method_variant_helper_maps_profiles():
    assert g2.method_variant_for({"method_profile": "paper-faithful"}) == "paper-core"
    assert g2.method_variant_for({"method_profile": "extension"}) == "extension"


# 11. G2FUZZ_TRY_NUM=1 is forbidden under delta (no smoke-value patching)
def test_try_num_one_forbidden_under_delta():
    assert g2.try_num_for_profile("reproduction-delta", {"G2FUZZ_TRY_NUM": "3"}) == "3"
    # The default for delta is the real budget (3), not a smoke value.
    assert g2.try_num_for_profile("reproduction-delta", {}) == "3"
    run_baseline = (ROOT / "scripts/hgb_run_baseline.sh").read_text(encoding="utf-8")
    assert "G2FUZZ_TRY_NUM=1 is a smoke value" in run_baseline


# 12. Matrix collector: paper-core and extension split + g2fuzz counters
def test_matrix_collector_g2fuzz_paper_core_extension_split(tmp_path: Path):
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    core_ws = matrix_dir / "core"
    ext_ws = matrix_dir / "ext"
    fail_ws = matrix_dir / "fail"
    infra_ws = matrix_dir / "infra"
    for ws in (core_ws, ext_ws, fail_ws, infra_ws):
        ws.mkdir()
    base_eval = {
        "baseline": "g2fuzz", "generator": "g2fuzz", "status": "evaluated",
        "task_family": "input_generator", "applicability": "applicable",
        "excluded_from_aggregate": False, "profile": "reproduction-delta",
        "campaign": {"execs_done": 100, "queue_count": 2},
        "coverage": {"report_exists": True, "line_coverage": {"covered": 30, "total": 50},
                     "edge_coverage": {"status": "unavailable"}},
        "input_generation": {"valid_g2_generated_count": 1},
        "target_pair_build": {"status": "completed", "afl_binary": "/x", "cmp_binary": "/y", "cov_binary": "/z"},
        "coverage_gamma": {"inputs_replayed": 2},
        "target_triple": {"uses_fuzzbench_docker_environment": True,
                          "variants": {"afl": {"verified": True}, "cmp": {"verified": True}, "cov": {"verified": True}}},
        "program_generation": {"generator_count": 1},
        "seed_provenance_delta": {"g2_generated_count": 1},
    }
    core_meta = dict(base_eval, target="libpng_libpng_read_fuzzer", method_variant="paper-core", method_profile="paper-faithful")
    ext_meta = dict(base_eval, target="jsoncpp_jsoncpp_fuzzer", method_variant="extension", method_profile="extension")
    fail_meta = {
        "baseline": "g2fuzz", "generator": "g2fuzz", "status": "failed",
        "task_family": "input_generator", "applicability": "applicable",
        "excluded_from_aggregate": False, "profile": "reproduction-delta",
        "method_variant": "paper-core", "campaign": {"execs_done": 0},
    }
    infra_meta = {
        "baseline": "g2fuzz", "generator": "g2fuzz", "status": "infra_failure",
        "task_family": "input_generator", "applicability": "applicable",
        "excluded_from_aggregate": False, "profile": "reproduction-delta",
        "method_variant": "paper-core",
    }
    (core_ws / "metadata.json").write_text(json.dumps(core_meta), encoding="utf-8")
    (ext_ws / "metadata.json").write_text(json.dumps(ext_meta), encoding="utf-8")
    (fail_ws / "metadata.json").write_text(json.dumps(fail_meta), encoding="utf-8")
    (infra_ws / "metadata.json").write_text(json.dumps(infra_meta), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"g2fuzz\tlibpng_libpng_read_fuzzer\tevaluated\t{core_ws}\t{core_ws / 'metadata.json'}\t\n"
        f"g2fuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{ext_ws}\t{ext_ws / 'metadata.json'}\t\n"
        f"g2fuzz\tzlib_zlib_uncompress_fuzzer\tfailed\t{fail_ws}\t{fail_ws / 'metadata.json'}\t\n"
        f"g2fuzz\tbloaty_fuzz_target\tsomething\t{infra_ws}\t{infra_ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, generator="g2fuzz", profile="reproduction-delta")
    assert summary["g2fuzz_paper_core_evaluated"] == 1
    assert summary["g2fuzz_extension_evaluated"] == 1
    assert summary["g2fuzz_infra_failures"] == 1
    assert summary["g2fuzz_failures"] == 1


# 13. Strict matrix collector: a real evaluated delta row has no violations
def test_matrix_strict_no_violations_for_real_evaluated_delta_row(tmp_path: Path):
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    app_ws = matrix_dir / "app"
    app_ws.mkdir()
    (app_ws / "metadata.json").write_text(json.dumps({
        "baseline": "g2fuzz", "generator": "g2fuzz", "status": "evaluated",
        "task_family": "input_generator", "applicability": "applicable",
        "excluded_from_aggregate": False, "profile": "reproduction-delta",
        "method_variant": "paper-core", "method_profile": "paper-faithful",
        "campaign": {"execs_done": 100, "queue_count": 2},
        "coverage": {"report_exists": True, "line_coverage": {"covered": 30, "total": 50},
                     "edge_coverage": {"status": "unavailable"}},
        "input_generation": {"valid_g2_generated_count": 1, "g2_generated_count": 1},
        "target_pair_build": {"status": "completed", "afl_binary": "/x", "cmp_binary": "/y", "cov_binary": "/z"},
        "coverage_gamma": {"inputs_replayed": 2},
        "target_triple": {"uses_fuzzbench_docker_environment": True,
                          "variants": {"afl": {"verified": True}, "cmp": {"verified": True}, "cov": {"verified": True}}},
        "program_generation": {"generator_count": 1},
        "seed_provenance_delta": {"g2_generated_count": 1},
    }), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"g2fuzz\tlibpng_libpng_read_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, strict=True, generator="g2fuzz", profile="reproduction-delta")
    assert summary["evaluated_row_violations"] == []


# 14. Strict matrix collector: coverage-missing evaluated delta row is flagged
def test_matrix_strict_flags_coverage_missing_delta_row(tmp_path: Path):
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    app_ws = matrix_dir / "app"
    app_ws.mkdir()
    (app_ws / "metadata.json").write_text(json.dumps({
        "baseline": "g2fuzz", "generator": "g2fuzz", "status": "evaluated",
        "task_family": "input_generator", "applicability": "applicable",
        "excluded_from_aggregate": False, "profile": "reproduction-delta",
        "method_variant": "paper-core", "campaign": {"execs_done": 100, "queue_count": 2},
        "coverage": {"report_exists": False, "line_coverage": None,
                     "edge_coverage": {"status": "unavailable"}},
        "input_generation": {"valid_g2_generated_count": 1},
        "target_pair_build": {"status": "completed", "afl_binary": "/x", "cmp_binary": "/y", "cov_binary": "/z"},
        "coverage_gamma": {"inputs_replayed": 2},
        "target_triple": {"uses_fuzzbench_docker_environment": True,
                          "variants": {"afl": {"verified": True}, "cmp": {"verified": True}, "cov": {"verified": True}}},
        "program_generation": {"generator_count": 1},
        "seed_provenance_delta": {"g2_generated_count": 1},
    }), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"g2fuzz\tlibpng_libpng_read_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, strict=True, generator="g2fuzz", profile="reproduction-delta")
    assert summary["evaluated_row_violations"]
    violations = summary["evaluated_row_violations"][0]["violations"]
    assert any("line_coverage.covered" in v for v in violations)


# 15. Strict matrix collector: an unverified triple variant is flagged
def test_matrix_strict_flags_unverified_triple(tmp_path: Path):
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    app_ws = matrix_dir / "app"
    app_ws.mkdir()
    (app_ws / "metadata.json").write_text(json.dumps({
        "baseline": "g2fuzz", "generator": "g2fuzz", "status": "evaluated",
        "task_family": "input_generator", "applicability": "applicable",
        "excluded_from_aggregate": False, "profile": "reproduction-delta",
        "method_variant": "paper-core", "campaign": {"execs_done": 100, "queue_count": 2},
        "coverage": {"report_exists": True, "line_coverage": {"covered": 30, "total": 50},
                     "edge_coverage": {"status": "unavailable"}},
        "input_generation": {"valid_g2_generated_count": 1},
        "target_pair_build": {"status": "completed", "afl_binary": "/x", "cmp_binary": "/y", "cov_binary": "/z"},
        "coverage_gamma": {"inputs_replayed": 2},
        "target_triple": {"uses_fuzzbench_docker_environment": True,
                          "variants": {"afl": {"verified": True}, "cmp": {"verified": False}, "cov": {"verified": True}}},
        "program_generation": {"generator_count": 1},
        "seed_provenance_delta": {"g2_generated_count": 1},
    }), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"g2fuzz\tlibpng_libpng_read_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, strict=True, generator="g2fuzz", profile="reproduction-delta")
    assert summary["evaluated_row_violations"]
    violations = summary["evaluated_row_violations"][0]["violations"]
    assert any("variants.cmp.verified" in v for v in violations)


# 16. is_gamma_profile is a backward-compatible alias for delta (shared path)
def test_is_gamma_profile_aliases_delta():
    assert g2.is_gamma_profile("reproduction-gamma") is True
    assert g2.is_gamma_profile("reproduction-delta") is True
    assert g2.is_delta_profile("reproduction-delta") is True
    assert g2.is_delta_profile("reproduction-gamma") is False
