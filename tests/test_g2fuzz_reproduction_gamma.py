"""Gamma reproduction tests for the G2Fuzz input-generator pipeline.

These tests exercise the paper-consistent G2Fuzz reproduction contract from
``plans/g2fuzz_reproduction_gamma.md`` with fake Docker/CLI fixtures so they
pass without real external checkouts, Docker, AFL++ builds, or model access.

G2Fuzz is an ``input_generator`` (it synthesizes Python input generators and
seeds for a fixed native FuzzBench target pair, then drives its modified
AFL++), never a harness generator.
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


g2 = load_module("g2fuzz_target_pipeline_gamma", ROOT / "docker/common/g2fuzz_target_pipeline.py")
builder = load_module("hgb_fuzzbench_builder_gamma", ROOT / "docker/common/hgb_fuzzbench_builder.py")
contract_mod = load_module("g2fuzz_contract_gamma", ROOT / "docker/common/g2fuzz_contract.py")
matrix_collector = load_module("hgb_collect_matrix_gamma", ROOT / "scripts/hgb_collect_matrix.py")


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

    def __init__(self, coverage_stdout: str = COVERAGE_JSON):
        self.commands = []
        self.images: set[str] = set()
        self.coverage_stdout = coverage_stdout

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
                if len(cmd) >= 4:
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
        profile="reproduction-gamma",
        protocol="paper-native",
    )
    if runner is not None:
        pipeline.runner = runner
    return pipeline


# 1. All 20 valuable targets have G2Fuzz adapters with contract_probe: true
def test_all_valuable_targets_have_adapters_with_contract_probe() -> None:
    valuable = g2.valuable_targets(ROOT / "metadata")
    adapters = g2.load_adapters(ROOT / "metadata")

    assert len(valuable) == 20
    assert set(valuable) == set(adapters)
    for adapter in adapters.values():
        assert adapter.get("contract_probe") is True
        assert adapter["applicability"] == "applicable"
        assert adapter["method_profile"] in {"paper-faithful", "extension"}


# 2. Target pair builder refuses direct-host build.sh path in reproduction-gamma
def test_gamma_refuses_direct_host_build_sh(tmp_path: Path) -> None:
    pipeline = make_pipeline(tmp_path)
    # The gamma pipeline must not call auto_build_pair (direct build.sh).
    # Verify that build_target_pair dispatches to build_target_triple_gamma
    # which uses Docker, not auto_build_pair.
    assert g2.is_gamma_profile("reproduction-gamma")
    # auto_build_pair uses build_command_pair which runs "bash <build.sh>"
    # directly on the host; gamma must use the Docker triple builder instead.
    commands = builder.g2fuzz_target_triple_build_commands(
        benchmark_dir=tmp_path / "target" / "fuzzbench_benchmark",
        image_tag_base="hgb-g2fuzz-test",
        fuzz_target="libpng_libpng_read_fuzzer",
        program_id="libpng_libpng_read_fuzzer",
    )
    for variant in ("afl", "cmp", "cov"):
        build_cmd = commands[variant]["build_command"]
        assert build_cmd[0] == "docker"
        assert build_cmd[1] == "build"
        # None of the build commands invoke build.sh directly on the host.
        assert "bash" not in build_cmd or build_cmd[0] != "bash"


# 3. Three distinct build commands/images for .afl, .cmp, .cov
def test_triple_build_emits_three_distinct_docker_builds(tmp_path: Path) -> None:
    bench_dir = tmp_path / "bench"
    bench_dir.mkdir()
    (bench_dir / "Dockerfile").write_text("FROM gcr.io/fuzzbench/base-builder\nRUN compile\n", encoding="utf-8")
    commands = builder.g2fuzz_target_triple_build_commands(
        benchmark_dir=bench_dir,
        image_tag_base="hgb-g2fuzz-triple",
        fuzz_target="libpng_libpng_read_fuzzer",
        program_id="libpng_libpng_read_fuzzer",
    )
    assert commands["build_mode"] == "fuzzbench_docker_triple"
    tags = {commands[v]["image_tag"] for v in ("afl", "cmp", "cov")}
    assert len(tags) == 3  # three distinct image tags
    for variant in ("afl", "cmp", "cov"):
        assert commands[variant]["build_command"][0] == "docker"
        assert commands[variant]["build_command"][1] == "build"
        assert commands[variant]["dockerfile"] == str(bench_dir / "Dockerfile")


# 4. CmpLog build includes AFL_LLVM_CMPLOG=1
def test_cmplog_build_includes_afl_llvm_cmplog() -> None:
    bench_dir = Path("/tmp/bench")
    commands = builder.g2fuzz_target_triple_build_commands(
        benchmark_dir=bench_dir,
        image_tag_base="hgb-g2fuzz-test",
        fuzz_target="t",
        program_id="t",
    )
    # cmp variant must have AFL_LLVM_CMPLOG=1
    cmp_args = commands["cmp"]["build_args"]
    assert "AFL_LLVM_CMPLOG=1" in cmp_args
    assert commands["cmp"]["env"]["AFL_LLVM_CMPLOG"] == "1"
    # afl variant must NOT have AFL_LLVM_CMPLOG=1
    afl_args = commands["afl"]["build_args"]
    assert "AFL_LLVM_CMPLOG=1" not in afl_args
    assert commands["afl"]["env"]["AFL_LLVM_CMPLOG"] == "0"


# 5. Coverage build includes coverage instrumentation flags
def test_coverage_build_includes_coverage_flags() -> None:
    bench_dir = Path("/tmp/bench")
    commands = builder.g2fuzz_target_triple_build_commands(
        benchmark_dir=bench_dir,
        image_tag_base="hgb-g2fuzz-test",
        fuzz_target="t",
        program_id="t",
    )
    cov_env = commands["cov"]["env"]
    assert "-fprofile-instr-generate" in cov_env["CFLAGS"]
    assert "-fcoverage-mapping" in cov_env["CFLAGS"]
    assert "-fprofile-instr-generate" in cov_env["CXXFLAGS"]
    assert "-fcoverage-mapping" in cov_env["CXXFLAGS"]
    # cov uses the coverage engine, not afl
    cov_args = commands["cov"]["build_args"]
    assert "FUZZING_ENGINE=coverage" in cov_args
    assert "FUZZING_ENGINE=afl" not in cov_args


# 6. Prebuilt G2FUZZ_TARGET_DIR is excluded from reproduction aggregate
def test_prebuilt_target_dir_excluded_from_gamma(tmp_path: Path) -> None:
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
            "--profile", "reproduction-gamma",
            "--protocol", "paper-native",
        ],
        cwd=ROOT, env=env, text=True, capture_output=True, check=False,
    )
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    # Gamma must refuse the prebuilt pair, not use it.
    assert metadata["status"] == "infra_missing"
    assert "G2FUZZ_TARGET_DIR" in metadata["reason"]
    assert proc.returncode != 0
    # hgb_run_baseline.sh also refuses G2FUZZ_TARGET_DIR in gamma.
    run_baseline = (ROOT / "scripts/hgb_run_baseline.sh").read_text(encoding="utf-8")
    assert "g2fuzz/reproduction-gamma: G2FUZZ_TARGET_DIR is forbidden" in run_baseline


# 7. Contract probe must pass before campaign
def test_contract_probe_runs_before_campaign(tmp_path: Path) -> None:
    runner = FakeDockerRunner()
    program_gen = fake_program_gen(tmp_path / "program_gen.py")
    afl = fake_afl_fuzz(tmp_path / "afl-fuzz")
    coverage = fake_coverage_report(tmp_path / "coverage.json")
    pipeline = make_pipeline(tmp_path, runner=runner)
    os.environ["G2FUZZ_PROGRAM_GEN"] = str(program_gen)
    os.environ["G2FUZZ_AFL_FUZZ"] = str(afl)
    os.environ["G2FUZZ_COVERAGE_REPORT"] = str(coverage)
    os.environ["G2FUZZ_AFL_TIMEOUT_SECONDS"] = "5"
    code = pipeline.full()
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert code == 0, metadata.get("reason")
    # contract.json exists in target_pair dir
    contract_path = tmp_path / "workspace" / "target_pair" / "contract.json"
    assert contract_path.is_file()
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    assert contract["valid"] is True
    # The contract probe ran before the campaign stage completed.
    assert metadata["stages"]["target_pair_built"]["status"] == "complete"
    assert metadata["stages"]["campaign"]["status"] == "complete"


# 8. Generated seed count excludes config/source/log/common/preseed files
def test_generated_seed_count_excludes_non_inputs(tmp_path: Path) -> None:
    produced = tmp_path / "gen_seeds"
    produced.mkdir()
    (produced / "input_000").write_bytes(b'{"k": 0}')
    (produced / "evolved.py").write_text("x=1\n", encoding="utf-8")
    (produced / "meta.json").write_text("{}", encoding="utf-8")
    (produced / "run.log").write_text("log\n", encoding="utf-8")
    (produced / "config.yaml").write_text("k: v\n", encoding="utf-8")
    (produced / "preseed_corpus").write_bytes(b"seed")
    (produced / "common_0000_seed").write_bytes(b"common")
    (produced / "hgb_corpus_0000").write_bytes(b"corpus")
    (produced / "manifest.txt").write_text("m\n", encoding="utf-8")
    (produced / "readme.txt").write_text("r\n", encoding="utf-8")
    (produced / "model_setting.json").write_text("{}", encoding="utf-8")
    assert g2.is_generated_input_candidate(produced / "input_000")
    assert not g2.is_generated_input_candidate(produced / "evolved.py")
    assert not g2.is_generated_input_candidate(produced / "meta.json")
    assert not g2.is_generated_input_candidate(produced / "run.log")
    assert not g2.is_generated_input_candidate(produced / "config.yaml")
    assert not g2.is_generated_input_candidate(produced / "preseed_corpus")
    assert not g2.is_generated_input_candidate(produced / "common_0000_seed")
    assert not g2.is_generated_input_candidate(produced / "hgb_corpus_0000")
    assert not g2.is_generated_input_candidate(produced / "manifest.txt")
    assert not g2.is_generated_input_candidate(produced / "readme.txt")
    assert not g2.is_generated_input_candidate(produced / "model_setting.json")


# 9. Campaign timeout only counts complete if execs_done > 0 and queue/crash evidence
def test_campaign_execs_done_zero_not_completed(tmp_path: Path) -> None:
    runner = FakeDockerRunner()
    program_gen = fake_program_gen(tmp_path / "program_gen.py")
    afl = fake_afl_fuzz(tmp_path / "afl-fuzz", execs_done=0, queue=True)
    coverage = fake_coverage_report(tmp_path / "coverage.json")
    pipeline = make_pipeline(tmp_path, runner=runner)
    os.environ["G2FUZZ_PROGRAM_GEN"] = str(program_gen)
    os.environ["G2FUZZ_AFL_FUZZ"] = str(afl)
    os.environ["G2FUZZ_COVERAGE_REPORT"] = str(coverage)
    os.environ["G2FUZZ_AFL_TIMEOUT_SECONDS"] = "5"
    code = pipeline.full()
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert code != 0
    assert metadata["stages"]["campaign"]["status"] != "complete"
    assert metadata["campaign"]["execs_done"] == 0
    assert metadata["status"] != "evaluated"


# 10. Coverage fails if only AFL path counters are present
def test_coverage_fails_on_afl_paths_only(tmp_path: Path) -> None:
    runner = FakeDockerRunner(coverage_stdout="")
    program_gen = fake_program_gen(tmp_path / "program_gen.py")
    afl = fake_afl_fuzz(tmp_path / "afl-fuzz")
    pipeline = make_pipeline(tmp_path, runner=runner)
    os.environ["G2FUZZ_PROGRAM_GEN"] = str(program_gen)
    os.environ["G2FUZZ_AFL_FUZZ"] = str(afl)
    os.environ["G2FUZZ_AFL_TIMEOUT_SECONDS"] = "5"
    # No G2FUZZ_COVERAGE_REPORT -> must try replay; empty stdout -> no report.
    os.environ.pop("G2FUZZ_COVERAGE_REPORT", None)
    code = pipeline.full()
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert code != 0
    assert metadata["stages"]["coverage"]["status"] != "complete"
    assert metadata["coverage"]["line_coverage"] is None
    assert metadata["coverage"]["edge_coverage"]["status"] == "unavailable"
    assert metadata["status"] != "evaluated"


# 11. status=evaluated requires target pair, program generation, valid seeds, campaign, coverage
def test_evaluated_requires_full_closed_loop(tmp_path: Path) -> None:
    runner = FakeDockerRunner()
    program_gen = fake_program_gen(tmp_path / "program_gen.py")
    afl = fake_afl_fuzz(tmp_path / "afl-fuzz")
    coverage = fake_coverage_report(tmp_path / "coverage.json")
    pipeline = make_pipeline(tmp_path, runner=runner)
    os.environ["G2FUZZ_PROGRAM_GEN"] = str(program_gen)
    os.environ["G2FUZZ_AFL_FUZZ"] = str(afl)
    os.environ["G2FUZZ_COVERAGE_REPORT"] = str(coverage)
    os.environ["G2FUZZ_AFL_TIMEOUT_SECONDS"] = "5"
    code = pipeline.full()
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert code == 0, metadata.get("reason")
    assert metadata["status"] == "evaluated"
    assert metadata["task_family"] == "input_generator"
    assert metadata["baseline"] == "g2fuzz"
    assert metadata["profile"] == "reproduction-gamma"
    # Gamma schema: g2fuzz nested object
    assert metadata["g2fuzz"]["program_id"] == "libpng_libpng_read_fuzzer"
    assert metadata["g2fuzz"]["cmplog_enabled"] is True
    assert metadata["g2fuzz"]["g2_generated_seeds"] >= 1
    assert metadata["g2fuzz"]["valid_g2_generated_seeds"] >= 1
    # Gamma schema: target_pair with afl/cmp/cov
    for variant in ("afl", "cmp", "cov"):
        assert metadata["target_pair"][variant]["path"]
        assert metadata["target_pair"][variant]["sha256"]
        assert Path(metadata["target_pair"][variant]["path"]).is_file()
    # Gamma schema: campaign with queued_paths
    assert metadata["campaign_gamma"]["execs_done"] > 0
    assert metadata["campaign_gamma"]["queued_paths"] > 0
    # Gamma schema: coverage with line/region/function and inputs_replayed
    assert metadata["coverage_gamma"]["line_coverage"] > 0
    assert metadata["coverage_gamma"]["inputs_replayed"] > 0
    # All target pair binaries exist
    assert (tmp_path / "workspace" / "target_pair" / "target.afl").is_file()
    assert (tmp_path / "workspace" / "target_pair" / "target.cmp").is_file()
    assert (tmp_path / "workspace" / "target_pair" / "target.cov").is_file()
    # Build logs exist
    for variant in ("afl", "cmp", "cov"):
        assert (tmp_path / "workspace" / "target_pair" / f"build.{variant}.log").is_file()
    # Contract.json exists
    assert (tmp_path / "workspace" / "target_pair" / "contract.json").is_file()
    # Coverage outputs exist
    assert (tmp_path / "workspace" / "coverage" / "coverage.json").is_file()
    # Seed provenance with merged_initial
    provenance = [
        json.loads(line)
        for line in (tmp_path / "workspace" / "seeds" / "provenance.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    source_classes = {r["source_class"] for r in provenance}
    assert "g2_generated" in source_classes
    assert "merged_initial" in source_classes
    # All stages complete
    for stage in g2.STAGE_NAMES:
        assert metadata["stages"][stage]["status"] == "complete", stage
    # Method profile and protocol
    assert metadata["method_profile"] == "paper-faithful"
    assert metadata["protocol"] == "paper-native"
