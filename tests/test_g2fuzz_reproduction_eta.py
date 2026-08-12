"""Eta reproduction tests for the G2Fuzz input-generator pipeline.

These tests exercise the canonical strictest paper-native G2Fuzz reproduction
contract from ``plans/g2fuzz_reproduction_eta.md`` with fake Docker/CLI
fixtures so they pass without real external checkouts, Docker, AFL++ builds,
or model access.

G2Fuzz is an ``input_generator`` (it synthesizes Python input generators and
seeds for a fixed native FuzzBench target triple, then drives its modified
AFL++ with CmpLog), never a harness generator. It is kept out of the
harness-generator leaderboard.

The eta plan adds these requirements on top of zeta:
* eta is the canonical strictest profile; zeta/epsilon/delta remain aliases.
* eta profile acceptance and G2FUZZ_TARGET_DIR rejection.
* Fake AFL/program_gen timeout process-group kill.
* CmpLog env reaches the build environment.
* Runtime closure/wrapper exists and is used by campaign.
* Precomputed coverage report rejected outside fixture mode.
* Evaluated row requires target triple, instrumentation check, generated
  seed, AFL queue, execs, and real coverage.
* Paper-core and extension aggregation remain separate.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
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


g2 = load_module("g2fuzz_target_pipeline_eta", ROOT / "docker/common/g2fuzz_target_pipeline.py")
builder = load_module("hgb_fuzzbench_builder_eta", ROOT / "docker/common/hgb_fuzzbench_builder.py")
matrix_collector = load_module("hgb_collect_matrix_eta", ROOT / "scripts/hgb_collect_matrix.py")


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
    """Simulates the G2Fuzz triple Docker build and the coverage replay shell."""

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
        profile="reproduction-eta",
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


def _run_env():
    env = dict(os.environ)
    env["PATH"] = str(ROOT / "scripts") + os.pathsep + env.get("PATH", "")
    return env


# ---------------------------------------------------------------------------
# E0. Profile acceptance and strictness
# ---------------------------------------------------------------------------


def test_reproduction_eta_is_the_strictest_profile():
    assert g2.is_gamma_profile("reproduction-eta") is True
    assert g2.is_delta_profile("reproduction-eta") is True
    assert g2.is_zeta_profile("reproduction-eta") is True
    assert g2.is_eta_profile("reproduction-eta") is True
    # zeta, epsilon and delta remain accepted.
    assert g2.is_delta_profile("reproduction-zeta") is True
    assert g2.is_delta_profile("reproduction-epsilon") is True
    assert g2.is_delta_profile("reproduction-delta") is True
    assert g2.is_gamma_profile("reproduction-gamma") is True


def test_reproduction_eta_profile_accepted_by_host_runner():
    proc = subprocess.run(
        ["bash", str(ROOT / "scripts/hgb_run_baseline.sh"), "--dry-run",
         "--generator", "g2fuzz", "--target", "libpng_libpng_read_fuzzer",
         "--profile", "reproduction-eta", "--protocol", "paper-native"],
        cwd=ROOT, text=True, capture_output=True, check=False, env=_run_env(),
    )
    assert proc.returncode == 0, proc.stderr


def test_dry_run_reports_input_generator_task_family():
    proc = subprocess.run(
        ["bash", str(ROOT / "scripts/hgb_run_baseline.sh"), "--dry-run",
         "--generator", "g2fuzz", "--target", "libpng_libpng_read_fuzzer",
         "--profile", "reproduction-eta", "--protocol", "paper-native"],
        cwd=ROOT, text=True, capture_output=True, check=False, env=_run_env(),
    )
    assert proc.returncode == 0, proc.stderr
    workspace = proc.stdout.strip().splitlines()[-1]
    result = json.loads((Path(workspace) / "result.json").read_text(encoding="utf-8"))
    assert result["task_family"] == "input_generator"
    assert result["profile"] == "reproduction-eta"
    assert result["method_variant"] == "paper-faithful"


def test_unknown_profile_exits_with_code_2():
    proc = subprocess.run(
        ["bash", str(ROOT / "scripts/hgb_run_baseline.sh"), "--dry-run",
         "--generator", "g2fuzz", "--target", "libpng_libpng_read_fuzzer",
         "--profile", "reproduction-nonexistent", "--protocol", "paper-native"],
        cwd=ROOT, text=True, capture_output=True, check=False, env=_run_env(),
    )
    assert proc.returncode == 2, proc.stderr
    assert "invalid profile" in proc.stderr


def test_entrypoint_accepts_reproduction_eta():
    entrypoint = (ROOT / "docker/g2fuzz/entrypoint.sh").read_text(encoding="utf-8")
    assert "reproduction-eta" in entrypoint
    assert '"$HGB_BASELINE_PROFILE" == "reproduction-eta"' in entrypoint


# ---------------------------------------------------------------------------
# E1. G2FUZZ_TARGET_DIR rejection
# ---------------------------------------------------------------------------


def test_eta_refuses_prebuilt_target_dir(tmp_path: Path):
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
            "--profile", "reproduction-eta",
            "--protocol", "paper-native",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode != 0
    metadata_path = tmp_path / "workspace" / "metadata.json"
    assert metadata_path.is_file()
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["status"] in {"infra_missing", "infra_failure"}
    assert "G2FUZZ_TARGET_DIR" in metadata.get("reason", "")


# ---------------------------------------------------------------------------
# E2. Fake AFL/program_gen timeout process-group kill
# ---------------------------------------------------------------------------


def test_run_subprocess_kills_process_group_on_timeout(tmp_path: Path):
    script = (
        "#!/usr/bin/env python3\n"
        "import signal, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
        "time.sleep(3600)\n"
    )
    fake = make_executable(tmp_path / "hang.py", script)
    log = tmp_path / "log.txt"
    start = time.time()
    code, timed_out = g2.run_subprocess([str(fake)], log, timeout=3)
    elapsed = time.time() - start
    assert timed_out is True
    assert code == 124
    assert elapsed < 20, f"process group kill took {elapsed:.1f}s"


def test_pytest_auto_cap_kills_long_running_subprocess(tmp_path: Path):
    script = (
        "#!/usr/bin/env python3\n"
        "import signal, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
        "time.sleep(86400)\n"
    )
    fake = make_executable(tmp_path / "long_afl.py", script)
    log = tmp_path / "log.txt"
    start = time.time()
    code, timed_out = g2.run_subprocess([str(fake)], log, timeout=86400)
    elapsed = time.time() - start
    assert timed_out is True
    assert code == 124
    assert elapsed < 40


def test_run_subprocess_normal_completion(tmp_path: Path):
    script = "#!/usr/bin/env python3\nprint('ok')\n"
    fake = make_executable(tmp_path / "ok.py", script)
    log = tmp_path / "log.txt"
    code, timed_out = g2.run_subprocess([str(fake)], log, timeout=10)
    assert code == 0
    assert timed_out is False


# ---------------------------------------------------------------------------
# E3. CmpLog env reaches the build environment
# ---------------------------------------------------------------------------


def test_cmplog_build_arg_present_in_triple_commands():
    commands = builder.g2fuzz_target_triple_build_commands(
        benchmark_dir=Path("/bench"),
        image_tag_base="hgb-g2fuzz-test",
        fuzz_target="fuzz_target",
        program_id="prog",
    )
    cmp_build_args = commands["cmp"]["build_args"]
    cmp_env = commands["cmp"]["env"]
    assert any("AFL_LLVM_CMPLOG=1" in arg for arg in cmp_build_args), cmp_build_args
    assert cmp_env.get("AFL_LLVM_CMPLOG") == "1", cmp_env
    afl_env = commands["afl"]["env"]
    assert afl_env.get("AFL_LLVM_CMPLOG") == "0", afl_env


def test_triple_build_commands_recorded(tmp_path: Path):
    code, metadata, pipeline, workspace = run_full(tmp_path)
    assert code == 0, metadata.get("reason")
    build_commands = json.loads((workspace / "target_pair" / "build_commands.json").read_text(encoding="utf-8"))
    assert build_commands["build_mode"] == "fuzzbench_docker_triple"
    assert "afl" in build_commands
    assert "cmp" in build_commands
    assert "cov" in build_commands


# ---------------------------------------------------------------------------
# E4. Runtime closure/wrapper exists and is used by campaign
# ---------------------------------------------------------------------------


def test_runtime_environment_and_wrappers_exist(tmp_path: Path):
    code, metadata, pipeline, workspace = run_full(tmp_path)
    assert code == 0, metadata.get("reason")
    assert (workspace / "target_pair" / "runtime_environment.json").is_file()
    runtime_env = json.loads((workspace / "target_pair" / "runtime_environment.json").read_text(encoding="utf-8"))
    assert runtime_env.get("uses_fuzzbench_docker_environment") is True
    for variant in ("afl", "cmp", "cov"):
        assert (workspace / "target" / f"run_{variant}.sh").is_file()


def test_campaign_command_uses_cmplog_target(tmp_path: Path):
    code, metadata, pipeline, workspace = run_full(tmp_path)
    assert code == 0, metadata.get("reason")
    cmd = (workspace / "campaign" / "command.txt").read_text(encoding="utf-8")
    assert " -c " in cmd
    assert "target.cmp" in cmd


# ---------------------------------------------------------------------------
# E5. Precomputed coverage report rejected outside fixture mode
# ---------------------------------------------------------------------------


def test_eta_rejects_coverage_report_in_production(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    coverage = fake_coverage_report(tmp_path / "cov.json")
    package = make_target_package(tmp_path)
    pipeline = g2.G2FuzzPipeline(
        workspace=tmp_path / "workspace",
        target="libpng_libpng_read_fuzzer",
        target_package=package,
        artifact_dir=tmp_path / "artifact",
        metadata_root=ROOT / "metadata",
        profile="reproduction-eta",
        protocol="paper-native",
    )
    pipeline.runner = FakeDockerRunner()
    saved = dict(os.environ)
    os.environ["G2FUZZ_PROGRAM_GEN"] = str(fake_program_gen(tmp_path / "program_gen.py"))
    os.environ["G2FUZZ_AFL_FUZZ"] = str(fake_afl_fuzz(tmp_path / "afl-fuzz"))
    os.environ["G2FUZZ_COVERAGE_REPORT"] = str(coverage)
    os.environ["G2FUZZ_AFL_TIMEOUT_SECONDS"] = "5"
    os.environ.pop("PYTEST_CURRENT_TEST", None)
    try:
        code = pipeline.full()
    finally:
        os.environ.clear()
        os.environ.update(saved)
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] != "evaluated"
    assert metadata["stages"]["coverage"]["status"] == "failed"


def test_eta_accepts_coverage_report_in_fixture_mode(tmp_path: Path):
    code, metadata, pipeline, workspace = run_full(tmp_path, set_coverage_report=True)
    assert code == 0, metadata.get("reason")
    assert metadata["status"] == "evaluated"
    assert metadata["coverage"]["report_exists"] is True


# ---------------------------------------------------------------------------
# E6. Evaluated row requires full closed loop
# ---------------------------------------------------------------------------


def test_eta_evaluated_requires_full_closed_loop(tmp_path: Path):
    code, metadata, pipeline, workspace = run_full(tmp_path)
    assert code == 0, metadata.get("reason")
    assert metadata["status"] == "evaluated"
    assert metadata["task_family"] == "input_generator"
    assert metadata["target_pair_build"]["status"] == "completed"
    assert metadata["target_triple"]["uses_fuzzbench_docker_environment"] is True
    for v in ("afl", "cmp", "cov"):
        assert metadata["target_triple"]["variants"][v]["verified"] is True
    assert metadata["instrumentation_check"]["all_passed"] is True
    assert metadata["program_generation"]["generator_count"] > 0
    assert metadata["seed_provenance_delta"]["g2_generated_count"] > 0
    assert metadata["input_generation"]["valid_g2_generated_count"] > 0
    assert metadata["campaign"]["execs_done"] > 0
    assert metadata["coverage"]["report_exists"] is True
    assert metadata["coverage"]["line_coverage"]["covered"] > 0
    assert metadata["runtime_environment"]
    assert (workspace / "campaign" / "command.txt").is_file()
    assert (workspace / "campaign" / "output" / "default" / "fuzzer_stats").is_file()


def test_eta_evaluated_fails_without_real_coverage(tmp_path: Path):
    code, metadata, pipeline, workspace = run_full(
        tmp_path, coverage_stdout="", set_coverage_report=False
    )
    assert code != 0
    assert metadata["status"] != "evaluated"
    assert metadata["stages"]["coverage"]["status"] == "failed"


def test_eta_evaluated_fails_with_zero_execs(tmp_path: Path):
    program_gen = fake_program_gen(tmp_path / "program_gen.py")
    afl = fake_afl_fuzz(tmp_path / "afl-fuzz", execs_done=0, queue=False)
    coverage = fake_coverage_report(tmp_path / "coverage.json")
    pipeline = make_pipeline(tmp_path, runner=FakeDockerRunner())
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
    assert metadata["status"] != "evaluated"
    assert metadata["stages"]["campaign"]["status"] == "failed"


# ---------------------------------------------------------------------------
# E7. Paper-core and extension aggregation remain separate
# ---------------------------------------------------------------------------


def test_method_variant_paper_core_for_paper_native_targets(tmp_path: Path):
    code, metadata, pipeline, workspace = run_full(tmp_path, target="libpng_libpng_read_fuzzer")
    assert code == 0, metadata.get("reason")
    assert metadata["method_variant"] == "paper-core"
    assert metadata["method_profile"] == "paper-faithful"
    assert metadata["applicability_group"] == "paper-core"


def test_method_variant_extension_for_extension_targets(tmp_path: Path):
    code, metadata, pipeline, workspace = run_full(tmp_path, target="jsoncpp_jsoncpp_fuzzer")
    assert code == 0, metadata.get("reason")
    assert metadata["status"] == "evaluated"
    assert metadata["method_variant"] == "extension"
    assert metadata["method_profile"] == "extension"
    assert metadata["applicability_group"] == "extension"


def test_matrix_collector_g2fuzz_paper_core_extension_split(tmp_path: Path):
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    core_ws = matrix_dir / "core"
    ext_ws = matrix_dir / "ext"
    for ws in (core_ws, ext_ws):
        ws.mkdir()
    base_eval = {
        "baseline": "g2fuzz", "generator": "g2fuzz", "status": "evaluated",
        "task_family": "input_generator", "applicability": "applicable",
        "excluded_from_aggregate": False, "profile": "reproduction-eta",
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
        "instrumentation_check": {"all_passed": True},
        "runtime_environment": {"strategy": "extracted_out_closure", "uses_fuzzbench_docker_environment": True},
    }
    core_meta = dict(base_eval, target="libpng_libpng_read_fuzzer", method_variant="paper-core", method_profile="paper-faithful", applicability_group="paper-core")
    ext_meta = dict(base_eval, target="jsoncpp_jsoncpp_fuzzer", method_variant="extension", method_profile="extension", applicability_group="extension")
    (core_ws / "metadata.json").write_text(json.dumps(core_meta), encoding="utf-8")
    (ext_ws / "metadata.json").write_text(json.dumps(ext_meta), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"g2fuzz\tlibpng_libpng_read_fuzzer\tevaluated\t{core_ws}\t{core_ws / 'metadata.json'}\t\n"
        f"g2fuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{ext_ws}\t{ext_ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, strict=True, generator="g2fuzz", profile="reproduction-eta")
    assert summary["evaluated_row_violations"] == []


def test_matrix_collector_eta_flags_missing_instrumentation(tmp_path: Path):
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    app_ws = matrix_dir / "app"
    app_ws.mkdir()
    (app_ws / "metadata.json").write_text(json.dumps({
        "baseline": "g2fuzz", "generator": "g2fuzz", "status": "evaluated",
        "task_family": "input_generator", "applicability": "applicable",
        "excluded_from_aggregate": False, "profile": "reproduction-eta",
        "method_variant": "paper-core",
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
        "instrumentation_check": {"all_passed": False},
        "runtime_environment": {"strategy": "extracted_out_closure"},
    }), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"g2fuzz\tlibpng_libpng_read_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, strict=True, generator="g2fuzz", profile="reproduction-eta")
    assert summary["evaluated_row_violations"]
    violations = summary["evaluated_row_violations"][0]["violations"]
    assert any("instrumentation_check" in v for v in violations)


def test_valuable_target_set_has_twenty_targets():
    hgb_targets = load_module("hgb_targets_eta", ROOT / "scripts/hgb_targets.py")
    registry = hgb_targets.load_registry(ROOT)
    valuable = hgb_targets.targets_for_set(registry, "valuable")
    assert len(valuable) == 20


def test_matrix_runner_wrapper_accepts_eta_args():
    wrapper = (ROOT / "scripts/hgb_run_baseline_matrix.sh").read_text(encoding="utf-8")
    assert "hgb_generate_matrix.sh" in wrapper
    assert "--profile" in wrapper
    assert "--campaign-seconds" in wrapper
    assert '--generators "$generators"' in wrapper
    assert '--profile "$profile"' in wrapper


def test_matrix_collector_accepts_input_generator_flag():
    proc = subprocess.run(
        ["python3", str(ROOT / "scripts/hgb_collect_matrix.py"), "--help"],
        cwd=ROOT, capture_output=True, text=True, timeout=30,
    )
    assert "--require-input-generator-evaluated" in proc.stdout
    assert "--fail-on-invariant-violations" in proc.stdout
