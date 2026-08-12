"""Eta reproduction tests for the ELFuzz input-generator pipeline.

These tests exercise the canonical strictest paper-native ELFuzz reproduction
contract from ``plans/elfuzz_reproduction_eta.md`` with fake Docker/CLI
runners so they pass without real external checkouts, Docker, TGI, or model
access.

ELFuzz is an ``input_generator`` (it synthesizes and evolves input-producing
fuzzer programs against a fixed native FuzzBench target, then replays
generated/campaign inputs on a coverage-instrumented SUT), never a harness
generator. It is kept out of the harness-generator leaderboard.

The eta plan adds these requirements on top of zeta:
* eta is the canonical strictest profile; zeta/epsilon/delta remain aliases.
* eta profile acceptance and strictness (reject_prebuilt_binary,
  require_coverage_build, require_containerized_sut_runtime).
* Invalid targets stop before Docker/model/ELFuzz calls.
* Fake long-running ELFuzz subprocess is killed and leaves no children.
* Produced-input classifier excludes prompts/configs/logs/python/preseeds.
* Adapter alias cannot be used as actual execution target.
* eta evaluated row requires generated fuzzer, generated inputs, valid target
  execution, nonzero campaign, and real coverage.
* Coverage missing fails with reason_code=coverage_report_missing.
* Matrix collector supports --require-input-generator-evaluated and
  --expect-invalid for the 9 applicable + 11 Invalid valuable-set contract.
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


elf = load_module("elfuzz_target_pipeline_eta", ROOT / "docker/common/elfuzz_target_pipeline.py")
campaign_mod = load_module("hgb_input_campaign_eta", ROOT / "docker/common/hgb_input_campaign.py")
matrix_collector = load_module("hgb_collect_matrix_eta", ROOT / "scripts/hgb_collect_matrix.py")


APPLICABLE = {
    "curl_curl_fuzzer_http",
    "jsoncpp_jsoncpp_fuzzer",
    "libxml2_xml",
    "libxslt_xpath",
    "mruby_mruby_fuzzer_8c8bbd",
    "php_php-fuzz-parser_0dbedb",
    "re2_fuzzer",
    "sqlite3_ossfuzz",
    "systemd_fuzz-link-parser",
}
INVALID = {
    "bloaty_fuzz_target",
    "freetype2_ftfuzzer",
    "harfbuzz_hb-shape-fuzzer",
    "lcms_cms_transform_fuzzer",
    "libjpeg-turbo_libjpeg_turbo_fuzzer",
    "libpcap_fuzz_both",
    "libpng_libpng_read_fuzzer",
    "mbedtls_fuzz_dtlsclient",
    "openh264_decoder_fuzzer",
    "openssl_x509",
    "zlib_zlib_uncompress_fuzzer",
}

COVERAGE_JSON = json.dumps({
    "data": [{"totals": {"lines": {"count": 100, "covered": 27},
                         "functions": {"count": 10, "covered": 5},
                         "regions": {"count": 50, "covered": 12}},
              "functions": [{"name": "jsoncpp_parse", "count": 5}]}],
    "type": "llvm.coverage.json.export", "version": "2.0.1",
})


def make_executable(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)
    return path


def make_target_package(base: Path, target: str = "jsoncpp_jsoncpp_fuzzer") -> Path:
    package = base / "target"
    bench = package / "fuzzbench_benchmark"
    bench.mkdir(parents=True)
    (package / "target_manifest.json").write_text(
        json.dumps({"target": target, "project": target.split("_", 1)[0], "fuzz_target": target, "fuzzbench_commit": "fixture"}) + "\n",
        encoding="utf-8",
    )
    (bench / "benchmark.yaml").write_text(f"project: {target}\nfuzz_target: {target}\n", encoding="utf-8")
    (bench / "Dockerfile").write_text("FROM gcr.io/fuzzbench/base-builder\nCOPY . /src/\nRUN compile\n", encoding="utf-8")
    (bench / "build.sh").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    (bench / "build.sh").chmod(0o755)
    return package


def fake_elfuzz_cli(path: Path, project_root: Path) -> Path:
    script = """#!/usr/bin/env python3
import os, sys, json
from pathlib import Path
root = Path(os.environ.get("ELFUZZ_PROJECT_ROOT", ""))
fuzzer_dir = Path(os.environ.get("ELFUZZ_FUZZER_PROGRAMS_DIR", root / "evaluation" / "elmfuzzers"))
produced_dir = Path(os.environ.get("ELFUZZ_PRODUCED_INPUTS_DIR", root / "extradata" / "seeds" / "raw" / "elm"))
campaign_dir = Path(os.environ.get("ELFUZZ_CAMPAIGN_OUTPUT_DIR", root / "extradata" / "rq1" / "afl_results"))
cmd = sys.argv[1] if len(sys.argv) > 1 else ""
benchmark = sys.argv[-1] if sys.argv else ""
if cmd == "setup": sys.exit(0)
if cmd == "download": sys.exit(0)
if cmd == "synth":
    fuzzer_dir.mkdir(parents=True, exist_ok=True)
    (fuzzer_dir / "evolved_fuzzer.py").write_text("def gen():\\n    return b'{}'\\n", encoding="utf-8")
    rec = Path(os.environ.get("ELFUZZ_LINEAGE_DIR", root / "extradata" / "evolution_record" / "Jsoncpp"))
    rec.mkdir(parents=True, exist_ok=True)
    with (rec / "lineage.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps({"iteration": 1, "parent": "seed", "child": "evolved_fuzzer.py"}) + "\\n")
        f.write(json.dumps({"iteration": 2, "parent": "evolved_fuzzer.py", "child": "evolved_fuzzer2.py"}) + "\\n")
    (fuzzer_dir / "evolved_fuzzer2.py").write_text("def gen():\\n    return b'{}'\\n", encoding="utf-8")
    sys.exit(0)
if cmd == "produce":
    produced_dir.mkdir(parents=True, exist_ok=True)
    for i in range(3):
        (produced_dir / f"input_{i:03d}").write_bytes(b'{"k": %d}' % i)
    sys.exit(0)
if cmd == "run":
    out = campaign_dir / f"{benchmark}_elfuzz_1"
    (out / "default" / "queue").mkdir(parents=True, exist_ok=True)
    (out / "default" / "fuzzer_stats").write_text("execs_done : 100\\npaths_total : 2\\n", encoding="utf-8")
    (out / "default" / "queue" / "id:000000").write_bytes(b'{"k": 0}')
    sys.exit(0)
sys.exit(0)
"""
    return make_executable(path, script)


class FakeRunnerResult:
    def __init__(self, command, exit_code=0, stdout="", stderr=""):
        self.command = list(command)
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


class FakeDockerRunner:
    """Simulates the ELFuzz SUT Docker build, containerized wrappers, and the coverage replay shell."""

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
            if sub == "run":
                shell_cmd = " ".join(cmd[3:]) if len(cmd) > 3 else ""
                if "llvm-cov export" in shell_cmd and "LLVM_PROFILE_FILE" in shell_cmd:
                    return FakeRunnerResult(cmd, 0, self.coverage_stdout, "")
                if "/out/" in shell_cmd:
                    return FakeRunnerResult(cmd, 0, "ok", "")
        if head == "sh":
            joined = " ".join(cmd)
            if "llvm-cov export" in joined and "LLVM_PROFILE_FILE" in joined:
                return FakeRunnerResult(cmd, 0, self.coverage_stdout, "")
        return FakeRunnerResult(cmd, 0, "", "")


def base_env(tmp_path: Path, cli: Path, project_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "ELFUZZ_CLI": str(cli),
            "ELFUZZ_PROJECT_ROOT": str(project_root),
            "ELFUZZ_FUZZER_PROGRAMS_DIR": str(project_root / "evaluation" / "elmfuzzers"),
            "ELFUZZ_PRODUCED_INPUTS_DIR": str(project_root / "extradata" / "seeds" / "raw" / "jsoncpp" / "elm"),
            "ELFUZZ_CAMPAIGN_OUTPUT_DIR": str(project_root / "extradata" / "rq1" / "afl_results"),
            "ELFUZZ_REQUIRE_HF_TOKEN": "0",
            "ELFUZZ_REQUIRE_GPU": "0",
            "ELFUZZ_SKIP_DOWNLOAD": "1",
            "ELFUZZ_STAGE_TIMEOUT_SECONDS": "60",
            "HGB_BASELINE_PROFILE": "reproduction-eta",
            "HGB_BASELINE_PROTOCOL": "paper-native",
            "HGB_METADATA_DIR": str(ROOT / "metadata"),
            "HGB_GENERATOR_ARTIFACT_DIR": str(ROOT / "artifacts" / "elfuzz"),
            "ELFUZZ_ALLOW_SUT_BUILD": "1",
        }
    )
    return env


def run_pipeline_inproc(tmp_path, target="jsoncpp_jsoncpp_fuzzer", runner=None, env=None):
    project_root = tmp_path / "project"
    project_root.mkdir(exist_ok=True)
    cli = fake_elfuzz_cli(tmp_path / "elfuzz", project_root)
    if env is None:
        env = base_env(tmp_path, cli, project_root)
    package = make_target_package(tmp_path, target)
    pipeline = elf.ELFuzzPipeline(
        workspace=tmp_path / "workspace",
        target=target,
        target_package=package,
        artifact_dir=tmp_path / "artifact",
        metadata_root=ROOT / "metadata",
        profile="reproduction-eta",
        protocol="paper-native",
    )
    if runner is None:
        runner = FakeDockerRunner()
    pipeline.runner = runner
    pipeline.project_root = project_root
    saved_env = dict(os.environ)
    try:
        os.environ.update({k: v for k, v in env.items() if k.startswith("ELFUZZ_") or k.startswith("HGB_")})
        code = pipeline.full()
    finally:
        os.environ.clear()
        os.environ.update(saved_env)
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    return code, metadata, pipeline, tmp_path / "workspace"


def _run_env():
    env = dict(os.environ)
    env["PATH"] = str(ROOT / "scripts") + os.pathsep + env.get("PATH", "")
    return env


# ---------------------------------------------------------------------------
# E0. Profile acceptance and strictness
# ---------------------------------------------------------------------------


def test_reproduction_eta_is_the_strictest_paper_native_profile():
    budget = elf.budget_for_profile("reproduction-eta", {})
    assert budget["reject_prebuilt_binary"] is True
    assert budget["require_coverage_build"] is True
    assert budget["paper_core"] is True
    assert budget["method_variant"] == "paper-faithful"
    assert budget["evolution_iterations"] >= 2
    assert budget["excluded_from_aggregate"] is False
    # eta-specific: containerized SUT runtime is required (same as zeta).
    assert budget["require_containerized_sut_runtime"] is True


def test_reproduction_eta_preserves_zeta_epsilon_delta_aliases():
    zeta = elf.budget_for_profile("reproduction-zeta", {})
    assert zeta["reject_prebuilt_binary"] is True
    assert zeta["require_coverage_build"] is True
    assert zeta.get("require_containerized_sut_runtime") is True
    eps = elf.budget_for_profile("reproduction-epsilon", {})
    assert eps["reject_prebuilt_binary"] is True
    assert eps["require_coverage_build"] is True
    # epsilon does NOT require containerized SUT runtime (eta/zeta-only).
    assert eps.get("require_containerized_sut_runtime") is False
    delta = elf.budget_for_profile("reproduction-delta", {})
    assert delta["reject_prebuilt_binary"] is True
    assert delta.get("require_containerized_sut_runtime") is False


def test_reproduction_eta_profile_accepted_by_host_runner():
    proc = subprocess.run(
        ["bash", str(ROOT / "scripts/hgb_run_baseline.sh"), "--dry-run",
         "--generator", "elfuzz", "--target", "jsoncpp_jsoncpp_fuzzer",
         "--profile", "reproduction-eta", "--protocol", "paper-native"],
        cwd=ROOT, text=True, capture_output=True, check=False, env=_run_env(),
    )
    assert proc.returncode == 0, proc.stderr


def test_dry_run_reports_input_generator_task_family():
    proc = subprocess.run(
        ["bash", str(ROOT / "scripts/hgb_run_baseline.sh"), "--dry-run",
         "--generator", "elfuzz", "--target", "jsoncpp_jsoncpp_fuzzer",
         "--profile", "reproduction-eta", "--protocol", "paper-native"],
        cwd=ROOT, text=True, capture_output=True, check=False, env=_run_env(),
    )
    assert proc.returncode == 0, proc.stderr
    workspace = proc.stdout.strip().splitlines()[-1]
    result = json.loads((Path(workspace) / "result.json").read_text(encoding="utf-8"))
    assert result["task_family"] == "input_generator"
    assert result["profile"] == "reproduction-eta"
    assert result["method_variant"] == "paper-faithful"


def test_entrypoint_accepts_reproduction_eta():
    entrypoint = (ROOT / "docker/elfuzz/entrypoint.sh").read_text(encoding="utf-8")
    assert "reproduction-eta" in entrypoint
    assert '"$HGB_BASELINE_PROFILE" == "reproduction-eta"' in entrypoint
    assert "ELFUZZ_REQUIRE_CONTAINERIZED_SUT_RUNTIME" in entrypoint


# ---------------------------------------------------------------------------
# E1. Invalid targets stop before Docker/model/ELFuzz calls
# ---------------------------------------------------------------------------


def test_invalid_preflight_returns_before_docker_model_tgi(tmp_path: Path):
    out = tmp_path / "result.json"
    env = {
        "HGB_BASELINE_PROFILE": "reproduction-eta",
        "HGB_BASELINE_PROTOCOL": "paper-native",
        "HGB_METADATA_DIR": str(ROOT / "metadata"),
        "HF_TOKEN": "",
        "DOCKER_HOST": "",
    }
    proc = subprocess.run(
        [sys.executable, str(ROOT / "docker/common/elfuzz_target_pipeline.py"), "write-invalid",
         "--target", "libpng_libpng_read_fuzzer", "--metadata-root", str(ROOT / "metadata"), "--out", str(out)],
        cwd=ROOT, env={**os.environ, **env}, text=True, capture_output=True, check=False,
    )
    assert proc.returncode == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["status"] == "not_applicable"
    assert data["applicability"] == "Invalid"
    assert data["reason_code"] == "elfuzz_non_text_target"
    assert data["exclude_from_aggregate"] is True
    assert data["excluded_from_aggregate"] is True
    assert data["profile"] == "reproduction-eta"
    assert data["protocol"] == "paper-native"
    assert data["task_family"] == "input_generator"
    assert data["method_variant"] == "paper-faithful"
    for stage in elf.STAGE_NAMES:
        assert data["stages"][stage]["status"] == "not_applicable"


def test_host_runner_returns_invalid_before_docker_socket_check():
    proc = subprocess.run(
        ["bash", str(ROOT / "scripts/hgb_run_baseline.sh"),
         "--generator", "elfuzz", "--target", "libpng_libpng_read_fuzzer",
         "--profile", "reproduction-eta", "--protocol", "paper-native"],
        cwd=ROOT, text=True, capture_output=True, check=False, env=_run_env(),
    )
    assert proc.returncode == 0
    workspace = proc.stdout.strip().splitlines()[-1]
    result = json.loads((Path(workspace) / "result.json").read_text(encoding="utf-8"))
    assert result["status"] == "not_applicable"
    assert result["applicability"] == "Invalid"
    assert result["reason_code"] == "elfuzz_non_text_target"
    assert result["excluded_from_aggregate"] is True


# ---------------------------------------------------------------------------
# E2. Hanging tests and subprocess termination
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
    code, timed_out = elf.run_subprocess([str(fake)], log, timeout=3)
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
    fake = make_executable(tmp_path / "long_run.py", script)
    log = tmp_path / "log.txt"
    start = time.time()
    code, timed_out = elf.run_subprocess([str(fake)], log, timeout=86400)
    elapsed = time.time() - start
    assert timed_out is True
    assert code == 124
    assert elapsed < 40


# ---------------------------------------------------------------------------
# E3. Produced-input classifier excludes prompts/configs/logs/python/preseeds
# ---------------------------------------------------------------------------


def test_produced_input_classification_excludes_non_payloads(tmp_path: Path):
    produced = tmp_path / "produced"
    produced.mkdir()
    (produced / "input_000").write_bytes(b'{"k": 0}')
    (produced / "prompt_001").write_text("p\n", encoding="utf-8")
    (produced / "evolved.py").write_text("x=1\n", encoding="utf-8")
    (produced / "seed_fuzzer.py").write_text("x=1\n", encoding="utf-8")
    (produced / "manifest.json").write_text("{}", encoding="utf-8")
    (produced / "lineage.jsonl").write_text("{}\n", encoding="utf-8")
    (produced / "run.log").write_text("log\n", encoding="utf-8")
    (produced / "stats.txt").write_text("s\n", encoding="utf-8")
    (produced / "coverage.profraw").write_bytes(b"raw")
    (produced / "coverage.profdata").write_bytes(b"data")
    (produced / "config.yaml").write_text("k: v\n", encoding="utf-8")
    (produced / "preseed_corpus").write_bytes(b"seed")
    inputs = [p for p in produced.iterdir() if elf.is_produced_input(p)]
    assert {p.name for p in inputs} == {"input_000"}
    assert {p.name for p in produced.iterdir() if campaign_mod.is_produced_input(p)} == {"input_000"}
    manifest = campaign_mod.write_produced_input_provenance(produced, tmp_path / "provenance.json")
    assert manifest["produced_input_count"] == 1
    excluded_names = {e["path"] for e in manifest["excluded_files"]}
    assert "prompt_001" in excluded_names
    assert manifest["accepted_files"][0]["path"] == "input_000"
    assert "sha256" in manifest["accepted_files"][0]


# ---------------------------------------------------------------------------
# E4. Adapter alias cannot be used as actual execution target
# ---------------------------------------------------------------------------


def test_extension_adapters_no_aliasing():
    violations = elf.validate_no_aliasing(ROOT / "metadata")
    assert violations == []
    adapters = elf.load_adapters(ROOT / "metadata")
    for target in ("curl_curl_fuzzer_http", "libxslt_xpath", "mruby_mruby_fuzzer_8c8bbd",
                   "php_php-fuzz-parser_0dbedb", "systemd_fuzz-link-parser"):
        entry = adapters[target]
        assert entry.get("adapter_class") == elf.EXTENSION
        assert entry.get("hgb_adapter") is True
        yaml_path = ROOT / entry["adapter_dir"] / "adapter.yaml"
        assert yaml_path.is_file()
        parsed = elf.parse_simple_yaml(yaml_path)
        assert str(parsed.get("target")) == target
        assert str(parsed.get("upstream_benchmark", "")) not in elf.UPSTREAM_NATIVE_BENCHMARKS


def test_result_records_reported_target_not_alias(tmp_path: Path):
    code, metadata, pipeline, workspace = run_pipeline_inproc(tmp_path, target="jsoncpp_jsoncpp_fuzzer")
    assert code == 0
    assert metadata["reported_target"] == "jsoncpp_jsoncpp_fuzzer"
    assert metadata["actual_sut_fuzz_target"] == "jsoncpp_jsoncpp_fuzzer"
    assert metadata["actual_sut_project"] == "jsoncpp"
    assert metadata["alias_used_for_execution"] is False


# ---------------------------------------------------------------------------
# E5. eta evaluated row requires full closed loop
# ---------------------------------------------------------------------------


def test_eta_builds_containerized_sut_wrappers(tmp_path: Path):
    code, metadata, pipeline, workspace = run_pipeline_inproc(tmp_path)
    assert code == 0, metadata.get("reason")
    assert metadata["status"] == "evaluated"
    sut = workspace / "sut"
    # eta plan §3: containerized SUT wrappers must exist.
    assert (sut / "wrappers" / "run_native_one.sh").is_file()
    assert (sut / "wrappers" / "run_coverage_corpus.sh").is_file()
    assert (sut / "containerized_wrappers.json").is_file()
    wrapper_manifest = json.loads((sut / "containerized_wrappers.json").read_text(encoding="utf-8"))
    assert wrapper_manifest["containerized"] is True
    assert metadata["build"]["containerized_sut_runtime"] is True
    assert metadata["build"]["uses_fuzzbench_docker_environment"] is True


def test_eta_evaluated_requires_full_closed_loop(tmp_path: Path):
    code, metadata, pipeline, workspace = run_pipeline_inproc(tmp_path)
    assert code == 0, metadata.get("reason")
    assert metadata["status"] == "evaluated"
    assert metadata["task_family"] == "input_generator"
    assert metadata["applicability"] == "applicable"
    assert metadata["method_variant"] == "paper-faithful"
    assert metadata["exclude_from_aggregate"] is False
    # Real generation evidence (eta plan §4).
    assert metadata["method"]["generated_fuzzer_program_count"] > 0
    assert metadata["elfuzz"]["fuzzer_programs"] >= 1
    assert metadata["elfuzz"]["generated_inputs"] >= 1
    assert metadata["elfuzz"]["valid_generated_inputs"] >= 1
    # eta plan §4: evolution_iterations >= 2.
    assert metadata["elfuzz"]["evolution_iterations"] >= 2
    # Real campaign + coverage evidence (eta plan §5).
    assert metadata["campaign"]["execs_done"] > 0
    assert metadata["campaign"]["queue_count"] > 0
    assert metadata["coverage"]["report_exists"] is True
    assert metadata["coverage"]["line_coverage"]["covered"] > 0
    assert metadata["coverage"]["edge_coverage"]["status"] == "unavailable"
    # Build provenance from the FuzzBench Docker environment (eta plan §3).
    assert metadata["build"]["uses_fuzzbench_docker_environment"] is True
    assert metadata["build"]["containerized_sut_runtime"] is True
    # actual_sut_fuzz_target matches the reported target.
    assert metadata["actual_sut_fuzz_target"] == metadata["reported_target"]
    # All canonical stages completed.
    for stage in elf.STAGE_NAMES:
        assert metadata["stages"][stage]["status"] == "complete", stage
    # Campaign evidence artifacts (eta plan §5).
    assert (workspace / "campaign" / "command.txt").is_file()
    assert (workspace / "campaign" / "target_runtime.log").is_file()
    assert (workspace / "campaign" / "target_runtime.json").is_file()


# ---------------------------------------------------------------------------
# E6. Coverage missing fails with reason_code=coverage_report_missing
# ---------------------------------------------------------------------------


def test_coverage_fails_when_report_missing(tmp_path: Path):
    code, metadata, pipeline, workspace = run_pipeline_inproc(
        tmp_path, runner=FakeDockerRunner(coverage_stdout="")
    )
    assert code != 0
    assert metadata["status"] != "evaluated"
    assert metadata["stages"]["coverage"]["status"] == "failed"
    assert metadata["reason_code"] == "coverage_report_missing"
    cov = json.loads((workspace / "coverage" / "coverage.json").read_text(encoding="utf-8"))
    assert cov["report_exists"] is False
    assert cov["edge_coverage"]["status"] == "unavailable"
    assert cov["line_coverage"] is None or cov.get("total_lines", 0) == 0
    assert (workspace / "coverage" / "coverage_diagnostic.json").is_file()


def test_eta_rejects_prebuilt_binary(tmp_path: Path):
    project_root = tmp_path / "project"
    project_root.mkdir()
    cli = fake_elfuzz_cli(tmp_path / "elfuzz", project_root)
    binary = make_executable(tmp_path / "bin", "#!/usr/bin/env bash\nexit 0\n")
    env = base_env(tmp_path, cli, project_root)
    env["ELFUZZ_TARGET_BINARY"] = str(binary)
    code, metadata, pipeline, workspace = run_pipeline_inproc(tmp_path, runner=FakeDockerRunner(), env=env)
    assert code != 0
    assert metadata["status"] in {"infra_missing", "infra_failure"}
    assert metadata["stages"]["target_build"]["status"] in {"infra_missing", "infra_failure"}


# ---------------------------------------------------------------------------
# E7. Strict matrix collector invariants
# ---------------------------------------------------------------------------


def test_matrix_strict_no_violations_for_real_evaluated_row(tmp_path: Path):
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    app_ws = matrix_dir / "app"
    app_ws.mkdir()
    (app_ws / "metadata.json").write_text(json.dumps({
        "baseline": "elfuzz", "generator": "elfuzz", "status": "evaluated",
        "task_family": "input_generator", "applicability": "applicable",
        "exclude_from_aggregate": False, "excluded_from_aggregate": False,
        "profile": "reproduction-eta", "method_variant": "paper-faithful",
        "reported_target": "jsoncpp_jsoncpp_fuzzer",
        "actual_sut_fuzz_target": "jsoncpp_jsoncpp_fuzzer",
        "generated_input_count": 3, "elfuzz": {"fuzzer_programs": 1, "generated_inputs": 3,
        "valid_generated_inputs": 2, "evolution_iterations": 2},
        "input_generation": {"fuzzer_program_count": 1, "generated_input_count": 3,
        "valid_generated_input_count": 2, "evolution_iterations_completed": 2},
        "campaign": {"execs_done": 100, "queue_count": 2},
        "coverage": {"report_exists": True, "line_coverage": {"covered": 27, "total": 100},
                     "edge_coverage": {"status": "unavailable"}},
        "build": {"uses_fuzzbench_docker_environment": True, "containerized_sut_runtime": True},
    }), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"elfuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, strict=True, generator="elfuzz", profile="reproduction-eta")
    assert summary["evaluated_row_violations"] == []


def test_matrix_strict_flags_eta_missing_containerized_runtime(tmp_path: Path):
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    app_ws = matrix_dir / "app"
    app_ws.mkdir()
    (app_ws / "metadata.json").write_text(json.dumps({
        "baseline": "elfuzz", "generator": "elfuzz", "status": "evaluated",
        "task_family": "input_generator", "applicability": "applicable",
        "exclude_from_aggregate": False, "profile": "reproduction-eta",
        "method_variant": "paper-faithful", "reported_target": "jsoncpp_jsoncpp_fuzzer",
        "actual_sut_fuzz_target": "jsoncpp_jsoncpp_fuzzer",
        "generated_input_count": 3, "elfuzz": {"fuzzer_programs": 1, "generated_inputs": 3,
        "valid_generated_inputs": 2, "evolution_iterations": 2},
        "campaign": {"execs_done": 100, "queue_count": 2},
        "coverage": {"report_exists": True, "line_coverage": {"covered": 27, "total": 100},
                     "edge_coverage": {"status": "unavailable"}},
        "build": {"uses_fuzzbench_docker_environment": True, "containerized_sut_runtime": False},
    }), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"elfuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, strict=True, generator="elfuzz", profile="reproduction-eta")
    assert summary["evaluated_row_violations"]
    violations = summary["evaluated_row_violations"][0]["violations"]
    assert any("containerized" in v for v in violations)


def test_matrix_strict_flags_eta_low_evolution_iterations(tmp_path: Path):
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    app_ws = matrix_dir / "app"
    app_ws.mkdir()
    (app_ws / "metadata.json").write_text(json.dumps({
        "baseline": "elfuzz", "generator": "elfuzz", "status": "evaluated",
        "task_family": "input_generator", "applicability": "applicable",
        "exclude_from_aggregate": False, "profile": "reproduction-eta",
        "method_variant": "paper-faithful", "reported_target": "jsoncpp_jsoncpp_fuzzer",
        "actual_sut_fuzz_target": "jsoncpp_jsoncpp_fuzzer",
        "generated_input_count": 3, "elfuzz": {"fuzzer_programs": 1, "generated_inputs": 3,
        "valid_generated_inputs": 2, "evolution_iterations": 1},
        "campaign": {"execs_done": 100, "queue_count": 2},
        "coverage": {"report_exists": True, "line_coverage": {"covered": 27, "total": 100},
                     "edge_coverage": {"status": "unavailable"}},
        "build": {"uses_fuzzbench_docker_environment": True, "containerized_sut_runtime": True},
    }), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"elfuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, strict=True, generator="elfuzz", profile="reproduction-eta")
    assert summary["evaluated_row_violations"]
    violations = summary["evaluated_row_violations"][0]["violations"]
    assert any("evolution_iterations" in v for v in violations)


def test_matrix_collector_valuable_set_counts(tmp_path: Path):
    # 9 applicable + 11 Invalid across the valuable set (eta plan §6).
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    rows = ["generator\ttarget\tstatus\tworkspace\tmetadata\tsummary"]
    for target in INVALID:
        ws = matrix_dir / "inv" / target
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "metadata.json").write_text(json.dumps({
            "baseline": "elfuzz", "generator": "elfuzz", "status": "not_applicable",
            "task_family": "input_generator", "applicability": "Invalid",
            "reason_code": "elfuzz_non_text_target", "exclude_from_aggregate": True,
            "excluded_from_aggregate": True, "profile": "reproduction-eta",
        }), encoding="utf-8")
        rows.append(f"elfuzz\t{target}\tnot_applicable\t{ws}\t{ws / 'metadata.json'}\t")
    for target in APPLICABLE:
        ws = matrix_dir / "app" / target
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "metadata.json").write_text(json.dumps({
            "baseline": "elfuzz", "generator": "elfuzz", "status": "failed",
            "task_family": "input_generator", "applicability": "applicable",
            "exclude_from_aggregate": False, "excluded_from_aggregate": False,
            "profile": "reproduction-eta", "campaign": {"execs_done": 0},
        }), encoding="utf-8")
        rows.append(f"elfuzz\t{target}\tfailed\t{ws}\t{ws / 'metadata.json'}\t")
    (matrix_dir / "matrix.tsv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    summary = matrix_collector.collect(matrix_dir, generator="elfuzz", profile="reproduction-eta")
    assert summary["not_applicable_pairs"] == 11
    assert summary["applicable_pairs"] == 9


def test_matrix_require_input_generator_evaluated_flags_failures(tmp_path: Path):
    # Applicable input-generator rows that are not evaluated must surface as
    # require_input_generator_evaluated_violations (eta plan §6/§8).
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    rows = ["generator\ttarget\tstatus\tworkspace\tmetadata\tsummary"]
    for target in APPLICABLE:
        ws = matrix_dir / "app" / target
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "metadata.json").write_text(json.dumps({
            "baseline": "elfuzz", "generator": "elfuzz", "status": "failed",
            "task_family": "input_generator", "applicability": "applicable",
            "exclude_from_aggregate": False, "excluded_from_aggregate": False,
            "profile": "reproduction-eta", "campaign": {"execs_done": 0},
        }), encoding="utf-8")
        rows.append(f"elfuzz\t{target}\tfailed\t{ws}\t{ws / 'metadata.json'}\t")
    for target in INVALID:
        ws = matrix_dir / "inv" / target
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "metadata.json").write_text(json.dumps({
            "baseline": "elfuzz", "generator": "elfuzz", "status": "not_applicable",
            "task_family": "input_generator", "applicability": "Invalid",
            "reason_code": "elfuzz_non_text_target", "exclude_from_aggregate": True,
            "excluded_from_aggregate": True, "profile": "reproduction-eta",
        }), encoding="utf-8")
        rows.append(f"elfuzz\t{target}\tnot_applicable\t{ws}\t{ws / 'metadata.json'}\t")
    (matrix_dir / "matrix.tsv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    summary = matrix_collector.collect(
        matrix_dir, generator="elfuzz", profile="reproduction-eta",
        require_input_generator_evaluated=True, expect_invalid=11,
    )
    assert len(summary["require_input_generator_evaluated_violations"]) == 9
    assert summary["expect_invalid_violation"] is None


def test_matrix_expect_invalid_mismatch(tmp_path: Path):
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    rows = ["generator\ttarget\tstatus\tworkspace\tmetadata\tsummary"]
    for target in INVALID:
        ws = matrix_dir / "inv" / target
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "metadata.json").write_text(json.dumps({
            "baseline": "elfuzz", "generator": "elfuzz", "status": "not_applicable",
            "task_family": "input_generator", "applicability": "Invalid",
            "exclude_from_aggregate": True, "excluded_from_aggregate": True,
            "profile": "reproduction-eta",
        }), encoding="utf-8")
        rows.append(f"elfuzz\t{target}\tnot_applicable\t{ws}\t{ws / 'metadata.json'}\t")
    (matrix_dir / "matrix.tsv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    # Expect 5 invalid rows but 11 exist: mismatch.
    summary = matrix_collector.collect(matrix_dir, generator="elfuzz", profile="reproduction-eta", expect_invalid=5)
    assert summary["expect_invalid_violation"] is not None
    assert "found 11" in summary["expect_invalid_violation"]


def test_valuable_target_set_has_twenty_targets():
    hgb_targets = load_module("hgb_targets_eta", ROOT / "scripts/hgb_targets.py")
    registry = hgb_targets.load_registry(ROOT)
    valuable = hgb_targets.targets_for_set(registry, "valuable")
    assert len(valuable) == 20
    assert APPLICABLE.issubset(set(valuable))
    assert INVALID.issubset(set(valuable))


def test_matrix_runner_wrapper_accepts_eta_args():
    wrapper = (ROOT / "scripts/hgb_run_baseline_matrix.sh").read_text(encoding="utf-8")
    assert "hgb_generate_matrix.sh" in wrapper
    assert "--profile" in wrapper
    assert "--campaign-seconds" in wrapper
    assert '--generators "$generators"' in wrapper
    assert '--profile "$profile"' in wrapper


def test_matrix_collector_accepts_input_generator_and_expect_invalid_flags():
    proc = subprocess.run(
        ["python3", str(ROOT / "scripts/hgb_collect_matrix.py"), "--help"],
        cwd=ROOT, capture_output=True, text=True, timeout=30,
    )
    assert "--require-input-generator-evaluated" in proc.stdout
    assert "--expect-invalid" in proc.stdout
    assert "--fail-on-invariant-violations" in proc.stdout
