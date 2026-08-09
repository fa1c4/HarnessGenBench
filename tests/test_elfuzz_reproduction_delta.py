"""Delta reproduction tests for the ELFuzz input-generator pipeline.

These tests exercise the strict paper-native ELFuzz reproduction contract from
``plans/elfuzz_reproduction_delta.md`` with fake Docker/CLI runners so they
pass without real external checkouts, Docker, TGI, or model access.

ELFuzz is an ``input_generator`` (it synthesizes/evolves input-producing fuzzer
programs against a fixed native FuzzBench target, then replays generated/campaign
inputs on a coverage-instrumented SUT), never a harness generator.

The tests target the exact HGB5 issues called out by the plan:
profile not accepted by the host runner, produced-input misclassification
(``prompt_001`` counted as an input), coverage report missing but status
evaluated, zero-exec campaigns, Invalid rows miscounted by the matrix
collector, and upstream-benchmark aliasing for extension targets.
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


elf = load_module("elfuzz_target_pipeline_delta", ROOT / "docker/common/elfuzz_target_pipeline.py")
campaign_mod = load_module("hgb_input_campaign_delta", ROOT / "docker/common/hgb_input_campaign.py")
matrix_collector = load_module("hgb_collect_matrix_delta", ROOT / "scripts/hgb_collect_matrix.py")


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
    """Simulates the ELFuzz SUT Docker build and the coverage replay shell."""

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
            "HGB_BASELINE_PROFILE": "reproduction-delta",
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
        profile="reproduction-delta",
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


# 1. reproduction-delta profile is accepted by the host runner
def test_reproduction_delta_profile_accepted_by_host_runner():
    run_baseline = (ROOT / "scripts/hgb_run_baseline.sh").read_text(encoding="utf-8")
    assert "reproduction-delta" in run_baseline
    # The strict invariants (forbid ELFUZZ_TARGET_BINARY, require coverage replay)
    # are wired for reproduction-delta.
    assert "reproduction-delta" in run_baseline
    # A dry run validates the profile/protocol without Docker or LLM calls.
    proc = subprocess.run(
        ["bash", str(ROOT / "scripts/hgb_run_baseline.sh"), "--dry-run",
         "--generator", "elfuzz", "--target", "jsoncpp_jsoncpp_fuzzer",
         "--profile", "reproduction-delta", "--protocol", "paper-native"],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    assert proc.returncode == 0, proc.stderr


# 2. Invalid preflight returns before Docker/model/TGI; schema-v2 exclude_from_aggregate
def test_invalid_preflight_before_docker_model_tgi(tmp_path: Path):
    out = tmp_path / "result.json"
    env = {
        "HGB_BASELINE_PROFILE": "reproduction-delta",
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
    assert data["profile"] == "reproduction-delta"
    assert data["protocol"] == "paper-native"
    assert data["task_family"] == "input_generator"
    # Plan section 2 stage view.
    assert data["stages"]["applicability"]["status"] == "completed"
    assert data["stages"]["generation"]["status"] == "not_applicable"
    assert data["stages"]["campaign"]["status"] == "not_applicable"
    assert data["stages"]["coverage"]["status"] == "not_applicable"
    # No Docker/TGI/model stage started: every canonical stage is not_applicable.
    for stage in elf.STAGE_NAMES:
        assert data["stages"][stage]["status"] == "not_applicable"
    # The host-side preflight must run before any Docker/model/TGI startup.
    harness = (ROOT / "scripts/hgb_generate_harness.sh").read_text(encoding="utf-8")
    assert harness.index("ELFuzz supports text-input targets only") < harness.index("ensure_artifacts_present")


# 3. produced input classification: prompt_001 is not a produced input
def test_produced_input_classification_excludes_prompts(tmp_path: Path):
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
    # The shared campaign classifier agrees.
    assert {p.name for p in produced.iterdir() if campaign_mod.is_produced_input(p)} == {"input_000"}
    # The provenance manifest excludes prompt_001 with a reason.
    manifest = campaign_mod.write_produced_input_provenance(produced, tmp_path / "provenance.json")
    assert manifest["produced_input_count"] == 1
    excluded_names = {e["path"] for e in manifest["excluded_files"]}
    assert "prompt_001" in excluded_names
    assert manifest["accepted_files"][0]["path"] == "input_000"
    assert "sha256" in manifest["accepted_files"][0]


# 4. delta budget is strict paper-faithful
def test_delta_budget_is_strict_paper_faithful():
    budget = elf.budget_for_profile("reproduction-delta", {})
    assert budget["reject_prebuilt_binary"] is True
    assert budget["require_coverage_build"] is True
    assert budget["paper_core"] is True
    assert budget["method_variant"] == "paper-faithful"
    assert budget["evolution_iterations"] >= 2
    assert budget["excluded_from_aggregate"] is False
    # reproduction-gamma remains a backward-compatible alias with the same strictness.
    gamma = elf.budget_for_profile("reproduction-gamma", {})
    assert gamma["reject_prebuilt_binary"] is True
    assert gamma["require_coverage_build"] is True


# 5. delta rejects a prebuilt ELFUZZ_TARGET_BINARY
def test_delta_rejects_prebuilt_binary(tmp_path: Path):
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


# 6. delta builds native+coverage SUT from the FuzzBench Docker environment
def test_delta_builds_native_and_coverage_sut(tmp_path: Path):
    code, metadata, pipeline, workspace = run_pipeline_inproc(tmp_path)
    assert code == 0, metadata.get("reason")
    assert metadata["status"] == "evaluated"
    sut = workspace / "sut"
    contract = json.loads((sut / "contract.json").read_text(encoding="utf-8"))
    assert contract["uses_fuzzbench_docker_environment"] is True
    assert Path(contract["native"]["binary_path"]).is_file()
    assert Path(contract["coverage"]["binary_path"]).is_file()
    assert contract["native"]["verified_executable"] is True
    assert contract["coverage"]["verified_executable"] is True
    assert (sut / "build_logs" / "native.log").is_file()
    assert (sut / "build_logs" / "coverage.log").is_file()
    runner = pipeline.runner
    build_cmds = [c for c in runner.commands if c[:2] == ["docker", "build"]]
    assert len(build_cmds) >= 2


# 7. extension adapters invoke their own target IDs, not upstream aliases
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
    # The reported target equals the actual SUT fuzz target; no alias used.
    assert metadata["reported_target"] == "jsoncpp_jsoncpp_fuzzer"
    assert metadata["actual_sut_fuzz_target"] == "jsoncpp_jsoncpp_fuzzer"
    assert metadata["actual_sut_project"] == "jsoncpp"
    assert metadata["alias_used_for_execution"] is False


# 8. evaluated requires the full closed loop (real evidence)
def test_evaluated_requires_full_closed_loop(tmp_path: Path):
    code, metadata, pipeline, workspace = run_pipeline_inproc(tmp_path)
    assert code == 0, metadata.get("reason")
    assert metadata["status"] == "evaluated"
    assert metadata["task_family"] == "input_generator"
    assert metadata["applicability"] == "applicable"
    # Schema-v2 fields (plan global invariant 5).
    for key in ("task_family", "profile", "protocol", "method_variant", "status",
                "applicability", "stages", "artifacts", "build", "campaign",
                "coverage", "reproducibility", "error", "exclude_from_aggregate"):
        assert key in metadata, key
    assert metadata["method_variant"] == "paper-faithful"
    assert metadata["exclude_from_aggregate"] is False
    # Real generation evidence.
    assert metadata["method"]["generated_fuzzer_program_count"] > 0
    assert metadata["elfuzz"]["fuzzer_programs"] >= 1
    assert metadata["elfuzz"]["generated_inputs"] >= 1
    assert metadata["elfuzz"]["valid_generated_inputs"] >= 1
    assert metadata["elfuzz"]["evolution_iterations"] >= 1
    # Real campaign + coverage evidence.
    assert metadata["campaign"]["execs_done"] > 0
    assert metadata["coverage"]["report_exists"] is True
    assert metadata["coverage"]["line_coverage"]["covered"] > 0
    assert metadata["coverage"]["edge_coverage"]["status"] == "unavailable"
    # Build provenance from the FuzzBench Docker environment.
    assert metadata["build"]["uses_fuzzbench_docker_environment"] is True
    # All canonical stages completed.
    for stage in elf.STAGE_NAMES:
        assert metadata["stages"][stage]["status"] == "complete", stage


# 9. coverage fails when the report is missing (empty replay stdout)
def test_coverage_fails_when_report_missing(tmp_path: Path):
    code, metadata, pipeline, workspace = run_pipeline_inproc(tmp_path, runner=FakeDockerRunner(coverage_stdout=""))
    assert code != 0
    assert metadata["status"] != "evaluated"
    assert metadata["stages"]["coverage"]["status"] == "failed"
    assert metadata["reason_code"] == "coverage_report_missing"
    cov = json.loads((workspace / "coverage" / "coverage.json").read_text(encoding="utf-8"))
    assert cov["report_exists"] is False
    assert cov["edge_coverage"]["status"] == "unavailable"
    assert cov["line_coverage"] is None or cov.get("total_lines", 0) == 0
    # A diagnostic was written, never a fake coverage.json with AFL path counters.
    assert (workspace / "coverage" / "coverage_diagnostic.json").is_file()
    diag = json.loads((workspace / "coverage" / "coverage_diagnostic.json").read_text(encoding="utf-8"))
    assert diag["line_coverage"] is None


# 10. AFL paths_total alone must not populate line/edge coverage
def test_afl_paths_alone_not_line_coverage():
    summary = campaign_mod.coverage_from_campaign(
        stats={"execs_done": 0, "paths_total": 99}, report_path=None, queue_count=99
    )
    assert summary["edge_coverage"]["status"] == "unavailable"
    assert summary["line_coverage"] is None
    assert summary["complete"] is False
    verify = campaign_mod.verify_campaign_execs({"execs_done": 0, "paths_total": 99})
    assert verify["has_executions"] is False
    assert verify["paths_only"] is True


# 11. zero-exec campaign fails and never reaches evaluated
def test_zero_exec_campaign_fails(tmp_path: Path):
    project_root = tmp_path / "project"
    project_root.mkdir()
    cli = fake_elfuzz_cli(tmp_path / "elfuzz", project_root)
    # A CLI whose campaign writes zero executions.
    zero_cli = make_executable(
        tmp_path / "zero_elfuzz",
        "#!/usr/bin/env python3\nimport os, sys\nfrom pathlib import Path\n"
        "root=Path(os.environ.get('ELFUZZ_PROJECT_ROOT',''))\ncmd=sys.argv[1] if len(sys.argv)>1 else ''\n"
        "benchmark=sys.argv[-1] if sys.argv else ''\n"
        "if cmd=='synth':\n"
        "  d=Path(os.environ['ELFUZZ_FUZZER_PROGRAMS_DIR']); d.mkdir(parents=True,exist_ok=True)\n"
        "  (d/'f.py').write_text('x=1\\n')\n  sys.exit(0)\n"
        "if cmd=='produce':\n"
        "  d=Path(os.environ['ELFUZZ_PRODUCED_INPUTS_DIR']); d.mkdir(parents=True,exist_ok=True)\n"
        "  (d/'in_0').write_bytes(b'{}')\n  sys.exit(0)\n"
        "if cmd=='run':\n"
        "  d=Path(os.environ['ELFUZZ_CAMPAIGN_OUTPUT_DIR'])/(benchmark+'_elfuzz_1')\n"
        "  (d/'default'/'queue').mkdir(parents=True,exist_ok=True)\n"
        "  (d/'default'/'fuzzer_stats').write_text('execs_done : 0\\npaths_total : 3\\n')\n"
        "  (d/'default'/'queue'/'id:0').write_bytes(b'{}')\n  sys.exit(0)\n"
        "sys.exit(0)\n",
    )
    env = base_env(tmp_path, zero_cli, project_root)
    code, metadata, pipeline, workspace = run_pipeline_inproc(tmp_path, runner=FakeDockerRunner(), env=env)
    assert code != 0
    assert metadata["status"] != "evaluated"
    assert metadata["stages"]["campaign"]["status"] == "failed"


# 12. matrix collector counts Invalid as not-applicable, not failed/success
def test_matrix_collector_counts_invalid_as_not_applicable(tmp_path: Path):
    matrix_dir = tmp_path / "matrix" / "run"
    inv_ws = tmp_path / "invalid"
    app_ws = tmp_path / "applicable"
    matrix_dir.mkdir(parents=True)
    inv_ws.mkdir()
    app_ws.mkdir()
    (inv_ws / "metadata.json").write_text(json.dumps({
        "baseline": "elfuzz", "generator": "elfuzz", "status": "not_applicable",
        "task_family": "input_generator", "applicability": "Invalid",
        "reason_code": "elfuzz_non_text_target", "exclude_from_aggregate": True,
        "excluded_from_aggregate": True, "profile": "reproduction-delta",
    }), encoding="utf-8")
    (app_ws / "metadata.json").write_text(json.dumps({
        "baseline": "elfuzz", "generator": "elfuzz", "status": "evaluated",
        "task_family": "input_generator", "applicability": "applicable",
        "exclude_from_aggregate": False, "excluded_from_aggregate": False,
        "profile": "reproduction-delta", "method_variant": "paper-faithful",
        "generated_input_count": 3, "elfuzz": {"fuzzer_programs": 1, "generated_inputs": 3,
        "valid_generated_inputs": 2}, "input_generation": {"fuzzer_program_count": 1,
        "generated_input_count": 3, "valid_generated_input_count": 2},
        "campaign": {"execs_done": 100, "queue_count": 2},
        "coverage": {"report_exists": True, "line_coverage": {"covered": 27, "total": 100},
                     "edge_coverage": {"status": "unavailable"}},
        "build": {"uses_fuzzbench_docker_environment": True},
    }), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"elfuzz\tlibpng_libpng_read_fuzzer\tnot_applicable\t{inv_ws}\t{inv_ws / 'metadata.json'}\t\n"
        f"elfuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, generator="elfuzz", profile="reproduction-delta")
    assert summary["not_applicable_pairs"] == 1
    assert summary["applicable_pairs"] == 1
    assert summary["applicable_evaluated_pairs"] == 1
    assert summary["failed_pairs"] == 0


# 13. matrix collector: 9 applicable + 11 Invalid across the valuable set
def test_matrix_collector_valuable_set_counts(tmp_path: Path):
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
            "excluded_from_aggregate": True, "profile": "reproduction-delta",
        }), encoding="utf-8")
        rows.append(f"elfuzz\t{target}\tnot_applicable\t{ws}\t{ws / 'metadata.json'}\t")
    for target in APPLICABLE:
        ws = matrix_dir / "app" / target
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "metadata.json").write_text(json.dumps({
            "baseline": "elfuzz", "generator": "elfuzz", "status": "failed",
            "task_family": "input_generator", "applicability": "applicable",
            "exclude_from_aggregate": False, "excluded_from_aggregate": False,
            "profile": "reproduction-delta", "campaign": {"execs_done": 0},
        }), encoding="utf-8")
        rows.append(f"elfuzz\t{target}\tfailed\t{ws}\t{ws / 'metadata.json'}\t")
    (matrix_dir / "matrix.tsv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    summary = matrix_collector.collect(matrix_dir, generator="elfuzz", profile="reproduction-delta")
    assert summary["not_applicable_pairs"] == 11
    assert summary["applicable_pairs"] == 9


# 14. strict matrix collector: a real evaluated elfuzz delta row has no violations
def test_matrix_strict_no_violations_for_real_evaluated_row(tmp_path: Path):
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    app_ws = matrix_dir / "app"
    app_ws.mkdir()
    (app_ws / "metadata.json").write_text(json.dumps({
        "baseline": "elfuzz", "generator": "elfuzz", "status": "evaluated",
        "task_family": "input_generator", "applicability": "applicable",
        "exclude_from_aggregate": False, "excluded_from_aggregate": False,
        "profile": "reproduction-delta", "method_variant": "paper-faithful",
        "generated_input_count": 3, "elfuzz": {"fuzzer_programs": 1, "generated_inputs": 3,
        "valid_generated_inputs": 2}, "input_generation": {"fuzzer_program_count": 1,
        "generated_input_count": 3, "valid_generated_input_count": 2},
        "campaign": {"execs_done": 100, "queue_count": 2},
        "coverage": {"report_exists": True, "line_coverage": {"covered": 27, "total": 100},
                     "edge_coverage": {"status": "unavailable"}},
        "build": {"uses_fuzzbench_docker_environment": True},
    }), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"elfuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, strict=True, generator="elfuzz", profile="reproduction-delta")
    assert summary["evaluated_row_violations"] == []


# 15. strict matrix collector: a coverage-missing evaluated row is flagged
def test_matrix_strict_flags_coverage_missing_evaluated_row(tmp_path: Path):
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    app_ws = matrix_dir / "app"
    app_ws.mkdir()
    (app_ws / "metadata.json").write_text(json.dumps({
        "baseline": "elfuzz", "generator": "elfuzz", "status": "evaluated",
        "task_family": "input_generator", "applicability": "applicable",
        "exclude_from_aggregate": False, "profile": "reproduction-delta",
        "method_variant": "paper-faithful", "generated_input_count": 3,
        "elfuzz": {"fuzzer_programs": 1, "generated_inputs": 3, "valid_generated_inputs": 2},
        "campaign": {"execs_done": 100, "queue_count": 2},
        "coverage": {"report_exists": False, "line_coverage": None,
                     "edge_coverage": {"status": "unavailable"}},
        "build": {"uses_fuzzbench_docker_environment": True},
    }), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"elfuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, strict=True, generator="elfuzz", profile="reproduction-delta")
    assert summary["evaluated_row_violations"]
    violations = summary["evaluated_row_violations"][0]["violations"]
    assert any("report_exists" in v for v in violations)
