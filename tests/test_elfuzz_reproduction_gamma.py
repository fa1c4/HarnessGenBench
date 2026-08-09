"""Gamma reproduction tests for the ELFuzz input-generator pipeline.

These tests exercise the paper-consistent ELFuzz reproduction contract from
``plans/elfuzz_reproduction_gamma.md`` with fake Docker/CLI runners so they
pass without real external checkouts, Docker, TGI, or model access.

ELFuzz is an ``input_generator`` (it synthesizes/evolves input-producing fuzzer
programs against a fixed native FuzzBench target, then replays generated/campaign
inputs on a coverage-instrumented SUT), never a harness generator.
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


elf = load_module("elfuzz_target_pipeline_gamma", ROOT / "docker/common/elfuzz_target_pipeline.py")
campaign_mod = load_module("hgb_input_campaign_gamma", ROOT / "docker/common/hgb_input_campaign.py")
matrix_collector = load_module("hgb_collect_matrix_gamma", ROOT / "scripts/hgb_collect_matrix.py")


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
    """Simulates the ELFuzz SUT Docker build and the coverage replay shell.

    - ``docker build`` succeeds and records the image tag.
    - ``docker image inspect`` returns a fake digest.
    - ``docker create`` returns a container name.
    - ``docker cp <container>:/out/<fuzz_target> <host>`` writes a real fake
      executable binary to the host path so smoke/coverage replay work.
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
                # cmd: docker cp <container>:/out/<fuzz_target> <host_path>
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
            "HGB_BASELINE_PROFILE": "reproduction-gamma",
            "HGB_BASELINE_PROTOCOL": "paper-native",
            "HGB_METADATA_DIR": str(ROOT / "metadata"),
            "HGB_GENERATOR_ARTIFACT_DIR": str(ROOT / "artifacts" / "elfuzz"),
            "ELFUZZ_ALLOW_SUT_BUILD": "1",
        }
    )
    return env


def run_full(
    tmp_path: Path,
    env: dict[str, str],
    target: str = "jsoncpp_jsoncpp_fuzzer",
    runner=None,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    workspace = tmp_path / "workspace"
    package = make_target_package(tmp_path, target)
    env = dict(env)
    env["HGB_TARGET_PACKAGE"] = str(package)
    if runner is not None:
        env["ELFUZZ_ALLOW_SUT_BUILD"] = "1"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "docker/common/elfuzz_target_pipeline.py"), "full",
         "--workspace", str(workspace), "--target", target, "--target-package", str(package),
         "--artifact-dir", str(tmp_path / "artifact"), "--metadata-root", str(ROOT / "metadata"),
         "--profile", env.get("HGB_BASELINE_PROFILE", "reproduction-gamma"), "--protocol", env.get("HGB_BASELINE_PROTOCOL", "paper-native")],
        cwd=ROOT, env=env, text=True, capture_output=True, check=False,
    )
    return proc, workspace


# 1. all 20 valuable targets present
def test_all_valuable_targets_present_in_manifest() -> None:
    valuable = elf.valuable_targets(ROOT / "metadata")
    adapters = elf.load_adapters(ROOT / "metadata")
    assert set(valuable) == set(adapters), "manifest must cover exactly the valuable set"
    assert len(valuable) == 20


# 2. exactly 9 applicable and 11 Invalid
def test_exactly_nine_applicable_eleven_invalid() -> None:
    adapters = elf.load_adapters(ROOT / "metadata")
    applicable = [t for t, e in adapters.items() if e.get("applicability") == "applicable"]
    invalid = [t for t, e in adapters.items() if e.get("applicability") == "Invalid"]
    assert set(applicable) == APPLICABLE
    assert set(invalid) == INVALID
    assert len(applicable) == 9
    assert len(invalid) == 11
    for target in INVALID:
        cls = elf.classify_target(target, ROOT / "metadata")
        assert cls["applicability"] == "Invalid"
        assert cls["reason_code"] == "elfuzz_non_text_target"


# 3. invalid preflight returns before Docker/model/TGI helper calls
def test_invalid_preflight_before_docker_model_tgi(tmp_path: Path) -> None:
    out = tmp_path / "result.json"
    env = {
        "HGB_BASELINE_PROFILE": "reproduction-gamma",
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
    for stage in elf.STAGE_NAMES:
        assert data["stages"][stage]["status"] == "not_applicable"
    harness = (ROOT / "scripts/hgb_generate_harness.sh").read_text(encoding="utf-8")
    assert harness.index("ELFuzz supports text-input targets only") < harness.index("ensure_artifacts_present")
    # The host-side preflight must run before any Docker/model/TGI startup.
    run_baseline = (ROOT / "scripts/hgb_run_baseline.sh").read_text(encoding="utf-8")
    assert "reproduction-gamma" in run_baseline


# 4. applicable targets require FuzzBench native+coverage builds; prebuilt binary rejected
def test_gamma_rejects_prebuilt_binary(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    cli = fake_elfuzz_cli(tmp_path / "elfuzz", project_root)
    binary = make_executable(tmp_path / "bin", "#!/usr/bin/env bash\nexit 0\n")
    env = base_env(tmp_path, cli, project_root)
    env["ELFUZZ_TARGET_BINARY"] = str(binary)
    proc, workspace = run_full(tmp_path, env)
    metadata = json.loads((workspace / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] in {"infra_missing", "infra_failure"}
    assert metadata["stages"]["target_build"]["status"] in {"infra_missing", "infra_failure"}
    assert proc.returncode != 0


def test_gamma_builds_native_and_coverage_sut(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    cli = fake_elfuzz_cli(tmp_path / "elfuzz", project_root)
    runner = FakeDockerRunner()
    env = base_env(tmp_path, cli, project_root)
    # Inject the fake runner via a small wrapper: the pipeline reads
    # self.runner = default_docker_runner; we patch it through env by using a
    # subprocess that imports a shim. Instead, drive the pipeline in-process.
    package = make_target_package(tmp_path, "jsoncpp_jsoncpp_fuzzer")
    env["HGB_TARGET_PACKAGE"] = str(package)
    pipeline = elf.ELFuzzPipeline(
        workspace=tmp_path / "workspace",
        target="jsoncpp_jsoncpp_fuzzer",
        target_package=package,
        artifact_dir=tmp_path / "artifact",
        metadata_root=ROOT / "metadata",
        profile="reproduction-gamma",
        protocol="paper-native",
    )
    pipeline.runner = runner
    pipeline.project_root = project_root
    # Point the CLI/produce/campaign env at the fake project root.
    os.environ.update({k: v for k, v in env.items() if k.startswith("ELFUZZ_")})
    code = pipeline.full()
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert code == 0, metadata.get("reason")
    assert metadata["status"] == "evaluated"
    # Native and coverage SUT binaries were built and extracted.
    sut = tmp_path / "workspace" / "sut"
    contract = json.loads((sut / "contract.json").read_text(encoding="utf-8"))
    assert contract["native"]["binary_path"]
    assert contract["coverage"]["binary_path"]
    assert Path(contract["native"]["binary_path"]).is_file()
    assert Path(contract["coverage"]["binary_path"]).is_file()
    assert (sut / "build_logs" / "native.log").is_file()
    assert (sut / "build_logs" / "coverage.log").is_file()
    # A docker build was issued for both variants.
    build_cmds = [c for c in runner.commands if c[:2] == ["docker", "build"]]
    assert len(build_cmds) >= 2


# 5. extension adapters do not run alias jsoncpp/libxml2 unless actual target matches
def test_extension_adapters_no_aliasing() -> None:
    violations = elf.validate_no_aliasing(ROOT / "metadata")
    assert violations == []
    adapters = elf.load_adapters(ROOT / "metadata")
    for target, entry in adapters.items():
        if entry.get("applicability") != "applicable":
            continue
        benchmark = str(entry["upstream_benchmark"])
        if entry.get("adapter_class") == elf.EXTENSION:
            assert entry.get("hgb_adapter") is True
            assert benchmark not in elf.UPSTREAM_NATIVE_BENCHMARKS
            yaml_path = ROOT / entry["adapter_dir"] / "adapter.yaml"
            assert yaml_path.is_file()
            parsed = elf.parse_simple_yaml(yaml_path)
            assert str(parsed.get("target")) == target
            # The adapter must NOT alias an unrelated upstream benchmark.
            assert str(parsed.get("upstream_benchmark", "")) not in elf.UPSTREAM_NATIVE_BENCHMARKS


# 6. adapter files are loaded into the generated ELFuzz benchmark directory
def test_adapter_files_loaded_into_benchmark_dir(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    cli = fake_elfuzz_cli(tmp_path / "elfuzz", project_root)
    runner = FakeDockerRunner()
    env = base_env(tmp_path, cli, project_root)
    package = make_target_package(tmp_path, "jsoncpp_jsoncpp_fuzzer")
    env["HGB_TARGET_PACKAGE"] = str(package)
    pipeline = elf.ELFuzzPipeline(
        workspace=tmp_path / "workspace",
        target="jsoncpp_jsoncpp_fuzzer",
        target_package=package,
        artifact_dir=tmp_path / "artifact",
        metadata_root=ROOT / "metadata",
        profile="reproduction-gamma",
        protocol="paper-native",
    )
    pipeline.runner = runner
    pipeline.project_root = project_root
    os.environ.update({k: v for k, v in env.items() if k.startswith("ELFUZZ_")})
    code = pipeline.full()
    assert code == 0
    bench_dir = tmp_path / "workspace" / "adapter" / "benchmark"
    assert (bench_dir / "format.md").is_file()
    assert (bench_dir / "seed_fuzzer.py").is_file()
    assert (bench_dir / "adapter.yaml").is_file()
    assert (bench_dir / "benchmark.json").is_file()
    bjson = json.loads((bench_dir / "benchmark.json").read_text(encoding="utf-8"))
    assert bjson["target"] == "jsoncpp_jsoncpp_fuzzer"
    assert bjson["sut_run_command"]
    assert bjson["coverage_command"]
    assert bjson["produced_input_dir"]
    # The synth/run command passed --hgb-benchmark-dir pointing at this dir.
    synth_cmd = (tmp_path / "workspace" / "synthesis" / "command.txt").read_text(encoding="utf-8")
    assert "--hgb-benchmark-dir" in synth_cmd
    assert str(bench_dir) in synth_cmd


# 7. generated input counter excludes configs, fuzzer source, logs, prompts, preseed
def test_generated_input_counter_excludes_non_inputs(tmp_path: Path) -> None:
    produced = tmp_path / "produced"
    produced.mkdir()
    (produced / "input_000").write_bytes(b'{"k": 0}')
    (produced / "evolved.py").write_text("x=1\n", encoding="utf-8")
    (produced / "meta.json").write_text("{}", encoding="utf-8")
    (produced / "run.log").write_text("log\n", encoding="utf-8")
    (produced / "config.yaml").write_text("k: v\n", encoding="utf-8")
    (produced / "preseed_corpus").write_bytes(b"seed")
    (produced / "lineage.jsonl").write_text("{}\n", encoding="utf-8")
    (produced / "manifest.txt").write_text("m\n", encoding="utf-8")
    (produced / "prompt_001").write_text("p\n", encoding="utf-8")
    inputs = [p for p in produced.iterdir() if elf.is_produced_input(p)]
    assert {p.name for p in inputs} == {"input_000"}
    assert not elf.is_produced_input(produced / "evolved.py")
    assert not elf.is_produced_input(produced / "meta.json")
    assert not elf.is_produced_input(produced / "run.log")
    assert not elf.is_produced_input(produced / "config.yaml")
    assert not elf.is_produced_input(produced / "preseed_corpus")
    assert not elf.is_produced_input(produced / "lineage.jsonl")
    assert not elf.is_produced_input(produced / "manifest.txt")
    assert not elf.is_produced_input(produced / "prompt_001")
    assert elf.is_produced_input(produced / "input_000")


# 8. coverage fails if only AFL path counters are available
def test_coverage_fails_on_afl_paths_only(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    cli = fake_elfuzz_cli(tmp_path / "elfuzz", project_root)
    # A runner that never produces a coverage report (only AFL-style stats).
    runner = FakeDockerRunner(coverage_stdout="")
    env = base_env(tmp_path, cli, project_root)
    package = make_target_package(tmp_path, "jsoncpp_jsoncpp_fuzzer")
    env["HGB_TARGET_PACKAGE"] = str(package)
    pipeline = elf.ELFuzzPipeline(
        workspace=tmp_path / "workspace",
        target="jsoncpp_jsoncpp_fuzzer",
        target_package=package,
        artifact_dir=tmp_path / "artifact",
        metadata_root=ROOT / "metadata",
        profile="reproduction-gamma",
        protocol="paper-native",
    )
    pipeline.runner = runner
    pipeline.project_root = project_root
    os.environ.update({k: v for k, v in env.items() if k.startswith("ELFUZZ_")})
    code = pipeline.full()
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert code != 0
    assert metadata["status"] != "evaluated"
    assert metadata["stages"]["coverage"]["status"] in {"failed", "quality_failure"}
    # The coverage summary must not label AFL paths_total as line coverage.
    cov = json.loads((tmp_path / "workspace" / "coverage" / "coverage.json").read_text(encoding="utf-8"))
    assert cov["edge_coverage"]["status"] == "unavailable"
    assert cov["line_coverage"] is None or cov.get("total_lines", 0) == 0


# 9. status=evaluated requires generated inputs, validation, real SUT execution, coverage
def test_evaluated_requires_full_closed_loop(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    cli = fake_elfuzz_cli(tmp_path / "elfuzz", project_root)
    runner = FakeDockerRunner()
    env = base_env(tmp_path, cli, project_root)
    package = make_target_package(tmp_path, "jsoncpp_jsoncpp_fuzzer")
    env["HGB_TARGET_PACKAGE"] = str(package)
    pipeline = elf.ELFuzzPipeline(
        workspace=tmp_path / "workspace",
        target="jsoncpp_jsoncpp_fuzzer",
        target_package=package,
        artifact_dir=tmp_path / "artifact",
        metadata_root=ROOT / "metadata",
        profile="reproduction-gamma",
        protocol="paper-native",
    )
    pipeline.runner = runner
    pipeline.project_root = project_root
    os.environ.update({k: v for k, v in env.items() if k.startswith("ELFUZZ_")})
    code = pipeline.full()
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert code == 0, metadata.get("reason")
    assert metadata["status"] == "evaluated"
    assert metadata["task_family"] == "input_generator"
    assert metadata["applicability"] == "applicable"
    assert metadata["baseline"] == "elfuzz"
    # Nested elfuzz object (plan section 9).
    assert metadata["elfuzz"]["fuzzer_programs"] >= 1
    assert metadata["elfuzz"]["generated_inputs"] >= 1
    assert metadata["elfuzz"]["valid_generated_inputs"] >= 1
    assert metadata["elfuzz"]["evolution_iterations"] >= 1
    # Real SUT execution: native + coverage binaries exist.
    assert isinstance(metadata["elfuzz"]["adapter_class"], str)
    contract = json.loads((tmp_path / "workspace" / "sut" / "contract.json").read_text(encoding="utf-8"))
    assert Path(contract["native"]["binary_path"]).is_file()
    assert Path(contract["coverage"]["binary_path"]).is_file()
    # Real coverage replay with line/region/function data.
    cov = json.loads((tmp_path / "workspace" / "coverage" / "coverage.json").read_text(encoding="utf-8"))
    assert cov["total_lines"] > 0
    assert cov["covered_lines"] > 0
    assert cov["inputs_replayed"] > 0
    assert cov["line_coverage"] is not None
    assert cov["region_coverage"] is not None
    assert cov["function_coverage"] is not None
    # All canonical stages completed.
    for stage in elf.STAGE_NAMES:
        assert metadata["stages"][stage]["status"] == "complete", stage
    # Generated input directories exist.
    assert (tmp_path / "workspace" / "generated_inputs" / "produced").is_dir()
    assert (tmp_path / "workspace" / "fuzzer_programs").exists() or (tmp_path / "workspace" / "synthesis" / "fuzzer_programs").is_dir()


def test_gamma_budget_is_paper_faithful() -> None:
    budget = elf.budget_for_profile("reproduction-gamma", {})
    assert budget["reject_prebuilt_binary"] is True
    assert budget["require_coverage_build"] is True
    assert budget["paper_core"] is True
    assert budget["method_variant"] == "paper-faithful"
    assert budget["evolution_iterations"] >= 2


def test_gamma_invalid_target_excluded_from_aggregate(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    inv_ws = tmp_path / "invalid"
    app_ws = tmp_path / "applicable"
    matrix_dir.mkdir(parents=True)
    inv_ws.mkdir()
    app_ws.mkdir()
    (inv_ws / "metadata.json").write_text(json.dumps({
        "baseline": "elfuzz", "generator": "elfuzz", "status": "not_applicable",
        "task_family": "input_generator", "applicability": "Invalid",
        "reason_code": "elfuzz_non_text_target", "excluded_from_aggregate": True,
    }), encoding="utf-8")
    (app_ws / "metadata.json").write_text(json.dumps({
        "baseline": "elfuzz", "generator": "elfuzz", "status": "evaluated",
        "task_family": "input_generator", "applicability": "applicable",
        "excluded_from_aggregate": False,
        "generated_input_count": 3,
        "coverage": {"line_coverage": {"covered": 7, "total": 10}},
    }), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"elfuzz\tlibpng_libpng_read_fuzzer\tnot_applicable\t{inv_ws}\t{inv_ws / 'metadata.json'}\t\n"
        f"elfuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir)
    assert summary["not_applicable_pairs"] == 1
    assert summary["applicable_pairs"] == 1
    assert summary["applicable_evaluated_pairs"] == 1
    assert len(summary["coverage_by_applicable_evaluated"]) == 1
