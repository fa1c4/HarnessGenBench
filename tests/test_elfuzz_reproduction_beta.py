"""Beta reproduction tests for the ELFuzz input-generator pipeline.

These tests exercise the paper-consistent ELFuzz reproduction contract from
``plans/elfuzz_reproduction_beta.md`` with fake runners so they pass without
real external checkouts, Docker, TGI, or model access.

ELFuzz is an ``input_generator`` (it synthesizes/evolves input-producing fuzzer
programs against a fixed native FuzzBench target), never a harness generator.
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


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


elf = load_module("elfuzz_target_pipeline_beta", ROOT / "docker/common/elfuzz_target_pipeline.py")
campaign_mod = load_module("hgb_input_campaign_beta", ROOT / "docker/common/hgb_input_campaign.py")
matrix_collector = load_module("hgb_collect_matrix_beta", ROOT / "scripts/hgb_collect_matrix.py")


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


def fake_target_binary(path: Path, body: str = "#!/usr/bin/env bash\nexit 0\n") -> Path:
    return make_executable(path, body)


def base_env(tmp_path: Path, cli: Path, binary: Path, project_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "ELFUZZ_CLI": str(cli),
            "ELFUZZ_TARGET_BINARY": str(binary),
            "ELFUZZ_PROJECT_ROOT": str(project_root),
            "ELFUZZ_FUZZER_PROGRAMS_DIR": str(project_root / "evaluation" / "elmfuzzers"),
            "ELFUZZ_PRODUCED_INPUTS_DIR": str(project_root / "extradata" / "seeds" / "raw" / "jsoncpp" / "elm"),
            "ELFUZZ_CAMPAIGN_OUTPUT_DIR": str(project_root / "extradata" / "rq1" / "afl_results"),
            "ELFUZZ_REQUIRE_HF_TOKEN": "0",
            "ELFUZZ_REQUIRE_GPU": "0",
            "ELFUZZ_SKIP_DOWNLOAD": "1",
            "ELFUZZ_STAGE_TIMEOUT_SECONDS": "60",
            "ELFUZZ_COVERAGE_REPLAY": "0",
            "HGB_BASELINE_PROFILE": "alpha",
            "HGB_BASELINE_PROTOCOL": "paper-native",
            "HGB_METADATA_DIR": str(ROOT / "metadata"),
            "HGB_GENERATOR_ARTIFACT_DIR": str(ROOT / "artifacts" / "elfuzz"),
        }
    )
    return env


def run_full(tmp_path: Path, env: dict[str, str], target: str = "jsoncpp_jsoncpp_fuzzer") -> subprocess.CompletedProcess[str]:
    workspace = tmp_path / "workspace"
    package = make_target_package(tmp_path, target)
    return subprocess.run(
        [sys.executable, str(ROOT / "docker/common/elfuzz_target_pipeline.py"), "full",
         "--workspace", str(workspace), "--target", target, "--target-package", str(package),
         "--artifact-dir", str(tmp_path / "artifact"), "--metadata-root", str(ROOT / "metadata"),
         "--profile", env.get("HGB_BASELINE_PROFILE", "alpha"), "--protocol", env.get("HGB_BASELINE_PROTOCOL", "paper-native")],
        cwd=ROOT, env=env, text=True, capture_output=True, check=False,
    )


# 1. invalid gate occurs before Docker/model/TGI
def test_invalid_gate_before_docker_model_tgi(tmp_path: Path) -> None:
    out = tmp_path / "result.json"
    env = {
        "HGB_BASELINE_PROFILE": "alpha",
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
    # No Docker/model/TGI stages started: every stage is not_applicable.
    for stage in elf.STAGE_NAMES:
        assert data["stages"][stage]["status"] == "not_applicable"
    # The host-side harness gate precedes artifact checkout.
    harness = (ROOT / "scripts/hgb_generate_harness.sh").read_text(encoding="utf-8")
    assert harness.index("ELFuzz supports text-input targets only") < harness.index("ensure_artifacts_present")


# 2. every valuable target classified
def test_every_valuable_target_classified() -> None:
    valuable = elf.valuable_targets(ROOT / "metadata")
    adapters = elf.load_adapters(ROOT / "metadata")
    assert set(valuable) == set(adapters)
    elf.validate_adapter_coverage(ROOT / "metadata")
    for target in APPLICABLE:
        cls = elf.classify_target(target, ROOT / "metadata")
        assert cls["applicability"] == "applicable"
    for target in INVALID:
        cls = elf.classify_target(target, ROOT / "metadata")
        assert cls["applicability"] == "Invalid"
        assert cls["reason_code"] == "elfuzz_non_text_target"


# 3. duplicates are rejected
def test_duplicate_adapters_rejected(tmp_path: Path) -> None:
    meta = tmp_path / "metadata"
    meta.mkdir()
    (meta / "fuzzbench_targets.json").write_text(json.dumps({"target_sets": {"valuable": {"targets": ["a_target", "b_target"]}}}), encoding="utf-8")
    (meta / "elfuzz_target_adapters.yaml").write_text(
        "schema_version: 1\ngenerator: elfuzz\ntask_family: input_generator\ntargets:\n"
        "  - target: a_target\n    applicability: Invalid\n    input_kind: non-text\n    reason_code: elfuzz_non_text_target\n"
        "  - target: a_target\n    applicability: Invalid\n    input_kind: non-text\n    reason_code: elfuzz_non_text_target\n",
        encoding="utf-8",
    )
    with pytest.raises(elf.PipelineError):
        elf.load_adapters(meta)


# 4. unknown valuable target fails until classified
def test_unknown_valuable_target_fails(tmp_path: Path) -> None:
    meta = tmp_path / "metadata"
    meta.mkdir()
    (meta / "fuzzbench_targets.json").write_text(json.dumps({"target_sets": {"valuable": {"targets": ["ghost_target", "classified_target"]}}}), encoding="utf-8")
    (meta / "elfuzz_target_adapters.yaml").write_text(
        "schema_version: 1\ngenerator: elfuzz\ntask_family: input_generator\ntargets:\n"
        "  - target: classified_target\n    applicability: Invalid\n    input_kind: non-text\n    reason_code: elfuzz_non_text_target\n",
        encoding="utf-8",
    )
    with pytest.raises(elf.PipelineError):
        elf.validate_adapter_coverage(meta)


# 5. applicable target cannot use jsoncpp/libxml2 alias unless adapter target equals actual target
def test_no_upstream_aliasing_for_extension_targets() -> None:
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


def test_aliasing_rejected_when_adapter_target_differs(tmp_path: Path) -> None:
    meta = tmp_path / "metadata"
    meta.mkdir()
    (meta / "fuzzbench_targets.json").write_text(json.dumps({"target_sets": {"valuable": {"targets": ["curl_curl_fuzzer_http", "jsoncpp_jsoncpp_fuzzer"]}}}), encoding="utf-8")
    (meta / "elfuzz_target_adapters.yaml").write_text(
        "schema_version: 1\ngenerator: elfuzz\ntask_family: input_generator\ntargets:\n"
        "  - target: jsoncpp_jsoncpp_fuzzer\n    applicability: applicable\n    input_kind: text\n    upstream_benchmark: jsoncpp\n"
        "    adapter_class: upstream-native\n    adapter_id: jsoncpp\n    build_mode: fuzzbench_native\n    input_mode: file\n    argv: [\"@@\"]\n"
        "    format: JSON\n    format_spec: repro/elfuzz/targets/jsoncpp_jsoncpp_fuzzer/format.md\n    adapter_dir: repro/elfuzz/targets/jsoncpp_jsoncpp_fuzzer\n"
        "    seed_template: repro/elfuzz/targets/jsoncpp_jsoncpp_fuzzer/seed_fuzzer.py\n    validity_check: json\n    timeout_seconds: 5\n"
        "  - target: curl_curl_fuzzer_http\n    applicability: applicable\n    input_kind: text\n    upstream_benchmark: jsoncpp\n"
        "    adapter_class: extension\n    adapter_id: curl_http\n    build_mode: fuzzbench_native\n    input_mode: file\n    argv: [\"@@\"]\n"
        "    format: HTTP\n    format_spec: repro/elfuzz/targets/curl_curl_fuzzer_http/format.md\n    adapter_dir: repro/elfuzz/targets/curl_curl_fuzzer_http\n"
        "    seed_template: repro/elfuzz/targets/curl_curl_fuzzer_http/seed_fuzzer.py\n    validity_check: http_response\n    timeout_seconds: 5\n",
        encoding="utf-8",
    )
    # curl declares upstream_benchmark: jsoncpp (an alias) without hgb_adapter.
    with pytest.raises(elf.PipelineError):
        elf.validate_no_aliasing(meta)


# 6. adapter files are passed to ELFuzz command
def test_adapter_files_passed_to_elfuzz_command(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    cli = fake_elfuzz_cli(tmp_path / "elfuzz", project_root)
    binary = fake_target_binary(tmp_path / "bin")
    env = base_env(tmp_path, cli, binary, project_root)
    result = run_full(tmp_path, env)
    assert result.returncode == 0, result.stderr
    synth_cmd = (tmp_path / "workspace" / "synthesis" / "command.txt").read_text(encoding="utf-8")
    run_cmd = (tmp_path / "workspace" / "campaign" / "command.txt").read_text(encoding="utf-8")
    assert "--format-spec" in synth_cmd
    assert "format.md" in synth_cmd
    assert "--seed-fuzzer" in synth_cmd
    assert "seed_fuzzer.py" in synth_cmd
    assert "--hgb-adapter" in synth_cmd
    assert "adapter.yaml" in synth_cmd
    assert "--format-spec" in run_cmd
    # adapter hashes were recorded
    hashes = json.loads((tmp_path / "workspace" / "config" / "adapter_hashes.json").read_text(encoding="utf-8"))
    assert "format_spec" in hashes or "adapter_yaml" in hashes


# 7. target build requires /out/<fuzz_target> and rejects build.sh
def test_target_build_rejects_build_sh(tmp_path: Path) -> None:
    build_sh = tmp_path / "build.sh"
    build_sh.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    build_sh.chmod(0o755)
    v = elf.verify_target_binary(build_sh, "anything")
    assert v["is_build_sh"] is True
    assert v["ok"] is False


def test_target_build_requires_executable_nonzero(tmp_path: Path) -> None:
    empty = tmp_path / "fuzz_target"
    empty.write_text("", encoding="utf-8")
    v = elf.verify_target_binary(empty, "fuzz_target")
    assert v["exists"] is True
    assert v["nonzero_size"] is False
    assert v["ok"] is False


def test_delegated_build_cannot_complete_without_executable(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    cli = fake_elfuzz_cli(tmp_path / "elfuzz", project_root)
    package = make_target_package(tmp_path, "jsoncpp_jsoncpp_fuzzer")
    workspace = tmp_path / "workspace"
    env = base_env(tmp_path, cli, fake_target_binary(tmp_path / "bin"), project_root)
    env["ELFUZZ_TARGET_BINARY"] = ""  # no prebuilt binary
    proc = subprocess.run(
        [sys.executable, str(ROOT / "docker/common/elfuzz_target_pipeline.py"), "full",
         "--workspace", str(workspace), "--target", "jsoncpp_jsoncpp_fuzzer", "--target-package", str(package),
         "--artifact-dir", str(tmp_path / "artifact"), "--metadata-root", str(ROOT / "metadata"),
         "--profile", "alpha", "--protocol", "paper-native"],
        cwd=ROOT, env=env, text=True, capture_output=True, check=False,
    )
    metadata = json.loads((workspace / "metadata.json").read_text(encoding="utf-8"))
    # Without a binary and without Docker, build fails as infra_failure/infra_missing.
    assert metadata["status"] in {"infra_failure", "infra_missing"}
    assert metadata["stages"]["target_build"]["status"] in {"infra_failure", "infra_missing"}
    assert proc.returncode != 0


def test_exact_target_name_must_match_out_path(tmp_path: Path) -> None:
    real = tmp_path / "jsoncpp_jsoncpp_fuzzer"
    make_executable(real, "#!/usr/bin/env bash\nexit 0\n")
    v = elf.verify_target_binary(real, "jsoncpp_jsoncpp_fuzzer")
    assert v["name_matches"] is True
    assert v["ok"] is True
    wrong = tmp_path / "not_the_target"
    make_executable(wrong, "#!/usr/bin/env bash\nexit 0\n")
    v2 = elf.verify_target_binary(wrong, "jsoncpp_jsoncpp_fuzzer")
    assert v2["name_matches"] is False
    assert v2["ok"] is False


# 8. generated input count excludes .py, .json, logs, configs, preseed files
def test_generated_input_count_excludes_non_inputs(tmp_path: Path) -> None:
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
    inputs = [p for p in produced.iterdir() if elf.is_produced_input(p)]
    assert {p.name for p in inputs} == {"input_000", "preseed_corpus"} or {p.name for p in inputs} == {"input_000"}
    # preseed_corpus: stem "preseed_corpus" is in ignored_stems -> excluded
    assert not elf.is_produced_input(produced / "evolved.py")
    assert not elf.is_produced_input(produced / "meta.json")
    assert not elf.is_produced_input(produced / "run.log")
    assert not elf.is_produced_input(produced / "config.yaml")
    assert not elf.is_produced_input(produced / "preseed_corpus")
    assert not elf.is_produced_input(produced / "lineage.jsonl")
    assert not elf.is_produced_input(produced / "manifest.txt")
    assert elf.is_produced_input(produced / "input_000")


# 9. validation fails if all generated inputs fail target execution
def test_validation_fails_if_all_inputs_fail_target(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    cli = fake_elfuzz_cli(tmp_path / "elfuzz", project_root)
    # A target binary that always exits 77 (libFuzzer misuse / crash).
    binary = fake_target_binary(tmp_path / "bin", "#!/usr/bin/env bash\nexit 77\n")
    env = base_env(tmp_path, cli, binary, project_root)
    result = run_full(tmp_path, env)
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] in {"failed", "quality_failure", "infra_failure"}
    assert metadata["stages"]["generated_input_validation"]["status"] in {"failed", "quality_failure"}
    assert metadata.get("input_generation", {}).get("valid_generated_input_count") == 0
    assert result.returncode != 0


# 10. campaign cannot complete with zero executions
def test_campaign_cannot_complete_with_zero_execs(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    zero_cli = make_executable(
        tmp_path / "zero_elfuzz",
        "#!/usr/bin/env python3\nimport os, sys, json\nfrom pathlib import Path\n"
        "root=Path(os.environ.get('ELFUZZ_PROJECT_ROOT',''))\ncmd=sys.argv[1] if len(sys.argv)>1 else ''\nbenchmark=sys.argv[-1] if sys.argv else ''\n"
        "if cmd=='synth':\n  d=Path(os.environ['ELFUZZ_FUZZER_PROGRAMS_DIR']); d.mkdir(parents=True,exist_ok=True)\n  (d/'f.py').write_text('x=1\\n')\n  sys.exit(0)\n"
        "if cmd=='produce':\n  d=Path(os.environ['ELFUZZ_PRODUCED_INPUTS_DIR']); d.mkdir(parents=True,exist_ok=True)\n  (d/'in_0').write_bytes(b'{}')\n  sys.exit(0)\n"
        "if cmd=='run':\n  d=Path(os.environ['ELFUZZ_CAMPAIGN_OUTPUT_DIR'])/(benchmark+'_elfuzz_1')\n  (d/'default'/'queue').mkdir(parents=True,exist_ok=True)\n"
        "  (d/'default'/'fuzzer_stats').write_text('execs_done : 0\\npaths_total : 3\\n')\n  sys.exit(0)\nsys.exit(0)\n",
    )
    binary = fake_target_binary(tmp_path / "bin")
    env = base_env(tmp_path, zero_cli, binary, project_root)
    result = run_full(tmp_path, env)
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] in {"failed", "quality_failure", "infra_failure"}
    assert metadata["stages"]["campaign"]["status"] in {"failed", "quality_failure"}
    assert result.returncode != 0


# 11. coverage cannot complete from AFL path count alone
def test_coverage_cannot_complete_from_afl_paths_alone() -> None:
    summary = campaign_mod.coverage_from_campaign(stats={"execs_done": 0, "paths_total": 5}, report_path=None, queue_count=5)
    assert summary["complete"] is False
    assert summary["edge_coverage"]["status"] == "unavailable"
    assert summary["edge_coverage"]["value"] is None
    verify = campaign_mod.verify_campaign_execs({"execs_done": 0, "paths_total": 5})
    assert verify["has_executions"] is False
    assert verify["paths_only"] is True


def test_coverage_completes_with_execs_and_report(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(json.dumps({"data": [{"totals": {"lines": {"count": 10, "covered": 7}, "functions": {"count": 4, "covered": 3}, "regions": {"count": 8, "covered": 5}}}]}), encoding="utf-8")
    summary = campaign_mod.coverage_from_campaign(stats={"execs_done": 100, "paths_total": 2}, report_path=report, queue_count=2)
    assert summary["complete"] is True
    assert summary["line_coverage"]["covered"] == 7
    assert summary["edge_coverage"]["status"] == "unavailable"


# 12. invalid rows excluded from aggregate
def test_invalid_rows_excluded_from_aggregate(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    inv_ws = tmp_path / "invalid"
    app_ws = tmp_path / "applicable"
    matrix_dir.mkdir(parents=True)
    inv_ws.mkdir()
    app_ws.mkdir()
    (inv_ws / "metadata.json").write_text(json.dumps({"generator": "elfuzz", "status": "not_applicable", "task_family": "input_generator", "applicability": "Invalid", "reason_code": "elfuzz_non_text_target"}), encoding="utf-8")
    (app_ws / "metadata.json").write_text(json.dumps({"generator": "elfuzz", "status": "evaluated", "task_family": "input_generator", "applicability": "applicable", "generated_input_count": 3, "coverage": {"line_coverage": {"covered": 7, "total": 10}}}), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"elfuzz\tlibpng_libpng_read_fuzzer\tnot_applicable\t{inv_ws}\t{inv_ws / 'metadata.json'}\t\n"
        f"elfuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir)
    # Invalid row is counted as not_applicable but excluded from the denominator.
    assert summary["not_applicable_pairs"] == 1
    assert summary["applicable_pairs"] == 1
    assert summary["applicable_evaluated_pairs"] == 1
    assert summary["completed_pairs"] == 1
    assert summary["failed_pairs"] == 0
    # Coverage only for applicable evaluated rows.
    assert len(summary["coverage_by_applicable_evaluated"]) == 1
    assert summary["coverage_by_applicable_evaluated"][0]["coverage"]["line_coverage"]["covered"] == 7


# 13. full fake applicable target reaches evaluated with the beta stage contract
def test_applicable_target_reaches_evaluated_with_beta_contract(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    cli = fake_elfuzz_cli(tmp_path / "elfuzz", project_root)
    binary = fake_target_binary(tmp_path / "bin")
    env = base_env(tmp_path, cli, binary, project_root)
    result = run_full(tmp_path, env)
    assert result.returncode == 0, result.stderr
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "evaluated"
    assert metadata["task_family"] == "input_generator"
    assert metadata["applicability"] == "applicable"
    # Goal-stage aliases present and completed.
    for stage in ("target_build", "seed_fuzzer_synthesis", "evolution", "generated_input_validation", "campaign", "coverage"):
        assert metadata["stages"][stage]["status"] == "complete", stage
    # Nested result schema (paper section 9).
    assert metadata["input_generation"]["fuzzer_program_count"] >= 1
    assert metadata["input_generation"]["generated_input_count"] >= 1
    assert metadata["input_generation"]["valid_generated_input_count"] >= 1
    assert metadata["input_generation"]["evolution_iterations_completed"] >= 1
    assert metadata["campaign"]["execs_done"] > 0
    # Coverage is a real report path, edge coverage is unavailable (not AFL paths).
    assert metadata["coverage"]["report_exists"] is True
    assert metadata["coverage"]["edge_coverage"]["status"] == "unavailable"
    # Generation directories were written.
    assert (tmp_path / "workspace" / "synthesis" / "generations").is_dir()
    gens = list((tmp_path / "workspace" / "synthesis" / "generations").glob("generation_*"))
    assert gens


# 14. compat-smoke may use one iteration; alpha may not
def test_compat_smoke_one_iteration_allowed() -> None:
    smoke = elf.budget_for_profile("compat-smoke", {})
    assert smoke["evolution_iterations"] == 1
    assert smoke["excluded_from_aggregate"] is True
    alpha = elf.budget_for_profile("alpha", {})
    assert alpha["evolution_iterations"] >= 2
    assert alpha.get("evolution_seconds") >= 1
