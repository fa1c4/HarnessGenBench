"""Shared matrix collector tests for input-generator rows.

Tests the ``--require-input-generator-evaluated`` and ``--expect-invalid``
flags and the eta/zeta-specific input-generator invariant checks in
``scripts/hgb_collect_matrix.py`` (plans elfuzz_reproduction_eta.md §6/§8 and
g2fuzz_reproduction_zeta.md §7).
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


collector = load_module("hgb_collect_matrix_input_gen", ROOT / "scripts/hgb_collect_matrix.py")


APPLICABLE = {
    "curl_curl_fuzzer_http", "jsoncpp_jsoncpp_fuzzer", "libxml2_xml",
    "libxslt_xpath", "mruby_mruby_fuzzer_8c8bbd", "php_php-fuzz-parser_0dbedb",
    "re2_fuzzer", "sqlite3_ossfuzz", "systemd_fuzz-link-parser",
}
INVALID = {
    "bloaty_fuzz_target", "freetype2_ftfuzzer", "harfbuzz_hb-shape-fuzzer",
    "lcms_cms_transform_fuzzer", "libjpeg-turbo_libjpeg_turbo_fuzzer",
    "libpcap_fuzz_both", "libpng_libpng_read_fuzzer", "mbedtls_fuzz_dtlsclient",
    "openh264_decoder_fuzzer", "openssl_x509", "zlib_zlib_uncompress_fuzzer",
}


def _write_matrix(matrix_dir: Path, applicable_meta_fn, invalid_meta_fn) -> None:
    rows = ["generator\ttarget\tstatus\tworkspace\tmetadata\tsummary"]
    for target in INVALID:
        ws = matrix_dir / "inv" / target
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "metadata.json").write_text(json.dumps(invalid_meta_fn(target)), encoding="utf-8")
        rows.append(f"elfuzz\t{target}\tnot_applicable\t{ws}\t{ws / 'metadata.json'}\t")
    for target in APPLICABLE:
        ws = matrix_dir / "app" / target
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "metadata.json").write_text(json.dumps(applicable_meta_fn(target)), encoding="utf-8")
        rows.append(f"elfuzz\t{target}\t{applicable_meta_fn(target).get('status', 'evaluated')}\t{ws}\t{ws / 'metadata.json'}\t")
    (matrix_dir / "matrix.tsv").write_text("\n".join(rows) + "\n", encoding="utf-8")


def _eta_evaluated_meta(target: str) -> dict:
    return {
        "baseline": "elfuzz", "generator": "elfuzz", "status": "evaluated",
        "task_family": "input_generator", "applicability": "applicable",
        "exclude_from_aggregate": False, "excluded_from_aggregate": False,
        "profile": "reproduction-eta", "method_variant": "paper-faithful",
        "reported_target": target, "actual_sut_fuzz_target": target,
        "generated_input_count": 3,
        "elfuzz": {"fuzzer_programs": 1, "generated_inputs": 3, "valid_generated_inputs": 2, "evolution_iterations": 2},
        "input_generation": {"fuzzer_program_count": 1, "generated_input_count": 3, "valid_generated_input_count": 2, "evolution_iterations_completed": 2},
        "campaign": {"execs_done": 100, "queue_count": 2},
        "coverage": {"report_exists": True, "line_coverage": {"covered": 27, "total": 100}, "edge_coverage": {"status": "unavailable"}},
        "build": {"uses_fuzzbench_docker_environment": True, "containerized_sut_runtime": True},
    }


def _eta_invalid_meta(target: str) -> dict:
    return {
        "baseline": "elfuzz", "generator": "elfuzz", "status": "not_applicable",
        "task_family": "input_generator", "applicability": "Invalid",
        "reason_code": "elfuzz_non_text_target", "exclude_from_aggregate": True,
        "excluded_from_aggregate": True, "profile": "reproduction-eta",
    }


def _eta_failed_meta(target: str) -> dict:
    return {
        "baseline": "elfuzz", "generator": "elfuzz", "status": "failed",
        "task_family": "input_generator", "applicability": "applicable",
        "exclude_from_aggregate": False, "excluded_from_aggregate": False,
        "profile": "reproduction-eta", "campaign": {"execs_done": 0},
    }


# ---------------------------------------------------------------------------
# --require-input-generator-evaluated
# ---------------------------------------------------------------------------


def test_require_input_generator_evaluated_passes_when_all_evaluated(tmp_path: Path):
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    _write_matrix(matrix_dir, _eta_evaluated_meta, _eta_invalid_meta)
    summary = collector.collect(matrix_dir, generator="elfuzz", profile="reproduction-eta",
                                require_input_generator_evaluated=True, expect_invalid=11)
    assert summary["require_input_generator_evaluated_violations"] == []
    assert summary["expect_invalid_violation"] is None


def test_require_input_generator_evaluated_flags_failed_rows(tmp_path: Path):
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    _write_matrix(matrix_dir, _eta_failed_meta, _eta_invalid_meta)
    summary = collector.collect(matrix_dir, generator="elfuzz", profile="reproduction-eta",
                                require_input_generator_evaluated=True)
    assert len(summary["require_input_generator_evaluated_violations"]) == 9
    targets = {v["target"] for v in summary["require_input_generator_evaluated_violations"]}
    assert targets == APPLICABLE


def test_require_input_generator_evaluated_skips_invalid_rows(tmp_path: Path):
    # Invalid rows must NOT be flagged by --require-input-generator-evaluated.
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    _write_matrix(matrix_dir, _eta_failed_meta, _eta_invalid_meta)
    summary = collector.collect(matrix_dir, generator="elfuzz", profile="reproduction-eta",
                                require_input_generator_evaluated=True)
    for v in summary["require_input_generator_evaluated_violations"]:
        assert v["target"] not in INVALID


def test_require_input_generator_evaluated_skips_excluded_rows(tmp_path: Path):
    # Excluded rows (e.g. compat-smoke) must NOT be flagged.
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    rows = ["generator\ttarget\tstatus\tworkspace\tmetadata\tsummary"]
    ws = matrix_dir / "app"
    ws.mkdir()
    meta = _eta_failed_meta("jsoncpp_jsoncpp_fuzzer")
    meta["excluded_from_aggregate"] = True
    (ws / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    rows.append(f"elfuzz\tjsoncpp_jsoncpp_fuzzer\tfailed\t{ws}\t{ws / 'metadata.json'}\t")
    (matrix_dir / "matrix.tsv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    summary = collector.collect(matrix_dir, generator="elfuzz", profile="reproduction-eta",
                                require_input_generator_evaluated=True)
    assert summary["require_input_generator_evaluated_violations"] == []


# ---------------------------------------------------------------------------
# --expect-invalid
# ---------------------------------------------------------------------------


def test_expect_invalid_exact_match(tmp_path: Path):
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    _write_matrix(matrix_dir, _eta_evaluated_meta, _eta_invalid_meta)
    summary = collector.collect(matrix_dir, generator="elfuzz", profile="reproduction-eta", expect_invalid=11)
    assert summary["expect_invalid_violation"] is None
    assert summary["expect_invalid_actual"] == 11


def test_expect_invalid_mismatch(tmp_path: Path):
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    _write_matrix(matrix_dir, _eta_evaluated_meta, _eta_invalid_meta)
    summary = collector.collect(matrix_dir, generator="elfuzz", profile="reproduction-eta", expect_invalid=5)
    assert summary["expect_invalid_violation"] is not None
    assert "found 11" in summary["expect_invalid_violation"]


def test_expect_invalid_zero(tmp_path: Path):
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    _write_matrix(matrix_dir, _eta_evaluated_meta, _eta_invalid_meta)
    summary = collector.collect(matrix_dir, generator="elfuzz", profile="reproduction-eta", expect_invalid=0)
    assert summary["expect_invalid_violation"] is not None


# ---------------------------------------------------------------------------
# eta/zeta input-generator invariant checks
# ---------------------------------------------------------------------------


def test_eta_evaluated_row_violations_for_missing_containerized_runtime(tmp_path: Path):
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    meta = _eta_evaluated_meta("jsoncpp_jsoncpp_fuzzer")
    meta["build"]["containerized_sut_runtime"] = False
    ws = matrix_dir / "app"
    ws.mkdir()
    (ws / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"elfuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{ws}\t{ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = collector.collect(matrix_dir, strict=True, generator="elfuzz", profile="reproduction-eta")
    assert summary["evaluated_row_violations"]
    assert any("containerized" in v for v in summary["evaluated_row_violations"][0]["violations"])


def test_eta_evaluated_row_violations_for_low_evolution_iterations(tmp_path: Path):
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    meta = _eta_evaluated_meta("jsoncpp_jsoncpp_fuzzer")
    meta["elfuzz"]["evolution_iterations"] = 1
    ws = matrix_dir / "app"
    ws.mkdir()
    (ws / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"elfuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{ws}\t{ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = collector.collect(matrix_dir, strict=True, generator="elfuzz", profile="reproduction-eta")
    assert summary["evaluated_row_violations"]
    assert any("evolution_iterations" in v for v in summary["evaluated_row_violations"][0]["violations"])


def test_eta_evaluated_row_violations_for_sut_target_mismatch(tmp_path: Path):
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    meta = _eta_evaluated_meta("jsoncpp_jsoncpp_fuzzer")
    meta["actual_sut_fuzz_target"] = "libxml2_xml"
    ws = matrix_dir / "app"
    ws.mkdir()
    (ws / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"elfuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{ws}\t{ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = collector.collect(matrix_dir, strict=True, generator="elfuzz", profile="reproduction-eta")
    assert summary["evaluated_row_violations"]
    assert any("actual_sut_fuzz_target" in v for v in summary["evaluated_row_violations"][0]["violations"])


def test_zeta_evaluated_row_violations_for_missing_containerized_runtime(tmp_path: Path):
    # zeta is an alias and must enforce the same containerized SUT runtime check.
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    meta = _eta_evaluated_meta("jsoncpp_jsoncpp_fuzzer")
    meta["profile"] = "reproduction-zeta"
    meta["build"]["containerized_sut_runtime"] = False
    ws = matrix_dir / "app"
    ws.mkdir()
    (ws / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"elfuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{ws}\t{ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = collector.collect(matrix_dir, strict=True, generator="elfuzz", profile="reproduction-zeta")
    assert summary["evaluated_row_violations"]
    assert any("containerized" in v for v in summary["evaluated_row_violations"][0]["violations"])


def test_epsilon_evaluated_row_does_not_require_containerized_runtime(tmp_path: Path):
    # epsilon does NOT require containerized SUT runtime (eta/zeta-only).
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    meta = _eta_evaluated_meta("jsoncpp_jsoncpp_fuzzer")
    meta["profile"] = "reproduction-epsilon"
    meta["build"]["containerized_sut_runtime"] = False
    ws = matrix_dir / "app"
    ws.mkdir()
    (ws / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"elfuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{ws}\t{ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = collector.collect(matrix_dir, strict=True, generator="elfuzz", profile="reproduction-epsilon")
    violations = summary["evaluated_row_violations"][0]["violations"] if summary["evaluated_row_violations"] else []
    assert not any("containerized" in v for v in violations)


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def test_cli_accepts_all_input_generator_flags():
    proc = subprocess.run(
        ["python3", str(ROOT / "scripts/hgb_collect_matrix.py"), "--help"],
        cwd=ROOT, capture_output=True, text=True, timeout=30,
    )
    assert "--require-input-generator-evaluated" in proc.stdout
    assert "--expect-invalid" in proc.stdout
    assert "--require-evaluated" in proc.stdout
    assert "--fail-on-invariant-violations" in proc.stdout


def test_cli_require_input_generator_evaluated_exits_nonzero_on_failure(tmp_path: Path):
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    _write_matrix(matrix_dir, _eta_failed_meta, _eta_invalid_meta)
    proc = subprocess.run(
        ["python3", str(ROOT / "scripts/hgb_collect_matrix.py"), str(matrix_dir),
         "--generator", "elfuzz", "--profile", "reproduction-eta",
         "--require-input-generator-evaluated"],
        cwd=ROOT, capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 2
    assert "input-generator" in proc.stderr


def test_cli_expect_invalid_exits_nonzero_on_mismatch(tmp_path: Path):
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    _write_matrix(matrix_dir, _eta_evaluated_meta, _eta_invalid_meta)
    proc = subprocess.run(
        ["python3", str(ROOT / "scripts/hgb_collect_matrix.py"), str(matrix_dir),
         "--generator", "elfuzz", "--profile", "reproduction-eta",
         "--expect-invalid", "5"],
        cwd=ROOT, capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 2
    assert "found 11" in proc.stderr


def test_cli_expect_invalid_passes_on_match(tmp_path: Path):
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    _write_matrix(matrix_dir, _eta_evaluated_meta, _eta_invalid_meta)
    proc = subprocess.run(
        ["python3", str(ROOT / "scripts/hgb_collect_matrix.py"), str(matrix_dir),
         "--generator", "elfuzz", "--profile", "reproduction-eta",
         "--expect-invalid", "11"],
        cwd=ROOT, capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0
