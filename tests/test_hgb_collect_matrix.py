from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
_DOCKER_COMMON = REPO_ROOT / "docker" / "common"
if str(_DOCKER_COMMON) not in sys.path:
    sys.path.insert(0, str(_DOCKER_COMMON))
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


collector = _load_module("hgb_collect_matrix_shared", "scripts/hgb_collect_matrix.py")


def _eta_meta(**overrides) -> dict:
    base = {
        "task_family": "harness_generator",
        "generator": "ckgfuzzer",
        "profile": "reproduction-eta",
        "method_variant": "paper-faithful",
        "status": "evaluated",
        "applicability": "applicable",
        "excluded_from_aggregate": False,
        "stages": {n: "completed" for n in ("candidate_build", "sanitizer_smoke", "api_reachability", "campaign", "coverage")},
        "metrics": {
            "coverage": {"line_coverage": {"covered": 27}, "function_coverage": {"covered": 5},
                          "region_coverage": {"covered": 12}, "copy_out_ok": True,
                          "coverage_report_path": "/tmp/coverage.json", "inputs_replayed": 3},
            "campaign": {"execs_done": 500, "crashes": 0, "timeouts": 0, "final_corpus_file_count": 3},
        },
        "build": {"overlay_audit": {"matches_candidate": True}},
        "selected_candidate": {
            "copy_audit": {"exact_copy": False, "near_duplicate_reference": False},
            "build": {"overlay_audit": {"matches_candidate": True}},
            "campaign": {"final_corpus_file_count": 3},
            "coverage": {"copy_out_ok": True, "coverage_report_path": "/tmp/coverage.json", "inputs_replayed": 3},
        },
        "candidate": {"contains_reference_canary": False, "near_duplicate_reference": False},
    }
    base.update(overrides)
    return base


def test_eta_is_in_strict_reproduction_profiles() -> None:
    assert "reproduction-eta" in collector.STRICT_REPRODUCTION_PROFILES
    assert "reproduction-zeta" in collector.STRICT_REPRODUCTION_PROFILES
    assert "reproduction-epsilon" in collector.STRICT_REPRODUCTION_PROFILES
    assert "reproduction-delta" in collector.STRICT_REPRODUCTION_PROFILES
    assert "reproduction-eta" in collector.ETA_PROFILES


def test_extract_ckgfuzzer_row_eta_paper_equivalent() -> None:
    row = collector.extract_ckgfuzzer_row(_eta_meta())
    assert row["paper_equivalent_eta"] is True
    assert row["paper_equivalent_strict"] is True
    assert row["copy_out_ok"] is True
    assert row["inputs_replayed"] == 3
    assert row["coverage_report_path"] == "/tmp/coverage.json"


def test_extract_ckgfuzzer_row_eta_flips_on_coverage_gap() -> None:
    # copy_out_ok False flips the eta gate.
    meta = _eta_meta()
    meta["metrics"]["coverage"]["copy_out_ok"] = False
    meta["selected_candidate"]["coverage"]["copy_out_ok"] = False
    assert collector.extract_ckgfuzzer_row(meta)["paper_equivalent_eta"] is False
    # missing coverage_report_path flips the eta gate.
    meta = _eta_meta()
    meta["metrics"]["coverage"]["coverage_report_path"] = ""
    meta["selected_candidate"]["coverage"]["coverage_report_path"] = ""
    assert collector.extract_ckgfuzzer_row(meta)["paper_equivalent_eta"] is False
    # inputs_replayed <= 0 flips the eta gate.
    meta = _eta_meta()
    meta["metrics"]["coverage"]["inputs_replayed"] = 0
    meta["selected_candidate"]["coverage"]["inputs_replayed"] = 0
    assert collector.extract_ckgfuzzer_row(meta)["paper_equivalent_eta"] is False


def test_evaluated_row_violations_eta_coverage_invariants(tmp_path: Path) -> None:
    cov_file = tmp_path / "coverage.json"
    cov_file.write_text("{}", encoding="utf-8")
    meta = _eta_meta()
    meta["selected_candidate"]["coverage"] = {
        "copy_out_ok": False, "coverage_report_path": "", "inputs_replayed": 0,
    }
    violations = collector.evaluated_row_violations(meta)
    assert any("copy_out_ok" in v for v in violations)
    assert any("coverage_report_path" in v for v in violations)
    assert any("inputs_replayed" in v for v in violations)
    # A clean eta row with an existing coverage report has no eta coverage
    # violations.
    meta = _eta_meta()
    meta["selected_candidate"]["coverage"]["coverage_report_path"] = str(cov_file)
    violations = collector.evaluated_row_violations(meta)
    assert not any("copy_out_ok" in v for v in violations)
    assert not any("coverage_report_path" in v for v in violations)
    assert not any("inputs_replayed" in v for v in violations)


def test_evaluated_row_violations_zeta_does_not_enforce_eta_coverage_fields() -> None:
    meta = _eta_meta()
    meta["profile"] = "reproduction-zeta"
    meta["selected_candidate"]["coverage"] = {"line_coverage": {"covered": 27}}
    violations = collector.evaluated_row_violations(meta)
    assert not any("copy_out_ok" in v for v in violations)
    assert not any("coverage_report_path" in v for v in violations)
    assert not any("inputs_replayed" in v for v in violations)


def test_collect_matrix_dir_fail_on_invariant_violations_flag() -> None:
    import subprocess
    proc = subprocess.run(
        ["python3", "scripts/hgb_collect_matrix.py", "--help"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30,
    )
    assert "--fail-on-invariant-violations" in proc.stdout
    assert "--require-evaluated" in proc.stdout


def test_collect_require_evaluated_flags_missing_evaluated_rows(tmp_path: Path) -> None:
    # An applicable harness-generator row that is not evaluated must surface as
    # a require_evaluated_violation.
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    meta = _eta_meta(status="quality_failure")
    meta_path = matrix_dir / "ckgfuzzer_jsoncpp.json"
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\n"
        f"ckgfuzzer\tjsoncpp_jsoncpp_fuzzer\tquality_failure\t{matrix_dir}\t{meta_path}\n",
        encoding="utf-8",
    )
    summary = collector.collect(matrix_dir, generator="ckgfuzzer", profile="reproduction-eta", require_evaluated=True)
    assert summary.get("require_evaluated_violations")
