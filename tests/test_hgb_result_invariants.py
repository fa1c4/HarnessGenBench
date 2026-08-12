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


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


hgb_result = _load_module("hgb_result_invariants", "docker/common/hgb_result.py")


def _evaluated_base(profile: str = "reproduction-eta", cov_report: str = "/tmp/coverage.json") -> dict:
    return {
        "profile": profile,
        "status": "evaluated",
        "stages": {s: "completed" for s in hgb_result.STAGE_NAMES},
        "metrics": {
            "coverage": {"line_coverage": {"covered": 27}, "report_exists": True,
                          "copy_out_ok": True, "inputs_replayed": 3,
                          "coverage_report_path": cov_report},
            "campaign": {"execs_done": 500, "final_corpus_file_count": 3},
        },
        "selected_candidate": {
            "overlaid": True,
            "copy_audit": {"near_duplicate_reference": False, "exact_copy": False},
            "coverage": {"copy_out_ok": True, "inputs_replayed": 3,
                          "coverage_report_path": cov_report},
        },
    }


def test_method_variant_mapping_for_all_strict_profiles() -> None:
    for p in ("reproduction-eta", "reproduction-zeta", "reproduction-epsilon", "reproduction-delta", "reproduction-gamma"):
        result = hgb_result.build_result(
            profile=p, protocol="blind-project", target="t", status="evaluated",
            stages={n: "completed" for n in hgb_result.STAGE_NAMES},
        )
        assert result["method_variant"] == "paper-faithful", p


def test_assert_evaluated_invariants_pass_for_clean_eta(tmp_path: Path) -> None:
    cov_file = tmp_path / "coverage.json"
    cov_file.write_text("{}", encoding="utf-8")
    base = _evaluated_base(cov_report=str(cov_file))
    assert hgb_result.assert_evaluated_invariants(base) == []


def test_assert_evaluated_invariants_reject_missing_final_corpus() -> None:
    base = _evaluated_base()
    base["metrics"]["campaign"]["final_corpus_file_count"] = 0
    violations = hgb_result.assert_evaluated_invariants(base)
    assert any("final corpus" in v for v in violations)


def test_assert_evaluated_invariants_reject_near_duplicate() -> None:
    base = _evaluated_base()
    base["selected_candidate"]["copy_audit"]["near_duplicate_reference"] = True
    violations = hgb_result.assert_evaluated_invariants(base)
    assert any("near-duplicate" in v for v in violations)


def test_assert_evaluated_invariants_reject_zero_covered_lines() -> None:
    base = _evaluated_base()
    base["metrics"]["coverage"]["line_coverage"]["covered"] = 0
    violations = hgb_result.assert_evaluated_invariants(base)
    assert any("covered <= 0" in v for v in violations)


def test_assert_evaluated_invariants_eta_coverage_gaps(tmp_path: Path) -> None:
    cov_file = tmp_path / "coverage.json"
    cov_file.write_text("{}", encoding="utf-8")
    # copy_out_ok != true
    bad = _evaluated_base(cov_report=str(cov_file))
    bad["selected_candidate"]["coverage"]["copy_out_ok"] = False
    assert any("copy_out_ok" in v for v in hgb_result.assert_evaluated_invariants(bad))
    # missing coverage_report_path
    bad = _evaluated_base(cov_report=str(cov_file))
    bad["selected_candidate"]["coverage"]["coverage_report_path"] = ""
    assert any("coverage_report_path" in v for v in hgb_result.assert_evaluated_invariants(bad))
    # coverage_report_path does not exist
    bad = _evaluated_base(cov_report=str(cov_file))
    bad["selected_candidate"]["coverage"]["coverage_report_path"] = str(tmp_path / "missing.json")
    assert any("does not exist" in v for v in hgb_result.assert_evaluated_invariants(bad))
    # inputs_replayed <= 0
    bad = _evaluated_base(cov_report=str(cov_file))
    bad["selected_candidate"]["coverage"]["inputs_replayed"] = 0
    assert any("inputs_replayed" in v for v in hgb_result.assert_evaluated_invariants(bad))


def test_assert_evaluated_invariants_zeta_does_not_require_eta_coverage_fields() -> None:
    # zeta is an alias of the strict family but does not enforce the eta-only
    # coverage copy_out_ok/coverage_report_path/inputs_replayed invariants.
    base = _evaluated_base(profile="reproduction-zeta")
    # No eta coverage fields on the selected candidate.
    base["selected_candidate"]["coverage"] = {"line_coverage": {"covered": 27}}
    violations = hgb_result.assert_evaluated_invariants(base)
    assert not any("copy_out_ok" in v for v in violations)
    assert not any("coverage_report_path" in v for v in violations)
    assert not any("inputs_replayed" in v for v in violations)


def test_select_best_candidate_rejects_near_duplicate_and_canary() -> None:
    good = {
        "candidate_id": "cand_001",
        "stages": {s: "completed" for s in hgb_result.EVALUATION_STAGES},
        "copy_audit": {"exact_copy": False, "near_duplicate_reference": False, "contains_reference_canary": False},
        "sanitizer_smoke": {},
        "api_reachability": {"status": "not_requested"},
        "coverage": {"line_coverage": {"covered": 27}},
        "campaign": {"execs_done": 500},
        "overlaid": True,
    }
    assert hgb_result.select_best_candidate([good])["candidate_id"] == "cand_001"
    for key in ("exact_copy", "near_duplicate_reference", "contains_reference_canary"):
        bad = json.loads(json.dumps(good))
        bad["copy_audit"][key] = True
        assert hgb_result.select_best_candidate([bad]) is None, key
