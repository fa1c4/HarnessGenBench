from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("hgb_reconcile_ckgfuzzer_false_audit", ROOT / "scripts/hgb_reconcile_ckgfuzzer_false_audit.py")
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_reconciliation_updates_repair_rounds_tokens_and_retries(tmp_path: Path) -> None:
    run = tmp_path / "ckgfuzzer/target/run"
    run.mkdir(parents=True)
    stats_path = run / "statistics.json"
    stats_path.write_text(json.dumps({"status": "failed", "exit_code": 5, "driver_fix_rounds": None}))
    (run / "api_traces").mkdir()
    (run / "api_traces/summary.json").write_text(json.dumps({"driver_fix_rounds": 2}))
    module.update_statistics(run, {
        "total_count": 3, "input_tokens": 41, "output_tokens": 52,
        "driver_fix_rounds": 2, "retry_count": 1,
        "input_usage_missing_count": 0, "output_usage_missing_count": 0,
    }, evaluation_retries=2)
    result = json.loads(stats_path.read_text())
    assert (result["status"], result["exit_code"]) == ("evaluated", 0)
    assert (result["llm_calls_observed"], result["read_tokens"], result["write_tokens"]) == (3, 41, 52)
    assert (result["driver_fix_rounds"], result["evaluation_retry_count"], result["retry_count"]) == (2, 2, 3)
    assert stats_path.with_suffix(".pre_reconciliation.json").is_file()
    aggregate = json.loads((tmp_path / "ckgfuzzer/statistics.json").read_text())
    assert aggregate["runs"]["target"]["run"]["driver_fix_rounds"] == 2


def test_container_coverage_report_must_be_copied_out(tmp_path: Path) -> None:
    report = tmp_path / "evaluation/cand_008/coverage/coverage.json"
    result = {"selected_candidate": {"coverage": {"coverage_report_path":
              "/workspace/evaluation/cand_008/coverage/coverage.json"}}}
    with pytest.raises(ValueError, match="was not copied"):
        module.evaluator_result_for_host_invariants(tmp_path, result)
    report.parent.mkdir(parents=True)
    report.write_text("{}")
    checked = module.evaluator_result_for_host_invariants(tmp_path, result)
    assert checked["selected_candidate"]["coverage"]["coverage_report_path"] == str(report.resolve())
    assert result["selected_candidate"]["coverage"]["coverage_report_path"].startswith("/workspace/")


def test_ckg_statistics_include_upstream_and_feedback_fixes(tmp_path: Path) -> None:
    run = tmp_path / "ckgfuzzer/target/run"
    run.mkdir(parents=True)
    (run / "metadata.json").write_text(json.dumps({"ckgfuzzer": {"compilation_repair_attempts": 6}}))
    feedback = run / "repair/feedback_round_1"
    feedback.mkdir(parents=True)
    (feedback / "repair_attempts.json").write_text(json.dumps({"count": 2}))
    (run / "manual_driver_fix_rounds.json").write_text(json.dumps({"count": 1}))
    (run / "statistics.json").write_text("{}")
    module.update_statistics(run, {"total_count": 1, "input_tokens": 2, "output_tokens": 3}, 0)
    stats = json.loads((run / "statistics.json").read_text())
    assert stats["driver_fix_rounds"] == 9
    assert stats["driver_fix_rounds_source"].endswith("+manual_driver_fix_rounds.json")


def test_ckg_statistics_count_manual_fix_when_interrupted_run_has_no_metadata(tmp_path: Path) -> None:
    run = tmp_path / "ckgfuzzer/target/run"
    run.mkdir(parents=True)
    (run / "manual_driver_fix_rounds.json").write_text(json.dumps({"count": 1}))
    module.update_statistics(run, {"total_count": 1}, 0)
    stats = json.loads((run / "statistics.json").read_text())
    assert stats["driver_fix_rounds"] == 1
    assert stats["driver_fix_rounds_source"].endswith("+manual_driver_fix_rounds.json")
