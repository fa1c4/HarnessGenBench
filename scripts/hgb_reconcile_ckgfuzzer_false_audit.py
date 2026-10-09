#!/usr/bin/env python3
"""Correct completed CKG runs rejected by the former overbroad canary audit.

Reconciliation is limited to runs whose independent evaluator already passed
every stage and whose generator-visible files pass a fresh canary scan. The
original metadata and result are retained beside the corrected files.
"""

from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker/common"))
from ckgfuzzer_profile import audit_leakage  # noqa: E402
import hgb_record_statistics  # noqa: E402
import hgb_result  # noqa: E402


REQUIRED_STAGES = ("candidate_overlay", "copy_audit", "candidate_build", "sanitizer_smoke", "api_reachability", "campaign", "coverage")
CORRECTABLE_REASONS = ("ckg_reference_leakage:", "ckg_method_evidence_missing:",
                       "CKGFuzzer fuzzing stage exited", "CKGFuzzer external evaluation interrupted after generation")


def load_metadata(path: Path) -> dict:
    raw = path.read_text()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        start = raw.find('"reference_leakage_audit":')
        end = raw.find(',\n  "excluded_from_aggregate":', start)
        if start < 0 or end < 0:
            raise
        repaired = raw[:start] + '"reference_leakage_audit": {}' + raw[end:]
        return json.loads(repaired)


def evaluator_result_for_host_invariants(run: Path, result: dict) -> dict:
    """Map a container coverage artifact to its copied-out host path for checks."""
    checked = copy.deepcopy(result)
    coverage = (checked.get("selected_candidate") or {}).get("coverage") or {}
    raw = str(coverage.get("coverage_report_path") or "")
    if raw.startswith("/workspace/evaluation/"):
        mapped = (run / raw.removeprefix("/workspace/")).resolve()
        if not mapped.is_relative_to((run / "evaluation").resolve()) or not mapped.is_file():
            raise ValueError("container coverage report was not copied into this run")
        coverage["coverage_report_path"] = str(mapped)
    return checked


def update_statistics(run: Path, trace: dict, evaluation_retries: int) -> None:
    path = run / "statistics.json"
    stats = json.loads(path.read_text()) if path.is_file() else {}
    backup = path.with_suffix(".pre_reconciliation.json")
    if path.is_file() and not backup.exists():
        backup.write_bytes(path.read_bytes())
    stats.update({
        "status": "evaluated", "exit_code": 0,
        "llm_calls_observed": int(trace.get("total_count") or 0),
        "llm_failed_calls_observed": int(trace.get("error_count") or 0),
        "read_tokens": int(trace.get("input_tokens") or 0),
        "write_tokens": int(trace.get("output_tokens") or 0),
        "read_token_usage_missing_calls": int(trace.get("input_usage_missing_count") or 0),
        "write_token_usage_missing_calls": int(trace.get("output_usage_missing_count") or 0),
        "evaluation_retry_count": evaluation_retries,
        "retry_count": int(trace.get("retry_count") or 0) + evaluation_retries,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })
    rounds, rounds_source = hgb_record_statistics.repair_rounds(run, "ckgfuzzer")
    stats["driver_fix_rounds"] = rounds
    stats["driver_fix_rounds_source"] = rounds_source
    stats["token_totals_complete"] = not (stats["read_token_usage_missing_calls"] or stats["write_token_usage_missing_calls"])
    temporary = path.with_suffix(".reconciled.tmp")
    temporary.write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)
    baseline_root = run.parent.parent
    with (baseline_root / ".statistics.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        aggregate_path = baseline_root / "statistics.json"
        aggregate = hgb_record_statistics.read_json(aggregate_path)
        aggregate.setdefault("runs", {}).setdefault(run.parent.name, {})[run.name] = stats
        aggregate["updated_at"] = stats["updated_at"]
        hgb_record_statistics.atomic_json(aggregate_path, aggregate)


def reconcile(run: Path, evaluator_result_path: Path | None = None) -> dict:
    meta_path = run / "metadata.json"
    result_path = run / "result.json"
    evaluated_path = evaluator_result_path or (run / "evaluation/result.json")
    if not evaluated_path.resolve().is_relative_to((run / "evaluation").resolve()):
        raise ValueError("evaluator result must be inside this run's evaluation directory")
    eval_result = json.loads(evaluated_path.read_text())
    if meta_path.is_file():
        meta = load_metadata(meta_path)
    elif evaluator_result_path and (run / "generated_harnesses").is_dir():
        # A stopped raw evaluator can leave no final metadata even though
        # CodeQL, model generation, and an independent repaired-candidate
        # evaluator all have durable evidence. The checks below must all pass
        # before this minimal interrupted-run record is written.
        meta = {
            "generator": "ckgfuzzer", "target": run.parent.name,
            "profile": eval_result.get("profile", ""),
            "protocol": eval_result.get("protocol", ""),
            "status": "failed",
            "reason": "CKGFuzzer external evaluation interrupted after generation",
        }
    else:
        raise ValueError("CKGFuzzer metadata is missing")
    final_evaluator_path = run / "evaluation/result.json"
    final_evaluator = json.loads(final_evaluator_path.read_text()) if final_evaluator_path.is_file() else {}
    if meta.get("status") == "evaluated" and final_evaluator.get("status") == "evaluated":
        trace = json.loads((run / "api_traces/summary.json").read_text())
        update_statistics(run, trace, len(list((run / "evaluation").glob("feedback_trial*/result.json"))))
        return {"status": "already_evaluated", "run": str(run)}
    prior_reason = str(meta.get("reason", ""))
    if meta.get("status") == "evaluated" and evaluator_result_path:
        # Recover a prior reconciliation interrupted between its metadata and
        # evaluator-result writes (for example by directory permissions).
        prior_reason = str((meta.get("reconciliation") or {}).get("original_reason", ""))
    if not prior_reason.startswith(CORRECTABLE_REASONS):
        raise ValueError("run did not fail solely on the known finalization audit bug")
    if eval_result.get("status") != "evaluated":
        raise ValueError("independent evaluator did not pass")
    violations = hgb_result.assert_evaluated_invariants(evaluator_result_for_host_invariants(run, eval_result))
    if violations:
        raise ValueError("independent evaluator result violates evaluated invariants: " + "; ".join(violations))
    if any((eval_result.get("stages") or {}).get(stage) != "completed" for stage in REQUIRED_STAGES):
        raise ValueError("independent evaluator stages are incomplete")
    selected = eval_result.get("selected_candidate") or {}
    candidate_name = Path(selected.get("candidate_path", "")).name
    if not candidate_name or "000_hgb_" in candidate_name:
        raise ValueError("selected candidate is missing or source-derived rescue")
    selected_path = selected["candidate_path"]
    if selected_path.startswith("/workspace/"):
        candidate = run / selected_path.removeprefix("/workspace/")
    else:
        candidate = Path(selected_path)
        if not candidate.is_absolute():
            candidate = ROOT / candidate
    if not candidate.is_file() or hashlib.sha256(candidate.read_bytes()).hexdigest() != selected.get("candidate_sha256"):
        raise ValueError("selected candidate hash does not match evaluator record")
    if not candidate.resolve().is_relative_to(run.resolve()):
        raise ValueError("selected candidate is outside this CKGFuzzer run")
    copy_audit = selected.get("copy_audit") or {}
    if any(copy_audit.get(key) for key in ("exact_copy", "near_duplicate_reference", "contains_reference_canary")):
        raise ValueError("candidate failed reference-copy audit")
    if not (selected.get("build") or {}).get("overlay_audit", {}).get("matches_candidate"):
        raise ValueError("candidate overlay hash did not match")
    metrics = eval_result.get("metrics") or {}
    if int((metrics.get("campaign") or {}).get("execs_done") or 0) <= 0:
        raise ValueError("no campaign executions")
    if int(((metrics.get("coverage") or {}).get("line_coverage") or {}).get("covered") or 0) <= 0:
        raise ValueError("no real source coverage")
    graph = json.loads((run / "ckg/query_results.json").read_text())
    trace = json.loads((run / "api_traces/summary.json").read_text())
    if int(graph.get("nodes") or 0) <= 0 or int(trace.get("total_count") or 0) <= 0:
        raise ValueError("CodeQL graph or model-call evidence is missing")
    host_command = dict(line.split("=", 1) for line in (run / "host_command.txt").read_text().splitlines() if "=" in line)
    package = Path(host_command["target_package"])
    canary = copy_audit.get("canary")
    if not canary:
        for report in sorted((run / "evaluation/candidates").glob("cand_*.json")):
            try:
                canary = (json.loads(report.read_text()).get("copy_audit") or {}).get("canary")
            except (OSError, ValueError):
                continue
            if canary:
                break
    if not canary:
        raise ValueError("evaluator canary is missing")
    audit = audit_leakage(package / "generator_input/source_input", canary, extra_dirs=[
        run / "generated_harnesses", run / "docker_shared", run / "api_traces",
        run / "logs/fuzzing.log", run / "repair", run / "ckg",
    ])
    if audit["leaked"]:
        raise ValueError(f"generator-visible files contain evaluator canary: {audit['hit_count']} hits")
    original_reason = meta.get("reason", "")
    meta.update({
        "status": "evaluated", "reason": "none", "exit_code": 0,
        "failed_stage": "none", "analysis_mode": "codeql",
        "codeql_graph_nodes": graph["nodes"], "api_trace_total_count": trace["total_count"],
        "reference_leakage_audit": audit, "metrics": metrics,
        "selected_candidate": selected,
        "reconciliation": {"kind": "independent_evaluator_recheck" if evaluator_result_path else "false_finalization_audit",
                           "original_reason": original_reason, "evaluator_result": str(evaluated_path)},
    })
    result = json.loads(result_path.read_text()) if result_path.is_file() else {}
    result.update({"status": "evaluated", "reason": "", "metrics": metrics,
                   "generator": "ckgfuzzer", "target": meta.get("target", run.parent.name),
                   "profile": eval_result.get("profile", meta.get("profile", "")),
                   "reference_leakage_audit": audit, "stages": {**(result.get("stages") or {}), **eval_result["stages"]}})
    writes = [(meta_path, meta), (result_path, result)]
    if evaluator_result_path and evaluator_result_path != run / "evaluation/result.json":
        writes.append((run / "evaluation/result.json", eval_result))
    for path, value in writes:
        backup = path.with_suffix(".pre_reconciliation.json")
        if path.is_file() and not backup.exists():
            backup.write_bytes(path.read_bytes())
        temporary = path.with_suffix(".reconciled.tmp")
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        temporary.replace(path)
    update_statistics(run, trace, len(list((run / "evaluation").glob("feedback_trial*/result.json"))))
    return {"status": "evaluated", "run": str(run), "execs_done": metrics["campaign"]["execs_done"],
            "covered_lines": metrics["coverage"]["line_coverage"]["covered"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run", type=Path)
    parser.add_argument("--evaluator-result", type=Path)
    args = parser.parse_args()
    print(json.dumps(reconcile(args.run.resolve(), args.evaluator_result.resolve() if args.evaluator_result else None), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
