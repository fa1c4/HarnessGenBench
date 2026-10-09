#!/usr/bin/env python3
"""Persist per-run and per-baseline resource and driver-repair statistics."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path


def read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def atomic_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def count_promefuzz_fixes(workspace: Path) -> int:
    log = workspace / "logs" / "generate.log"
    if not log.is_file():
        return 0
    count = 0
    pattern = re.compile(r"(?:Build|ASan) error detected in fuzz driver \d+, fixing\.\.\.")
    with log.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            count += bool(pattern.search(line))
    return count


def repair_rounds(workspace: Path, baseline: str) -> tuple[int | None, str]:
    summary = read_json(workspace / "api_traces" / "summary.json")
    manual = read_json(workspace / "manual_driver_fix_rounds.json")
    extra = int(manual.get("count") or 0)
    if "driver_fix_rounds" in summary:
        source = "api_traces/summary.json:driver_fix_rounds"
        return int(summary["driver_fix_rounds"]) + extra, source + ("+manual_driver_fix_rounds.json" if extra else "")
    snapshot = read_json(workspace / "driver_fix_rounds.json")
    if "count" in snapshot:
        return int(snapshot["count"]) + extra, str(snapshot.get("source", "snapshot")) + ("+manual_driver_fix_rounds.json" if extra else "")
    if baseline == "promefuzz":
        return count_promefuzz_fixes(workspace) + extra, "logs/generate.log:fixing_events" + ("+manual_driver_fix_rounds.json" if extra else "")
    if baseline == "oss-fuzz-gen":
        directory = workspace / "generation" / "work" / "repair_iterations"
        return len(list(directory.glob("round_*.txt"))) if directory.is_dir() else 0, "generation/work/repair_iterations"
    if baseline == "ckgfuzzer":
        metadata = read_json(workspace / "metadata.json")
        method = metadata.get("ckgfuzzer") or {}
        if isinstance(method, dict) and isinstance(method.get("compilation_repair_attempts"), int):
            return method["compilation_repair_attempts"], "metadata.json:ckgfuzzer.compilation_repair_attempts"
        return None, "not_reported"
    return None, "not_applicable_input_generator"


def run_statistics(workspace: Path, baseline: str, target: str, run_id: str, exit_code: int, status_override: str = "") -> dict:
    summary = read_json(workspace / "api_traces" / "summary.json")
    metadata = read_json(workspace / "metadata.json")
    if not metadata:
        metadata = read_json(workspace / "result.json")
    rounds, rounds_source = repair_rounds(workspace, baseline)
    calls = int(summary.get("total_count") or 0)
    usage_only = int(summary.get("usage_only_count") or 0)
    input_missing = int(summary.get("input_usage_missing_count") or 0)
    output_missing = int(summary.get("output_usage_missing_count") or 0)
    # ELFuzz records the proxy's provider response and the outer TGI response.
    # A provider response with usage accounts for one outer TGI event.
    if baseline == "elfuzz":
        input_missing = max(0, input_missing - usage_only)
        output_missing = max(0, output_missing - usage_only)
    accounted = summary.get("usage_accounting_version") == 1
    no_model_run = metadata.get("status") in {"dry_run_ok", "not_applicable"}
    available = accounted or no_model_run
    evaluation_retry_count = int(read_json(workspace / "evaluation_retry_count.json").get("count") or 0)
    observed_retry_count = int(summary.get("retry_count") or 0) if available else None
    return {
        "schema_version": 1,
        "baseline": baseline,
        "target": target,
        "run_id": run_id,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "status": status_override or metadata.get("status", "unknown"),
        "exit_code": exit_code,
        "llm_calls_observed": calls,
        "llm_failed_calls_observed": int(summary.get("error_count") or 0),
        "retry_count": (observed_retry_count + evaluation_retry_count) if observed_retry_count is not None else (evaluation_retry_count or None),
        "evaluation_retry_count": evaluation_retry_count,
        "retry_count_scope": "instrumented_baseline_retry_loops_plus_evaluation_retries; provider_sdk_internal_retries_not_observed" if accounted else "evaluation_retries_only_or_unavailable_legacy_trace",
        "read_tokens": int(summary.get("input_tokens") or 0) if available else None,
        "write_tokens": int(summary.get("output_tokens") or 0) if available else None,
        "token_usage_extra_provider_responses": usage_only,
        "read_token_usage_missing_calls": input_missing,
        "write_token_usage_missing_calls": output_missing,
        "token_totals_complete": bool(
            accounted
            and (calls or usage_only)
            and not input_missing
            and not output_missing
            and not int(summary.get("error_count") or 0)
        ),
        "token_count_source": "provider_reported_usage_only; no_text_estimation",
        "driver_fix_rounds": rounds,
        "driver_fix_rounds_source": rounds_source,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--baseline", required=True, choices=("oss-fuzz-gen", "ckgfuzzer", "promefuzz", "elfuzz", "g2fuzz"))
    parser.add_argument("--target")
    parser.add_argument("--run-id")
    parser.add_argument("--exit-code", type=int, default=0)
    parser.add_argument("--status", default="", help="temporary run state, such as running")
    parser.add_argument("--snapshot-fixes", action="store_true", help="save repair count before compact cleanup")
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    if args.snapshot_fixes:
        count, source = repair_rounds(workspace, args.baseline)
        atomic_json(workspace / "driver_fix_rounds.json", {"count": count, "source": source})
        return
    target = args.target or workspace.parent.name
    run_id = args.run_id or workspace.name
    data = run_statistics(workspace, args.baseline, target, run_id, args.exit_code, args.status)
    atomic_json(workspace / "statistics.json", data)
    baseline_root = workspace.parent.parent
    aggregate_path = baseline_root / "statistics.json"
    with (baseline_root / ".statistics.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        aggregate = read_json(aggregate_path)
        aggregate.update({"schema_version": 1, "baseline": args.baseline, "updated_at": data["updated_at"]})
        aggregate.setdefault("runs", {}).setdefault(target, {})[run_id] = data
        atomic_json(aggregate_path, aggregate)


if __name__ == "__main__":
    main()
