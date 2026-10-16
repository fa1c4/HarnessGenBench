#!/usr/bin/env python3
"""Retry unfinished Phase B pairs after the active matrix has released its CSV."""

from __future__ import annotations

import argparse
import collections
import csv
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINES = ("ckgfuzzer", "promefuzz", "oss-fuzz-gen", "g2fuzz", "elfuzz")


def status_counts(csv_path: Path) -> collections.Counter[str]:
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    return collections.Counter(row[f"{baseline}_status"] for row in rows for baseline in BASELINES)


def wait_until_stopped(unit: str) -> None:
    while True:
        check = subprocess.run(["systemctl", "--user", "is-active", unit],
                               capture_output=True, text=True, check=False)
        state = check.stdout.strip()
        if state in {"inactive", "failed", "unknown"}:
            return
        # An unavailable user bus or an unexpected response is not evidence
        # that the 32 active jobs ended; wait instead of launching more jobs.
        time.sleep(60)


def reconcile_completed_rows(csv_path: Path, original_run_id: str, campaign_seconds: int) -> int:
    """Recover completed jobs whose CSV update failed on protected AFL files."""
    if not original_run_id:
        return 0
    sys.path.insert(0, str(ROOT / "scripts"))
    import hgb_eval_all

    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        rows = list(reader)
    fixed = 0
    for record in rows:
        target = record.get("target", "")
        for baseline in BASELINES:
            if record.get(f"{baseline}_status") != "runner_failed":
                continue
            safe = re.sub(r"[^A-Za-z0-9_]+", "_", f"{baseline}_{target}")
            run = ROOT / "workspace" / baseline / target / f"{original_run_id}_{safe}"
            if not run.is_dir():
                continue
            try:
                repaired = hgb_eval_all.result_row(ROOT, baseline, target, run, campaign_seconds, 0)
            except (OSError, ValueError):
                continue
            if repaired["status"] != "evaluated":
                continue
            for metric, value in repaired.items():
                field = f"{baseline}_{metric}"
                if field in fields:
                    record[field] = value
            fixed += 1
    if fixed:
        with tempfile.NamedTemporaryFile("w", newline="", encoding="utf-8", dir=csv_path.parent,
                                         delete=False) as handle:
            temp = Path(handle.name)
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
        temp.replace(csv_path)
    return fixed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--date", required=True)
    parser.add_argument("--after-unit", required=True)
    parser.add_argument("--max-attempts", type=int, default=2)
    parser.add_argument("--parallel-worker", type=int, default=32)
    parser.add_argument("--memory-per-job-gib", type=int, default=8)
    parser.add_argument("--campaign-seconds", type=int, default=86400)
    parser.add_argument("--run-id-prefix", default="eval_all_phase_b_retry")
    parser.add_argument("--original-run-id", default="",
                        help="recover completed jobs from the original run before retrying")
    args = parser.parse_args()
    if min(args.max_attempts, args.parallel_worker, args.memory_per_job_gib,
           args.campaign_seconds) < 1:
        parser.error("attempts, workers, memory, and campaign duration must be positive")
    output = ROOT / "workspace/eval_all" / f"{args.date}.csv"
    legacy_output = ROOT / "results/eval_all" / f"{args.date}.csv"
    if not output.is_file() and legacy_output.is_file():
        output = legacy_output
    print(f"Waiting for {args.after_unit} before retrying unfinished pairs", flush=True)
    wait_until_stopped(args.after_unit)
    if not output.is_file():
        print(f"Missing Phase B CSV: {output}", file=sys.stderr, flush=True)
        return 2
    fixed = reconcile_completed_rows(output, args.original_run_id, args.campaign_seconds)
    print(f"Recovered {fixed} completed rows from original run artifacts", flush=True)
    for attempt in range(1, args.max_attempts + 1):
        counts = status_counts(output)
        remaining = sum(count for status, count in counts.items() if status not in ("evaluated", "N/A"))
        print(f"Before retry {attempt}: {dict(counts)}", flush=True)
        if remaining == 0:
            return 0
        snapshot = output.with_name(f"{args.date}.before_retry_{attempt}.csv")
        shutil.copy2(output, snapshot)
        run_id = f"{args.run_id_prefix}_{args.date.replace('-', '')}_r{attempt}"
        command = [sys.executable, str(ROOT / "scripts/hgb_eval_all.py"),
                   "--phase", "fuzz", "--resume", "--date", args.date,
                   "--output", str(output),
                   "--run-id", run_id, "--parallel-worker", str(args.parallel_worker),
                   "--memory-per-job-gib", str(args.memory_per_job_gib),
                   "--campaign-seconds", str(args.campaign_seconds)]
        print(f"Starting retry {attempt}: {remaining} unfinished pairs; snapshot={snapshot}", flush=True)
        subprocess.run(command, cwd=ROOT / "workspace", check=False)
    counts = status_counts(output)
    remaining = sum(count for status, count in counts.items() if status not in ("evaluated", "N/A"))
    print(f"After {args.max_attempts} retry attempts: {dict(counts)}", flush=True)
    return 1 if remaining else 0


if __name__ == "__main__":
    raise SystemExit(main())
