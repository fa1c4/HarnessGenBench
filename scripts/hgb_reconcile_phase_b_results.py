#!/usr/bin/env python3
"""Update an eval-all CSV from completed Phase B run artifacts."""

from __future__ import annotations

import argparse
import csv
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import hgb_eval_all


def reconcile(csv_path: Path, pairs: list[list[str]], budget: int,
              not_before_epoch: float = 0) -> set[tuple[str, str]]:
    with csv_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = list(reader.fieldnames or [])
        rows = list(reader)
    by_target = {row["target"]: row for row in rows}
    done: set[tuple[str, str]] = set()
    changed = False
    for baseline, target, raw in pairs:
        if baseline not in hgb_eval_all.BASELINES or target not in by_target:
            raise ValueError(f"unknown baseline or target: {baseline} {target}")
        run = (ROOT / raw).resolve(strict=True)
        if not run.is_relative_to(ROOT / "workspace" / baseline / target):
            raise ValueError(f"run is outside pair workspace: {run}")
        result_file = run / ("evaluation/result.json" if baseline in hgb_eval_all.BASELINES[:3]
                             else "result.json")
        if not result_file.is_file() or result_file.stat().st_mtime <= not_before_epoch:
            continue
        record = hgb_eval_all.result_row(ROOT, baseline, target, run, budget, 0)
        row = by_target[target]
        for metric in hgb_eval_all.METRICS:
            field = f"{baseline}_{metric}"
            if field in row:
                row[field] = str(record.get(metric, ""))
        row[f"{baseline}_run"] = str(run.relative_to(ROOT))
        done.add((baseline, target))
        changed = True
        print(f"{baseline} {target}: {record['status']} ({record['reason']})", flush=True)
    if changed:
        with tempfile.NamedTemporaryFile("w", newline="", encoding="utf-8",
                                         dir=csv_path.parent, delete=False) as handle:
            temp = Path(handle.name)
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
        temp.replace(csv_path)
    return done


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=ROOT / "workspace/eval_all/2026-10-12.csv")
    parser.add_argument("--pair", nargs=3, action="append", required=True,
                        metavar=("BASELINE", "TARGET", "RUN"))
    parser.add_argument("--campaign-seconds", type=int, default=86400)
    parser.add_argument("--wait", action="store_true")
    parser.add_argument("--poll-seconds", type=int, default=60)
    parser.add_argument("--timeout-seconds", type=int, default=108000)
    parser.add_argument("--not-before-epoch", type=float, default=0,
                        help="ignore results last written before this Unix time")
    args = parser.parse_args()
    if min(args.campaign_seconds, args.poll_seconds, args.timeout_seconds) < 1:
        parser.error("duration, poll, and timeout must be positive")
    csv_path = args.csv.resolve(strict=True)
    if not csv_path.is_relative_to(ROOT / "workspace"):
        parser.error("CSV must be under workspace")
    pending = args.pair
    deadline = time.monotonic() + args.timeout_seconds
    while pending:
        done = reconcile(csv_path, pending, args.campaign_seconds, args.not_before_epoch)
        pending = [pair for pair in pending if (pair[0], pair[1]) not in done]
        if not pending or not args.wait:
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(args.poll_seconds)
    if pending:
        print("pending: " + ", ".join(f"{b} {t}" for b, t, _ in pending), file=sys.stderr)
    return 0 if not pending else 1


if __name__ == "__main__":
    raise SystemExit(main())
