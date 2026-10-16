#!/usr/bin/env python3
"""Finish failed Phase B harness evaluations from their saved 24-hour corpora.

Only CKGFuzzer, PromeFuzz, and OSS-Fuzz-Gen use this recovery path. It validates
the original campaign log and corpus.tar before starting an evaluator that
skips fuzzing. The existing CSV is updated atomically after each job.
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import os
import queue
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker/common"))
sys.path.insert(0, str(ROOT / "scripts"))
import hgb_eval_all
import hgb_fuzzbench_builder

BASELINES = ("ckgfuzzer", "promefuzz", "oss-fuzz-gen")


def read_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def save_rows(path: Path, fields: list[str], rows: list[dict[str, str]]) -> None:
    with tempfile.NamedTemporaryFile("w", newline="", encoding="utf-8", dir=path.parent,
                                     delete=False) as handle:
        temp = Path(handle.name)
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    temp.replace(path)


def update_row(record: dict[str, str], baseline: str, result: dict) -> None:
    for metric in hgb_eval_all.METRICS:
        field = f"{baseline}_{metric}"
        if field in record:
            record[field] = str(result.get(metric, ""))


def recover_one(record: dict[str, str], baseline: str, budget: int, cpu: int,
                memory_gib: int) -> tuple[str, str, int]:
    target = record["target"]
    run = (ROOT / record[f"{baseline}_run"]).resolve(strict=True)
    if not run.is_relative_to(ROOT / "workspace" / baseline / target):
        raise ValueError(f"run path escapes pair workspace: {run}")
    provenance = json.loads((run / "phase_b_source.json").read_text(encoding="utf-8"))
    source = provenance["selected_phase_a_run"]
    cmd = [sys.executable, str(ROOT / "scripts/hgb_replay_saved.py"),
           "--baseline", baseline, "--target", target,
           "--source-run", source, "--run-id", run.name,
           "--campaign-seconds", str(budget), "--cpu", str(cpu),
           "--memory-gib", str(memory_gib), "--recover-existing"]
    with (run / "recovery.launch.log").open("w", encoding="utf-8") as log:
        completed = subprocess.run(cmd, cwd=run, stdout=log, stderr=subprocess.STDOUT, check=False)
    return baseline, target, completed.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=ROOT / "workspace/eval_all/2026-10-12.csv")
    parser.add_argument("--parallel-worker", type=int, default=4)
    parser.add_argument("--campaign-seconds", type=int, default=86400)
    parser.add_argument("--memory-per-job-gib", type=int, default=8)
    parser.add_argument("--baseline", choices=BASELINES, action="append")
    parser.add_argument("--max-jobs", type=int, default=0,
                        help="limit actual recovery jobs for a small verification run")
    args = parser.parse_args()
    if min(args.parallel_worker, args.campaign_seconds, args.memory_per_job_gib) < 1:
        parser.error("workers, duration, and memory must be positive")
    csv_path = args.csv.resolve(strict=True)
    if not csv_path.is_relative_to(ROOT / "workspace"):
        parser.error("CSV must be in workspace")
    fields, rows = read_rows(csv_path)
    chosen = tuple(args.baseline or BASELINES)
    jobs: list[tuple[dict[str, str], str]] = []
    for record in rows:
        for baseline in chosen:
            if record.get(f"{baseline}_status") in {"evaluated", "N/A"}:
                continue
            run = (ROOT / record[f"{baseline}_run"]).resolve(strict=True)
            if not run.is_relative_to(ROOT / "workspace" / baseline / record["target"]):
                continue
            result = hgb_eval_all.result_row(ROOT, baseline, record["target"], run,
                                             args.campaign_seconds, 0)
            if result["status"] == "evaluated":
                update_row(record, baseline, result)
                print(f"reconciled {baseline} {record['target']}", flush=True)
                continue
            try:
                hgb_fuzzbench_builder.load_saved_campaign(
                    run / "evaluation/cand_001", args.campaign_seconds)
            except (OSError, ValueError) as exc:
                print(f"skipped {baseline} {record['target']}: {exc}", flush=True)
                continue
            jobs.append((record, baseline))
    save_rows(csv_path, fields, rows)
    if args.max_jobs:
        jobs = jobs[:args.max_jobs]
    cpus = sorted(os.sched_getaffinity(0))
    workers = min(args.parallel_worker, len(cpus), max(1, len(jobs)))
    print(f"coverage-only recovery: {len(jobs)} jobs, {workers} workers; original campaigns retained", flush=True)
    cpu_tokens: queue.Queue[int] = queue.Queue()
    for cpu in cpus[:workers]:
        cpu_tokens.put(cpu)

    def run_with_cpu(record: dict[str, str], baseline: str) -> tuple[str, str, int]:
        cpu = cpu_tokens.get()
        try:
            return recover_one(record, baseline, args.campaign_seconds, cpu,
                               args.memory_per_job_gib)
        finally:
            cpu_tokens.put(cpu)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {}
        for record, baseline in jobs:
            future = pool.submit(run_with_cpu, record, baseline)
            futures[future] = (record, baseline)
        for future in as_completed(futures):
            record, baseline = futures[future]
            target = record["target"]
            try:
                _, _, code = future.result()
                run = ROOT / record[f"{baseline}_run"]
                result = hgb_eval_all.result_row(ROOT, baseline, target, run,
                                                 args.campaign_seconds, code)
                update_row(record, baseline, result)
                print(f"{baseline} {target}: {result['status']} ({result['reason']})", flush=True)
            except Exception as exc:
                print(f"{baseline} {target}: recovery error: {exc}", flush=True)
            save_rows(csv_path, fields, rows)
    counts = collections.Counter(record[f"{baseline}_status"] for record in rows
                                 for baseline in hgb_eval_all.BASELINES)
    print(f"final CSV: {csv_path}; statuses={dict(counts)}", flush=True)
    return 0 if all(key in {"evaluated", "N/A"} for key in counts) else 1


if __name__ == "__main__":
    raise SystemExit(main())
