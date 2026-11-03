#!/usr/bin/env python3
"""Finish Phase B coverage from verified saved campaigns without fuzzing again.

The same-date Phase A manifest supplies the shared G2Fuzz target package for
every baseline. Campaign duration and execution evidence are checked before
recovery; incomplete corpora remain failed. The CSV is updated after each job.
"""

from __future__ import annotations

import argparse
import collections
import csv
import fcntl
import json
import os
import queue
import re
import subprocess
import sys
import tarfile
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker/common"))
sys.path.insert(0, str(ROOT / "scripts"))
import hgb_eval_all
import hgb_fuzzbench_builder

BASELINES = hgb_eval_all.BASELINES


def manifest_for_csv(csv_path: Path, requested: Path | None) -> Path:
    match = re.match(r"^(\d{4}-\d{2}-\d{2})(?:\.|$)", csv_path.name)
    if match is None:
        raise ValueError("CSV name must begin with its YYYY-MM-DD evaluation date")
    date = match.group(1)
    manifest = (requested or csv_path.with_name(f"{date}.phase_a.json")).resolve(strict=True)
    if manifest.name != f"{date}.phase_a.json":
        raise ValueError(f"Phase A manifest must belong to CSV date {date}")
    return manifest


def canonical_sources(manifest: Path) -> dict[str, tuple[str, Path]]:
    """Map each target to its verified G2Fuzz source and target package."""
    records = json.loads(manifest.read_text(encoding="utf-8")).get("records", [])
    canonical: dict[str, tuple[str, Path]] = {}
    for item in records:
        if item.get("baseline") != "g2fuzz" or item.get("status") != "ready":
            continue
        target = str(item.get("target") or "")
        raw = str(item.get("source_run") or "")
        ready, detail = hgb_eval_all.source_ready("g2fuzz", target, raw)
        if not ready:
            raise ValueError(f"unverified canonical G2Fuzz source for {target}: {detail}")
        import hgb_replay_saved
        selected, source = hgb_replay_saved.phase_a_source("g2fuzz", raw)
        package = Path(hgb_replay_saved.host_command(source)["target_package"]).resolve(strict=True)
        if target in canonical:
            raise ValueError(f"duplicate canonical G2Fuzz source for {target}")
        canonical[target] = (str(selected), package)
    if not canonical:
        raise ValueError(f"no verified G2Fuzz sources in {manifest}")
    return canonical


def checked_run(record: dict[str, str], baseline: str,
                canonical: dict[str, tuple[str, Path]]) -> tuple[Path, str, str]:
    target = record["target"]
    raw = record.get(f"{baseline}_run") or ""
    if not raw:
        raise ValueError("missing Phase B run path")
    run = (ROOT / raw).resolve(strict=True)
    if not run.is_relative_to(ROOT / "workspace" / baseline / target):
        raise ValueError(f"run path escapes pair workspace: {run}")
    if target not in canonical:
        raise ValueError("same-date manifest has no verified G2Fuzz source")
    canonical_source, canonical_package = canonical[target]
    provenance = json.loads((run / "phase_b_source.json").read_text(encoding="utf-8"))
    if provenance.get("baseline") != baseline or provenance.get("target") != target:
        raise ValueError("Phase B provenance baseline/target mismatch")
    source = str(provenance.get("selected_phase_a_run") or "")
    if not source:
        raise ValueError("Phase B provenance has no selected Phase A run")
    raw_package = str(provenance.get("canonical_target_package") or "")
    if not raw_package or Path(raw_package).resolve(strict=True) != canonical_package:
        raise ValueError("Phase B target package differs from same-date canonical G2Fuzz package")
    return run, source, canonical_source


def g2_saved_campaign_ready(run: Path, budget: int) -> None:
    result = hgb_eval_all.read_json(run / "result.json")
    campaign = result.get("campaign") or {}
    stages = result.get("stages") or {}
    elapsed = hgb_eval_all.campaign_elapsed("g2fuzz", run, campaign)
    if elapsed is None or elapsed < hgb_eval_all.minimum_campaign_elapsed(budget):
        raise ValueError("saved G2Fuzz campaign has no verified full duration")
    if int(campaign.get("execs_done") or 0) <= 0:
        raise ValueError("saved G2Fuzz campaign has no recorded target executions")
    for stage in ("target_pair_build", "generated_input_validation", "campaign"):
        if (stages.get(stage) or {}).get("status") != "complete":
            raise ValueError(f"saved G2Fuzz {stage} stage is incomplete")
    if any(isinstance(value, dict) and value.get("status") == "failed"
           for name, value in stages.items() if name != "coverage"):
        raise ValueError("saved G2Fuzz run has a failed non-coverage stage")
    corpus = run / "coverage/corpus"
    if not corpus.is_dir() or not any(path.is_file() for path in corpus.iterdir()):
        raise ValueError("saved G2Fuzz coverage corpus is empty")


def saved_campaign_ready(baseline: str, run: Path, budget: int) -> None:
    if baseline == "g2fuzz":
        g2_saved_campaign_ready(run, budget)
    else:
        work = run / "evaluation/cand_001" if baseline in BASELINES[:3] else run
        hgb_fuzzbench_builder.load_saved_campaign(work, budget)


def saved_corpus_file_count(baseline: str, run: Path) -> int:
    if baseline == "g2fuzz":
        return sum(path.is_file() for path in (run / "coverage/corpus").rglob("*"))
    work = run / "evaluation/cand_001" if baseline in BASELINES[:3] else run
    record = hgb_eval_all.read_json(work / "campaign/campaign.json")
    count = int(record.get("final_corpus_file_count") or 0)
    return count if count > 0 else sum(path.is_file() for path in (work / "corpus").rglob("*"))


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
        handle.flush()
        os.fsync(handle.fileno())
    try:
        temp.replace(path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temp.unlink(missing_ok=True)


def update_row(record: dict[str, str], baseline: str, result: dict) -> None:
    for metric in hgb_eval_all.METRICS:
        field = f"{baseline}_{metric}"
        if field in record:
            record[field] = str(result.get(metric, ""))


def verified_lcov_path(run: Path, baseline: str) -> Path:
    """Require a nonempty host LCOV inside the same Phase B run."""
    relative = "evaluation/result.json" if baseline in BASELINES[:3] else "result.json"
    result = hgb_eval_all.read_json(run / relative)
    coverage = result.get("coverage") or (result.get("metrics") or {}).get("coverage") or {}
    raw = str(coverage.get("coverage_report_path") or coverage.get("report_path") or "")
    if not raw.endswith(".lcov"):
        raise ValueError("evaluated result has no LCOV report path")
    if raw.startswith("/workspace/"):
        host = run / raw.removeprefix("/workspace/")
    else:
        host = Path(raw)
        if not host.is_absolute():
            raise ValueError("LCOV report path is not absolute")
    try:
        host = host.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"LCOV report is missing: {raw}") from exc
    if not host.is_relative_to(run.resolve()) or not host.is_file() or host.stat().st_size == 0:
        raise ValueError(f"LCOV report is empty or outside run: {host}")
    return host


def recovery_command(record: dict[str, str], baseline: str, run: Path,
                     source: str, canonical_source: str, budget: int,
                     cpu: int, memory_gib: int) -> list[str]:
    target = record["target"]
    return [sys.executable, str(ROOT / "scripts/hgb_replay_saved.py"),
            "--baseline", baseline, "--target", target,
            "--source-run", source, "--canonical-source-run", canonical_source,
            "--run-id", run.name, "--campaign-seconds", str(budget),
            "--cpu", str(cpu), "--memory-gib", str(memory_gib),
            "--recover-existing"]


def recover_one(record: dict[str, str], baseline: str, run: Path,
                source: str, canonical_source: str, budget: int, cpu: int,
                memory_gib: int) -> tuple[str, str, int]:
    target = record["target"]
    cmd = recovery_command(record, baseline, run, source, canonical_source,
                           budget, cpu, memory_gib)
    with (run / "recovery.launch.log").open("w", encoding="utf-8") as log:
        completed = subprocess.run(cmd, cwd=run, stdout=log, stderr=subprocess.STDOUT, check=False)
    return baseline, target, completed.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path, default=ROOT / "workspace/eval_all/2026-10-12.csv")
    parser.add_argument("--manifest", type=Path,
                        help="same-date Phase A manifest; defaults to <CSV date>.phase_a.json")
    parser.add_argument("--parallel-worker", type=int, default=4)
    parser.add_argument("--campaign-seconds", type=int, default=86400)
    parser.add_argument("--memory-per-job-gib", type=int, default=8)
    parser.add_argument("--baseline", choices=BASELINES, action="append")
    parser.add_argument("--max-jobs", type=int, default=0,
                        help="limit actual recovery jobs for a small verification run")
    parser.add_argument("--dry-run", action="store_true",
                        help="list eligible and skipped trials without writing files or starting Docker")
    args = parser.parse_args()
    if min(args.parallel_worker, args.campaign_seconds, args.memory_per_job_gib) < 1 or args.max_jobs < 0:
        parser.error("workers, duration, and memory must be positive")
    csv_path = args.csv.resolve(strict=True)
    if not csv_path.is_relative_to(ROOT / "workspace"):
        parser.error("CSV must be in workspace")
    try:
        manifest = manifest_for_csv(csv_path, args.manifest)
        canonical = canonical_sources(manifest)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        parser.error(f"cannot validate same-date Phase A manifest: {exc}")
    if args.dry_run:
        return recover_csv(args, csv_path, manifest, canonical)
    lock_path = csv_path.parent / f"{csv_path.name}.lock"
    with lock_path.open("w") as lock_handle:
        try:
            fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            parser.error(f"another evaluation coordinator owns {csv_path}")
        return recover_csv(args, csv_path, manifest, canonical)


def recover_csv(args: argparse.Namespace, csv_path: Path, manifest: Path,
                canonical: dict[str, tuple[str, Path]]) -> int:
    fields, rows = read_rows(csv_path)
    chosen = tuple(args.baseline or BASELINES)
    jobs: list[tuple[dict[str, str], str, Path, str, str]] = []
    skipped = 0
    for record in rows:
        for baseline in chosen:
            if record.get(f"{baseline}_status") in {"evaluated", "N/A"}:
                continue
            trial = record.get("trial") or "1"
            label = f"trial {trial} {baseline} {record['target']}"
            try:
                run, source, canonical_source = checked_run(record, baseline, canonical)
            except (OSError, KeyError, TypeError, ValueError) as exc:
                skipped += 1
                print(f"skip {label}: {exc}", flush=True)
                continue
            result = hgb_eval_all.result_row(ROOT, baseline, record["target"], run,
                                             args.campaign_seconds, 0)
            if (result["status"] == "evaluated"
                    and result["coverage_contract"] == "canonical-g2-lcov-v1"):
                try:
                    verified_lcov_path(run, baseline)
                except ValueError as exc:
                    print(f"reconcile unavailable {label}: {exc}; retrying coverage", flush=True)
                else:
                    if not args.dry_run:
                        update_row(record, baseline, result)
                    print(f"reconciled {label}", flush=True)
                    continue
            try:
                saved_campaign_ready(baseline, run, args.campaign_seconds)
            except (OSError, TypeError, ValueError, tarfile.TarError) as exc:
                skipped += 1
                print(f"skip {label}: {exc}", flush=True)
                continue
            jobs.append((record, baseline, run, source, canonical_source))
            print(f"eligible {label}: saved campaign verified; run={run}", flush=True)
    jobs.sort(key=lambda job: (saved_corpus_file_count(job[1], job[2]),
                               job[0]["target"], job[1], int(job[0].get("trial") or 1)))
    eligible_count = len(jobs)
    if args.max_jobs:
        jobs = jobs[:args.max_jobs]
    if args.dry_run:
        if args.max_jobs:
            for record, baseline, run, _, _ in jobs:
                print(f"selected trial {record.get('trial') or '1'} {baseline} "
                      f"{record['target']}: corpus_files={saved_corpus_file_count(baseline, run)}",
                      flush=True)
        print(f"dry-run: {eligible_count} eligible, {skipped} skipped, "
              f"{len(jobs)} selected; "
              f"manifest={manifest}; CSV unchanged", flush=True)
        return 0
    save_rows(csv_path, fields, rows)
    cpus = sorted(os.sched_getaffinity(0))
    workers = min(args.parallel_worker, len(cpus), max(1, len(jobs)))
    print(f"saved-campaign recovery: {len(jobs)} jobs, {workers} workers; "
          "original campaigns retained", flush=True)
    cpu_tokens: queue.Queue[int] = queue.Queue()
    for cpu in cpus[:workers]:
        cpu_tokens.put(cpu)

    def run_with_cpu(job: tuple[dict[str, str], str, Path, str, str]) -> tuple[str, str, int]:
        record, baseline, run, source, canonical_source = job
        cpu = cpu_tokens.get()
        try:
            return recover_one(record, baseline, run, source, canonical_source,
                               args.campaign_seconds, cpu, args.memory_per_job_gib)
        finally:
            cpu_tokens.put(cpu)

    job_failures = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {}
        for job in jobs:
            record, baseline, _, _, _ = job
            future = pool.submit(run_with_cpu, job)
            futures[future] = (record, baseline)
        for future in as_completed(futures):
            record, baseline = futures[future]
            target = record["target"]
            try:
                _, _, code = future.result()
                run = ROOT / record[f"{baseline}_run"]
                result = hgb_eval_all.result_row(ROOT, baseline, target, run,
                                                 args.campaign_seconds, code)
                if result["status"] == "evaluated":
                    try:
                        if result["coverage_contract"] != "canonical-g2-lcov-v1":
                            raise ValueError("missing canonical coverage contract")
                        verified_lcov_path(run, baseline)
                    except ValueError as exc:
                        result["status"] = "quality_failure"
                        result["reason"] = f"coverage recovery LCOV invalid: {exc}"
                if code and result["status"] == "evaluated":
                    result["status"] = "infra_failure"
                    result["reason"] = f"coverage recovery exited {code}"
                if result["status"] != "evaluated":
                    job_failures += 1
                update_row(record, baseline, result)
                print(f"{baseline} {target}: {result['status']} ({result['reason']})", flush=True)
            except Exception as exc:
                job_failures += 1
                print(f"{baseline} {target}: recovery error: {exc}", flush=True)
            save_rows(csv_path, fields, rows)
    counts = collections.Counter(record.get(f"{baseline}_status", "") for record in rows
                                 for baseline in hgb_eval_all.BASELINES)
    print(f"recovery jobs: {len(jobs) - job_failures}/{len(jobs)} succeeded; "
          f"final CSV: {csv_path}; statuses={dict(counts)}", flush=True)
    return 0 if job_failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
