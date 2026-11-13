#!/usr/bin/env python3
"""Prepare, run, and measure MAGMA baseline campaigns.

The MAGMA protocol evaluates every (baseline, target) cell with five
independent 86,400-second libFuzzer campaigns against the MAGMA-native ASan
build, then replays every saved corpus against the matching llvm_cov build.

Artifacts selected for each cell live in a JSON manifest written by the
generation/selection stage:

    {
      "targets": ["libpng", ...],
      "baselines": ["oss-fuzz-gen", ...],
      "cells": {
        "oss-fuzz-gen": {
          "libpng": {"kind": "harness", "path": "/abs/harness.c", "api": "..."}
        },
        "elfuzz": {
          "libpng": {"kind": "corpus", "path": "/abs/corpus"}
        }
      }
    }

Commands
--------
``prepare``   build the ASan and llvm_cov binaries for every selected harness
              (one build per baseline x target, reused by all five trials).
``run``       launch the campaign queue (resumable; writes run.meta.json).
``coverage``  replay the five saved corpora per cell against the prepared
              llvm_cov binary and write coverage.json.
``status``    summarize campaign/coverage progress.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "workspace/magma"
EVAL = ROOT / "scripts/hgb_magma_eval.py"
METADATA = ROOT / "metadata/magma_targets.yaml"


def targets() -> dict[str, dict]:
    return yaml.safe_load(METADATA.read_text(encoding="utf-8"))["targets"]


def load_manifest(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def cell_key(baseline: str, target: str) -> str:
    safe = baseline.replace("/", "_")
    return f"{safe}/{target}"


def run_logged(command: list[str], log: Path, env: dict | None = None) -> int:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as handle:
        handle.write(f"$ {' '.join(command)}\n")
        handle.flush()
        code = subprocess.run(command, stdout=handle, stderr=subprocess.STDOUT,
                              env=env, check=False).returncode
        handle.write(f"[exit {code}]\n")
    return code


def variant_binary(baseline: str, target: str, fuzzer: str, program: str) -> Path:
    return WORK / "builds" / f"variant_{baseline}_{target}_{fuzzer}" / program


def prepare(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.manifest))
    specs = targets()
    jobs: list[tuple[str, str, dict]] = []
    for baseline, per_target in manifest["cells"].items():
        for target, cell in per_target.items():
            if cell.get("kind") == "harness":
                jobs.append((baseline, target, cell))
    log_dir = WORK / "runs" / args.batch / "prepare"
    failures = 0
    for baseline, target, cell in jobs:
        spec = specs[target]
        work = WORK / "builds" / f"variant_{baseline}_{target}_libfuzzer_asan"
        log = log_dir / f"{baseline}_{target}_asan.log"
        if not (work / spec["program"]).is_file():
            code = run_logged(
                [sys.executable, str(EVAL), "--target", target, "--fuzzer", "libfuzzer_asan",
                 "rebuild", "--work", str(work), "--harness", cell["path"]],
                log,
            )
            failures += code != 0
        cov_work = WORK / "builds" / f"variant_{baseline}_{target}_llvm_cov"
        cov_log = log_dir / f"{baseline}_{target}_cov.log"
        if args.coverage_binaries and not (cov_work / spec["program"]).is_file():
            code = run_logged(
                [sys.executable, str(EVAL), "--target", target, "--fuzzer", "llvm_cov",
                 "rebuild", "--work", str(cov_work), "--harness", cell["path"]],
                cov_log,
            )
            failures += code != 0
    # Native corpus-generator cells also need an llvm_cov build of the native harness.
    for target in manifest["targets"]:
        cov_work = WORK / "builds" / f"variant_native_{target}_llvm_cov"
        if args.coverage_binaries and not (cov_work / specs[target]["program"]).is_file():
            code = run_logged(
                [sys.executable, str(EVAL), "--target", target, "--fuzzer", "llvm_cov",
                 "rebuild", "--work", str(cov_work)],
                log_dir / f"native_{target}_cov.log",
            )
            failures += code != 0
    print(f"prepare done, failures={failures}")
    return 1 if failures else 0


def _campaign_one(index: int, baseline: str, target: str, trial: int,
                  manifest: dict, specs: dict, batch: str, seconds: int,
                  results: list) -> None:
    spec = specs[target]
    cell = manifest["cells"][baseline][target]
    out = WORK / "campaigns" / batch / f"{baseline}_{target}" / f"trial_{trial}"
    done = out / "campaign.done"
    if done.is_file():
        results[index] = (baseline, target, trial, "skipped")
        return
    command = [sys.executable, str(EVAL), "--target", target,
               "--fuzzer", "libfuzzer_asan", "campaign",
               "--seconds", str(seconds), "--out", str(out)]
    if cell.get("kind") == "harness":
        binary = variant_binary(baseline, target, "libfuzzer_asan", spec["program"])
        if not binary.is_file():
            results[index] = (baseline, target, trial, "missing_binary")
            return
        command += ["--binary", str(binary)]
    elif cell.get("kind") == "corpus":
        command += ["--seeds", cell["path"]]
    log = WORK / "runs" / batch / "logs" / f"{baseline}_{target}_t{trial}.log"
    code = run_logged(command, log)
    if code == 0:
        done.write_text("ok\n", encoding="utf-8")
    results[index] = (baseline, target, trial, f"exit_{code}")


def run_campaigns(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.manifest))
    specs = targets()
    jobs = []
    for baseline in manifest["baselines"]:
        for target in manifest["targets"]:
            if target not in manifest["cells"].get(baseline, {}):
                continue
            for trial in range(1, args.trials + 1):
                jobs.append((baseline, target, trial))
    results: list = [None] * len(jobs)
    work_queue: queue.Queue = queue.Queue()
    for index, job in enumerate(jobs):
        work_queue.put((index, *job))

    def worker() -> None:
        while True:
            try:
                index, baseline, target, trial = work_queue.get_nowait()
            except queue.Empty:
                return
            try:
                _campaign_one(index, baseline, target, trial, manifest, specs,
                              args.batch, args.seconds, results)
            except Exception as exc:  # keep the queue alive
                results[index] = (baseline, target, trial, f"exception:{exc}")
            finally:
                work_queue.task_done()

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(min(args.workers, len(jobs)))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    counts: dict[str, int] = {}
    for item in results:
        if item:
            counts[item[3]] = counts.get(item[3], 0) + 1
    print(json.dumps({"batch": args.batch, "cells": len(jobs), "outcomes": counts}, indent=2))
    return 0


def coverage_cell(baseline: str, target: str, trial: int, manifest: dict,
                  specs: dict, batch: str, results: list, index: int) -> None:
    spec = specs[target]
    cell = manifest["cells"][baseline][target]
    corpus = WORK / "campaigns" / batch / f"{baseline}_{target}" / f"trial_{trial}" / "final_corpus"
    out = WORK / "coverage" / batch / f"{baseline}_{target}" / f"trial_{trial}"
    done = out / "coverage.json"
    if done.is_file():
        results[index] = (baseline, target, trial, "skipped")
        return
    if not corpus.is_dir():
        results[index] = (baseline, target, trial, "missing_corpus")
        return
    if cell.get("kind") == "harness":
        cov_bin = variant_binary(baseline, target, "llvm_cov", spec["program"])
    else:
        cov_bin = variant_binary("native", target, "llvm_cov", spec["program"])
        if not cov_bin.is_file():
            cov_bin = WORK / "builds" / f"native_{target}_llvm_cov" / spec["program"]
    if not cov_bin.is_file():
        results[index] = (baseline, target, trial, "missing_cov_binary")
        return
    command = [sys.executable, str(EVAL), "--target", target, "--fuzzer", "llvm_cov",
               "coverage", "--corpus", str(corpus), "--out", str(out),
               "--binary", str(cov_bin)]
    log = WORK / "runs" / batch / "logs" / f"cov_{baseline}_{target}_t{trial}.log"
    code = run_logged(command, log)
    results[index] = (baseline, target, trial, f"exit_{code}")


def run_coverage(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.manifest))
    specs = targets()
    jobs = []
    for baseline in manifest["baselines"]:
        for target in manifest["targets"]:
            if target not in manifest["cells"].get(baseline, {}):
                continue
            for trial in range(1, args.trials + 1):
                jobs.append((baseline, target, trial))
    results: list = [None] * len(jobs)
    work_queue: queue.Queue = queue.Queue()
    for index, job in enumerate(jobs):
        work_queue.put((index, *job))

    def worker() -> None:
        while True:
            try:
                index, baseline, target, trial = work_queue.get_nowait()
            except queue.Empty:
                return
            try:
                coverage_cell(baseline, target, trial, manifest, specs,
                              args.batch, results, index)
            except Exception as exc:
                results[index] = (baseline, target, trial, f"exception:{exc}")
            finally:
                work_queue.task_done()

    threads = [threading.Thread(target=worker, daemon=True)
               for _ in range(min(args.workers, len(jobs)))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    counts: dict[str, int] = {}
    for item in results:
        if item:
            counts[item[3]] = counts.get(item[3], 0) + 1
    print(json.dumps({"batch": args.batch, "cells": len(jobs), "outcomes": counts}, indent=2))
    return 0


def status(args: argparse.Namespace) -> int:
    manifest = load_manifest(Path(args.manifest))
    rows = []
    for baseline in manifest["baselines"]:
        for target in manifest["targets"]:
            if target not in manifest["cells"].get(baseline, {}):
                continue
            campaign = sum(
                1 for trial in range(1, args.trials + 1)
                if (WORK / "campaigns" / args.batch / f"{baseline}_{target}"
                    / f"trial_{trial}" / "campaign.done").is_file()
            )
            coverage = sum(
                1 for trial in range(1, args.trials + 1)
                if (WORK / "coverage" / args.batch / f"{baseline}_{target}"
                    / f"trial_{trial}" / "coverage.json").is_file()
            )
            rows.append({"baseline": baseline, "target": target,
                         "campaigns": campaign, "coverage": coverage})
    print(json.dumps(rows, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--manifest", required=True)
    prep.add_argument("--batch", required=True)
    prep.add_argument("--coverage-binaries", action="store_true")
    prep.set_defaults(func=prepare)

    camp = sub.add_parser("run")
    camp.add_argument("--manifest", required=True)
    camp.add_argument("--batch", required=True)
    camp.add_argument("--seconds", type=int, default=86400)
    camp.add_argument("--trials", type=int, default=5)
    camp.add_argument("--workers", type=int, default=64)
    camp.set_defaults(func=run_campaigns)

    cov = sub.add_parser("coverage")
    cov.add_argument("--manifest", required=True)
    cov.add_argument("--batch", required=True)
    cov.add_argument("--trials", type=int, default=5)
    cov.add_argument("--workers", type=int, default=32)
    cov.set_defaults(func=run_coverage)

    stat = sub.add_parser("status")
    stat.add_argument("--manifest", required=True)
    stat.add_argument("--batch", required=True)
    stat.add_argument("--trials", type=int, default=5)
    stat.set_defaults(func=status)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
