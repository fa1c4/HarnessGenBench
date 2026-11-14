#!/usr/bin/env python3
"""Launch the five-trial 86,400-second MAGMA matrix from a cell manifest.

The manifest carries the already-built campaign/coverage binaries from the
smoke phase, so this launcher does not rebuild anything. Each cell runs
``--trials`` independent campaigns; campaigns are scheduled with a fixed worker
pool (the 24 h matrix uses 150 workers). A separate coverage phase replays each
trial's final corpus with the matching llvm_cov binary.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "workspace/magma"
EVAL = ROOT / "scripts/hgb_magma_eval.py"


def run_trial_campaign(baseline: str, target: str, cell: dict, trial: int,
                       batch: str, seconds: int) -> list[str]:
    out = WORK / "campaigns" / batch / f"{baseline}_{target}" / f"trial_{trial}"
    if (out / "campaign.done").is_file():
        return []
    out.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, str(EVAL), "--target", target, "--fuzzer", "libfuzzer_asan",
           "campaign", "--binary", str(WORK / cell["binary"]), "--seconds", str(seconds),
           "--rss-limit-mb", "2048", "--out", str(out)]
    if cell.get("kind") == "corpus":
        cmd += ["--seeds", str(WORK / cell["seeds"])]
    log = out / "campaign.log"
    with log.open("w", encoding="utf-8", errors="replace") as handle:
        code = subprocess.run(cmd, stdout=handle, stderr=subprocess.STDOUT).returncode
    return [f"{baseline}/{target}/trial_{trial}: exit {code}"] if code != 0 else []


def run_trial_coverage(baseline: str, target: str, cell: dict, trial: int,
                       batch: str) -> list[str]:
    corpus = WORK / "campaigns" / batch / f"{baseline}_{target}" / f"trial_{trial}" / "final_corpus"
    if not corpus.is_dir():
        return [f"{baseline}/{target}/trial_{trial}: missing final_corpus"]
    out = WORK / "coverage" / batch / f"{baseline}_{target}" / f"trial_{trial}"
    if (out / "coverage.json").is_file():
        return []
    out.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, str(EVAL), "--target", target, "--fuzzer", "llvm_cov",
           "coverage", "--binary", str(WORK / cell["cov_binary"]),
           "--corpus", str(corpus), "--out", str(out)]
    log = out / "coverage.log"
    with log.open("w", encoding="utf-8", errors="replace") as handle:
        code = subprocess.run(cmd, stdout=handle, stderr=subprocess.STDOUT).returncode
    return [f"{baseline}/{target}/trial_{trial}: coverage exit {code}"] if code != 0 else []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=str(WORK / "selection_24h.json"))
    parser.add_argument("--batch", default="magma24h")
    parser.add_argument("--seconds", type=int, default=86400)
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--workers", type=int, default=150)
    parser.add_argument("--phase", choices=("campaign", "coverage", "all"), default="all")
    args = parser.parse_args()
    data = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    cells = [(b, t, c) for b, per in data["cells"].items() for t, c in per.items()]
    tasks = [(b, t, c, trial) for b, t, c in cells for trial in range(1, args.trials + 1)]
    failures: list[str] = []
    if args.phase in ("campaign", "all"):
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(run_trial_campaign, b, t, c, trial, args.batch, args.seconds)
                       for b, t, c, trial in tasks]
            for future in as_completed(futures):
                failures.extend(future.result())
        print(json.dumps({"phase": "campaign", "cells": len(cells), "trials": len(tasks),
                          "failures": failures}, indent=2))
    if args.phase in ("coverage", "all"):
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(run_trial_coverage, b, t, c, trial, args.batch)
                       for b, t, c, trial in tasks]
            for future in as_completed(futures):
                failures.extend(future.result())
        print(json.dumps({"phase": "coverage", "cells": len(cells), "trials": len(tasks),
                          "failures": failures}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
