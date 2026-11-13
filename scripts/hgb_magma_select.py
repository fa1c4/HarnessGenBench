#!/usr/bin/env python3
"""Select the MAGMA-phase artifact for each (baseline, target) cell.

Harness generators: choose the generated harness the generator's own
independent evaluator selected (``evaluation/result.json``), else the candidate
whose source actually calls the committed entry API, preferring the candidate
with the highest measured coverage.  Corpus generators: use the corpus written
by the corpus pipeline.

The result is a manifest consumed by ``scripts/hgb_magma_campaigns.py``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "workspace/magma"
METADATA = ROOT / "metadata/magma_targets.yaml"


def specs() -> dict[str, dict]:
    return yaml.safe_load(METADATA.read_text(encoding="utf-8"))["targets"]


def entry_apis() -> dict[str, str]:
    data = yaml.safe_load(METADATA.read_text(encoding="utf-8"))["targets"]
    return {target: spec["entry_api"] for target, spec in data.items()}


def call_patterns(api: str) -> list[str]:
    short = api.split("::")[-1]
    return [rf"\b{re.escape(api)}\s*\(", rf"\bOSS_FUZZ_{re.escape(short)}\s*\(",
            rf"\b{re.escape(short)}\s*\("]


def source_score(path: Path, api: str) -> int:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return -1
    score = 0
    for index, pattern in enumerate(call_patterns(api)):
        if re.search(pattern, text):
            score += 10 - index * 3
    if "LLVMFuzzerTestOneInput" in text:
        score += 2
    # Penalize harnesses that never touch the fuzzer input.
    if re.search(r"\bsize\b", text) and re.search(r"\bdata\b", text):
        score += 1
    return score


def run_dirs(baseline: str, target: str) -> list[Path]:
    if baseline == "oss-fuzz-gen":
        base = ROOT / "workspace/oss-fuzz-gen" / f"magma_{target}"
    elif baseline in {"ckgfuzzer", "promefuzz"}:
        base = ROOT / "workspace" / baseline / f"magma_{target}"
    else:
        base = ROOT / "workspace" / baseline / f"magma_{target}"
    dirs = []
    current = WORK / "generation" / baseline / target / "current"
    if current.is_symlink() or current.is_dir():
        dirs.append(current.resolve())
    if base.is_dir():
        dirs.extend(sorted((p for p in base.iterdir() if p.is_dir()),
                           key=lambda p: p.name, reverse=True))
    seen: list[Path] = []
    for directory in dirs:
        if directory not in seen and directory.is_dir():
            seen.append(directory)
    return seen


def evaluator_selection(run_dir: Path) -> tuple[Path | None, dict]:
    result = run_dir / "evaluation/result.json"
    if not result.is_file():
        return None, {}
    try:
        data = json.loads(result.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, {}
    selected = data.get("selected_candidate") or {}
    path = selected.get("candidate_path") or ""
    if path and Path(path).is_file():
        coverage = selected.get("coverage") or {}
        return Path(path), {
            "source": "generator_evaluator",
            "status": data.get("status"),
            "coverage_percent": coverage.get("percent"),
        }
    return None, {"source": "generator_evaluator", "status": data.get("status")}


def candidate_files(run_dir: Path, suffixes: tuple[str, ...]) -> list[Path]:
    files = []
    for directory in (run_dir / "generated_harnesses", run_dir / "generated_inputs"):
        if directory.is_dir():
            files.extend(path for path in directory.rglob("*")
                         if path.is_file() and path.suffix.lower() in suffixes)
    return sorted(files)


def select_harness(baseline: str, target: str, api: str) -> tuple[Path | None, dict]:
    for run_dir in run_dirs(baseline, target):
        selected, evidence = evaluator_selection(run_dir)
        if selected is not None:
            return selected, {**evidence, "run_dir": str(run_dir)}
        candidates = candidate_files(run_dir, (".c", ".cc", ".cpp", ".cxx"))
        if not candidates:
            continue
        scored = sorted(
            ((source_score(path, api), path) for path in candidates),
            key=lambda item: (-item[0], len(item[1].read_text(errors="ignore"))),
        )
        best_score, best = scored[0]
        if best_score <= 0:
            continue
        return best, {
            "source": "api_text_match",
            "run_dir": str(run_dir),
            "api": api,
            "score": best_score,
            "candidates": [str(path) for _, path in scored],
        }
    return None, {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(WORK / "selection.json"))
    parser.add_argument("--baselines", default="oss-fuzz-gen,ckgfuzzer,promefuzz,elfuzz,g2fuzz")
    parser.add_argument("--targets", default="libpng,libsndfile,libtiff,libxml2,lua,openssl,php,poppler,sqlite3")
    parser.add_argument("--corpus-root", default=str(WORK / "corpus"))
    args = parser.parse_args()
    target_specs = specs()
    apis = entry_apis()
    baselines = [b.strip() for b in args.baselines.split(",") if b.strip()]
    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    selected_root = WORK / "selected"
    manifest = {"targets": targets, "baselines": baselines, "cells": {}}
    for baseline in baselines:
        manifest["cells"][baseline] = {}
        for target in targets:
            spec = target_specs[target]
            cell_dir = selected_root / baseline / target
            if baseline == "elfuzz" and target_specs[target].get("elfuzz_applicable") is False:
                print(f"skip elfuzz/{target}: upstream text-only contract (N/A)")
                continue
            if baseline == "ckgfuzzer" and target_specs[target].get("ckgfuzzer_skip_macro_api"):
                print(f"skip ckgfuzzer/{target}: macro-declared entry API (not evaluated)")
                continue
            if baseline in {"oss-fuzz-gen", "ckgfuzzer", "promefuzz"}:
                harness, evidence = select_harness(baseline, target, apis[target])
                if harness is None:
                    print(f"missing harness: {baseline}/{target}")
                    continue
                cell_dir.mkdir(parents=True, exist_ok=True)
                destination = cell_dir / f"harness{harness.suffix.lower()}"
                shutil.copy2(harness, destination)
                (cell_dir / "provenance.json").write_text(
                    json.dumps({**evidence, "original": str(harness),
                                "entry_api": apis[target]}, indent=2) + "\n",
                    encoding="utf-8")
                manifest["cells"][baseline][target] = {
                    "kind": "harness",
                    "path": str(destination),
                    "api": apis[target],
                    "original": str(harness),
                }
                print(f"harness {baseline}/{target}: {harness} -> {destination}")
            else:
                corpus = Path(args.corpus_root) / baseline / target
                if (corpus / "corpus").is_dir():
                    corpus = corpus / "corpus"
                if not corpus.is_dir() or not any(p.is_file() for p in corpus.iterdir()):
                    print(f"missing corpus: {baseline}/{target} ({corpus})")
                    continue
                manifest["cells"][baseline][target] = {
                    "kind": "corpus",
                    "path": str(corpus),
                }
                print(f"corpus {baseline}/{target}: {corpus}")
    Path(args.out).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
