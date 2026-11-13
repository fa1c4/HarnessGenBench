#!/usr/bin/env python3
"""Build the MAGMA five-trial baseline table from saved campaign coverage.

Reads ``workspace/magma/coverage/<batch>/<baseline>_<target>/trial_N`` (or a
flat ``<baseline>_<target>`` for smoke batches), intersects the instrumented
target-source line sets across baselines per target, and renders
mean ± sample stdev coverage plus a crash table into
``results/magma_baselines_5times.md``.

This is the final report generator; it is not run until the 5x86,400 s
campaigns have been measured.
"""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "workspace/magma"
METADATA = ROOT / "metadata/magma_targets.yaml"

TARGETS = ["libpng", "libsndfile", "libtiff", "libxml2", "lua", "openssl", "php", "poppler", "sqlite3"]
BASELINES = ["oss-fuzz-gen", "ckgfuzzer", "promefuzz", "elfuzz", "g2fuzz"]
LABELS = {"oss-fuzz-gen": "OSS-Fuzz-Gen", "ckgfuzzer": "CKGFuzzer",
          "promefuzz": "PromeFuzz", "elfuzz": "ELFuzz", "g2fuzz": "G2Fuzz"}


def specs() -> dict[str, dict]:
    return yaml.safe_load(METADATA.read_text(encoding="utf-8"))["targets"]


def read_lcov(path: Path, target: str) -> dict[tuple[str, int], bool]:
    spec = specs()[target]
    proj = spec["project_root"]
    harness = f"{proj}/{spec['harness']}"
    ids: dict[tuple[str, int], bool] = {}
    current = ""
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("SF:"):
            current = line[3:].strip()
        elif line.startswith("DA:"):
            fields = line[3:].split(",")
            if len(fields) < 2 or not fields[0].isdigit() or not fields[1].isdigit():
                continue
            if not current.startswith(proj) or current == harness:
                continue
            ids[(current, int(fields[0]))] = int(fields[1]) > 0
    return ids


def cell_trials(batch: Path, baseline: str, target: str) -> list[Path]:
    stem = f"{baseline}_{target}"
    directory = batch / stem
    if not directory.is_dir():
        return []
    trials = sorted(directory.glob("trial_*"))
    if trials:
        return [trial for trial in trials if (trial / "coverage.lcov").is_file()]
    return [directory] if (directory / "coverage.lcov").is_file() else []


def crashes(trial: Path) -> int:
    # coverage/<batch>/<stem>/trial_N  -> campaigns/<batch>/<stem>/trial_N/crashes
    # flat smoke layout <stem> shares the leaf name with the stem directory.
    batch, stem = trial.parts[-3], trial.parts[-2]
    if trial.name == stem:
        directory = WORK / "campaigns" / batch / stem / "crashes"
    else:
        directory = WORK / "campaigns" / batch / stem / trial.name / "crashes"
    if directory.is_dir():
        return sum(1 for path in directory.iterdir() if path.is_file())
    return 0


def campaign_seconds(trial: Path) -> int | None:
    log = WORK / "campaigns" / trial.parts[-3] / trial.parts[-2] / trial.name / "campaign.log"
    if not log.is_file():
        return None
    text = log.read_text(encoding="utf-8", errors="replace")
    marker = "HGB_CAMPAIGN_END_EPOCH="
    if marker in text:
        return None
    return None


def fmt_mean(values: list[int], denominator: int) -> str:
    if not values:
        return "—"
    mean = statistics.mean(values)
    if len(values) > 1:
        stdev = statistics.stdev(values)
        cell = f"{mean:,.0f} ± {stdev:,.0f}"
    else:
        cell = f"{mean:,.0f}"
    percent = 100 * mean / denominator if denominator else 0
    return f"{cell} ({percent:.2f}%)"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", default="magma_v1")
    parser.add_argument("--min-trials", type=int, default=1)
    parser.add_argument("--out", default=str(ROOT / "results/magma_baselines_5times.md"))
    parser.add_argument("--title", default="MAGMA baseline coverage (five 24-hour campaigns)")
    args = parser.parse_args()
    batch = WORK / "coverage" / args.batch
    if not batch.is_dir():
        raise SystemExit(f"missing coverage batch: {batch}")

    lines_by_cell: dict[tuple[str, str], list[dict]] = {}
    for baseline in BASELINES:
        for target in TARGETS:
            trials = cell_trials(batch, baseline, target)
            entries = []
            for trial in trials:
                entries.append({
                    "lcov": read_lcov(trial / "coverage.lcov", target),
                    "crashes": crashes(trial),
                    "trial": trial,
                })
            if entries:
                lines_by_cell[(baseline, target)] = entries

    common: dict[str, set[tuple[str, int]]] = {}
    for target in TARGETS:
        sets = [set(entry["lcov"]) for (baseline, t), entries in lines_by_cell.items()
                if t == target for entry in entries]
        if sets:
            common[target] = set.intersection(*sets)

    header = ["Baseline"] + [f"`{t}`" for t in TARGETS]
    table = ["| " + " | ".join(header) + " |", "| :--- | " + " | ".join("---:" for _ in TARGETS) + " |"]
    crash_table = ["| " + " | ".join(header) + " |", "| :--- | " + " | ".join("---:" for _ in TARGETS) + " |"]
    for baseline in BASELINES:
        cells = []
        crash_cells = []
        for target in TARGETS:
            entries = lines_by_cell.get((baseline, target), [])
            if not entries:
                spec = specs()[target]
                not_applicable = (
                    (baseline == "elfuzz" and spec.get("elfuzz_applicable") is False)
                    or (baseline == "ckgfuzzer" and spec.get("ckgfuzzer_skip_macro_api"))
                )
                if not_applicable:
                    cells.append("N/A")
                    crash_cells.append("N/A")
                else:
                    cells.append("—")
                    crash_cells.append("—")
                continue
            denominator = len(common.get(target, set()))
            if len(entries) < args.min_trials:
                cells.append(f"n={len(entries)}")
                crash_cells.append("—")
                continue
            covered = [sum(1 for line_id in common[target] if entry["lcov"].get(line_id)) for entry in entries]
            cells.append(f"{fmt_mean(covered, denominator)}")
            crash_values = [entry["crashes"] for entry in entries]
            crash_cells.append(f"{statistics.mean(crash_values):.1f} ± {statistics.stdev(crash_values):.1f}"
                               if len(crash_values) > 1 else f"{crash_values[0]}")
        table.append(f"| {LABELS[baseline]} | " + " | ".join(cells) + " |")
        crash_table.append(f"| {LABELS[baseline]} | " + " | ".join(crash_cells) + " |")

    denominators = ["| Target | Common-source lines |", "| :--- | ---: |"]
    for target in TARGETS:
        if target in common:
            denominators.append(f"| `{target}` | {len(common[target]):,} |")
        else:
            denominators.append(f"| `{target}` | — |")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(
        [f"# {args.title}", "",
         f"Batch: `{args.batch}`. Coverage: target-source file:line IDs from the "
         "MAGMA-native `llvm_cov` replay, harness excluded; cells use the "
         "common-source projection across applicable baselines. Each cell is "
         "mean ± sample stdev over trials (n = trials); percent is the mean "
         "against the common denominator.", "",
         "## Coverage", ""] + table +
        ["", "## Crashes (ASan)", ""] + crash_table +
        ["", "## Denominators", ""] + denominators + [""])
    out.write_text(content, encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
