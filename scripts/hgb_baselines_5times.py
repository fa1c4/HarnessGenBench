#!/usr/bin/env python3
"""Merge Phase B evaluation batches and build the five-trial baseline table.

The 2026-11-06 batch holds G2Fuzz and ELFuzz and the 2026-11-08 batch holds the
three harness generators.  This script picks, per (baseline, target), the newest
batch that evaluated trials, writes one merged results CSV, audits it with
hgb_audit_coverage_integrity.py, and renders the mean +/- stdev coverage report.
A later G2Fuzz retry batch can be added with --batch when it has been measured.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINES = ("oss-fuzz-gen", "ckgfuzzer", "promefuzz", "elfuzz", "g2fuzz")
PRETTY = {
    "oss-fuzz-gen": "OSS-Fuzz-Gen",
    "ckgfuzzer": "CKGFuzzer",
    "promefuzz": "PromeFuzz",
    "elfuzz": "ELFuzz",
    "g2fuzz": "G2Fuzz",
}
METRICS = (
    "status", "campaign_seconds", "campaign_elapsed_seconds", "execs_done",
    "covered_lines", "raw_covered_lines", "sut_covered_lines", "sut_total_lines",
    "sut_source_files", "coverage_contract", "crashes", "read_tokens",
    "write_tokens", "retry_count", "driver_fix_rounds", "run", "reason",
)
DEFAULT_BATCHES = ("20261108-0739", "20261106-2123")
EVIDENCE_STATUSES = ("evaluated", "failed", "failed_exit_1", "quality_failure",
                     "short_campaign", "corpus_ready", "measuring", "running", "N/A")


def target_order() -> list[str]:
    return json.loads((ROOT / "metadata/fuzzbench_targets.json").read_text(
        encoding="utf-8"))["target_sets"]["valuable"]["targets"]


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def pick_batch(loaded: list[tuple[str, list[dict[str, str]]]],
               baseline: str, target: str) -> str:
    """Newest batch that evaluated this pair, else newest batch that ran it."""
    fallback = ""
    for batch, rows in loaded:  # newest first
        pair_rows = [row for row in rows if row["target"] == target]
        if not pair_rows:
            continue
        statuses = {row.get(f"{baseline}_status") for row in pair_rows}
        if "evaluated" in statuses:
            return batch
        if not fallback and statuses & set(EVIDENCE_STATUSES):
            fallback = batch
    return fallback


def merge(batches: list[str]) -> tuple[list[str], dict[tuple[int, str], dict[str, str]],
                                      dict[tuple[str, str], str]]:
    loaded = [(batch, read_rows(ROOT / "workspace/eval_all" / batch / "results.csv"))
              for batch in batches]
    order = target_order()
    targets = [name for name in order if any(
        row["target"] == name for _, rows in loaded for row in rows)]
    targets += sorted({row["target"] for _, rows in loaded for row in rows}
                      .difference(targets))
    chosen = {(baseline, target): pick_batch(loaded, baseline, target)
              for baseline in BASELINES for target in targets}
    merged: dict[tuple[int, str], dict[str, str]] = {}
    for batch_name, rows in loaded:
        for row in rows:
            trial = int(row.get("trial") or 1)
            target = row["target"]
            record = merged.setdefault((trial, target), {})
            for baseline in BASELINES:
                if chosen[baseline, target] != batch_name:
                    continue
                for metric in METRICS:
                    record[f"{baseline}_{metric}"] = row.get(f"{baseline}_{metric}", "")
    return targets, merged, chosen


def write_merged(path: Path, targets: list[str],
                 merged: dict[tuple[int, str], dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["trial", "target",
                                                    *[f"{b}_{m}" for b in BASELINES
                                                      for m in METRICS]])
        writer.writeheader()
        for trial in range(1, 6):
            for target in targets:
                writer.writerow({"trial": trial, "target": target,
                                 **merged.get((trial, target), {})})


def run_audit(merged_csv: Path, work: Path) -> dict[str, Path]:
    paths = {
        "audit": work / "hgb_baselines_5times.coverage_audit.csv",
        "corrected": work / "hgb_baselines_5times.corrected.csv",
        "source_sets": work / "hgb_baselines_5times.source_sets.csv",
        "common": work / "hgb_baselines_5times.common.csv",
    }
    command = [sys.executable, str(ROOT / "scripts/hgb_audit_coverage_integrity.py"),
               "--input", str(merged_csv)]
    for flag, path in (("--output", paths["audit"]),
                       ("--corrected-output", paths["corrected"]),
                       ("--source-sets-output", paths["source_sets"]),
                       ("--common-source-output", paths["common"])):
        command += [flag, str(path)]
    code = subprocess.run(command, cwd=ROOT, check=False).returncode
    if code:
        raise SystemExit(f"coverage audit failed with exit {code}")
    return paths


def measured(row: dict[str, str], baseline: str) -> tuple[int, int] | None:
    """Return (covered, total) target-source lines for an evaluated trial."""
    if row.get(f"{baseline}_status") != "evaluated":
        return None
    covered = str(row.get(f"{baseline}_sut_covered_lines") or "")
    total = str(row.get(f"{baseline}_sut_total_lines") or "")
    if not (covered.isdigit() and total.isdigit()) or int(total) <= 0:
        return None
    return int(covered), int(total)


def summarize(values: list[tuple[int, int]]) -> dict:
    if not values:
        return {"n": 0}
    counts = [covered for covered, _ in values]
    totals = sorted({total for _, total in values})
    mean = statistics.mean(counts)
    return {"n": len(counts), "mean": mean,
            "stdev": statistics.stdev(counts) if len(counts) > 1 else None,
            "percent": statistics.mean(100.0 * c / t for c, t in values),
            "totals": totals, "counts": counts}


def metric_label(metric: str) -> str:
    if metric == "common":
        return ("covered lines on the source set instrumented for every applicable baseline "
                "(common-source projection, intersection of the per-run instrumented file:line "
                "sets; harness and dependency lines excluded)")
    return ("covered target source lines under the canonical `canonical-g2-lcov-v1` LCOV "
            "contract (dependency and harness source lines excluded)")


def _da_counts(report_path: str, project: str, cache: dict[str, tuple[int, int]]) -> tuple[int, int]:
    """Return (covered, instrumented) project lines from DA records."""
    if report_path in cache:
        return cache[report_path]
    sys.path.insert(0, str(ROOT / "docker/common"))
    import hgb_coverage
    try:
        lines = hgb_coverage.lcov_project_lines(Path(report_path), project)
        value = (sum(1 for hits in lines.values() if hits > 0), len(lines))
    except (OSError, ValueError, hgb_coverage.CoverageError):
        value = (0, 0)
    cache[report_path] = value
    return value


def apply_metric(rows: list[dict[str, str]], common_rows: list[dict[str, str]],
                 metric: str, audit_rows: list[dict[str, str]] | None = None) -> list[dict[str, str]]:
    """Rewrite covered/total columns for the requested coverage metric.

    A cell is projected onto the common source set only when all five trials
    have a projected row; otherwise the whole cell keeps the canonical
    target-source counts and is marked with a dagger, so one cell never mixes
    two denominators.
    """
    audit = {(int(row.get("trial") or 1), row["target"], row["baseline"]): row
             for row in (audit_rows or [])}
    cache: dict[str, tuple[int, int]] = {}
    if metric == "sut" or not common_rows:
        return rows
    common = {(int(row.get("trial") or 1), row["target"]): row for row in common_rows}
    merged = {(int(row.get("trial") or 1), row["target"]): row for row in rows}
    targets = sorted({row["target"] for row in rows})
    projectable: set[tuple[str, str]] = set()
    for baseline in BASELINES:
        for target in targets:
            keys = [(trial, target) for trial in range(1, 6)]
            if all((common.get(key) or {}).get("common_source_status") == "projected"
                   and (merged.get(key) or {}).get(f"{baseline}_status") == "evaluated"
                   for key in keys):
                projectable.add((baseline, target))
    rewritten: list[dict[str, str]] = []
    for row in rows:
        record = dict(row)
        key = (int(row.get("trial") or 1), row["target"])
        source = common.get(key) or {}
        fallback = any((baseline, row["target"]) not in projectable
                       and row.get(f"{baseline}_status") == "evaluated"
                       for baseline in BASELINES)
        for baseline in BASELINES:
            if (baseline, row["target"]) not in projectable:
                if row.get(f"{baseline}_status") != "evaluated":
                    continue
                audit_row = audit.get((key[0], row["target"], baseline))
                if not audit_row or not audit_row.get("report_path"):
                    continue
                covered, total = _da_counts(str(audit_row["report_path"]),
                                            row["target"].split("_", 1)[0], cache)
                if total:
                    record[f"{baseline}_sut_covered_lines"] = str(covered)
                    record[f"{baseline}_sut_total_lines"] = str(total)
                continue
            covered = source.get(f"{baseline}_covered_lines", "")
            total = source.get("common_source_lines", "")
            if str(covered).isdigit() and str(total).isdigit() and int(total) > 0:
                record[f"{baseline}_sut_covered_lines"] = covered
                record[f"{baseline}_sut_total_lines"] = total
                record[f"{baseline}_coverage_contract"] = "common-target-lcov-v1"
        record["_fallback"] = "1" if fallback else ""
        rewritten.append(record)
    return rewritten


def collect(targets: list[str], rows: list[dict[str, str]]) -> dict[tuple[str, str], dict]:
    merged = {(int(row.get("trial") or 1), row["target"]): row for row in rows}
    stats: dict[tuple[str, str], dict] = {}
    for baseline in BASELINES:
        for target in targets:
            values, statuses, files = [], [], set()
            for trial in range(1, 6):
                row = merged.get((trial, target), {})
                statuses.append(row.get(f"{baseline}_status") or "missing")
                result = measured(row, baseline)
                if result is not None:
                    values.append(result)
                    files.add(row.get(f"{baseline}_sut_source_files") or "")
            fallback = any(merged.get((trial, target), {}).get("_fallback") == "1"
                           and merged.get((trial, target), {}).get(f"{baseline}_status") == "evaluated"
                           for trial in range(1, 6))
            stats[baseline, target] = {**summarize(values), "statuses": statuses,
                                       "source_files": sorted(f for f in files if f),
                                       "fallback": fallback}
    return stats


def table_lines(targets: list[str], stats: dict[tuple[str, str], dict]) -> list[str]:
    lines = ["| Fuzzer / artifact | " + " | ".join(f"`{t}`" for t in targets) + " |",
             "| :--- | " + " | ".join("---:" for _ in targets) + " |"]
    for baseline in BASELINES:
        cells = []
        for target in targets:
            info = stats[baseline, target]
            if all(status == "N/A" for status in info["statuses"]):
                cells.append("N/A")
            elif info["n"] == 0:
                cells.append("Failed")
            elif info["stdev"] is None:
                cells.append(f"{info['mean']:,.0f} (n=1)"
                             + (" †" if info.get("fallback") else ""))
            else:
                text = (f"{info['mean']:,.0f} ± {info['stdev']:,.0f} "
                        f"({info['percent']:.2f}%)")
                if info["n"] != 5:
                    text += f" n={info['n']}"
                if info.get("fallback"):
                    text += " †"
                cells.append(text)
        lines.append(f"| {PRETTY[baseline]} | " + " | ".join(cells) + " |")
    return lines


def completion_rows(targets: list[str], stats: dict[tuple[str, str], dict]) -> list[str]:
    lines = ["| Fuzzer / artifact | Applicable targets | 5/5 trials | 1–4 trials | 0 trials | N/A |",
             "| :--- | ---: | ---: | ---: | ---: | ---: |"]
    for baseline in BASELINES:
        cells = [stats[baseline, target] for target in targets]
        na = sum(all(status == "N/A" for status in info["statuses"]) for info in cells)
        five = sum(info["n"] == 5 for info in cells)
        partial = sum(0 < info["n"] < 5 for info in cells)
        zero = sum(info["n"] == 0 and any(status != "N/A" for status in info["statuses"])
                   for info in cells)
        lines.append(f"| {PRETTY[baseline]} | {len(cells) - na} | {five} | {partial} | "
                     f"{zero} | {na} |")
    return lines


def incomplete_lines(targets: list[str], stats: dict[tuple[str, str], dict]) -> list[str]:
    lines = ["| Fuzzer / artifact | Target | Evaluated trials | Statuses |",
             "| :--- | :--- | ---: | :--- |"]
    rows = 0
    for baseline in BASELINES:
        for target in targets:
            info = stats[baseline, target]
            if all(status == "N/A" for status in info["statuses"]) or info["n"] == 5:
                continue
            rows += 1
            lines.append(f"| {PRETTY[baseline]} | `{target}` | {info['n']}/5 | "
                         f"{'; '.join(info['statuses'])} |")
    return lines if rows else []


def source_note(common: dict[str, dict[str, str]], targets: list[str],
                instrumented: dict[str, list[int]]) -> list[str]:
    lines = ["| Target | Instrumented target lines (baseline builds) | Common-source lines | Retention |",
             "| :--- | :--- | ---: | ---: |"]
    for target in targets:
        record = common.get(target, {})
        counts = sorted(set(instrumented.get(target) or []))
        shown = (f"{min(counts):,}-{max(counts):,}" if len(counts) > 1
                 else f"{max(counts):,}" if counts else "—")
        if record.get("common_source_status") != "projected":
            lines.append(f"| `{target}` | {shown} | — | — |")
            continue
        lines.append(f"| `{target}` | {shown} | {int(record['common_source_lines']):,} | "
                     f"{float(record['common_source_retention_min']):.2f} |")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", action="append", default=None,
                        help=f"Batch id, newest first (default: {', '.join(DEFAULT_BATCHES)})")
    parser.add_argument("--work", type=Path, default=ROOT / "workspace/eval_all",
                        help="Directory for merged/audit CSVs and statistics JSON")
    parser.add_argument("--report", type=Path,
                        default=ROOT / "results/hgb_baselines_5times.md")
    parser.add_argument("--from-corrected", type=Path,
                        help="Use an existing corrected CSV instead of merging and auditing")
    parser.add_argument("--skip-audit", action="store_true",
                        help="Build the table from the merged CSV without re-auditing LCOV")
    parser.add_argument("--metric", choices=("sut", "common"), default="common",
                        help="Coverage metric: canonical target-source lines (sut) or the "
                             "common-source projection across applicable baselines (common)")
    parser.add_argument("--print-only", action="store_true")
    args = parser.parse_args()
    work: Path = args.work
    work.mkdir(parents=True, exist_ok=True)

    if args.from_corrected:
        data_csv = args.from_corrected
        common_csv = work / "hgb_baselines_5times.common.csv"
    else:
        batches = args.batch or list(DEFAULT_BATCHES)
        targets, merged, _ = merge(batches)
        merged_csv = work / "hgb_baselines_5times.merged.csv"
        write_merged(merged_csv, targets, merged)
        if args.skip_audit:
            data_csv, common_csv = merged_csv, None
        else:
            paths = run_audit(merged_csv, work)
            data_csv, common_csv = paths["corrected"], paths["common"]

    rows = read_rows(data_csv)
    order = target_order()
    data_targets = {row["target"] for row in rows}
    targets = [name for name in order if name in data_targets]
    targets += sorted(data_targets.difference(targets))
    common_rows = read_rows(common_csv) if common_csv and common_csv.is_file() else []
    audit_rows = (read_rows(work / "hgb_baselines_5times.coverage_audit.csv")
                  if (work / "hgb_baselines_5times.coverage_audit.csv").is_file() else [])
    rows = apply_metric(rows, common_rows, args.metric, audit_rows)
    stats = collect(targets, rows)
    common = {row["target"]: row for row in common_rows}
    table = table_lines(targets, stats)
    print("\n".join(table))
    print(f"\ndata: {data_csv}", file=sys.stderr)

    stats_json = work / "hgb_baselines_5times.stats.json"
    stats_json.write_text(json.dumps(
        {f"{b}|{t}": {k: v for k, v in stats[b, t].items() if k != "statuses"}
         | {"statuses": stats[b, t]["statuses"]}
         for b in BASELINES for t in targets}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    incomplete = incomplete_lines(targets, stats)
    if incomplete:
        print("\n".join(incomplete[2:]), file=sys.stderr)

    if args.print_only:
        return 0
    report = [
        "# Baseline coverage on the 20 FuzzBench valuable targets (five 24-hour campaigns)",
        "",
        "Report date: 2026-11-11. Campaigns ran on the shared FuzzBench target package with the "
        "canonical `canonical-g2-lcov-v1` coverage contract: every saved Phase B corpus is replayed "
        "against a coverage-instrumented FuzzBench build of the same target. The generated harness "
        "is compiled into the target tree, so the instrumented line set varies by baseline; cells "
        "count only the source set instrumented for every applicable baseline.",
        "",
        f"Each cell is **mean ± sample standard deviation over five independent 86,400-second "
        f"campaigns** of {metric_label(args.metric)}; the percentage in parentheses is the mean "
        f"against the same denominator. `N/A` means the target is outside "
        "ELFuzz's text-input scope; `Failed` means no coverage result survived the five trials; "
        "`n=k` marks a cell with fewer than five valid trials."
        + (" A dagger (†) marks a cell that could not yet be projected onto the common source set "
           "because at least one applicable baseline has no evaluated trial for that target; such a "
           "cell uses the canonical target-source denominator instead."
           if any(info.get("fallback") for info in stats.values()) else ""),
        "",
        "## Coverage table",
        "",
        *table,
        "",
        "## Completion",
        "",
        *completion_rows(targets, stats),
        "",
    ]
    if incomplete:
        report += ["## Incomplete cells", "", *incomplete, ""]
    instrumented: dict[str, list[int]] = {}
    audit_csv = work / "hgb_baselines_5times.coverage_audit.csv"
    if audit_csv.is_file():
        for record in read_rows(audit_csv):
            if record.get("trial") == "1" and record.get("integrity") == "sut_covered":
                value = str(record.get("instrumented_source_lines") or "")
                if value.isdigit():
                    instrumented.setdefault(record["target"], []).append(int(value))
    if common:
        report += ["## Denominators", "",
                   "The instrumented line set differs between baseline builds for several targets, "
                   "because each baseline's generated harness is compiled into the target tree. "
                   "The coverage table therefore counts only the file:line IDs instrumented for "
                   "every applicable baseline (common-source projection); retention is the smallest "
                   "share of a baseline's instrumented target lines kept by that intersection.", "",
                   *source_note(common, targets, instrumented), ""]
    report += [
        "## Sources and method",
        "",
        "| Batch | Baseline(s) | Phase B CSV |",
        "| :--- | :--- | :--- |",
        "| 2026-11-08 | OSS-Fuzz-Gen, CKGFuzzer, PromeFuzz | "
        "[`workspace/eval_all/20261108-0739/results.csv`](../workspace/eval_all/20261108-0739/results.csv) |",
        "| 2026-11-06 | G2Fuzz, ELFuzz | "
        "[`workspace/eval_all/20261106-2123/results.csv`](../workspace/eval_all/20261106-2123/results.csv) |",
        "",
        "Coverage was measured from the saved corpora with "
        "`python scripts/hgb_eval_all.py --phase measure --batch-id <id>`, then verified from the "
        "saved LCOV reports with `scripts/hgb_audit_coverage_integrity.py` on the merged CSV. "
        "Standard deviations are sample standard deviations (ddof=1); percentages divide the mean "
        "covered-line count by the target's instrumented target-line total.",
        "",
        "## Scope and retries",
        "",
        "* ELFuzz covers 9 of the 20 targets (text-input scope in "
        "`metadata/elfuzz_target_adapters.yaml`); the other 11 cells are `N/A` by design, not failures.",
        "* The 2026-11-06 G2Fuzz campaigns for `systemd_fuzz-link-parser` and "
        "`mruby_mruby_fuzzer_8c8bbd` failed for infrastructure reasons: the five systemd runners "
        "aborted at startup with ENOSPC (no space left on device), and three mruby runners lost "
        "their first AFL attempt to SIGKILL and then could not reacquire the stale AFL output "
        "directory (`Directory ... is in use`) for 13 retries. A 2026-11-11 retry of both targets "
        "was started and then stopped before its 24-hour campaigns completed, so those two cells "
        "report the trials that produced coverage (mruby 2/5, systemd 0/5) and are marked "
        "accordingly.",
        "* The audit re-parsed every saved LCOV report and compared the instrumented source sets. "
        "For nine targets the per-baseline sets differ (for example curl: 36,975 lines for the "
        "harness generators vs 44,474 for G2Fuzz/ELFuzz), because the generated harness is compiled "
        "into the target tree. The reported numbers are restricted to the common set, so a "
        "covered-line difference reflects target-code coverage rather than a larger denominator.",
        "",
        "## Reproduce",
        "",
        "```bash",
        "# measure the saved corpora (one coordinator per batch)",
        "python scripts/hgb_eval_all.py --phase measure --batch-id 20261108-0739 --measurer-worker 40",
        "python scripts/hgb_eval_all.py --phase measure --batch-id 20261106-2123 --measurer-worker 28",
        "python scripts/hgb_eval_all.py --phase measure --batch-id 20261111-1108 --measurer-worker 10",
        "",
        "# merge batches, audit the LCOV reports, and rebuild this report",
        "python scripts/hgb_baselines_5times.py --report results/hgb_baselines_5times.md",
        "# sensitivity check on the per-baseline canonical target-source denominator",
        "python scripts/hgb_baselines_5times.py --metric sut --report /tmp/hgb_sut.md",
        "```",
        "",
    ]
    args.report.write_text("\n".join(report), encoding="utf-8")
    print(f"report: {args.report}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
