#!/usr/bin/env python3
"""Audit Phase B target coverage and project the shared source-line set.

The audit preserves the original CSV, checks its saved LCOV reports, and writes
target-only counts plus a comparison on line IDs common to applicable baselines.
"""

from __future__ import annotations

import argparse
import csv
import gc
import hashlib
import json
from collections import defaultdict
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker/common"))
import hgb_coverage  # noqa: E402

BASELINES = ("ckgfuzzer", "promefuzz", "oss-fuzz-gen", "g2fuzz", "elfuzz")
HARNESS_BASELINES = BASELINES[:3]
FIELDS = ("trial", "target", "baseline", "status", "raw_covered_lines", "raw_total_lines",
          "sut_covered_lines", "sut_total_lines", "sut_source_files",
          "non_sut_covered_lines", "integrity", "report_path",
          "source_set_sha256", "instrumented_source_lines")


def write_source_set_csv(audit: Path, destination: Path) -> None:
    """Show target-source denominator differences without relabeling runs."""
    with audit.open(newline="", encoding="utf-8") as handle:
        records = list(csv.DictReader(handle))
    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for record in records:
        grouped[(record.get("trial", ""), record["target"])].append(record)
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=(
            "trial", "target", "min_sut_total_lines", "max_sut_total_lines",
            "max_to_min_ratio", "mismatch_over_20_percent", "totals_by_baseline",
            "source_set_status", "source_set_hashes_by_baseline"))
        writer.writeheader()
        for (trial, target), rows in grouped.items():
            totals = {row["baseline"]: int(row["sut_total_lines"])
                      for row in rows if row["integrity"] == "sut_covered"}
            smallest = min(totals.values()) if totals else 0
            largest = max(totals.values()) if totals else 0
            ratio = largest / smallest if smallest else 0
            applicable = [row for row in rows if row.get("status", "evaluated") != "N/A"]
            hashes = {row["baseline"]: row.get("source_set_sha256", "")
                      for row in rows if row["integrity"] == "sut_covered"}
            source_set_status = (
                "incomplete" if any(row.get("status", "evaluated") != "evaluated" or row["integrity"] != "sut_covered"
                                    for row in applicable) else
                "unverified" if not hashes or any(not value for value in hashes.values()) else
                "matching" if len(set(hashes.values())) == 1 else "mismatch")
            writer.writerow({
                "trial": trial, "target": target,
                "min_sut_total_lines": smallest, "max_sut_total_lines": largest,
                "max_to_min_ratio": round(ratio, 4),
                "mismatch_over_20_percent": ratio > 1.2,
                "totals_by_baseline": ";".join(f"{name}:{total}" for name, total in totals.items()),
                "source_set_status": source_set_status,
                "source_set_hashes_by_baseline": ";".join(
                    f"{name}:{value}" for name, value in hashes.items()),
            })


def write_corrected_trial_summary(corrected: Path, destination: Path) -> bool:
    """Recompute the five-trial summary from corrected target-source lines."""
    with corrected.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if "trial" not in (reader.fieldnames or []):
            return False
        records = list(reader)
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for record in records:
        grouped[record["target"]].append(record)
    fields = ("baseline", "target", "status", "evaluated_trials", "total_trials",
              "mean_covered_lines", "stdev_covered_lines", "trial_statuses")
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for target, target_records in grouped.items():
            target_records.sort(key=lambda row: int(row["trial"]))
            for baseline in BASELINES:
                statuses = [row[f"{baseline}_status"] for row in target_records]
                covered = [int(row[f"{baseline}_covered_lines"]) for row in target_records
                           if row[f"{baseline}_status"] == "evaluated"
                           and row.get(f"{baseline}_covered_lines", "").isdigit()]
                status = ("N/A" if all(value == "N/A" for value in statuses) else
                          "evaluated" if all(value == "evaluated" for value in statuses) else
                          "partial" if covered else "failed")
                writer.writerow({
                    "baseline": baseline, "target": target, "status": status,
                    "evaluated_trials": len(covered), "total_trials": len(target_records),
                    "mean_covered_lines": round(statistics.mean(covered), 3) if covered else "",
                    "stdev_covered_lines": round(statistics.stdev(covered), 3) if len(covered) > 1 else "",
                    "trial_statuses": ";".join(statuses),
                })
    return True


def write_corrected_csv(source: Path, audit: Path, destination: Path) -> None:
    """Retain the historical CSV and write project-only counts separately."""
    with source.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        original_fields = list(reader.fieldnames or [])
        rows = list(reader)
    with audit.open(newline="", encoding="utf-8") as handle:
        audited = {(r.get("trial", ""), r["target"], r["baseline"]): r
                   for r in csv.DictReader(handle)}
    added = [f"{b}_{name}" for b in BASELINES
             for name in ("raw_covered_lines", "sut_covered_lines", "sut_total_lines", "sut_source_files")]
    fields = original_fields + [name for name in added if name not in original_fields]
    for row in rows:
        for baseline in BASELINES:
            record = audited[row.get("trial", ""), row["target"], baseline]
            if record["status"] != "evaluated":
                continue
            row[f"{baseline}_raw_covered_lines"] = record["raw_covered_lines"]
            row[f"{baseline}_sut_covered_lines"] = record["sut_covered_lines"]
            row[f"{baseline}_sut_total_lines"] = record["sut_total_lines"]
            row[f"{baseline}_sut_source_files"] = record["sut_source_files"]
            row[f"{baseline}_covered_lines"] = record["sut_covered_lines"]
            if record["integrity"] != "sut_covered":
                row[f"{baseline}_status"] = "quality_failure"
                row[f"{baseline}_reason"] = record["integrity"]
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_common_source_csv(source: Path, audit: Path, destination: Path) -> list[tuple[str, str]]:
    """Count each corpus only on target file:line IDs instrumented for every applicable baseline."""
    with source.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = list(reader.fieldnames or [])
        rows = list(reader)
    with audit.open(newline="", encoding="utf-8") as handle:
        reports = {(r.get("trial", ""), r["target"], r["baseline"]): r
                   for r in csv.DictReader(handle)}
    fields += ["common_source_status", "common_source_lines", "common_source_files",
               "common_source_sha256", "common_source_retention_min"]
    failed: list[tuple[str, str]] = []
    for row in rows:
        target = row["target"]
        trial = row.get("trial", "")
        applicable = [b for b in BASELINES if row[f"{b}_status"] != "N/A"]
        if not applicable or any(row[f"{b}_status"] != "evaluated" or
                                 reports[trial, target, b]["integrity"] != "sut_covered"
                                 for b in applicable):
            row["common_source_status"] = "incomplete"
            failed.append((trial, target))
            for baseline in applicable:
                row[f"{baseline}_covered_lines"] = ""
            continue
        try:
            project = target.split("_", 1)[0]
            line_maps = {b: hgb_coverage.lcov_project_lines(
                Path(reports[trial, target, b]["report_path"]), project) for b in applicable}
            common = set.intersection(*(set(lines) for lines in line_maps.values()))
            if not common:
                raise hgb_coverage.CoverageError("no common instrumented target lines")
            digest = hashlib.sha256()
            for filename, number in sorted(common):
                digest.update(f"{filename}:{number}\n".encode("utf-8"))
            row.update(common_source_status="projected", common_source_lines=len(common),
                       common_source_files=len({filename for filename, _ in common}),
                       common_source_sha256=digest.hexdigest(),
                       common_source_retention_min=round(
                           min(len(common) / len(lines) for lines in line_maps.values()), 4))
            for baseline in applicable:
                row[f"{baseline}_covered_lines"] = sum(line_maps[baseline][key] > 0 for key in common)
                row[f"{baseline}_coverage_contract"] = "common-target-lcov-v1"
        except (OSError, ValueError, hgb_coverage.CoverageError) as exc:
            row["common_source_status"] = f"unverified: {exc}"
            failed.append((trial, target))
            for baseline in applicable:
                row[f"{baseline}_covered_lines"] = ""
        gc.collect()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return failed


def saved_report(run: Path, baseline: str, coverage: dict) -> Path:
    raw = str(coverage.get("coverage_report_path") or coverage.get("report_path") or "")
    path = Path(raw) if raw else Path()
    if raw.startswith("/workspace/"):
        path = run / raw.removeprefix("/workspace/")
    elif not raw or not path.is_file():
        path = run / "coverage/coverage.lcov" if baseline == "g2fuzz" else path
    return path


def audit_row(target: str, baseline: str, status: str, run: Path,
              trial: str = "") -> dict[str, object]:
    row: dict[str, object] = {key: "" for key in FIELDS}
    row.update(trial=trial, target=target, baseline=baseline, status=status)
    if status != "evaluated":
        row["integrity"] = "not_evaluated" if status != "N/A" else "N/A"
        return row
    result_path = run / ("evaluation/result.json" if baseline in HARNESS_BASELINES else "result.json")
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
        coverage = result.get("coverage") or (result.get("metrics") or {}).get("coverage") or {}
        report = saved_report(run, baseline, coverage)
        row["report_path"] = str(report)
        project = target.split("_", 1)[0]
        # Parse one report at a time. Some LLVM exports exceed 300 MiB.
        summary = hgb_coverage.summarize_coverage_report(
            report, project=project, require_project_coverage=False)
        raw = summary["line_coverage"]
        sut = summary["sut_line_coverage"]
        row.update(raw_covered_lines=raw["covered"], raw_total_lines=raw["total"],
                   sut_covered_lines=sut["covered"], sut_total_lines=sut["total"],
                   sut_source_files=sut["source_files"],
                   non_sut_covered_lines=raw["covered"] - sut["covered"],
                   integrity="sut_covered" if sut["covered"] else "no_sut_coverage")
        if report.suffix.lower() == ".lcov":
            source_set = hgb_coverage.lcov_project_source_set(report, project)
            row.update(source_set_sha256=source_set["source_set_sha256"],
                       instrumented_source_lines=source_set["instrumented_source_lines"])
    except (OSError, ValueError, KeyError, TypeError, hgb_coverage.CoverageError) as exc:
        row["integrity"] = str(exc)
    finally:
        gc.collect()
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "workspace/eval_all/2026-10-16.csv")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--corrected-output", type=Path)
    parser.add_argument("--source-sets-output", type=Path)
    parser.add_argument("--common-source-output", type=Path)
    parser.add_argument("--require-matching-source-sets", action="store_true",
                        help="Exit nonzero unless every target/trial has evaluated baselines and identical full LCOV source sets")
    parser.add_argument("--require-common-source", action="store_true",
                        help="Exit nonzero unless every target/trial has an evaluated common target-source projection")
    args = parser.parse_args()
    source = args.input.resolve(strict=True)
    output = (args.output or source.with_name(source.stem + ".coverage_audit.csv")).resolve()
    corrected = (args.corrected_output or source.with_name(source.stem + ".coverage_corrected.csv")).resolve()
    source_sets = (args.source_sets_output or source.with_name(source.stem + ".coverage_source_sets.csv")).resolve()
    common_source = (args.common_source_output or source.with_name(source.stem + ".coverage_common.csv")).resolve()
    if not all(path.is_relative_to(ROOT / "workspace") for path in (output, corrected, source_sets, common_source)):
        parser.error("audit outputs must be under workspace/")
    with source.open(newline="", encoding="utf-8") as handle:
        records = list(csv.DictReader(handle))
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for record in records:
            target = record["target"]
            for baseline in BASELINES:
                status = record[f"{baseline}_status"]
                run_name = record.get(f"{baseline}_run") or ""
                run = ROOT / run_name if run_name and run_name != "N/A" else ROOT / "workspace"
                row = audit_row(target, baseline, status, run, record.get("trial", ""))
                writer.writerow(row)
                handle.flush()
                print(f"{baseline} {target}: {row['integrity']}", flush=True)
    print(output)
    write_corrected_csv(source, output, corrected)
    print(corrected)
    write_source_set_csv(output, source_sets)
    print(source_sets)
    common_failures = write_common_source_csv(source, output, common_source)
    print(common_source)
    trial_summary = corrected.with_name(corrected.stem + ".summary.csv")
    if write_corrected_trial_summary(corrected, trial_summary):
        print(trial_summary)
    if args.require_matching_source_sets:
        with source_sets.open(newline="", encoding="utf-8") as handle:
            bad = [row for row in csv.DictReader(handle) if row["source_set_status"] != "matching"]
        if bad:
            print(f"source-set validation failed for {len(bad)} target/trial rows; see {source_sets}",
                  file=sys.stderr)
            return 1
    if args.require_common_source and common_failures:
        print(f"common-source validation failed for {len(common_failures)} target/trial rows; see {common_source}",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
