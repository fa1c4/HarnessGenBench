#!/usr/bin/env python3
"""Collect HarnessGenBench generator-target matrix metadata."""

from __future__ import annotations

import argparse
import collections
import csv
import json
from pathlib import Path
from typing import Any


SOFT_STATUSES = {
    "not_harness_generator",
    "needs_ofg_benchmark_yaml",
    "no_api_candidates",
    "missing_codeql",
    "upstream_cli_not_found",
    "needs_compile_commands",
    "target_not_supported_by_elfuzz",
    "source_input_missing",
    "soft_skip",
    "soft_skip_target_binaries_missing",
}


def read_rows(matrix_dir: Path) -> list[dict[str, str]]:
    matrix_file = matrix_dir / "matrix.tsv"
    if not matrix_file.exists():
        return []
    with matrix_file.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def load_metadata(path: str) -> dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def collect(matrix_dir: Path) -> dict[str, Any]:
    rows = read_rows(matrix_dir)
    records: list[dict[str, Any]] = []
    for row in rows:
        metadata = load_metadata(row.get("metadata", ""))
        records.append({"row": row, "metadata": metadata})
    total = len(records)
    statuses = collections.Counter((r["metadata"].get("status") or r["row"].get("status") or "missing_metadata") for r in records)
    completed = sum(statuses[s] for s in ("completed", "dry_run_ok"))
    soft_skipped = sum(count for status, count in statuses.items() if status in SOFT_STATUSES)
    missing_api_key = statuses.get("missing_api_key", 0)
    failed = total - completed - soft_skipped - missing_api_key
    harness_counts: collections.Counter[str] = collections.Counter()
    input_counts: collections.Counter[str] = collections.Counter()
    reasons: collections.Counter[str] = collections.Counter()
    for record in records:
        meta = record["metadata"]
        gen = meta.get("generator") or meta.get("fuzzer") or record["row"].get("generator") or "unknown"
        harness_counts[gen] += int(meta.get("generated_harness_count") or meta.get("generated_driver_count") or 0)
        input_counts[gen] += int(meta.get("generated_input_count") or meta.get("generated_seed_count") or 0)
        reason = meta.get("reason") or record["row"].get("status") or "unknown"
        if reason and reason != "none":
            reasons[str(reason)] += 1
    return {
        "matrix_dir": str(matrix_dir),
        "total_pairs": total,
        "completed_pairs": completed,
        "failed_pairs": failed,
        "soft_skipped_pairs": soft_skipped,
        "missing_api_key_count": missing_api_key,
        "statuses": dict(statuses),
        "generated_harness_counts_by_generator": dict(harness_counts),
        "generated_input_counts_by_generator": dict(input_counts),
        "top_failure_reasons": reasons.most_common(10),
    }


def write_outputs(matrix_dir: Path, summary: dict[str, Any]) -> None:
    (matrix_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (matrix_dir / "summary.tsv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(["metric", "value"])
        for key in ("total_pairs", "completed_pairs", "failed_pairs", "soft_skipped_pairs", "missing_api_key_count"):
            writer.writerow([key, summary[key]])
    lines = [
        "# HarnessGenBench Matrix Summary",
        "",
        f"- Total pairs: `{summary['total_pairs']}`",
        f"- Completed pairs: `{summary['completed_pairs']}`",
        f"- Failed pairs: `{summary['failed_pairs']}`",
        f"- Soft-skipped pairs: `{summary['soft_skipped_pairs']}`",
        f"- Missing API key count: `{summary['missing_api_key_count']}`",
        "",
        "## Statuses",
        "",
    ]
    for status, count in sorted(summary["statuses"].items()):
        lines.append(f"- `{status}`: {count}")
    if summary["top_failure_reasons"]:
        lines.extend(["", "## Top Reasons", ""])
        for reason, count in summary["top_failure_reasons"]:
            lines.append(f"- {count} x {reason}")
    (matrix_dir / "HGB_MATRIX_SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("matrix_dir")
    args = parser.parse_args()
    matrix_dir = Path(args.matrix_dir).resolve()
    matrix_dir.mkdir(parents=True, exist_ok=True)
    write_outputs(matrix_dir, collect(matrix_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
