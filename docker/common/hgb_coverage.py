#!/usr/bin/env python3
"""Parse LLVM source-based coverage reports and lcov traces.

The evaluator must never label libFuzzer unit counts or AFL paths as
line/edge coverage.  This module parses real LLVM ``llvm-cov export`` JSON
and lcov tracefiles, and produces the concise summary required by the beta
reproduction contract.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


class CoverageError(RuntimeError):
    """Raised when a coverage report is missing, unparseable, or fake."""


def parse_llvm_coverage_json(text: str) -> dict[str, Any]:
    """Parse LLVM source-based coverage JSON (``llvm-cov export -format=json``).

    Returns a normalized dict with ``line_coverage``, ``function_coverage``,
    ``region_coverage`` and ``edge_coverage`` (null for LLVM source-based
    reports, which do not report edges).
    """

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CoverageError(f"llvm coverage JSON is unparseable: {exc}") from exc
    if not isinstance(data, dict) or "data" not in data:
        raise CoverageError("llvm coverage JSON has no 'data' key")
    totals = {"lines": {"count": 0, "covered": 0}, "functions": {"count": 0, "covered": 0}, "regions": {"count": 0, "covered": 0}}
    for entry in data.get("data", []):
        entry_totals = entry.get("totals", {}) if isinstance(entry, dict) else {}
        for key in totals:
            sect = entry_totals.get(key, {})
            if not isinstance(sect, dict):
                continue
            totals[key]["count"] += int(sect.get("count", 0) or 0)
            totals[key]["covered"] += int(sect.get("covered", 0) or 0)
    lines = totals["lines"]
    funcs = totals["functions"]
    regions = totals["regions"]
    line_percent = round(100.0 * lines["covered"] / lines["count"], 2) if lines["count"] else 0.0
    func_percent = round(100.0 * funcs["covered"] / funcs["count"], 2) if funcs["count"] else 0.0
    region_percent = round(100.0 * regions["covered"] / regions["count"], 2) if regions["count"] else 0.0
    return {
        "line_coverage": {"covered": lines["covered"], "total": lines["count"], "percent": line_percent},
        "function_coverage": {"covered": funcs["covered"], "total": funcs["count"], "percent": func_percent},
        "regions": {"covered": regions["covered"], "total": regions["count"], "percent": region_percent},
        "edge_coverage": None,
        "source": "llvm_source_based",
    }


_LCOV_LINE = re.compile(r"^LF:(\d+)$")
_LCOV_COVERED = re.compile(r"^LH:(\d+)$")
_LCOV_FNF = re.compile(r"^FNF:(\d+)$")
_LCOV_FNH = re.compile(r"^FNH:(\d+)$")


def parse_lcov(text: str) -> dict[str, Any]:
    """Parse an lcov tracefile and return a normalized coverage summary."""

    lines_total = 0
    lines_covered = 0
    funcs_total = 0
    funcs_covered = 0
    for raw in text.splitlines():
        m = _LCOV_LINE.match(raw)
        if m:
            lines_total += int(m.group(1))
            continue
        m = _LCOV_COVERED.match(raw)
        if m:
            lines_covered += int(m.group(1))
            continue
        m = _LCOV_FNF.match(raw)
        if m:
            funcs_total += int(m.group(1))
            continue
        m = _LCOV_FNH.match(raw)
        if m:
            funcs_covered += int(m.group(1))
    line_percent = round(100.0 * lines_covered / lines_total, 2) if lines_total else 0.0
    func_percent = round(100.0 * funcs_covered / funcs_total, 2) if funcs_total else 0.0
    return {
        "line_coverage": {"covered": lines_covered, "total": lines_total, "percent": line_percent},
        "function_coverage": {"covered": funcs_covered, "total": funcs_total, "percent": func_percent},
        "regions": {"covered": 0, "total": 0, "percent": 0.0},
        "edge_coverage": None,
        "source": "lcov",
    }


def summarize_coverage_report(report_path: str | Path) -> dict[str, Any]:
    """Read a coverage report file (llvm JSON or lcov) and summarize it.

    Raises :class:`CoverageError` if the report is missing, empty, or does not
    look like a real coverage report.  A real report must have at least one
    total line; an empty/zero-total report is treated as fake coverage.
    """

    path = Path(report_path)
    if not path.is_file():
        raise CoverageError(f"coverage report not found: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        raise CoverageError("coverage report is empty")
    if path.suffix.lower() == ".json" or text.lstrip().startswith("{"):
        summary = parse_llvm_coverage_json(text)
    else:
        summary = parse_lcov(text)
    if summary["line_coverage"]["total"] == 0:
        raise CoverageError("coverage report has zero total lines; not a real coverage report")
    return summary


def write_coverage_outputs(work_dir: str | Path, summary: dict[str, Any], raw_text: str = "") -> dict[str, str]:
    """Write coverage.json and a concise lcov-ish summary under work_dir."""
    work = Path(work_dir)
    work.mkdir(parents=True, exist_ok=True)
    json_path = work / "coverage.json"
    json_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lcov_path = work / "coverage.lcov"
    if raw_text:
        lcov_path.write_text(raw_text, encoding="utf-8")
    else:
        lines = summary.get("line_coverage", {})
        funcs = summary.get("function_coverage", {})
        lcov_path.write_text(
            f"TN:hgb\nLF:{lines.get('total', 0)}\nLH:{lines.get('covered', 0)}\n"
            f"FNF:{funcs.get('total', 0)}\nFNH:{funcs.get('covered', 0)}\nend_of_record\n",
            encoding="utf-8",
        )
    return {"coverage_json": str(json_path), "coverage_lcov": str(lcov_path)}


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Summarize a coverage report")
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--work-dir", default="", type=Path)
    args = parser.parse_args()
    summary = summarize_coverage_report(args.report)
    print(json.dumps(summary, indent=2, sort_keys=True))
    if args.work_dir:
        write_coverage_outputs(args.work_dir, summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
