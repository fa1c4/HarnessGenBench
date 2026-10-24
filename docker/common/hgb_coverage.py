#!/usr/bin/env python3
"""Parse LLVM source-based coverage reports and lcov traces.

The evaluator must never label libFuzzer unit counts or AFL paths as
line/edge coverage.  This module parses real LLVM ``llvm-cov export`` JSON
and lcov tracefiles, and produces the concise summary required by the beta
reproduction contract.
"""

from __future__ import annotations

import json
import hashlib
import posixpath
import re
from pathlib import Path
from typing import Any


class CoverageError(RuntimeError):
    """Raised when a coverage report is missing, unparseable, or fake."""


_PROJECT_SOURCE_ROOTS = {
    "bloaty": "/src/bloaty/src/",  # Exclude bundled protobuf and re2.
    "curl": "/src/curl/lib/",
    "freetype2": "/src/freetype2/src/",
    "harfbuzz": "/src/harfbuzz/src/",
    "jsoncpp": "/src/jsoncpp/src/",
    "lcms": "/src/Little-CMS/",
    "libjpeg-turbo": "/src/libjpeg-turbo.main/",
    # FuzzBench's libxslt_xpath target exercises libxml2's XPath engine.
    # The libxslt tests/fuzz/xpath.c file is only its driver.
    "libxslt": ("/src/libxml2/", "/src/libxslt/libxslt/", "/src/libxslt/libexslt/"),
    "mbedtls": "/src/mbedtls/library/",
    "openh264": "/src/openh264/codec/",
    "php": "/src/php-src/",
    "sqlite3": "/src/sqlite3/bld/sqlite3.c",
}

# These are the projects in metadata/fuzzbench_targets.json's valuable set.
VALUABLE_PROJECTS = frozenset({
    "bloaty", "curl", "freetype2", "harfbuzz", "jsoncpp", "lcms",
    "libjpeg-turbo", "libpcap", "libpng", "libxml2", "libxslt",
    "mbedtls", "mruby", "openh264", "openssl", "php", "re2",
    "sqlite3", "systemd", "zlib",
})


def _source_path(filename: str) -> str:
    """Map the G2Fuzz coverage copy and compiler ../ paths to /src paths."""
    filename = filename.replace("/workspace/target/src_cov/", "/src/", 1)
    return posixpath.normpath(filename)


def _project_source(filename: str, project: str) -> bool:
    roots = _PROJECT_SOURCE_ROOTS.get(project, f"/src/{project}/")
    if isinstance(roots, str):
        roots = (roots,)
    path = _source_path(filename)
    if not any(path.startswith(root) for root in roots):
        return False
    # Generated drivers under the project tree are not library coverage.
    if project == "freetype2" and path.startswith("/src/freetype2/src/tools/ftfuzzer/"):
        return False
    if project == "jsoncpp" and path.startswith("/src/jsoncpp/src/test_lib_json/"):
        return False
    if project == "libjpeg-turbo" and "/fuzz/" in path:
        return False
    if project == "libxml2" and "/fuzz/" in path:
        return False
    if project == "openssl" and "/fuzz/" in path:
        return False
    if project == "libpcap" and "/testprogs/" in path:
        return False
    if project == "libpng" and "/contrib/oss-fuzz/" in path:
        return False
    if project == "php" and "/sapi/fuzzer/" in path:
        return False
    if project == "systemd" and ("/src/fuzz/" in path or
                                 path == "/src/systemd/src/udev/net/fuzz-link-parser.c"):
        return False
    return True


def _sut_summary(covered: int, total: int, files: int) -> dict[str, Any]:
    return {"covered": covered, "total": total,
            "percent": round(100.0 * covered / total, 2) if total else 0.0,
            "source_files": files}


def lcov_project_lines(report_path: str | Path, project: str) -> dict[tuple[str, int], int]:
    """Return instrumented target file:line IDs and their maximum hit counts."""
    path = Path(report_path)
    if not path.is_file() or path.suffix.lower() != ".lcov":
        raise CoverageError(f"full LCOV report required for source-set audit: {path}")
    current = ""
    line_hits: dict[tuple[str, int], int] = {}
    section_hits: dict[tuple[str, int], int] = {}
    section_total = 0
    def finish_section() -> None:
        if section_total > 0:
            for key, hits in section_hits.items():
                line_hits[key] = max(line_hits.get(key, 0), hits)
    with path.open(encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            if raw.startswith("SF:"):
                finish_section()
                section_hits.clear()
                section_total = 0
                source = _source_path(raw[3:].strip())
                current = source if _project_source(source, project) else ""
            elif current and raw.startswith("DA:"):
                fields = raw[3:].split(",", 2)
                if len(fields) >= 2:
                    fields[0] = fields[0].strip()
                    fields[1] = fields[1].strip()
                if len(fields) >= 2 and fields[0].isdecimal() and fields[1].isdecimal():
                    key = (current, int(fields[0]))
                    section_hits[key] = max(section_hits.get(key, 0), int(fields[1]))
            elif current and raw.startswith("LF:"):
                value = raw[3:].strip()
                section_total = int(value) if value.isdecimal() else 0
            elif raw.startswith("end_of_record"):
                finish_section()
                section_hits.clear()
                section_total = 0
                current = ""
    finish_section()
    if not line_hits:
        raise CoverageError(f"no executable {project} source lines in full LCOV report")
    return line_hits


def lcov_project_source_set(report_path: str | Path, project: str) -> dict[str, Any]:
    """Fingerprint executable target file:line IDs in a full LCOV export.

    The fingerprint covers the instrumented source set, independent of which
    lines the corpus happened to execute. Summary-only reports have no DA
    records and cannot pass this check.
    """
    line_ids = lcov_project_lines(report_path, project)
    digest = hashlib.sha256()
    for source, number in sorted(line_ids):
        digest.update(f"{source}:{number}\n".encode("utf-8"))
    return {"source_set_sha256": digest.hexdigest(),
            "instrumented_source_lines": len(line_ids),
            "instrumented_source_files": len({source for source, _ in line_ids})}


def parse_llvm_coverage_json(text: str, project: str = "") -> dict[str, Any]:
    """Parse LLVM source-based coverage JSON (``llvm-cov export -format=json``).

    Returns a normalized dict with ``line_coverage``, ``function_coverage``,
    ``region_coverage`` and ``edge_coverage`` (null for LLVM source-based
    reports, which do not report edges).  When the export is not
    ``-summary-only`` the covered function names are collected under
    ``covered_functions`` so the evaluator can match intended API symbols to
    real runtime evidence (plan section 8).
    """

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CoverageError(f"llvm coverage JSON is unparseable: {exc}") from exc
    if not isinstance(data, dict) or "data" not in data:
        raise CoverageError("llvm coverage JSON has no 'data' key")
    totals = {"lines": {"count": 0, "covered": 0}, "functions": {"count": 0, "covered": 0}, "regions": {"count": 0, "covered": 0}}
    covered_functions: list[str] = []
    sut_covered = sut_total = sut_files = 0
    for entry in data.get("data", []):
        entry_totals = entry.get("totals", {}) if isinstance(entry, dict) else {}
        for key in totals:
            sect = entry_totals.get(key, {})
            if not isinstance(sect, dict):
                continue
            totals[key]["count"] += int(sect.get("count", 0) or 0)
            totals[key]["covered"] += int(sect.get("covered", 0) or 0)
        if project:
            for file in entry.get("files", []):
                if not isinstance(file, dict) or not _project_source(str(file.get("filename") or ""), project):
                    continue
                lines = (file.get("summary") or {}).get("lines") or {}
                count = int(lines.get("count", 0) or 0)
                if count:
                    sut_files += 1
                    sut_total += count
                    sut_covered += int(lines.get("covered", 0) or 0)
        # Collect covered function names from the per-function array (present
        # when llvm-cov export is run without -summary-only).
        functions = entry.get("functions", []) if isinstance(entry, dict) else []
        if isinstance(functions, list):
            for func in functions:
                if not isinstance(func, dict):
                    continue
                if int(func.get("count", 0) or 0) > 0 and func.get("name"):
                    covered_functions.append(str(func["name"]))
    lines = totals["lines"]
    funcs = totals["functions"]
    regions = totals["regions"]
    line_percent = round(100.0 * lines["covered"] / lines["count"], 2) if lines["count"] else 0.0
    func_percent = round(100.0 * funcs["covered"] / funcs["count"], 2) if funcs["count"] else 0.0
    region_percent = round(100.0 * regions["covered"] / regions["count"], 2) if regions["count"] else 0.0
    # Rename "regions" to "region_coverage" for consistency with the plan.
    summary = {
        "line_coverage": {"covered": lines["covered"], "total": lines["count"], "percent": line_percent},
        "function_coverage": {"covered": funcs["covered"], "total": funcs["count"], "percent": func_percent},
        "region_coverage": {"covered": regions["covered"], "total": regions["count"], "percent": region_percent},
        "regions": {"covered": regions["covered"], "total": regions["count"], "percent": region_percent},
        "edge_coverage": None,
        "covered_functions": sorted(set(covered_functions)),
        "source": "llvm_source_based",
    }
    if project:
        summary["sut_line_coverage"] = _sut_summary(sut_covered, sut_total, sut_files)
    return summary


_LCOV_LINE = re.compile(r"^LF:(\d+)$")
_LCOV_COVERED = re.compile(r"^LH:(\d+)$")
_LCOV_FNF = re.compile(r"^FNF:(\d+)$")
_LCOV_FNH = re.compile(r"^FNH:(\d+)$")
_LCOV_FNDA = re.compile(r"^FNDA:(\d+),(.+)$")


def parse_lcov(text: str, project: str = "") -> dict[str, Any]:
    """Parse an lcov tracefile and return a normalized coverage summary."""

    lines_total = 0
    lines_covered = 0
    funcs_total = 0
    funcs_covered = 0
    covered_functions: set[str] = set()
    sut_covered = sut_total = sut_files = 0
    in_project = False
    for raw in text.splitlines():
        if raw.startswith("SF:"):
            in_project = bool(project and _project_source(raw[3:], project))
            continue
        m = _LCOV_LINE.match(raw)
        if m:
            lines_total += int(m.group(1))
            if in_project and int(m.group(1)):
                sut_total += int(m.group(1))
                sut_files += 1
            continue
        m = _LCOV_COVERED.match(raw)
        if m:
            lines_covered += int(m.group(1))
            if in_project:
                sut_covered += int(m.group(1))
            continue
        m = _LCOV_FNF.match(raw)
        if m:
            funcs_total += int(m.group(1))
            continue
        m = _LCOV_FNH.match(raw)
        if m:
            funcs_covered += int(m.group(1))
            continue
        m = _LCOV_FNDA.match(raw)
        if m and int(m.group(1)) > 0:
            covered_functions.add(m.group(2))
    line_percent = round(100.0 * lines_covered / lines_total, 2) if lines_total else 0.0
    func_percent = round(100.0 * funcs_covered / funcs_total, 2) if funcs_total else 0.0
    summary = {
        "line_coverage": {"covered": lines_covered, "total": lines_total, "percent": line_percent},
        "function_coverage": {"covered": funcs_covered, "total": funcs_total, "percent": func_percent},
        "regions": {"covered": 0, "total": 0, "percent": 0.0},
        "edge_coverage": None,
        "covered_functions": sorted(covered_functions),
        "source": "lcov",
    }
    if project:
        summary["sut_line_coverage"] = _sut_summary(sut_covered, sut_total, sut_files)
    return summary


def summarize_coverage_report(report_path: str | Path, project: str = "",
                              require_project_coverage: bool = True) -> dict[str, Any]:
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
        summary = parse_llvm_coverage_json(text, project=project)
    else:
        summary = parse_lcov(text, project=project)
    if summary["line_coverage"]["total"] == 0:
        raise CoverageError("coverage report has zero total lines; not a real coverage report")
    if project and require_project_coverage and summary["sut_line_coverage"]["covered"] == 0:
        raise CoverageError(f"coverage report has no covered {project} project source lines")
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
