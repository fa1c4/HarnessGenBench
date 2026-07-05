#!/usr/bin/env python3
"""Selected-harness API report helpers for HGB generator integrations."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

DEFAULT_API_REPORT = "/opt/hgb/metadata/fuzzbench_selected_harness_apis.json"


def default_api_report_path() -> str:
    return os.environ.get("HGB_SELECTED_API_REPORT") or DEFAULT_API_REPORT


def _norm(value: object) -> str:
    return str(value or "").strip().lower()


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        name = str(value or "").strip()
        if not name:
            continue
        key = name.split("::")[-1].lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(name)
    return result


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item or "").strip()]


def load_api_report(path: str | Path | None = None) -> dict[str, Any]:
    report_path = Path(path or default_api_report_path())
    if not report_path.is_file():
        return {"path": str(report_path), "rows": [], "_hgb_missing": True}
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"path": str(report_path), "rows": [], "_hgb_missing": True}
    if isinstance(data, dict):
        data.setdefault("path", str(report_path))
        rows = data.get("rows")
        data["rows"] = rows if isinstance(rows, list) else []
        return data
    if isinstance(data, list):
        return {"path": str(report_path), "rows": data}
    return {"path": str(report_path), "rows": [], "_hgb_missing": True}


def find_report_row(
    report: dict[str, Any],
    *,
    target_name: str = "",
    project: str = "",
    fuzz_target: str = "",
) -> dict[str, Any] | None:
    rows = report.get("rows") if isinstance(report, dict) else []
    if not isinstance(rows, list):
        return None
    target_norm = _norm(target_name)
    project_norm = _norm(project)
    fuzz_norm = _norm(fuzz_target)
    if target_norm:
        for row in rows:
            if isinstance(row, dict) and _norm(row.get("target")) == target_norm:
                return row
    if project_norm and fuzz_norm:
        for row in rows:
            if not isinstance(row, dict):
                continue
            if _norm(row.get("project")) == project_norm and _norm(row.get("fuzz_target")) == fuzz_norm:
                return row
    return None


def api_names_from_row(row: dict[str, Any] | None) -> tuple[list[str], str]:
    if not row:
        return [], ""
    for key, source in (
        ("candidate_api_names", "candidate_api_names"),
        ("direct_api_names", "direct_api_names"),
        ("curated_api_names", "curated_api_names"),
        ("harness_call_names", "harness_call_names"),
    ):
        names = _dedupe(_string_list(row.get(key)))
        if names:
            return names, source
    return [], ""


def select_report_api_names(
    *,
    report_path: str | Path | None = None,
    target_name: str = "",
    project: str = "",
    fuzz_target: str = "",
    max_records: int = 0,
) -> tuple[list[str], dict[str, Any]]:
    report = load_api_report(report_path)
    row = find_report_row(report, target_name=target_name, project=project, fuzz_target=fuzz_target)
    names, source_field = api_names_from_row(row)
    limit = max(0, int(max_records or 0))
    if limit:
        names = names[:limit]
    metadata = {
        "api_report_path": str(report.get("path") or report_path or default_api_report_path()),
        "api_report_missing": bool(report.get("_hgb_missing")),
        "api_report_row_found": row is not None,
        "api_report_source_field": source_field,
        "api_report_target": row.get("target", "") if isinstance(row, dict) else "",
        "api_candidate_names": names,
        "api_candidate_count": len(names),
    }
    return names, metadata

