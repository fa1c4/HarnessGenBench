#!/usr/bin/env python3
"""Best-effort C/C++ API extractor for target-aware generator bootstrapping."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from hgb_api_report import default_api_report_path, select_report_api_names
from ofg_api_rank import load_reference_calls, rank_records


DECL_RE = re.compile(
    r"(?m)^[ \t]*(?!#)"
    r"([A-Za-z_][A-Za-z0-9_:\<\>\*\&\s,~]*?)\s+"
    r"([A-Za-z_][A-Za-z0-9_:]*)\s*\(([^;{}#]*)\)\s*(?:;|\{)"
)
OF_DECL_RE = re.compile(
    r"(?m)^[ \t]*(?:ZEXTERN\s+)?"
    r"([A-Za-z_][A-Za-z0-9_:\<\>\*\&\s,~]*?(?:\s+ZEXPORT)?)\s+"
    r"([A-Za-z_][A-Za-z0-9_:]*)\s+OF\s*\(\((.*?)\)\)\s*;",
    re.S,
)
SKIP = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "main",
    "void",
    "LLVMFuzzerTestOneInput",
    "LLVMFuzzerInitialize",
    "OF",
}
EXTS = {".h", ".hh", ".hpp", ".hxx", ".c", ".cc", ".cpp", ".cxx"}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//.*", " ", text)


def split_params(params: str) -> list[str]:
    params = params.strip()
    if not params or params == "void":
        return []
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for char in params:
        if char in "(<[":
            depth += 1
        elif char in ")>]" and depth > 0:
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if current:
        parts.append("".join(current).strip())
    return [part for part in parts if part]


def parse_param(param: str) -> dict[str, str]:
    param = " ".join(param.replace("\n", " ").split())
    if param == "...":
        return {"name": "", "type": "..."}
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?$", param)
    if not match:
        return {"name": "", "type": param}
    name = match.group(1)
    type_part = param[: match.start(1)].rstrip()
    if not type_part or name in {"const", "volatile", "struct", "enum", "union"}:
        return {"name": "", "type": param}
    return {"name": name, "type": type_part}


def valid_name(name: str) -> bool:
    short = name.split("::")[-1]
    if short in SKIP or short.startswith("__"):
        return False
    if short.upper() == short and len(short) > 2:
        return False
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_:]*$", name))


def _clean_return_type(return_type: str) -> str:
    return " ".join(
        part for part in return_type.replace("ZEXPORT", " ").replace("ZEXTERN", " ").split()
        if part
    )


def make_record(name: str, return_type: str, params: str, path: Path | None = None, source: Path | None = None) -> dict[str, Any]:
    short_name = name.split("::")[-1]
    return_type = _clean_return_type(return_type)
    parsed_params = [parse_param(param) for param in split_params(params)]
    signature = f"{return_type.strip() or 'int'} {name}({', '.join(param.strip() for param in split_params(params))})"
    record: dict[str, Any] = {
        "name": short_name,
        "return_type": return_type.strip() or "int",
        "params": parsed_params,
        "signature": signature,
    }
    if path is not None:
        try:
            record["path"] = str(path.relative_to(source)) if source else str(path)
        except ValueError:
            record["path"] = str(path)
    return record


def source_files(source: Path) -> list[Path]:
    return [path for path in sorted(source.rglob("*")) if path.is_file() and path.suffix.lower() in EXTS]


def ctags_records(source: Path, limit: int) -> list[dict[str, Any]]:
    ctags = shutil.which("ctags")
    if not ctags:
        return []
    cmd = [
        ctags,
        "--output-format=json",
        "--languages=C,C++",
        "--kinds-C=f",
        "--kinds-C++=f",
        "--fields=+S",
        "-R",
        "-f",
        "-",
        str(source),
    ]
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, check=False, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0 and not proc.stdout.strip():
        return []

    seen: set[str] = set()
    records: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = str(item.get("name", ""))
        short_name = name.split("::")[-1]
        if not valid_name(name) or short_name in seen:
            continue
        signature = str(item.get("signature", "()"))
        params = signature.strip()[1:-1] if signature.startswith("(") and signature.endswith(")") else ""
        typeref = str(item.get("typeref", ""))
        return_type = typeref.split(":", 1)[1] if ":" in typeref else "int"
        path = Path(str(item.get("path", ""))) if item.get("path") else None
        records.append(make_record(name, return_type, params, path, source))
        seen.add(short_name)
        if len(records) >= limit:
            return records
    return records


def regex_records(source: Path, limit: int) -> list[dict[str, Any]]:
    seen: set[str] = set()
    records: list[dict[str, Any]] = []
    for path in source_files(source):
        try:
            text = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        matches = list(OF_DECL_RE.finditer(text)) + list(DECL_RE.finditer(text))
        for match in matches:
            return_type, name, params = match.groups()
            short_name = name.split("::")[-1]
            if not valid_name(name) or short_name in seen:
                continue
            seen.add(short_name)
            records.append(make_record(name, return_type, params, path, source))
            if len(records) >= limit:
                return records
    return records


def _merge_records(primary: list[dict[str, Any]], secondary: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in [*primary, *secondary]:
        name = str(record.get("name") or "")
        if not name or name in seen:
            continue
        seen.add(name)
        merged.append(record)
        if len(merged) >= limit:
            break
    return merged


def extract_details(source: Path, limit: int) -> list[dict[str, Any]]:
    regex = regex_records(source, limit)
    ctags = ctags_records(source, limit)
    return _merge_records(regex, ctags, limit)


def extract(source: Path, limit: int) -> list[str]:
    return [record["name"] for record in extract_details(source, limit)]


def _record_short_name(record: dict[str, Any]) -> str:
    return str(record.get("name") or "").split("::")[-1]


def _report_name_records(
    raw: list[dict[str, Any]],
    report_names: list[str],
    *,
    allow_name_only: bool,
) -> tuple[list[dict[str, Any]], list[str]]:
    order = {name.split("::")[-1].lower(): index for index, name in enumerate(report_names)}
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in raw:
        key = _record_short_name(record).lower()
        if key not in order or key in seen:
            continue
        item = dict(record)
        item["_hgb_selection_reason"] = "api_report_decl_match"
        selected.append(item)
        seen.add(key)
    selected.sort(key=lambda record: order.get(_record_short_name(record).lower(), 10_000))
    unmatched = [
        name for name in report_names
        if name.split("::")[-1].lower() not in seen
    ]
    if allow_name_only:
        for name in unmatched:
            item = make_record(name, "int", "")
            item["_hgb_selection_reason"] = "api_report_name_only"
            item["_hgb_name_only"] = True
            selected.append(item)
        unmatched = []
    return selected, unmatched


def effective_reference_dir(reference_dir: str, selected_reference_dir: str = "") -> str:
    if selected_reference_dir:
        return selected_reference_dir
    if not reference_dir:
        return ""
    root = Path(reference_dir)
    selected = root / "selected"
    if selected.is_dir():
        return str(selected)
    return reference_dir


def select_records(
    raw: list[dict[str, Any]],
    *,
    max_records: int,
    fallback_max: int,
    selection_mode: str,
    project: str,
    target_name: str,
    fuzz_target: str,
    reference_dir: str,
    keep_rejected: bool,
    api_report: str = "",
    report_mode: str = "report_first",
    allow_name_only_report_apis: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    report_metadata: dict[str, Any] = {}
    if report_mode != "dynamic_only":
        report_names, report_metadata = select_report_api_names(
            report_path=api_report or default_api_report_path(),
            target_name=target_name,
            project=project,
            fuzz_target=fuzz_target,
            max_records=max_records,
        )
        if report_names:
            report_records, unmatched_report_names = _report_name_records(
                raw,
                report_names,
                allow_name_only=allow_name_only_report_apis,
            )
            if report_records:
                metadata = {
                    "selection_mode": selection_mode,
                    "report_mode": report_mode,
                    "api_selection_source": "report",
                    "reference_dir": reference_dir,
                    "raw_candidate_count": len(raw),
                    "ranked_candidate_count": 0,
                    "reference_call_count": len(load_reference_calls(reference_dir)),
                    "direct_match_count": len(report_records),
                    "selected_count": len(report_records),
                    "fallback_used": False,
                    "fallback_max": fallback_max,
                    "max_records": max_records,
                    "selected_api_names": [str(record.get("name") or "") for record in report_records],
                    "direct_api_names": [str(record.get("name") or "") for record in report_records],
                    "unmatched_report_api_names": unmatched_report_names,
                }
                metadata.update(report_metadata)
                return report_records, metadata
        if report_mode == "report_only":
            metadata = {
                "selection_mode": selection_mode,
                "report_mode": report_mode,
                "api_selection_source": "report",
                "reference_dir": reference_dir,
                "raw_candidate_count": len(raw),
                "ranked_candidate_count": 0,
                "reference_call_count": len(load_reference_calls(reference_dir)),
                "direct_match_count": 0,
                "selected_count": 0,
                "fallback_used": False,
                "fallback_max": fallback_max,
                "max_records": max_records,
                "selected_api_names": [],
                "direct_api_names": [],
                "unmatched_report_api_names": report_metadata.get("api_candidate_names", []),
            }
            metadata.update(report_metadata)
            return [], metadata

    ranked = rank_records(
        raw,
        project=project,
        target_name=target_name,
        fuzz_target=fuzz_target,
        reference_dir=reference_dir,
        keep_rejected=keep_rejected,
    )
    reference_calls = load_reference_calls(reference_dir)
    direct = [
        record for record in ranked
        if str(record.get("name") or "").split("::")[-1].lower() in reference_calls
    ]
    fallback_used = bool(report_metadata and report_mode == "report_first")
    if selection_mode == "ranked":
        selected = ranked[:max_records]
    elif selection_mode == "selected_harness":
        selected = direct[:max_records]
    else:
        if direct:
            selected = direct[:max_records]
        else:
            fallback_used = True
            selected = ranked[:max(0, fallback_max)]
    metadata = {
        "selection_mode": selection_mode,
        "report_mode": report_mode,
        "api_selection_source": "dynamic",
        "reference_dir": reference_dir,
        "raw_candidate_count": len(raw),
        "ranked_candidate_count": len(ranked),
        "reference_call_count": len(reference_calls),
        "direct_match_count": len(direct),
        "selected_count": len(selected),
        "fallback_used": fallback_used,
        "fallback_max": fallback_max,
        "max_records": max_records,
        "selected_api_names": [str(record.get("name") or "") for record in selected],
        "direct_api_names": [str(record.get("name") or "") for record in direct[:max_records]],
    }
    metadata.update(report_metadata)
    return selected, metadata

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max", type=int, default=int(os.environ.get("HGB_SELECTED_API_MAX", "8") or "8"))
    parser.add_argument("--fallback-max", type=int, default=int(os.environ.get("HGB_SELECTED_API_FALLBACK_MAX", "4") or "4"))
    parser.add_argument("--details", action="store_true", help="write detailed API records instead of only names")
    parser.add_argument("--project", default="")
    parser.add_argument("--target-name", default="")
    parser.add_argument("--fuzz-target", default="")
    parser.add_argument("--reference-dir", default="")
    parser.add_argument("--selected-reference-dir", default="")
    parser.add_argument("--api-report", default=os.environ.get("HGB_SELECTED_API_REPORT", default_api_report_path()))
    parser.add_argument(
        "--report-mode",
        default=os.environ.get("HGB_API_REPORT_MODE", "report_first"),
        choices=("report_first", "report_only", "dynamic_only"),
    )
    parser.add_argument("--allow-name-only-report-apis", action="store_true")
    parser.add_argument(
        "--selection-mode",
        default=os.environ.get("HGB_API_SELECTION_MODE", "selected_harness_fallback"),
        choices=("ranked", "selected_harness", "selected_harness_fallback"),
    )
    parser.add_argument("--selection-metadata", default="")
    parser.add_argument("--keep-rejected", action="store_true")
    args = parser.parse_args()
    max_records = max(0, args.max)
    fallback_max = max(0, args.fallback_max)
    raw_limit = max(max(max_records, fallback_max) * 20, max_records, fallback_max, 1000)
    raw = extract_details(Path(args.source), raw_limit)
    ref_dir = effective_reference_dir(args.reference_dir, args.selected_reference_dir)
    selected, metadata = select_records(
        raw,
        max_records=max_records,
        fallback_max=fallback_max,
        selection_mode=args.selection_mode,
        project=args.project,
        target_name=args.target_name,
        fuzz_target=args.fuzz_target,
        reference_dir=ref_dir,
        keep_rejected=args.keep_rejected,
        api_report=args.api_report,
        report_mode=args.report_mode,
        allow_name_only_report_apis=args.allow_name_only_report_apis,
    )
    if args.details:
        data = selected
    else:
        data = [record["name"] for record in selected]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    if args.selection_metadata:
        metadata_path = Path(args.selection_metadata)
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(len(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
