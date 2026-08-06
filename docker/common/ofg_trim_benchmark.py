#!/usr/bin/env python3
"""Trim OSS-Fuzz-Gen benchmark YAMLs for HGB row-local execution."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

import yaml

from hgb_api_report import default_api_report_path, select_report_api_names
from ofg_api_rank import load_reference_calls, rank_records, reject_reason


def _trim_list(value, max_items: int):
    if isinstance(value, list) and max_items > 0:
        return value[:max_items]
    return value


def _normalise_function(function: Any) -> dict[str, Any] | None:
    if not isinstance(function, dict):
        return None
    item = dict(function)
    name = str(item.get("name") or "")
    signature = str(item.get("signature") or "")
    if not name and signature:
        name = signature.split("(", 1)[0].split()[-1]
        item["name"] = name
    if not signature and name:
        params = item.get("params") or []
        param_text = ", ".join(str(p.get("type", "")) for p in params if isinstance(p, dict))
        item["signature"] = f"{item.get('return_type') or item.get('return-type') or 'int'} {name}({param_text})"
    return item


def _blind_mode(args: argparse.Namespace) -> bool:
    if getattr(args, "blind", False):
        return True
    if os.environ.get("OFG_REFERENCE_DIAGNOSTIC", "0").strip().lower() in {"1", "true", "yes"}:
        return False
    protocol = os.environ.get("HGB_BASELINE_PROTOCOL") or os.environ.get("HGB_PROTOCOL") or ""
    return protocol.strip().lower() == "blind-project"


def _rank_functions(functions: Any, args: argparse.Namespace) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    report_metadata: dict[str, Any] = {}
    if not isinstance(functions, list):
        return [], [], report_metadata
    normalised = [item for item in (_normalise_function(function) for function in functions) if item]
    # In blind-project the selected-reference API report (derived from the
    # exact target harness) must not drive selection. Skip it entirely.
    if not _blind_mode(args) and args.report_mode != "dynamic_only":
        report_names, report_metadata = select_report_api_names(
            report_path=args.api_report or default_api_report_path(),
            target_name=args.target_name,
            project=args.project,
            fuzz_target=args.fuzz_target,
            max_records=args.max_functions,
        )
        if report_names:
            order = {name.split("::")[-1].lower(): index for index, name in enumerate(report_names)}
            matched = [
                item for item in normalised
                if str(item.get("name") or "").split("::")[-1].lower() in order
            ]
            matched.sort(key=lambda item: order.get(str(item.get("name") or "").split("::")[-1].lower(), 10_000))
            for item in matched:
                item["_hgb_score"] = 1000
                item["_hgb_score_reasons"] = ["api_report_candidate"]
            if matched or args.report_mode == "report_only":
                return matched, [], report_metadata
        if args.report_mode == "report_only":
            return [], [], report_metadata

    ranked = rank_records(
        normalised,
        project=args.project,
        target_name=args.target_name,
        fuzz_target=args.fuzz_target,
        reference_dir=args.reference_dir if not _blind_mode(args) else None,
    )
    reference_calls = load_reference_calls(args.reference_dir if not _blind_mode(args) else None)
    direct = [
        item for item in ranked
        if str(item.get("name") or "").split("::")[-1].lower() in reference_calls
    ]
    if args.selection_mode != "ranked" and reference_calls:
        ranked = direct
    rejected = []
    ranked_ids = {id(item) for item in ranked}
    for item in normalised:
        if id(item) not in ranked_ids and reject_reason(item):
            rejected.append({"name": item.get("name", ""), "signature": item.get("signature", ""), "reason": reject_reason(item)})
    report_metadata["blind_mode"] = _blind_mode(args)
    return ranked, rejected, report_metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="input_path", required=True)
    parser.add_argument("--out", dest="output_path", required=True)
    parser.add_argument("--max-functions", type=int, default=1)
    parser.add_argument("--metadata", dest="metadata_path")
    parser.add_argument("--project", default="")
    parser.add_argument("--target-name", default="")
    parser.add_argument("--fuzz-target", default="")
    parser.add_argument("--reference-dir", default="")
    parser.add_argument("--api-report", default=os.environ.get("HGB_SELECTED_API_REPORT", default_api_report_path()))
    parser.add_argument("--report-mode", default=os.environ.get("HGB_API_REPORT_MODE", "report_first"), choices=("report_first", "report_only", "dynamic_only"))
    parser.add_argument("--allow-test-files", action="store_true")
    parser.add_argument("--min-score", type=int, default=0)
    parser.add_argument("--selection-mode", default=os.environ.get("HGB_API_SELECTION_MODE", "selected_harness_fallback"), choices=("ranked", "selected_harness", "selected_harness_fallback"))
    parser.add_argument("--blind", action="store_true",
                        help="blind-project mode: skip reference/report-derived selection")
    args = parser.parse_args()

    src = Path(args.input_path)
    dst = Path(args.output_path)
    data = yaml.safe_load(src.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"unsupported benchmark YAML shape: {src}")

    functions = data.get("functions")
    test_files = data.get("test_files")
    original_function_count = len(functions) if isinstance(functions, list) else 0
    original_test_file_count = len(test_files) if isinstance(test_files, list) else 0

    ranked_functions, rejected_functions, report_metadata = _rank_functions(functions, args)
    low_confidence_functions: list[dict[str, Any]] = []
    if args.min_score > 0 and ranked_functions:
        confident_functions = []
        for item in ranked_functions:
            if int(item.get("_hgb_score", 0)) >= args.min_score:
                confident_functions.append(item)
            else:
                low_confidence_functions.append(item)
        ranked_functions = confident_functions
    if original_function_count and not ranked_functions:
        if low_confidence_functions and not rejected_functions:
            print("ofg_low_confidence_api_candidate: all benchmark functions scored below HGB minimum")
            for item in low_confidence_functions[:20]:
                print(json.dumps({"name": item.get("name", ""), "signature": item.get("signature", ""), "score": item.get("_hgb_score", 0), "reasons": item.get("_hgb_score_reasons", [])}, sort_keys=True))
        else:
            print("ofg_bad_api_candidate: all benchmark functions were rejected by HGB target-aware filtering")
            for item in rejected_functions[:20]:
                print(json.dumps(item, sort_keys=True))
        raise SystemExit(65)

    if not original_function_count and original_test_file_count and not args.allow_test_files:
        print("ofg_empty_unit_test_prompt: test-only benchmark YAML is disabled by default for HGB matrix rows")
        raise SystemExit(66)

    if ranked_functions:
        data["functions"] = _trim_list(ranked_functions, args.max_functions)
        data["test_files"] = None
    else:
        data["functions"] = _trim_list(functions, args.max_functions)
        data["test_files"] = _trim_list(test_files, args.max_functions)

    trimmed_functions = data.get("functions")
    trimmed_test_files = data.get("test_files")
    metadata = {
        "input": str(src),
        "output": str(dst),
        "max_functions": args.max_functions,
        "original_function_count": original_function_count,
        "trimmed_function_count": len(trimmed_functions) if isinstance(trimmed_functions, list) else 0,
        "original_test_file_count": original_test_file_count,
        "trimmed_test_file_count": len(trimmed_test_files) if isinstance(trimmed_test_files, list) else 0,
        "rejected_function_count": len(rejected_functions),
        "low_confidence_function_count": len(low_confidence_functions),
        "min_score": args.min_score,
        "api_selection_source": "report" if report_metadata.get("api_candidate_names") and ranked_functions else "dynamic",
        "report_mode": args.report_mode,
        "fallback_used": bool(report_metadata and not ranked_functions and args.report_mode == "report_first"),
    }
    metadata.update(report_metadata)

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    if args.metadata_path:
        Path(args.metadata_path).write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        print(json.dumps(metadata, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
