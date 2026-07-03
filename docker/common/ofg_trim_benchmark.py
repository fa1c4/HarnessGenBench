#!/usr/bin/env python3
"""Trim OSS-Fuzz-Gen benchmark YAMLs for HGB row-local execution."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml


def _trim_list(value, max_items: int):
    if isinstance(value, list) and max_items > 0:
        return value[:max_items]
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="input_path", required=True)
    parser.add_argument("--out", dest="output_path", required=True)
    parser.add_argument("--max-functions", type=int, default=1)
    parser.add_argument("--metadata", dest="metadata_path")
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
    }

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    if args.metadata_path:
        Path(args.metadata_path).write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        print(json.dumps(metadata, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
