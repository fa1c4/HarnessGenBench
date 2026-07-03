#!/usr/bin/env python3
"""Trim OSS-Fuzz-Gen benchmark YAMLs for HGB row-local execution."""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="input_path", required=True)
    parser.add_argument("--out", dest="output_path", required=True)
    parser.add_argument("--max-functions", type=int, default=1)
    args = parser.parse_args()

    src = Path(args.input_path)
    dst = Path(args.output_path)
    data = yaml.safe_load(src.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"unsupported benchmark YAML shape: {src}")

    functions = data.get("functions")
    if isinstance(functions, list) and args.max_functions > 0:
        data["functions"] = functions[: args.max_functions]

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
