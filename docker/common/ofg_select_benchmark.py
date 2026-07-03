#!/usr/bin/env python3
"""Select an OSS-Fuzz-Gen benchmark YAML for a HarnessGenBench target."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


YAML_SUFFIXES = {".yaml", ".yml"}


def _strip_scalar(value: str) -> str:
    value = value.strip().rstrip(",").strip()
    if " #" in value:
        value = value.split(" #", 1)[0].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def top_level_scalar(path: Path, key: str) -> str:
    pattern = re.compile(rf"^\s*[\"']?{re.escape(key)}[\"']?\s*:\s*(.*?)\s*$")
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw[:1].isspace():
            continue
        match = pattern.match(raw)
        if match:
            return _strip_scalar(match.group(1))
    return ""


def benchmark_set_rank(path: Path) -> tuple[int, str]:
    parts = path.parts
    for preferred in ("all", "new-light-fi", "comparison"):
        if preferred in parts:
            return (("all", "new-light-fi", "comparison").index(preferred), path.as_posix())
    return (99, path.as_posix())


def select_benchmark(
    benchmark_sets_dir: Path,
    project: str,
    fuzz_target: str = "",
    target_name: str = "",
    allow_project_fallback: bool = True,
) -> dict[str, Any]:
    target_values = {value for value in (fuzz_target, target_name) if value}
    project_matches: list[dict[str, Any]] = []
    exact_target_matches: list[dict[str, Any]] = []

    for candidate in sorted(benchmark_sets_dir.rglob("*")):
        if not candidate.is_file() or candidate.suffix.lower() not in YAML_SUFFIXES:
            continue
        yaml_project = top_level_scalar(candidate, "project")
        if yaml_project != project:
            continue
        yaml_target = top_level_scalar(candidate, "target_name")
        record = {
            "path": str(candidate),
            "selected_yaml_project": yaml_project,
            "selected_yaml_target_name": yaml_target,
        }
        project_matches.append(record)
        if yaml_target in target_values:
            exact_target_matches.append(record)

    def sort_key(record: dict[str, Any]) -> tuple[int, int, str]:
        path = Path(record["path"])
        stem_rank = 0 if path.stem == project else 1
        set_rank, path_text = benchmark_set_rank(path)
        return (stem_rank, set_rank, path_text)

    if exact_target_matches:
        selected = sorted(exact_target_matches, key=sort_key)[0]
        selected["benchmark_match_kind"] = "exact_project_target"
        selected["candidate_count"] = len(project_matches)
        return selected

    if allow_project_fallback and project_matches:
        selected = sorted(project_matches, key=sort_key)[0]
        selected["benchmark_match_kind"] = "exact_project"
        selected["candidate_count"] = len(project_matches)
        return selected

    return {
        "path": "",
        "selected_yaml_project": "",
        "selected_yaml_target_name": "",
        "benchmark_match_kind": "none",
        "candidate_count": len(project_matches),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-sets-dir", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--fuzz-target", default="")
    parser.add_argument("--target-name", default="")
    parser.add_argument("--allow-project-fallback", action="store_true")
    parser.add_argument("--out")
    args = parser.parse_args()

    result = select_benchmark(
        Path(args.benchmark_sets_dir),
        args.project,
        fuzz_target=args.fuzz_target,
        target_name=args.target_name,
        allow_project_fallback=args.allow_project_fallback,
    )
    output = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    print(output, end="")
    return 0 if result["path"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
