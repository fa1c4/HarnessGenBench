#!/usr/bin/env python3
"""Resolve the native source file replaced by a CKGFuzzer candidate.

Target packages deliberately remove reference harnesses from ``source_input``
before generation.  The package manifest preserves the selected path, which
is the only reliable way to place a generated candidate for native build
verification.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any


SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}
_SRC_PATH = re.compile(r"(?:\$\{SRC\}|\$SRC)/([^\s'\";)&|]+)")


class TargetHarnessError(RuntimeError):
    """The target package does not identify a native harness to replace."""


@dataclass(frozen=True)
class NativeHarness:
    selected_reference: str
    container_destination: str
    language: str
    source_suffix: str
    selection_reason: str


def _read_manifest(target_root: Path) -> dict[str, Any]:
    path = target_root / "target_manifest.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TargetHarnessError(f"invalid target manifest: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise TargetHarnessError(f"invalid target manifest object: {path}")
    return data


def _normal(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _safe_reference(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise TargetHarnessError(f"unsafe selected reference path: {value!r}")
    if path.parts[0] not in {"source_input", "fuzzbench_benchmark"}:
        raise TargetHarnessError(f"unsupported selected reference root: {value!r}")
    if path.suffix.lower() not in SOURCE_SUFFIXES:
        raise TargetHarnessError(f"selected reference is not a C/C++ source: {value!r}")
    return path


def _src_destinations(build_script: str) -> list[str]:
    destinations: list[str] = []
    for match in _SRC_PATH.finditer(build_script):
        value = match.group(1).rstrip(".,")
        path = PurePosixPath(value)
        if value and not path.is_absolute() and ".." not in path.parts:
            destinations.append(path.as_posix())
    return destinations


def _candidate_destination(path: PurePosixPath, src_paths: list[str]) -> tuple[str, int, str]:
    relative = PurePosixPath(*path.parts[1:]).as_posix()
    direct = relative if path.parts[0] == "source_input" else ""
    if direct in src_paths:
        return f"/src/{direct}", 1000, "exact $SRC path in native build"

    same_basename = [item for item in src_paths if PurePosixPath(item).name == path.name]
    if len(same_basename) == 1 and path.parts[0] == "fuzzbench_benchmark":
        return f"/src/{same_basename[0]}", 700, "$SRC basename in native build"

    if path.parts[0] == "source_input":
        return f"/src/{relative}", 250, "source snapshot path"
    return f"/src/{path.name}", 100, "benchmark-local fallback path"


def select_native_harness(target_root: Path, fuzz_target: str = "") -> NativeHarness:
    """Select one manifest-recorded native C/C++ harness for verification."""

    manifest = _read_manifest(target_root)
    selected = manifest.get("selected_reference_harness_files", [])
    if not isinstance(selected, list) or not selected:
        raise TargetHarnessError("target manifest has no selected reference harness file")

    build_script = target_root / "fuzzbench_benchmark" / "build.sh"
    build_text = build_script.read_text(encoding="utf-8", errors="replace") if build_script.is_file() else ""
    src_paths = _src_destinations(build_text)
    target_name = _normal(Path(fuzz_target).stem)
    candidates: list[tuple[int, NativeHarness]] = []
    for raw in selected:
        if not isinstance(raw, str):
            continue
        path = _safe_reference(raw)
        destination, build_score, reason = _candidate_destination(path, src_paths)
        stem = _normal(path.stem)
        name_score = 80 if target_name and stem == target_name else 40 if target_name and (stem in target_name or target_name in stem) else 0
        suffix = path.suffix.lower()
        candidates.append(
            (
                build_score + name_score,
                NativeHarness(
                    selected_reference=path.as_posix(),
                    container_destination=destination,
                    language="c" if suffix == ".c" else "c++",
                    source_suffix=suffix,
                    selection_reason=reason,
                ),
            )
        )
    if not candidates:
        raise TargetHarnessError("target manifest has no usable selected C/C++ reference harness")
    candidates.sort(key=lambda item: (-item[0], item[1].selected_reference))
    score, result = candidates[0]
    if len(candidates) > 1 and candidates[1][0] == score:
        tied = ", ".join(candidate.selected_reference for candidate_score, candidate in candidates if candidate_score == score)
        raise TargetHarnessError(f"ambiguous selected native harnesses: {tied}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-root", required=True, type=Path)
    parser.add_argument("--fuzz-target", default="")
    parser.add_argument("--field", choices=("json", "language", "destination"), default="json")
    args = parser.parse_args()
    try:
        result = select_native_harness(args.target_root, args.fuzz_target)
    except TargetHarnessError as exc:
        parser.error(str(exc))
    if args.field == "language":
        print(result.language)
    elif args.field == "destination":
        print(result.container_destination)
    else:
        print(json.dumps(asdict(result), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
