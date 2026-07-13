#!/usr/bin/env python3
"""Keep only usable source entries in a compilation database.

Generator integrations frequently get a non-empty ``compile_commands.json``
from a failed CMake configure.  Those files can contain only CMake compiler
probes, whose temporary sources disappear before an AST-based generator reads
them.  A non-empty database is therefore not enough: every retained record
must point at an existing C or C++ translation unit under an explicitly
allowed source root and have a usable working directory.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable


SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}
NOISE_PARTS = {"cmakefiles", "cmakescratch", "compilerid"}
NOISE_NAMES = {
    "cmakeccompilerabi.c",
    "cmakecxxcompilerabi.cpp",
    "cmakeccompilerid.c",
    "cmakecxxcompilerid.cpp",
}


def _resolve(value: object, directory: Path | None = None) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    path = Path(value)
    if not path.is_absolute() and directory is not None:
        path = directory / path
    return path.resolve(strict=False)


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def entry_is_usable(entry: object, source_roots: Iterable[Path]) -> bool:
    """Return whether one compilation-database entry is safe to consume."""

    if not isinstance(entry, dict):
        return False
    directory = _resolve(entry.get("directory"))
    if directory is None or not directory.is_dir():
        return False
    source = _resolve(entry.get("file"), directory)
    if source is None or not source.is_file() or source.suffix.lower() not in SOURCE_SUFFIXES:
        return False
    lower_parts = {part.lower() for part in source.parts}
    if lower_parts & NOISE_PARTS or source.name.lower() in NOISE_NAMES:
        return False
    roots = [root.resolve(strict=False) for root in source_roots]
    return any(_within(source, root) for root in roots)


def filter_compile_database(data: object, source_roots: Iterable[Path]) -> list[dict[str, Any]]:
    """Return only entries that refer to usable target translation units."""

    if not isinstance(data, list):
        return []
    roots = list(source_roots)
    return [entry for entry in data if entry_is_usable(entry, roots)]


def filter_file(input_path: Path, output_path: Path, source_roots: Iterable[Path]) -> tuple[int, int]:
    try:
        raw = json.loads(input_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid compilation database {input_path}: {exc}") from exc
    if not isinstance(raw, list):
        raise ValueError(f"compilation database is not a JSON array: {input_path}")
    retained = filter_compile_database(raw, source_roots)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=output_path.parent, prefix=f".{output_path.name}.", delete=False
    ) as tmp:
        json.dump(retained, tmp, indent=2)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, output_path)
    return len(raw), len(retained)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-root", action="append", required=True, type=Path)
    args = parser.parse_args()
    try:
        total, retained = filter_file(args.input, args.output, args.source_root)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps({"discarded": total - retained, "retained": retained, "total": total}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
