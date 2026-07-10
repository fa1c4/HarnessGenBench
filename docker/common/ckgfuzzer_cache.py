#!/usr/bin/env python3
"""Portable, bounded cache helpers for the CKGFuzzer integration."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any


CACHE_SCHEMA_VERSION = 2
PORTABLE_SOURCE_PREFIX = "@HGB_CKG_SOURCE@"
_PATH_JSON_FILES = (
    "codebase/api/src_api.json",
    "codebase/api/test_api.json",
)


class CacheValidationError(RuntimeError):
    """Raised when a cache entry is unsafe or incomplete."""


def _source_suffix(value: str, project_name: str, source_root: Path) -> str | None:
    value = value.replace("\\", "/")
    portable_prefix = f"{PORTABLE_SOURCE_PREFIX}/"
    if value == PORTABLE_SOURCE_PREFIX:
        return ""
    if value.startswith(portable_prefix):
        return value[len(portable_prefix) :]

    root_text = source_root.as_posix().rstrip("/")
    if value == root_text:
        return ""
    if value.startswith(f"{root_text}/"):
        return value[len(root_text) + 1 :]

    marker = "/source_code/"
    if marker not in value:
        return None
    tail = value.split(marker, 1)[1]
    project_prefix = f"{project_name}/"
    if tail == project_name:
        return ""
    if tail.startswith(project_prefix):
        return tail[len(project_prefix) :]
    return None


def portable_source_path(value: str, project_name: str, source_root: Path) -> str:
    suffix = _source_suffix(value, project_name, source_root)
    if suffix is None:
        return value
    return PORTABLE_SOURCE_PREFIX if not suffix else f"{PORTABLE_SOURCE_PREFIX}/{suffix}"


def resolved_source_path(value: str, project_name: str, source_root: Path) -> str:
    suffix = _source_suffix(value, project_name, source_root)
    if suffix is None:
        return value
    return str(source_root if not suffix else source_root / suffix)


def _rewrite_json(value: Any, rewrite) -> Any:
    if isinstance(value, dict):
        return {rewrite(str(key)): _rewrite_json(item, rewrite) for key, item in value.items()}
    if isinstance(value, list):
        return [_rewrite_json(item, rewrite) for item in value]
    if isinstance(value, str):
        return rewrite(value)
    return value


def rewrite_cache_paths(
    root: Path, project_name: str, source_root: Path, *, portable: bool
) -> list[Path]:
    rewrite = portable_source_path if portable else resolved_source_path
    rewritten: list[Path] = []
    for relative in _PATH_JSON_FILES:
        path = root / relative
        if not path.is_file():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        data = _rewrite_json(data, lambda value: rewrite(value, project_name, source_root))
        path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        rewritten.append(path)
    return rewritten


def _source_paths(src_api_path: Path) -> list[str]:
    data = json.loads(src_api_path.read_text(encoding="utf-8"))
    paths: list[str] = []
    for section in ("src", "head"):
        section_data = data.get(section, {})
        if isinstance(section_data, dict):
            paths.extend(str(path) for path in section_data)
    return paths


def validate_cache_tree(
    root: Path,
    project_name: str,
    source_root: Path,
    *,
    portable: bool,
    max_bytes: int,
    max_csv_bytes: int,
) -> dict[str, int]:
    required = (
        "api_list.json",
        "codebase/api/src_api.json",
        "api_summary/api_with_summary.json",
        "src/src_api_code.json",
        "api_combine/combined_call_graph.csv",
    )
    missing = [relative for relative in required if not (root / relative).is_file()]
    if missing:
        raise CacheValidationError(f"missing required cache files: {', '.join(missing)}")

    files = [path for path in root.rglob("*") if path.is_file()]
    total_bytes = sum(path.stat().st_size for path in files)
    if max_bytes > 0 and total_bytes > max_bytes:
        raise CacheValidationError(
            f"cache is {total_bytes} bytes, above configured limit {max_bytes}"
        )

    csv_files = [path for path in files if path.suffix.lower() == ".csv"]
    oversized_csv = [path for path in csv_files if max_csv_bytes > 0 and path.stat().st_size > max_csv_bytes]
    if oversized_csv:
        details = ", ".join(f"{path.name}={path.stat().st_size}" for path in oversized_csv[:4])
        raise CacheValidationError(
            f"cache CSV exceeds configured limit {max_csv_bytes}: {details}"
        )

    api_code = json.loads((root / "src/src_api_code.json").read_text(encoding="utf-8"))
    if not isinstance(api_code, dict) or not api_code:
        raise CacheValidationError("cache contains no resolved selected API source")

    src_api_path = root / "codebase/api/src_api.json"
    paths = _source_paths(src_api_path)
    if not paths:
        raise CacheValidationError("source API cache contains no source or header paths")
    if portable:
        invalid = [path for path in paths if not path.startswith(PORTABLE_SOURCE_PREFIX)]
        if invalid:
            raise CacheValidationError(f"cache contains non-portable source path: {invalid[0]}")
    else:
        unresolved = [path for path in paths if not Path(path).is_file()]
        if unresolved:
            raise CacheValidationError(f"cache source path does not resolve: {unresolved[0]}")

    return {
        "file_count": len(files),
        "csv_count": len(csv_files),
        "source_path_count": len(paths),
        "total_bytes": total_bytes,
    }


def _positive_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        return max(0, int(raw))
    except ValueError as exc:
        raise CacheValidationError(f"{name} must be an integer, got {raw!r}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("normalize", "rebase", "validate"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--portable", action="store_true")
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=_positive_int_env("CKGFUZZER_CACHE_MAX_BYTES", 1024 * 1024 * 1024),
    )
    parser.add_argument(
        "--max-csv-bytes",
        type=int,
        default=_positive_int_env("CKGFUZZER_CACHE_MAX_CSV_BYTES", 256 * 1024 * 1024),
    )
    args = parser.parse_args()

    try:
        if args.command == "normalize":
            rewritten = rewrite_cache_paths(
                args.root, args.project, args.source_root, portable=True
            )
            result = {"rewritten_files": len(rewritten)}
        elif args.command == "rebase":
            rewritten = rewrite_cache_paths(
                args.root, args.project, args.source_root, portable=False
            )
            result = {"rewritten_files": len(rewritten)}
        else:
            result = validate_cache_tree(
                args.root,
                args.project,
                args.source_root,
                portable=args.portable,
                max_bytes=args.max_bytes,
                max_csv_bytes=args.max_csv_bytes,
            )
    except (CacheValidationError, json.JSONDecodeError, OSError) as exc:
        print(f"ckgfuzzer_cache: {exc}", file=os.sys.stderr)
        return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
