#!/usr/bin/env python3
"""Package the latest HarnessGenBench generation/matrix results.

The script is intentionally standalone and uses only the Python standard library.
It is meant to be run after one or more baseline matrix commands, for example:

    python3 scripts/packing_generation_results.py --run-prefix valuable_eta_20260812_103800

With no arguments, it packages the single most recent matrix run under
``workspace/matrix``.  The output is always written to
``results/generation_package_<time>.zip``.
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)([^\s'\"<>]+)"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(openai[_-]?api[_-]?key\s*[=:]\s*)([^\s'\"<>]+)"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(hgb[_-]?llm[_-]?api[_-]?key\s*[=:]\s*)([^\s'\"<>]+)"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(hf[_-]?token\s*[=:]\s*)([^\s'\"<>]+)"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(huggingface[_-]?token\s*[=:]\s*)([^\s'\"<>]+)"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)([^\s'\"<>]+)"), r"\1<REDACTED>"),
    (re.compile(r"(?i)(bearer\s+)(sk-[A-Za-z0-9_\-]+)"), r"\1<REDACTED>"),
    (re.compile(r"sk-[A-Za-z0-9_\-]{16,}"), "sk-<REDACTED>"),
)

TEXT_SUFFIXES = {
    "", ".txt", ".md", ".json", ".jsonl", ".yaml", ".yml", ".log", ".out",
    ".err", ".stderr", ".stdout", ".tsv", ".csv", ".sh", ".py", ".c", ".cc",
    ".cpp", ".h", ".hpp", ".toml", ".ini", ".cfg", ".conf", ".dockerfile",
    ".Dockerfile", ".html", ".xml", ".profdata", ".profraw", ".lcov",
}

DEFAULT_EXCLUDE_DIRS = {
    ".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "node_modules", ".venv", "venv", "env", ".cache", "pip-cache",
}
DEFAULT_SECRET_FILES = {
    "configs/set_api_key.sh",
    ".env",
    "openai_key.txt",
    "api_key.txt",
    "hf_token.txt",
}
PACKAGE_RE = re.compile(r"^generation_package_.*\.zip$")


def repo_root_from_script() -> Path:
    return Path(__file__).resolve().parents[1]


def now_stamp() -> str:
    return _dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def path_mtime(path: Path) -> float:
    try:
        if path.is_file():
            return path.stat().st_mtime
        candidates = [path]
        for child_name in ("matrix.tsv", "summary.json", "run_config.txt"):
            child = path / child_name
            if child.exists():
                candidates.append(child)
        return max(p.stat().st_mtime for p in candidates if p.exists())
    except OSError:
        return 0.0


def discover_matrix_dirs(repo: Path, *, matrix_dir: str | None, run_id: str | None, run_prefix: str | None, all_recent: bool) -> list[Path]:
    matrix_root = repo / "workspace" / "matrix"
    if matrix_dir:
        selected = Path(matrix_dir).expanduser()
        if not selected.is_absolute():
            selected = repo / selected
        if not selected.exists():
            raise SystemExit(f"matrix dir does not exist: {selected}")
        return [selected.resolve()]
    if run_id:
        selected = matrix_root / run_id
        if not selected.exists():
            raise SystemExit(f"matrix run id does not exist under workspace/matrix: {run_id}")
        return [selected.resolve()]
    if not matrix_root.exists():
        raise SystemExit("no workspace/matrix directory exists; run a baseline matrix first")
    candidates = [p for p in matrix_root.iterdir() if p.is_dir() and (p / "matrix.tsv").exists()]
    if run_prefix:
        candidates = [p for p in candidates if p.name.startswith(run_prefix)]
        if not candidates:
            raise SystemExit(f"no matrix runs found with prefix: {run_prefix}")
        return sorted((p.resolve() for p in candidates), key=lambda p: p.name)
    if all_recent:
        if not candidates:
            raise SystemExit("no matrix runs found under workspace/matrix")
        latest_mtime = max(path_mtime(p) for p in candidates)
        # Include runs started near the latest run. This is useful when five
        # baseline matrices are run one after another without a shared prefix.
        cutoff = latest_mtime - 6 * 3600
        selected = [p for p in candidates if path_mtime(p) >= cutoff]
        return sorted((p.resolve() for p in selected), key=path_mtime)
    if not candidates:
        raise SystemExit("no matrix runs found under workspace/matrix")
    return [max(candidates, key=path_mtime).resolve()]


def read_matrix_rows(matrix_dir: Path) -> list[dict[str, str]]:
    matrix_file = matrix_dir / "matrix.tsv"
    if not matrix_file.exists():
        return []
    rows: list[dict[str, str]] = []
    with matrix_file.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh, delimiter="\t")
        for row in reader:
            rows.append({str(k): str(v or "") for k, v in row.items() if k is not None})
    return rows


def safe_rel(path: Path, repo: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        h = hashlib.sha256(str(path.resolve()).encode("utf-8", errors="replace")).hexdigest()[:12]
        return f"external_paths/{h}/{path.name}"


def should_exclude(path: Path, repo: Path) -> str | None:
    rel = safe_rel(path, repo)
    parts = set(Path(rel).parts)
    if parts & DEFAULT_EXCLUDE_DIRS:
        return "excluded transient/cache directory"
    if rel in DEFAULT_SECRET_FILES:
        return "excluded known secret file"
    if path.name in {"set_api_key.sh", "openai_key.txt", "api_key.txt", "hf_token.txt"}:
        return "excluded known secret file"
    if path.parent.name == "results" and PACKAGE_RE.match(path.name):
        return "excluded previous generation package zip"
    return None


def is_probably_text(path: Path, max_probe: int = 8192) -> bool:
    if path.suffix in TEXT_SUFFIXES:
        return True
    try:
        data = path.read_bytes()[:max_probe]
    except OSError:
        return False
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        try:
            data.decode("latin-1")
            # Avoid treating dense binary as latin-1 text.
            printable = sum(32 <= b < 127 or b in b"\r\n\t" for b in data)
            return bool(data) and printable / max(len(data), 1) > 0.85
        except UnicodeDecodeError:
            return False


def redact_text(text: str) -> str:
    out = text
    for pattern, repl in SECRET_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def iter_files(path: Path) -> Iterable[Path]:
    if path.is_file():
        yield path
        return
    if path.is_dir():
        for root, dirs, files in os.walk(path):
            root_path = Path(root)
            dirs[:] = [d for d in dirs if d not in DEFAULT_EXCLUDE_DIRS]
            for name in files:
                yield root_path / name


def add_path_to_zip(
    zf: zipfile.ZipFile,
    path: Path,
    repo: Path,
    manifest: dict[str, Any],
    *,
    prefix: str = "",
    max_file_bytes: int | None = None,
) -> None:
    path = path.resolve()
    if not path.exists():
        manifest["missing_paths"].append(str(path))
        return
    for file_path in iter_files(path):
        reason = should_exclude(file_path, repo)
        rel = safe_rel(file_path, repo)
        arcname = f"{prefix}{rel}" if prefix else rel
        if reason:
            manifest["skipped_files"].append({"path": rel, "reason": reason})
            continue
        try:
            st = file_path.lstat()
        except OSError as exc:
            manifest["skipped_files"].append({"path": rel, "reason": f"stat failed: {exc}"})
            continue
        if stat.S_ISLNK(st.st_mode):
            manifest["skipped_files"].append({"path": rel, "reason": "skipped symlink"})
            continue
        if max_file_bytes is not None and st.st_size > max_file_bytes:
            manifest["skipped_files"].append({
                "path": rel,
                "reason": f"file larger than max_file_mb ({st.st_size} bytes)",
                "size_bytes": st.st_size,
            })
            continue
        if arcname in manifest["_seen_arcnames"]:
            continue
        manifest["_seen_arcnames"].add(arcname)
        try:
            if is_probably_text(file_path):
                text = file_path.read_text(encoding="utf-8", errors="replace")
                redacted = redact_text(text)
                zf.writestr(arcname, redacted)
                manifest["included_files"].append({"path": rel, "archive_path": arcname, "size_bytes": st.st_size, "redacted_text": redacted != text})
            else:
                zf.write(file_path, arcname)
                manifest["included_files"].append({"path": rel, "archive_path": arcname, "size_bytes": st.st_size, "redacted_text": False})
        except OSError as exc:
            manifest["skipped_files"].append({"path": rel, "reason": f"read/write failed: {exc}"})


def parse_json_file(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def collect_referenced_paths(repo: Path, matrix_dirs: list[Path], rows_by_matrix: dict[str, list[dict[str, str]]]) -> list[Path]:
    paths: list[Path] = []
    for matrix_dir in matrix_dirs:
        paths.append(matrix_dir)
        run_id = matrix_dir.name
        tp = repo / "workspace" / "target-packages" / run_id
        if tp.exists():
            paths.append(tp)
        for row in rows_by_matrix.get(str(matrix_dir), []):
            for key in ("workspace", "metadata", "summary"):
                value = row.get(key, "").strip()
                if not value:
                    continue
                p = Path(value)
                if not p.is_absolute():
                    p = repo / p
                if p.exists():
                    paths.append(p)
                elif key == "workspace":
                    # Some rows contain an expected workspace path even when the
                    # pair failed before materializing metadata. Record the miss.
                    paths.append(p)
    # Add useful global metadata and source-side run contracts.
    for rel in (
        "README.md",
        "Makefile",
        "metadata/baseline_contracts.yaml",
        "metadata/work_index.yaml",
        "metadata/elfuzz_target_adapters.yaml",
        "metadata/g2fuzz_target_adapters.yaml",
        "metadata/fuzzbench_valuable_targets.yaml",
        "scripts/hgb_run_baseline.sh",
        "scripts/hgb_run_baseline_matrix.sh",
        "scripts/hgb_generate_matrix.sh",
        "scripts/hgb_collect_matrix.py",
        "scripts/packing_generation_results.py",
    ):
        p = repo / rel
        if p.exists():
            paths.append(p)
    return paths


def summarize_rows(rows_by_matrix: dict[str, list[dict[str, str]]]) -> dict[str, Any]:
    status_counts: Counter[str] = Counter()
    generator_counts: dict[str, Counter[str]] = {}
    total = 0
    for rows in rows_by_matrix.values():
        for row in rows:
            total += 1
            status = row.get("status") or ""
            gen = row.get("generator") or ""
            status_counts[status] += 1
            generator_counts.setdefault(gen, Counter())[status] += 1
    return {
        "row_count": total,
        "status_counts": dict(sorted(status_counts.items())),
        "generator_status_counts": {g: dict(sorted(c.items())) for g, c in sorted(generator_counts.items())},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package recent HarnessGenBench generation results into results/generation_package_<time>.zip")
    parser.add_argument("--matrix-dir", help="Specific workspace/matrix/<run_id> directory to package")
    parser.add_argument("--run-id", help="Specific matrix run id under workspace/matrix")
    parser.add_argument("--run-prefix", help="Package all matrix runs whose run id starts with this prefix")
    parser.add_argument("--all-recent", action="store_true", help="Package all matrix runs modified within 6 hours of the latest run")
    parser.add_argument("--output", help="Explicit output zip path; default is results/generation_package_<time>.zip")
    parser.add_argument("--max-file-mb", type=float, default=256.0, help="Skip files larger than this many MiB; use 0 for no limit (default: 256)")
    parser.add_argument("--include-results-dir", action="store_true", help="Also include non-package files already under results/")
    args = parser.parse_args(argv)

    repo = repo_root_from_script()
    max_file_bytes = None if args.max_file_mb == 0 else int(args.max_file_mb * 1024 * 1024)
    matrix_dirs = discover_matrix_dirs(repo, matrix_dir=args.matrix_dir, run_id=args.run_id, run_prefix=args.run_prefix, all_recent=args.all_recent)
    rows_by_matrix = {str(m): read_matrix_rows(m) for m in matrix_dirs}

    output = Path(args.output).expanduser() if args.output else repo / "results" / f"generation_package_{now_stamp()}.zip"
    if not output.is_absolute():
        output = repo / output
    output.parent.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, Any] = {
        "schema_version": 1,
        "created_at_local": _dt.datetime.now().isoformat(timespec="seconds"),
        "repo_root": str(repo),
        "selected_matrix_dirs": [safe_rel(m, repo) for m in matrix_dirs],
        "selection": {
            "matrix_dir": args.matrix_dir,
            "run_id": args.run_id,
            "run_prefix": args.run_prefix,
            "all_recent": args.all_recent,
        },
        "summary": summarize_rows(rows_by_matrix),
        "included_files": [],
        "skipped_files": [],
        "missing_paths": [],
        "_seen_arcnames": set(),
    }

    paths = collect_referenced_paths(repo, matrix_dirs, rows_by_matrix)
    if args.include_results_dir:
        results_dir = repo / "results"
        if results_dir.exists():
            paths.append(results_dir)

    # Preserve order while deduplicating by resolved path.
    deduped: list[Path] = []
    seen: set[str] = set()
    for p in paths:
        key = str(p.resolve()) if p.exists() else str(p)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(p)

    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for p in deduped:
            add_path_to_zip(zf, p, repo, manifest, max_file_bytes=max_file_bytes)
        # JSON cannot serialize the internal set; drop it before writing.
        seen_arcnames = manifest.pop("_seen_arcnames")
        manifest["archive_file_count"] = len(seen_arcnames) + 1
        zf.writestr("PACKAGE_MANIFEST.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    print(output)
    print(json.dumps({
        "package": str(output),
        "matrix_dirs": manifest["selected_matrix_dirs"],
        "row_count": manifest["summary"]["row_count"],
        "status_counts": manifest["summary"]["status_counts"],
        "skipped_files": len(manifest["skipped_files"]),
        "missing_paths": len(manifest["missing_paths"]),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
