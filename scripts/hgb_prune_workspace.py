#!/usr/bin/env python3
"""Dry-run-first workspace pruning for HarnessGenBench matrix runs."""

from __future__ import annotations

import argparse
import csv
import json
import shutil
from pathlib import Path
from typing import Any

TRANSIENT_DIR_NAMES = {
    "g2fuzz_output",
    "ofg-work",
    "oss-fuzz",
    "pip-cache",
    "promefuzz_build",
    "promefuzz_out",
}


def repo_root() -> Path:
    cur = Path(__file__).resolve()
    for candidate in [cur.parent, *cur.parents]:
        if (candidate / ".git").exists() or ((candidate / "scripts").is_dir() and (candidate / "metadata").is_dir()):
            return candidate
    return Path.cwd().resolve()


def read_rows(matrix_file: Path) -> list[dict[str, str]]:
    if not matrix_file.exists():
        raise SystemExit(f"missing matrix file: {matrix_file}")
    with matrix_file.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def load_metadata(path: str) -> dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def path_size(path: Path) -> int:
    if not path.exists():
        return 0
    total = 0
    try:
        total += path.lstat().st_size
    except OSError:
        return 0
    if path.is_file() or path.is_symlink():
        return total
    for child in path.rglob("*"):
        try:
            total += child.lstat().st_size
        except OSError:
            continue
    return total


def human_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "K", "M", "G", "T"):
        if value < 1024 or unit == "T":
            return f"{int(value)}B" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{size}B"


def inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False

def read_key_value_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def add_candidate(candidates: dict[Path, str], path: Path, reason: str, allowed_root: Path) -> None:
    if not path.exists() or not path.is_dir():
        return
    if not inside(path, allowed_root):
        return
    candidates[path.resolve()] = reason


def collect_candidates(rows: list[dict[str, str]], workspace: Path, include_targets: bool, include_transients: bool) -> dict[Path, str]:
    candidates: dict[Path, str] = {}
    target_root = workspace / "targets"
    for row in rows:
        meta = load_metadata(row.get("metadata", ""))
        workspace_s = row.get("workspace") or ""
        pair_workspace = Path(workspace_s) if workspace_s else None
        if include_targets:
            manifest = meta.get("target_manifest")
            if manifest:
                package_dir = Path(str(manifest)).parent
                if inside(package_dir, target_root):
                    add_candidate(candidates, package_dir, "per-pair-target-package", target_root)
            if pair_workspace and inside(pair_workspace, workspace):
                host_command = read_key_value_file(pair_workspace / "host_command.txt")
                host_target_package = host_command.get("target_package")
                if host_target_package:
                    package_dir = Path(host_target_package)
                    if inside(package_dir, target_root):
                        add_candidate(candidates, package_dir, "per-pair-target-package", target_root)
        if include_transients:
            if pair_workspace and inside(pair_workspace, workspace):
                for name in TRANSIENT_DIR_NAMES:
                    add_candidate(candidates, pair_workspace / name, f"transient:{name}", workspace)
    return candidates


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id", help="matrix run id, for example 20260701T082111Z")
    parser.add_argument("--workspace", default=str(repo_root() / "workspace"), help="HarnessGenBench workspace directory")
    parser.add_argument("--apply", action="store_true", help="actually remove candidate directories; default is dry-run")
    parser.add_argument("--no-target-packages", action="store_true", help="do not consider old per-pair target packages")
    parser.add_argument("--no-transients", action="store_true", help="do not consider known transient generator directories")
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    matrix_dir = workspace / "matrix" / args.run_id
    rows = read_rows(matrix_dir / "matrix.tsv")
    candidates = collect_candidates(
        rows,
        workspace,
        include_targets=not args.no_target_packages,
        include_transients=not args.no_transients,
    )
    by_reason: dict[str, int] = {}
    total = 0
    sized: list[tuple[int, Path, str]] = []
    for path, reason in sorted(candidates.items(), key=lambda item: str(item[0])):
        size = path_size(path)
        total += size
        by_reason[reason] = by_reason.get(reason, 0) + size
        sized.append((size, path, reason))

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(f"{mode} prune for run {args.run_id}")
    print(f"candidate_dirs\t{len(sized)}")
    print(f"reclaimable_bytes\t{total}")
    print(f"reclaimable_human\t{human_bytes(total)}")
    for reason, size in sorted(by_reason.items()):
        print(f"reason\t{reason}\t{human_bytes(size)}")
    for size, path, reason in sorted(sized, reverse=True)[:40]:
        print(f"candidate\t{human_bytes(size)}\t{reason}\t{path}")

    if args.apply:
        for _size, path, _reason in sized:
            shutil.rmtree(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
