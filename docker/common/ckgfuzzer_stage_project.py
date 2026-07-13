#!/usr/bin/env python3
"""Stage a HarnessGenBench target package for CKGFuzzer.

CKGFuzzer builds a synthetic Docker image for each target.  The image still
needs to look enough like the original FuzzBench builder for build.sh replay:
source repositories are rooted at $SRC, benchmark-local files are copied to
$SRC, and WORKDIR is mapped under the synthetic project root.
"""

from __future__ import annotations

import argparse
import json
import posixpath
import shlex
import shutil
from pathlib import Path
from typing import Any


def _copy_contents(src: Path, dst: Path) -> None:
    if not src.is_dir():
        return
    dst.mkdir(parents=True, exist_ok=True)
    for child in src.iterdir():
        target = dst / child.name
        if child.is_dir() and not child.is_symlink():
            shutil.copytree(child, target, symlinks=True, dirs_exist_ok=True)
        else:
            if target.exists() or target.is_symlink():
                target.unlink()
            shutil.copy2(child, target, follow_symlinks=False)


def _last_workdir(dockerfile: Path) -> str:
    if not dockerfile.is_file():
        return ""
    workdir = ""
    for raw_line in dockerfile.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not stripped.upper().startswith("WORKDIR"):
            continue
        value = stripped[len("WORKDIR") :].strip()
        if not value:
            continue
        try:
            parts = shlex.split(value, comments=True)
        except ValueError:
            parts = value.split()
        if parts:
            workdir = parts[0]
    return workdir


def map_workdir(workdir: str, project_name: str) -> str:
    """Map a FuzzBench WORKDIR into /src/<project_name>."""

    src_root = f"/src/{project_name}"
    if not workdir:
        return src_root
    workdir = workdir.strip()
    if workdir.startswith("${SRC}"):
        suffix = workdir[len("${SRC}") :]
        return posixpath.normpath(src_root + suffix)
    if workdir.startswith("$SRC"):
        suffix = workdir[len("$SRC") :]
        return posixpath.normpath(src_root + suffix)
    if workdir == "/src":
        return src_root
    if workdir.startswith("/src/"):
        return posixpath.normpath(src_root + workdir[len("/src") :])
    if workdir.startswith("/"):
        return posixpath.normpath(workdir)
    return posixpath.normpath(posixpath.join(src_root, workdir))


def stage_project(target_root: Path, project_dir: Path, analysis_dir: Path, project_name: str) -> dict[str, Any]:
    source_input = target_root / "source_input"
    benchmark = target_root / "fuzzbench_benchmark"
    if not source_input.is_dir():
        raise SystemExit(f"missing source_input: {source_input}")
    if not benchmark.is_dir():
        raise SystemExit(f"missing fuzzbench_benchmark: {benchmark}")

    if project_dir.exists():
        shutil.rmtree(project_dir)
    if analysis_dir.exists():
        shutil.rmtree(analysis_dir)
    project_dir.mkdir(parents=True, exist_ok=True)
    analysis_dir.mkdir(parents=True, exist_ok=True)

    _copy_contents(source_input, project_dir)
    _copy_contents(source_input, analysis_dir)

    # Reproduce Dockerfile COPY build.sh/*.dict/fuzzer sources to $SRC.  These
    # files are needed for build replay, but intentionally not copied to the
    # analysis source directory so generators do not see the benchmark answer.
    for child in benchmark.iterdir():
        # A package-only .dockerignore can intentionally hide a synthetic
        # top-level build.sh from native replay. It must not leak into the
        # distinct synthetic CKG project Docker context.
        if child.name in {"Dockerfile", "benchmark.yaml", ".dockerignore"}:
            continue
        target = project_dir / child.name
        if child.is_dir() and not child.is_symlink():
            shutil.copytree(child, target, symlinks=True, dirs_exist_ok=True)
        else:
            if target.exists() or target.is_symlink():
                target.unlink()
            shutil.copy2(child, target, follow_symlinks=False)

    workdir = _last_workdir(benchmark / "Dockerfile")
    build_dir = map_workdir(workdir, project_name)
    metadata = {
        "analysis_dir": str(analysis_dir),
        "benchmark_dir": str(benchmark),
        "build_dir": build_dir,
        "project_dir": str(project_dir),
        "project_name": project_name,
        "source_input_dir": str(source_input),
        "workdir": workdir,
    }
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-root", required=True)
    parser.add_argument("--project-dir", required=True)
    parser.add_argument("--analysis-dir", required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--metadata", default="")
    args = parser.parse_args()

    metadata = stage_project(
        Path(args.target_root),
        Path(args.project_dir),
        Path(args.analysis_dir),
        args.project_name,
    )
    if args.metadata:
        path = Path(args.metadata)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(metadata["build_dir"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
