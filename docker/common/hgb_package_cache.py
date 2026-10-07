"""Publish versioned target packages without replacing files used by consumers."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Callable

COMPLETE_FILE = ".hgb-package-complete.json"
CACHE_VERSION = 1


def fingerprint(inputs: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()


def tree_stamp(root: Path) -> list[tuple[Any, ...]]:
    """Check recipe inputs using metadata; do not reread potentially large corpora."""
    entries = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in {".git", "__pycache__"})
        for name in sorted([*dirs, *files]):
            if name.endswith(".pyc"):
                continue
            path = Path(directory) / name
            stat = path.lstat()
            entries.append((path.relative_to(root).as_posix(), stat.st_mode,
                            stat.st_size, stat.st_mtime_ns,
                            os.readlink(path) if path.is_symlink() else ""))
    return entries


def package_complete(package: Path, signature: str, inputs: dict[str, Any]) -> bool:
    """Validate publication metadata and required roots without scanning all sources."""
    try:
        marker = json.loads((package / COMPLETE_FILE).read_text())
        manifest_bytes = (package / "target_manifest.json").read_bytes()
        manifest = json.loads(manifest_bytes)
        if (marker.get("version") != CACHE_VERSION or marker.get("signature") != signature
                or marker.get("manifest_sha256") != hashlib.sha256(manifest_bytes).hexdigest()
                or manifest.get("source_status") not in {"materialized", "benchmark_only"}):
            return False
        for name in ("source_input", "reference_harnesses", "docs", "seeds", "dictionary", "fuzzbench_benchmark"):
            if not (package / name).is_dir():
                return False
        for record in manifest.get("source_repos", []):
            path = package / record.get("package_path", "")
            if not record.get("package_path") or not path.is_dir() or not any(path.iterdir()):
                return False
        if inputs["split_enabled"]:
            gen_root = package / "generator_input"
            ev_root = package / "evaluator_only"
            for name in ("source_input", "docs", "seeds", "dictionary", "build_metadata"):
                if not (gen_root / name).is_dir():
                    return False
            gen = json.loads((gen_root / "target_manifest.json").read_text())
            safe_gen = json.loads((gen_root / "target_manifest.generator.json").read_text())
            ev = json.loads((ev_root / "target_manifest.evaluator.json").read_text())
            mount = json.loads((ev_root / "evaluator_manifest.json").read_text())
            native = json.loads((ev_root / "native_harness_path.json").read_text())
            if (gen != safe_gen or gen.get("target") != manifest.get("target")
                    or gen.get("protocol_visibility") != "generator_input_only"
                    or ev.get("target") != manifest.get("target")
                    or mount.get("protocol_visibility") != "evaluator_only"):
                return False
            forbidden = ("reference_harness_dir", "reference_harness_files", "selected_reference_harness_dir",
                         "selected_reference_harness_files", "selected_reference_harness_count", "native_harness_path",
                         "native_harness_destination", "selected_harness_apis", "selected_harness_call_sequence",
                         "harness_body_digest")
            if any(key in gen for key in forbidden):
                return False
            for name in ("reference_harnesses", "selected_reference_harnesses", "benchmark_copy"):
                if not (ev_root / name).is_dir():
                    return False
            if not (ev_root / "reference_canary.txt").is_file():
                return False
            if inputs["require_split"] and (not native.get("selected_reference") or not native.get("container_destination")):
                return False
        return True
    except (OSError, ValueError, TypeError, KeyError):
        return False


@contextlib.contextmanager
def _lock(path: Path):
    with path.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def _publish_alias(destination: Path, package: Path) -> None:
    """Retain old real directories: an existing bind mount may still use them."""
    temporary = destination.with_name(f".{destination.name}.link-{uuid.uuid4().hex}")
    previous = None
    try:
        temporary.symlink_to(os.path.relpath(package, destination.parent), target_is_directory=True)
        if destination.exists() and not destination.is_symlink():
            if not destination.is_dir():
                raise ValueError(f"package output is not a directory: {destination}")
            previous = destination.with_name(f".{destination.name}.previous-{uuid.uuid4().hex}")
            os.replace(destination, previous)
        os.replace(temporary, destination)
    except BaseException:
        if previous is not None and not destination.exists():
            os.replace(previous, destination)
        raise
    finally:
        temporary.unlink(missing_ok=True)


def prepare_package(root: Path, target: str, output: Path, inputs: dict[str, Any],
                    build: Callable[[Path], Any], *, force: bool = False) -> Path:
    # Resolve parent aliases, but never follow an existing output alias: rebuilding
    # must publish a new version rather than mutate its old referent.
    output = output.expanduser().absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    output = output.parent.resolve() / output.name
    cache = Path(os.environ.get("HGB_TARGET_PACKAGE_CACHE_DIR", str(root / "workspace" / "target-package-cache"))).expanduser().resolve()
    cache.mkdir(parents=True, exist_ok=True)
    source_locks = root / "artifacts" / "fuzzbench-target-sources"
    source_locks.mkdir(parents=True, exist_ok=True)
    signature = fingerprint(inputs)
    target_key = hashlib.sha256(target.encode()).hexdigest()
    output_key = hashlib.sha256(str(output).encode()).hexdigest()
    # A target lock also serializes materialization of its mutable artifact checkout
    # when callers request different layouts or protocols concurrently.
    with _lock(source_locks / f".output-{output_key}.lock"), _lock(source_locks / f".package-{target_key}.lock"):
        versions = cache / signature
        versions.mkdir(exist_ok=True)
        current = versions / "current"
        if not force:
            for candidate in (output, current):
                if package_complete(candidate, signature, inputs):
                    version = candidate.resolve()
                    if version != output:
                        _publish_alias(output, version)
                    print(f"target package reused: {target} ({signature[:12]}; captured source revisions retained)", file=sys.stderr)
                    return version
        reason = "forced" if force else "cache miss"
        if not force and output.exists():
            try:
                previous_marker = json.loads((output / COMPLETE_FILE).read_text())
                reason = "incompatible inputs" if previous_marker.get("signature") != signature else "incomplete package"
            except (OSError, ValueError, TypeError):
                reason = "legacy or incomplete package without completion metadata"
        elif not force and current.exists():
            reason = "incomplete cached package"
        stage = Path(tempfile.mkdtemp(prefix=".building-", dir=versions))
        try:
            build(stage)
            manifest_bytes = (stage / "target_manifest.json").read_bytes()
            manifest = json.loads(manifest_bytes)
            marker = {"version": CACHE_VERSION, "signature": signature, "inputs": inputs,
                      "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                      "source_revisions": [{key: record.get(key) for key in
                                            ("dest", "requested_revision", "checked_out_commit", "captured_revision", "revision")}
                                           for record in manifest.get("source_repos", [])]}
            (stage / COMPLETE_FILE).write_text(json.dumps(marker, sort_keys=True, indent=2) + "\n")
            complete = package_complete(stage, signature, inputs)
            if not complete:
                # Preserve the best-effort monolithic result for a first build, but
                # never overwrite an existing valid/materialized package with it.
                for candidate in (output, current):
                    try:
                        old = json.loads((candidate / "target_manifest.json").read_text())
                        if old.get("source_status") in {"materialized", "benchmark_only"}:
                            raise RuntimeError("replacement package is incomplete; previous package preserved")
                    except (OSError, ValueError):
                        pass
                (stage / COMPLETE_FILE).unlink()
            version = versions / f"package-{uuid.uuid4().hex}"
            os.replace(stage, version)
            if complete:
                _publish_alias(current, version)
            _publish_alias(output, version)
            print(f"target package rebuilt: {target} ({reason}; {signature[:12]})", file=sys.stderr)
            return version
        finally:
            if stage.exists():
                shutil.rmtree(stage)
