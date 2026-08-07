#!/usr/bin/env python3
"""Physical split of a HarnessGenBench target package.

The blind-project protocol must expose only ``generator_input`` to a harness
generator container.  Reference harnesses, the selected-reference metadata,
and the exact native harness path live under ``evaluator_only`` and are mounted
exclusively for the evaluator.

Layout produced by :func:`split_package`::

    <package>/generator_input/
        source_input/   docs/   seeds/   dictionary/   build_metadata/
        source_repos.json
        target_manifest.json                # sanitized, generator-safe copy
        target_manifest.generator.json
    <package>/evaluator_only/
        reference_harnesses/   selected_reference_harnesses/
        benchmark_copy/   native_harness_path.json
        evaluator_manifest.json
        target_manifest.evaluator.json

This module is imported by ``scripts/hgb_targets.py`` (host) and by the
container-side evaluator, and by the offline pytest suite.  It must not depend
on any non-stdlib library.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

GENERATOR_INPUT_DIR = "generator_input"
EVALUATOR_ONLY_DIR = "evaluator_only"

GENERATOR_SUBDIRS = ("source_input", "docs", "seeds", "dictionary", "build_metadata")
EVALUATOR_SUBDIRS = (
    "reference_harnesses",
    "selected_reference_harnesses",
    "benchmark_copy",
)

# Fields that MUST NOT appear in target_manifest.generator.json because they
# leak the exact reference harness answer to a blind generator.
GENERATOR_FORBIDDEN_FIELDS = (
    "reference_harness_dir",
    "reference_harness_files",
    "selected_reference_harness_dir",
    "selected_reference_harness_files",
    "selected_reference_harness_count",
    "native_harness_path",
    "native_harness_destination",
    "selected_harness_apis",
    "selected_harness_call_sequence",
    "harness_body_digest",
)

# Tokens that must never be visible in a blind generator container.
BLIND_FORBIDDEN_PATH_TOKENS = (
    "reference_harnesses",
    "selected_reference",
    "fuzzbench_selected_harness_apis.json",
)


class PackageSplitError(RuntimeError):
    """The target package cannot be split into generator/evaluator halves."""


def _copy_tree(src: Path, dst: Path) -> None:
    if not src.exists():
        return
    dst.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)


def _move_contents(src: Path, dst: Path) -> None:
    if not src.is_dir():
        return
    dst.mkdir(parents=True, exist_ok=True)
    for child in src.iterdir():
        target = dst / child.name
        if target.exists():
            if target.is_dir() and not target.is_symlink():
                shutil.rmtree(target)
            else:
                target.unlink()
        shutil.move(str(child), str(target))


def _build_generator_manifest(full_manifest: dict[str, Any]) -> dict[str, Any]:
    """Return a manifest with all reference-harness fields stripped."""
    gen: dict[str, Any] = {}
    for key, value in full_manifest.items():
        if key in GENERATOR_FORBIDDEN_FIELDS:
            continue
        gen[key] = value
    gen["source_input_dir"] = "source_input"
    gen["docs_dir"] = "docs"
    gen["seeds_dir"] = "seeds"
    gen["dictionary_dir"] = "dictionary"
    gen["build_metadata_dir"] = "build_metadata"
    gen["protocol_visibility"] = "generator_input_only"
    return gen


def _build_evaluator_manifest(full_manifest: dict[str, Any], native_harness: dict[str, Any] | None) -> dict[str, Any]:
    ev: dict[str, Any] = dict(full_manifest)
    ev["reference_harness_dir"] = "reference_harnesses"
    ev["selected_reference_harness_dir"] = "selected_reference_harnesses"
    ev["benchmark_copy_dir"] = "benchmark_copy"
    ev["protocol_visibility"] = "evaluator_only"
    if native_harness:
        ev["native_harness_path"] = native_harness.get("selected_reference", "")
        ev["native_harness_destination"] = native_harness.get("container_destination", "")
    return ev


def _write_native_harness_path(evaluator_only: Path, native_harness: dict[str, Any] | None) -> None:
    payload = native_harness or {}
    (evaluator_only / "native_harness_path.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _write_evaluator_manifest(evaluator_only: Path) -> None:
    """Write evaluator_manifest.json naming the evaluator-only inputs.

    The split-aware sealed evaluator context validates that these files exist
    under /evaluator before combining them with /target/source_input.
    """
    payload = {
        "benchmark_copy_dir": "benchmark_copy",
        "native_harness_path_file": "native_harness_path.json",
        "reference_harnesses_dir": "reference_harnesses",
        "selected_reference_harnesses_dir": "selected_reference_harnesses",
        "target_manifest_file": "target_manifest.evaluator.json",
        "protocol_visibility": "evaluator_only",
    }
    (evaluator_only / "evaluator_manifest.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def split_package(package_dir: str | Path, *, native_harness: dict[str, Any] | None = None) -> dict[str, str]:
    """Split a monolithic target package into generator_input/evaluator_only.

    ``package_dir`` is the existing prepared package (with ``source_input``,
    ``reference_harnesses``, ``fuzzbench_benchmark``, ``target_manifest.json``).
    The function is idempotent: re-running it re-syncs the two halves.
    Returns a dict with the absolute paths of the two halves.
    """

    package = Path(package_dir)
    if not package.is_dir():
        raise PackageSplitError(f"target package not found: {package}")
    manifest_path = package / "target_manifest.json"
    if not manifest_path.is_file():
        raise PackageSplitError(f"target package missing target_manifest.json: {package}")
    full_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    generator_input = package / GENERATOR_INPUT_DIR
    evaluator_only = package / EVALUATOR_ONLY_DIR
    for half in (generator_input, evaluator_only):
        if half.exists():
            shutil.rmtree(half)
        half.mkdir(parents=True, exist_ok=True)

    # generator_input: source_input, docs, seeds, dictionary, build_metadata
    for sub in GENERATOR_SUBDIRS:
        src = package / sub
        if src.is_dir():
            _copy_tree(src, generator_input / sub)
        else:
            (generator_input / sub).mkdir(parents=True, exist_ok=True)
    # build_metadata holds the source provenance needed by the generator.
    if (package / "source_repos.json").is_file():
        shutil.copy2(package / "source_repos.json", generator_input / "build_metadata" / "source_repos.json")
        # Also expose source_repos.json at the generator_input top level so
        # consumers that read /target/source_repos.json (e.g. the split-aware
        # sealed evaluator context) find it under the blind generator mount.
        shutil.copy2(package / "source_repos.json", generator_input / "source_repos.json")

    generator_manifest = _build_generator_manifest(full_manifest)
    (generator_input / "target_manifest.generator.json").write_text(
        json.dumps(generator_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    # Sanitized generator-safe manifest at the canonical path so consumers that
    # read /target/target_manifest.json never see reference-harness fields and
    # never read the wrong (evaluator-only) manifest in blind mode.
    (generator_input / "target_manifest.json").write_text(
        json.dumps(generator_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # evaluator_only: reference_harnesses, selected_reference_harnesses, benchmark_copy
    references = package / "reference_harnesses"
    if references.is_dir():
        _copy_tree(references, evaluator_only / "reference_harnesses")
    else:
        (evaluator_only / "reference_harnesses").mkdir(parents=True, exist_ok=True)

    selected_dir = references / "selected"
    if selected_dir.is_dir():
        _copy_tree(selected_dir, evaluator_only / "selected_reference_harnesses")
    else:
        (evaluator_only / "selected_reference_harnesses").mkdir(parents=True, exist_ok=True)

    benchmark = package / "fuzzbench_benchmark"
    if benchmark.is_dir():
        _copy_tree(benchmark, evaluator_only / "benchmark_copy")
    else:
        (evaluator_only / "benchmark_copy").mkdir(parents=True, exist_ok=True)

    _write_native_harness_path(evaluator_only, native_harness)
    evaluator_manifest = _build_evaluator_manifest(full_manifest, native_harness)
    (evaluator_only / "target_manifest.evaluator.json").write_text(
        json.dumps(evaluator_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    # Concise evaluator manifest naming the evaluator-only files the sealed
    # context must combine (benchmark_copy, native_harness_path, reference
    # harnesses). This is distinct from the full target_manifest.evaluator.json
    # so the split-aware evaluator can validate its inputs by name.
    _write_evaluator_manifest(evaluator_only)

    return {
        "generator_input": str(generator_input),
        "evaluator_only": str(evaluator_only),
    }


def generator_manifest_has_no_reference_fields(generator_manifest: dict[str, Any]) -> list[str]:
    """Return a list of forbidden fields present in a generator manifest."""
    return [f for f in GENERATOR_FORBIDDEN_FIELDS if f in generator_manifest]


def audit_generator_input(generator_input: str | Path) -> dict[str, Any]:
    """Scan generator_input for forbidden reference-harness path tokens.

    Returns a dict with ``clean`` (bool) and ``hits`` (list of file paths).
    A clean generator_input must not contain ``reference_harnesses``,
    ``selected_reference``, or ``fuzzbench_selected_harness_apis.json``.
    """

    root = Path(generator_input)
    hits: list[str] = []
    if root.is_dir():
        for path in root.rglob("*"):
            name = path.name
            if any(token in name for token in BLIND_FORBIDDEN_PATH_TOKENS):
                hits.append(str(path))
            try:
                rel = str(path.relative_to(root))
            except ValueError:
                rel = str(path)
            if any(token in rel for token in BLIND_FORBIDDEN_PATH_TOKENS):
                if str(path) not in hits:
                    hits.append(str(path))
    return {"clean": not hits, "hits": sorted(set(hits))}


def load_generator_manifest(generator_input: str | Path) -> dict[str, Any]:
    path = Path(generator_input) / "target_manifest.generator.json"
    if not path.is_file():
        raise PackageSplitError(f"missing generator manifest: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def load_evaluator_manifest(evaluator_only: str | Path) -> dict[str, Any]:
    path = Path(evaluator_only) / "target_manifest.evaluator.json"
    if not path.is_file():
        raise PackageSplitError(f"missing evaluator manifest: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def load_native_harness_path(evaluator_only: str | Path) -> dict[str, Any]:
    path = Path(evaluator_only) / "native_harness_path.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Split a target package into generator_input/evaluator_only")
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--native-harness-json", default="")
    args = parser.parse_args()
    native = None
    if args.native_harness_json:
        native = json.loads(Path(args.native_harness_json).read_text(encoding="utf-8"))
    result = split_package(args.package, native_harness=native)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
