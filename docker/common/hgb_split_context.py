#!/usr/bin/env python3
"""Split-aware sealed evaluator context for HarnessGenBench.

In blind-project mode the target package is physically split into a
generator-visible half (``/target`` = ``generator_input``) and an
evaluator-only half (``/evaluator`` = ``evaluator_only``).  The shared harness
evaluator must combine files from *both* halves to build a reproducible
FuzzBench Docker context:

    /target/source_input               -> sealed/source_input
    /target/source_repos.json          -> sealed/source_repos.json
    /evaluator/benchmark_copy          -> sealed/fuzzbench_benchmark
    /evaluator/native_harness_path.json-> sealed/native_harness_path.json
    /evaluator/reference_harnesses     -> sealed/reference_harnesses (audit only)

The previous implementation called
``prepare_verification_context(evaluator_root, work_dir)`` which failed because
``evaluator_only/`` lacks ``source_input`` and ``source_repos.json``, or
``prepare_verification_context(target_root, work_dir)`` which failed because
``generator_input/`` lacks ``fuzzbench_benchmark``.  This module fixes that by
loading both halves explicitly and assembling the sealed context from the
correct source for each file.

Reference harnesses are copied into the sealed context *only* for the
evaluator-side similarity/copy audit that runs *after* generation.  They are
never copied into the generator workspace.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Reuse the Dockerfile rewriting / build-tool patching logic so the sealed
# context stays consistent with the monolithic verifier path.
from ckgfuzzer_verifier_context import (  # noqa: E402
    VerificationContextError,
    _assert_reproducible_sources,
    _copy_reference_harnesses,
    _patch_legacy_build_tool_bootstrap,
    _rewrite_dockerfile,
    _source_records,
    _SYNTHETIC_BUILD_SCRIPT_MARKER,
)


@dataclass
class SplitTargetContext:
    """Resolved paths from the generator and evaluator halves."""

    generator_root: Path
    evaluator_root: Path
    source_input: Path
    source_repos: Path
    benchmark_copy: Path
    native_harness_path: Path
    reference_harnesses: Path
    evaluator_manifest: Path

    @classmethod
    def load(cls, generator_root: str | Path, evaluator_root: str | Path) -> "SplitTargetContext":
        """Validate that both halves provide their required files.

        Raises :class:`VerificationContextError` naming the missing file.
        """
        gen = Path(generator_root)
        evl = Path(evaluator_root)

        source_input = gen / "source_input"
        if not source_input.is_dir() or not any(source_input.iterdir()):
            raise VerificationContextError(
                f"generator half missing source_input: {source_input}"
            )

        source_repos = gen / "source_repos.json"
        # source_repos.json may also live under build_metadata for older splits.
        if not source_repos.is_file():
            alt = gen / "build_metadata" / "source_repos.json"
            if alt.is_file():
                source_repos = alt
        if not source_repos.is_file():
            raise VerificationContextError(
                f"generator half missing source_repos.json: {source_repos}"
            )

        benchmark_copy = evl / "benchmark_copy"
        if not benchmark_copy.is_dir():
            raise VerificationContextError(
                f"evaluator half missing benchmark_copy: {benchmark_copy}"
            )
        dockerfile = benchmark_copy / "Dockerfile"
        if not dockerfile.is_file():
            raise VerificationContextError(
                f"evaluator half benchmark_copy missing Dockerfile: {dockerfile}"
            )

        native_harness_path = evl / "native_harness_path.json"
        if not native_harness_path.is_file():
            raise VerificationContextError(
                f"evaluator half missing native_harness_path.json: {native_harness_path}"
            )

        reference_harnesses = evl / "reference_harnesses"
        if not reference_harnesses.is_dir():
            # Some packages store references under selected_reference_harnesses.
            reference_harnesses = evl / "selected_reference_harnesses"
        if not reference_harnesses.is_dir():
            raise VerificationContextError(
                f"evaluator half missing reference_harnesses: {evl / 'reference_harnesses'}"
            )

        evaluator_manifest = evl / "evaluator_manifest.json"
        if not evaluator_manifest.is_file():
            # Not strictly required; fall back to the evaluator target manifest.
            evaluator_manifest = evl / "target_manifest.evaluator.json"

        return cls(
            generator_root=gen,
            evaluator_root=evl,
            source_input=source_input,
            source_repos=source_repos,
            benchmark_copy=benchmark_copy,
            native_harness_path=native_harness_path,
            reference_harnesses=reference_harnesses,
            evaluator_manifest=evaluator_manifest,
        )

    def read_native_harness(self) -> dict[str, Any]:
        try:
            return json.loads(self.native_harness_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise VerificationContextError(
                f"invalid native_harness_path.json: {self.native_harness_path}: {exc}"
            ) from exc

    def captured_unpinned_source_count(self) -> int:
        try:
            return sum(
                1
                for record in _source_records(self.generator_root)
                if record.get("revision_status") == "captured_unpinned"
            )
        except VerificationContextError:
            return 0


def _copytree(src: Path, dst: Path) -> None:
    if not src.exists():
        return
    dst.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)


def _mirror_benchmark_context_files(benchmark: Path, sealed: Path) -> int:
    """Expose benchmark-copy root files at the Docker build-context root.

    FuzzBench Dockerfiles frequently use root-relative ``COPY``/``ADD`` inputs
    such as ``seeds/``, ``target.cc`` or ``cms_transform_fuzzer.cc``. The split
    evaluator keeps a full ``fuzzbench_benchmark/`` audit copy, but Docker only
    sees paths rooted at ``sealed/``. Mirror the evaluator-only benchmark
    context there after synthetic wrappers have been removed.
    """

    mirrored = 0
    for child in sorted(benchmark.iterdir()):
        if child.name == "Dockerfile":
            continue
        destination = sealed / child.name
        if destination.exists() or destination.is_symlink():
            if destination.is_dir() and not destination.is_symlink():
                shutil.rmtree(destination)
            else:
                destination.unlink()
        if child.is_dir() and not child.is_symlink():
            shutil.copytree(child, destination, symlinks=True)
        else:
            shutil.copy2(child, destination, follow_symlinks=False)
        mirrored += 1
    return mirrored


def create_sealed_build_context(
    context: SplitTargetContext,
    work_dir: Path,
) -> dict[str, Any]:
    """Assemble a sealed Docker context from the split halves.

    The context directory layout::

        sealed/
            source_input/          <- from generator half
            source_repos.json      <- from generator half
            fuzzbench_benchmark/   <- from evaluator half (Dockerfile, build.sh)
            native_harness_path.json
            reference_harnesses/   <- evaluator-only, audit use only
            Dockerfile             <- rewritten from benchmark_copy

    Returns a dict with ``context_dir``, ``dockerfile``, ``mode``, and audit
    counters, compatible with the existing evaluator ``sealed_context`` shape.
    """

    # Validate source provenance using the generator half (has source_repos).
    _assert_reproducible_sources(context.generator_root)
    captured_unpinned = context.captured_unpinned_source_count()

    sealed = work_dir / "sealed_context"
    if sealed.exists():
        shutil.rmtree(sealed)
    sealed.mkdir(parents=True, exist_ok=True)

    # source_input and source_repos from the generator half.
    _copytree(context.source_input, sealed / "source_input")
    shutil.copy2(context.source_repos, sealed / "source_repos.json")

    # benchmark_copy from the evaluator half provides the Dockerfile + build.sh.
    benchmark_dst = sealed / "fuzzbench_benchmark"
    _copytree(context.benchmark_copy, benchmark_dst)

    # native_harness_path.json and reference harnesses from the evaluator half.
    shutil.copy2(context.native_harness_path, sealed / "native_harness_path.json")
    _copytree(context.reference_harnesses, sealed / "reference_harnesses")

    # Exclude a synthetic top-level build.sh that is not the real FuzzBench one.
    synthetic_build = benchmark_dst / "build.sh"
    excluded_synthetic_build = False
    if synthetic_build.is_file() and _SYNTHETIC_BUILD_SCRIPT_MARKER in synthetic_build.read_text(
        encoding="utf-8", errors="replace"
    ):
        synthetic_build.unlink()
        excluded_synthetic_build = True

    build_tool_fallbacks = _patch_legacy_build_tool_bootstrap(benchmark_dst)

    # Keep the evaluator-only benchmark copy under fuzzbench_benchmark for
    # auditability, and expose its build-context inputs at sealed/ so the
    # rewritten Dockerfile's root-relative COPY/ADD instructions still work.
    benchmark_context_file_count = _mirror_benchmark_context_files(benchmark_dst, sealed)

    # Rewrite the benchmark Dockerfile to use the sealed source snapshot.
    dockerfile_src = benchmark_dst / "Dockerfile"
    rewritten, removed = _rewrite_dockerfile(dockerfile_src)
    # Enforce the strict overlay copy order (reproduction-delta section 3):
    # the non-target sibling harness restore must NOT copy the selected native
    # harness, and the candidate overlay (already staged into source_input by
    # build_candidate_image) must be the final write at the native path.
    rewritten = rewritten.replace(
        "COPY hgb_reference_harnesses/ /src/",
        "COPY hgb_non_target_reference_harnesses/ /src/",
    )
    sealed_dockerfile = sealed / "Dockerfile"
    sealed_dockerfile.write_text(rewritten, encoding="utf-8")

    # Restore only non-target sibling harnesses into the sealed context so the
    # FuzzBench build can compile sibling fuzzers (e.g. Mbed TLS, OpenSSL)
    # WITHOUT overwriting the candidate at the native harness path. These are
    # evaluator-only; they never reach the generator workspace.
    native_dest = ""
    try:
        native_info = context.read_native_harness()
        native_dest = str(native_info.get("container_destination", ""))
    except VerificationContextError:
        native_dest = ""
    restore_audit = evaluator_restore_non_target_harnesses(
        context.reference_harnesses, native_dest, sealed,
    )

    return {
        "context_dir": str(sealed),
        "dockerfile": str(sealed_dockerfile),
        "mode": "split_sealed_source_snapshot",
        "removed_acquisition_commands": removed,
        "excluded_synthetic_build_script": excluded_synthetic_build,
        "captured_unpinned_source_count": captured_unpinned,
        "build_tool_fallbacks": build_tool_fallbacks,
        "generator_root": str(context.generator_root),
        "evaluator_root": str(context.evaluator_root),
        "reference_restore_audit": restore_audit,
        "benchmark_context_file_count": benchmark_context_file_count,
    }


def _copy_reference_harnesses_into(sealed: Path, reference_harnesses: Path) -> None:
    """Restore stripped reference harnesses into the sealed context.

    Mirrors ``_copy_reference_harnesses`` from ``ckgfuzzer_verifier_context``
    but reads from the evaluator-only ``reference_harnesses`` directory and
    writes into ``sealed/hgb_reference_harnesses`` so the FuzzBench build can
    compile sibling fuzzers.  The ``selected`` subdirectory is merged as a
    compatibility fallback.
    """

    destination = sealed / "hgb_reference_harnesses"
    destination.mkdir(parents=True, exist_ok=True)
    if not reference_harnesses.is_dir():
        return
    for child in reference_harnesses.iterdir():
        if child.name == "selected":
            continue
        target = destination / child.name
        if child.is_dir() and not child.is_symlink():
            shutil.copytree(child, target, symlinks=True, dirs_exist_ok=True)
        elif child.is_file() or child.is_symlink():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(child, target, follow_symlinks=False)
    selected = reference_harnesses / "selected"
    if selected.is_dir():
        for label in selected.iterdir():
            if label.is_dir():
                shutil.copytree(label, destination, symlinks=True, dirs_exist_ok=True)


def evaluator_restore_non_target_harnesses(
    reference_harnesses: Path,
    native_destination: str,
    sealed: Path,
) -> dict[str, Any]:
    """Restore only non-target sibling harnesses into the sealed context.

    HGB5 issue: ``_copy_reference_harnesses_into`` merged
    ``reference_harnesses/selected`` into ``hgb_reference_harnesses``, and the
    rewritten Dockerfile copied it over ``/src/`` *after* the candidate overlay,
    replacing the candidate with the reference harness.

    This strict restore copies only sibling harnesses that are NOT the selected
    native harness path, writes them into ``hgb_non_target_reference_harnesses``,
    and never copies the exact selected target harness.  Skipped paths are
    recorded in the returned audit so the evaluator can prove the candidate was
    the final write at the native path.
    """

    destination = sealed / "hgb_non_target_reference_harnesses"
    destination.mkdir(parents=True, exist_ok=True)
    rel_native = native_destination
    for prefix in ("/src/", "src/"):
        if rel_native.startswith(prefix):
            rel_native = rel_native[len(prefix):]
            break
    rel_native = rel_native.lstrip("/")
    native_name = Path(rel_native).name
    skipped: list[str] = []
    restored: list[str] = []
    if not reference_harnesses.is_dir():
        return {"restored": [], "skipped": [], "native_destination": native_destination}
    for child in reference_harnesses.iterdir():
        if child.name == "selected":
            continue
        target = destination / child.name
        if child.is_dir() and not child.is_symlink():
            shutil.copytree(child, target, symlinks=True, dirs_exist_ok=True)
            restored.append(child.name)
        elif child.is_file() or child.is_symlink():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(child, target, follow_symlinks=False)
            restored.append(child.name)
    # The selected/ directory holds the exact native harness. Skip the file that
    # matches the native destination path/name so it can never overwrite the
    # candidate; restore only the other siblings.
    selected = reference_harnesses / "selected"
    if selected.is_dir():
        for label in selected.iterdir():
            if not label.is_dir():
                continue
            for src in sorted(label.rglob("*")):
                if not src.is_file():
                    continue
                src_rel = src.relative_to(label)
                if str(src_rel) == rel_native or src.name == native_name:
                    skipped.append(str(src_rel))
                    continue
                dst = destination / src_rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                if not dst.exists():
                    shutil.copy2(src, dst, follow_symlinks=False)
                    restored.append(str(src_rel))
    audit = {
        "native_destination": native_destination,
        "restored": sorted(set(restored)),
        "skipped": sorted(set(skipped)),
    }
    (sealed / "reference_restore_audit.json").write_text(
        json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return audit


def verify_overlay_path(native_destination: str, sealed_context_dir: Path) -> Path:
    """Resolve the candidate overlay path inside the sealed source tree.

    The overlay path must be exact and inside the sealed project source tree
    or benchmark copy.  Path traversal (``..``) is rejected.
    """

    rel = native_destination
    for prefix in ("/src/", "src/"):
        if rel.startswith(prefix):
            rel = rel[len(prefix):]
            break
    if not rel or rel.startswith("/"):
        raise VerificationContextError(f"unsafe native destination: {native_destination}")
    if ".." in Path(rel).parts:
        raise VerificationContextError(f"path traversal in native destination: {native_destination}")
    overlay = sealed_context_dir / "source_input" / rel
    # Resolve and confirm it stays under the sealed context.
    try:
        resolved = overlay.resolve(strict=False)
        base = sealed_context_dir.resolve(strict=False)
        resolved.relative_to(base)
    except ValueError as exc:
        raise VerificationContextError(
            f"overlay path escapes sealed context: {native_destination}"
        ) from exc
    return overlay


def audit_candidate_reference_copy(
    candidate_path: Path,
    reference_harnesses: Path,
    *,
    canary: str = "",
) -> dict[str, Any]:
    """Compare a candidate to evaluator-only reference harnesses.

    Runs *after* generation.  Reports whether the candidate is an exact or
    near-exact copy of any reference harness, and whether the reference canary
    token leaked into the candidate.  This audit never runs before generation
    and never writes reference contents into generator-visible directories.
    """

    import hashlib

    result: dict[str, Any] = {
        "candidate": str(candidate_path),
        "exact_copy": False,
        "near_duplicate_reference": False,
        "contains_reference_canary": False,
        "matched_reference": "",
        "canary": canary,
    }
    if not candidate_path.is_file():
        result["error"] = "candidate file not found"
        return result
    candidate_bytes = candidate_path.read_bytes()
    candidate_sha = hashlib.sha256(candidate_bytes).hexdigest()
    if canary and canary.encode("utf-8", errors="replace") in candidate_bytes:
        result["contains_reference_canary"] = True

    if not reference_harnesses.is_dir():
        return result

    candidate_text = candidate_path.read_text(encoding="utf-8", errors="replace")
    # Normalize whitespace for a near-duplicate comparison.
    candidate_norm = "".join(candidate_text.split())

    for ref in sorted(reference_harnesses.rglob("*")):
        if not ref.is_file():
            continue
        if ref.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"}:
            continue
        try:
            ref_bytes = ref.read_bytes()
        except OSError:
            continue
        ref_sha = hashlib.sha256(ref_bytes).hexdigest()
        if ref_sha == candidate_sha:
            result["exact_copy"] = True
            result["near_duplicate_reference"] = True
            result["matched_reference"] = str(ref)
            return result
        ref_norm = "".join(ref.read_text(encoding="utf-8", errors="replace").split())
        if candidate_norm and ref_norm and candidate_norm == ref_norm:
            result["near_duplicate_reference"] = True
            result["matched_reference"] = str(ref)
            return result
        # Near-duplicate: high token overlap.
        if candidate_norm and ref_norm:
            shorter = min(len(candidate_norm), len(ref_norm))
            longer = max(len(candidate_norm), len(ref_norm))
            if shorter > 0 and shorter / longer >= 0.92:
                # Quick suffix/prefix overlap check.
                common = 0
                for a, b in zip(candidate_norm, ref_norm):
                    if a == b:
                        common += 1
                    else:
                        break
                if common / shorter >= 0.80:
                    result["near_duplicate_reference"] = True
                    result["matched_reference"] = str(ref)
                    return result
    return result


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Load and validate a split target context")
    parser.add_argument("--generator-root", required=True)
    parser.add_argument("--evaluator-root", required=True)
    parser.add_argument("--work-dir", default="")
    args = parser.parse_args()
    ctx = SplitTargetContext.load(args.generator_root, args.evaluator_root)
    info = {
        "generator_root": str(ctx.generator_root),
        "evaluator_root": str(ctx.evaluator_root),
        "source_input": str(ctx.source_input),
        "source_repos": str(ctx.source_repos),
        "benchmark_copy": str(ctx.benchmark_copy),
        "native_harness_path": str(ctx.native_harness_path),
        "reference_harnesses": str(ctx.reference_harnesses),
        "native_harness": ctx.read_native_harness(),
    }
    if args.work_dir:
        sealed = create_sealed_build_context(ctx, Path(args.work_dir))
        info["sealed_context"] = sealed
    print(json.dumps(info, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
