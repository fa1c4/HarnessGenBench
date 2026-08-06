#!/usr/bin/env python3
"""PromeFuzz harness evaluator.

PromeFuzz reuses the common HarnessGenBench harness evaluator (the same
component OSS-Fuzz-Gen uses) so there is no parallel, incompatible evaluation
abstraction. The common evaluator overlays each candidate at the exact native
harness destination, replays the pinned FuzzBench build, runs a sanitizer
smoke, verifies intended project/library API reachability, rejects no-op
harnesses, runs a fixed-budget campaign, and collects line/edge coverage. It
also performs post-generation exact-copy and AST/token similarity auditing.

This module is a thin PromeFuzz-named facade over ``ofg_evaluator`` so the
PromeFuzz entrypoint and tests can call ``promefuzz_evaluator`` without
duplicating evaluation logic.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

try:
    import ofg_evaluator
except Exception:  # pragma: no cover - allow standalone import during tests
    ofg_evaluator = None  # type: ignore[assignment]


def real_runner(command: Sequence[str], timeout: int | None = None) -> Any:
    """Default subprocess runner, mirroring the common evaluator's runner."""
    try:
        proc = subprocess.run(
            list(command), timeout=timeout, capture_output=True, text=True,
            errors="replace", check=False,
        )
        return ofg_evaluator.CommandResult(
            list(command), proc.returncode, proc.stdout or "", proc.stderr or ""
        ) if ofg_evaluator else proc
    except subprocess.TimeoutExpired as exc:
        return ofg_evaluator.CommandResult(
            list(command), 124, "", f"timed out: {exc}"
        ) if ofg_evaluator else None
    except OSError as exc:
        return ofg_evaluator.CommandResult(
            list(command), 127, "", f"could not run: {exc}"
        ) if ofg_evaluator else None


def evaluate_candidates(
    *,
    target_root: str | Path,
    candidates_dir: str | Path,
    work_dir: str | Path,
    fuzz_target: str,
    selected_functions: list[str] | None = None,
    runner: Callable[..., Any] | None = None,
    build_timeout: int = 1800,
    campaign_seconds: int = 60,
) -> dict[str, Any]:
    """Evaluate every PromeFuzz candidate through the common evaluator."""
    if ofg_evaluator is None:
        raise RuntimeError("ofg_evaluator is not available on this Python path")
    return ofg_evaluator.evaluate_candidates(
        target_root=target_root,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        fuzz_target=fuzz_target,
        selected_functions=selected_functions,
        runner=runner or real_runner,
        build_timeout=build_timeout,
        campaign_seconds=campaign_seconds,
    )


# Re-export the common no-op rejection and audit helpers so PromeFuzz tests
# exercise the same reachability semantics without importing ofg_evaluator
# directly.
reject_noop_harness = getattr(ofg_evaluator, "reject_noop_harness", None) if ofg_evaluator else None
exact_copy_audit = getattr(ofg_evaluator, "exact_copy_audit", None) if ofg_evaluator else None
token_similarity = getattr(ofg_evaluator, "token_similarity", None) if ofg_evaluator else None


def main() -> int:
    parser = argparse.ArgumentParser(description="PromeFuzz harness evaluator (common)")
    parser.add_argument("--target-root", required=True)
    parser.add_argument("--candidates-dir", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--fuzz-target", required=True)
    parser.add_argument("--selected-functions", nargs="*", default=[])
    parser.add_argument("--build-timeout", type=int, default=1800)
    parser.add_argument("--campaign-seconds", type=int, default=60)
    args = parser.parse_args()
    if ofg_evaluator is None:
        print(json.dumps({"verification_ran": False, "error": "ofg_evaluator unavailable"}))
        return 1
    result = evaluate_candidates(
        target_root=args.target_root,
        candidates_dir=args.candidates_dir,
        work_dir=args.work_dir,
        fuzz_target=args.fuzz_target,
        selected_functions=args.selected_functions,
        build_timeout=args.build_timeout,
        campaign_seconds=args.campaign_seconds,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("verification_ran") else 1


if __name__ == "__main__":
    raise SystemExit(main())
