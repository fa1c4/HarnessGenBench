#!/usr/bin/env python3
"""Shared run-level result semantics for HarnessGenBench harness generators.

This module centralizes the stage/status contract described by the beta
reproduction plans.  It is imported by the CKGFuzzer (and later PromeFuzz /
OSS-Fuzz-Gen) evaluators and entrypoints, and by the host-side pytest suite.

A row is ``evaluated`` only when the full closed loop completed for at least
one candidate: generation produced a non-empty candidate set, at least one
candidate was overlay-built, sanitizer-smoked, fuzzed with ``execs_done > 0``,
and measured by a real coverage report.  Anything else is a quality or
infrastructure failure -- never a silent success.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

# Canonical evaluator stage names, in order.
STAGE_NAMES = [
    "generation",
    "candidate_overlay",
    "copy_audit",
    "candidate_build",
    "sanitizer_smoke",
    "api_reachability",
    "campaign",
    "coverage",
]

# Allowed top-level statuses for a harness-generator run.
STATUS_EVALUATED = "evaluated"
STATUS_QUALITY_FAILURE = "quality_failure"
STATUS_INFRA_FAILURE = "infra_failure"
STATUS_NOT_APPLICABLE = "not_applicable"
STATUS_COMPAT_SMOKE_COMPLETED = "compat_smoke_completed"

ALLOWED_STATUSES = {
    STATUS_EVALUATED,
    STATUS_QUALITY_FAILURE,
    STATUS_INFRA_FAILURE,
    STATUS_NOT_APPLICABLE,
    STATUS_COMPAT_SMOKE_COMPLETED,
}

# Stages that must actually run (not merely "compiled") before a row may be
# considered evaluated.
EVALUATION_STAGES = {"candidate_overlay", "copy_audit", "candidate_build", "sanitizer_smoke", "api_reachability", "campaign", "coverage"}


def default_stages() -> dict[str, str]:
    return {name: "pending" for name in STAGE_NAMES}


def mark_stage(stages: dict[str, str], name: str, state: str) -> dict[str, str]:
    if name not in STAGE_NAMES:
        raise ValueError(f"unknown stage: {name}")
    stages[name] = state
    return stages


def _all_completed(stages: dict[str, str], names: Iterable[str]) -> bool:
    return all(stages.get(name) == "completed" for name in names)


def _any_failed(stages: dict[str, str], names: Iterable[str]) -> bool:
    return any(stages.get(name) == "failed" for name in names)


def result_status_from_stages(
    stages: dict[str, str],
    *,
    has_candidate_json: bool = True,
    coverage_covered_lines: int | None = None,
    campaign_execs_done: int = 0,
    candidate_overlaid: bool = True,
) -> str:
    """Derive the run-level status from evaluator stage output.

    ``evaluated`` is only returned when every evaluation stage completed, a
    per-candidate evaluator JSON exists, the candidate was actually overlaid,
    the campaign recorded ``execs_done > 0``, and a real coverage report
    measured a non-null covered-line count.
    """

    if _any_failed(stages, STAGE_NAMES):
        # A failure in generation or candidate_build with candidates produced
        # is a quality failure; a failure caused by tooling is infra.  The
        # caller may override, but by default an evaluator stage failure is a
        # quality failure (the generator's candidate was not good enough).
        if _any_failed(stages, ("generation",)) and not _any_failed(stages, EVALUATION_STAGES):
            return STATUS_QUALITY_FAILURE
        return STATUS_QUALITY_FAILURE
    if not _all_completed(stages, STAGE_NAMES):
        return STATUS_QUALITY_FAILURE
    # All stages completed -- enforce the non-trivial success conditions.
    if not has_candidate_json:
        return STATUS_QUALITY_FAILURE
    if not candidate_overlaid:
        return STATUS_QUALITY_FAILURE
    if campaign_execs_done <= 0:
        return STATUS_QUALITY_FAILURE
    if coverage_covered_lines is None:
        return STATUS_QUALITY_FAILURE
    return STATUS_EVALUATED


def classify_infra_failure(reason: str) -> bool:
    """Return True if a reason string indicates an infrastructure failure."""
    infra_markers = (
        "codeql_context",
        "verification_context_unreproducible",
        "docker",
        "checkout",
        "model",
        "evaluator",
        "tool",
        "infra",
        "leakage_audit",
        "no_candidate_source_files",
    )
    reason_l = reason.lower()
    return any(marker in reason_l for marker in infra_markers)


def build_result(
    *,
    generator: str = "ckgfuzzer",
    task_family: str = "harness_generator",
    profile: str,
    protocol: str,
    target: str,
    status: str | None = None,
    applicability: str = "applicable",
    stages: dict[str, str] | None = None,
    reason: str = "",
    method_variant: str = "",
    excluded_from_aggregate: bool = False,
    artifacts: dict[str, Any] | None = None,
    metrics: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
    selected_candidate: dict[str, Any] | None = None,
    candidate_count: int = 0,
    error: dict[str, Any] | None = None,
    reproducibility: dict[str, Any] | None = None,
) -> dict[str, Any]:
    stages = stages if stages is not None else default_stages()
    if status is None:
        status = result_status_from_stages(stages)
    if profile == "compat-smoke":
        excluded_from_aggregate = True
        if not method_variant:
            method_variant = "compat-smoke"
        if status == STATUS_EVALUATED:
            status = STATUS_COMPAT_SMOKE_COMPLETED
    if profile == "reproduction-gamma" and not method_variant:
        method_variant = "paper-faithful"
    if profile == "reproduction-delta" and not method_variant:
        method_variant = "paper-faithful"
    if profile == "reproduction-epsilon" and not method_variant:
        method_variant = "paper-faithful"
    if status not in ALLOWED_STATUSES and status not in {"failed", "partial_completed", "missing_api_key"}:
        # Normalize legacy statuses into the beta contract.  A bare "failed"
        # from the legacy entrypoint is preserved for backwards compatibility
        # with existing collectors; the beta evaluator always emits one of the
        # allowed statuses above.
        pass
    metrics = metrics or {}
    return {
        "schema_version": 3,
        "generator": generator,
        "task_family": task_family,
        "profile": profile,
        "protocol": protocol,
        "target": target,
        "status": status,
        "applicability": applicability,
        "reason": reason,
        "error": error or {},
        "stages": stages,
        "method_variant": method_variant or profile,
        "excluded_from_aggregate": excluded_from_aggregate,
        "candidate_count": candidate_count,
        "artifacts": artifacts or {},
        "metrics": metrics,
        "build": metrics.get("build", {}),
        "campaign": metrics.get("campaign", {}),
        "coverage": metrics.get("coverage", {}),
        "reproducibility": reproducibility or {},
        "provenance": provenance or {},
        "selected_candidate": selected_candidate or {},
    }


def write_result(result: dict[str, Any], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def select_best_candidate(candidates: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Choose the best evaluated candidate per section 6.7.

    Ordering:
      1. status=evaluated;
      2. no sanitizer misuse on all smoke samples;
      3. nonzero dynamic API reachability;
      4. highest covered lines;
      5. then highest execs.
    """

    def eligible(c: dict[str, Any]) -> bool:
        stages = c.get("stages", {})
        if not all(stages.get(s) == "completed" for s in EVALUATION_STAGES):
            return False
        # Reject candidates that are exact or near-exact copies of a reference
        # harness, or that contain the reference canary token (gamma §2.2).
        audit = c.get("copy_audit", {})
        if audit.get("exact_copy") or audit.get("contains_reference_canary"):
            return False
        smoke = c.get("sanitizer_smoke", {})
        if smoke.get("misuse_crash"):
            return False
        reach = c.get("api_reachability", {})
        # not_requested reachability (no intended API list) is acceptable;
        # otherwise require at least one reached API with real evidence.
        if reach.get("status") != "not_requested" and not reach.get("reached_apis"):
            return False
        cov = c.get("coverage", {})
        if cov.get("line_coverage", {}).get("covered") in (None, 0):
            return False
        campaign = c.get("campaign", {})
        if int(campaign.get("execs_done", 0) or 0) <= 0:
            return False
        return True

    eligible_candidates = [c for c in candidates if eligible(c)]
    if not eligible_candidates:
        return None
    eligible_candidates.sort(
        key=lambda c: (
            -int(c.get("coverage", {}).get("line_coverage", {}).get("covered", 0) or 0),
            -int(c.get("campaign", {}).get("execs_done", 0) or 0),
        )
    )
    return eligible_candidates[0]


def assert_evaluated_invariants(result: dict[str, Any]) -> list[str]:
    """Return a list of invariant violations for an ``evaluated`` result."""
    violations: list[str] = []
    if result.get("status") != STATUS_EVALUATED:
        return violations
    stages = result.get("stages", {})
    for stage in STAGE_NAMES:
        if stages.get(stage) != "completed":
            violations.append(f"stage {stage} is not completed for an evaluated row")
    cov = result.get("metrics", {}).get("coverage", {}) or result.get("selected_candidate", {}).get("coverage", {})
    line_cov = cov.get("line_coverage", {}) if isinstance(cov, dict) else {}
    if line_cov.get("covered") is None:
        violations.append("evaluated row has coverage.line_coverage.covered == null")
    campaign = result.get("metrics", {}).get("campaign", {}) or result.get("selected_candidate", {}).get("campaign", {})
    if int(campaign.get("execs_done", 0) or 0) <= 0:
        violations.append("evaluated row has campaign.execs_done <= 0")
    if not result.get("selected_candidate"):
        violations.append("evaluated row has no per-candidate evaluator JSON")
    if not result.get("selected_candidate", {}).get("overlaid"):
        violations.append("evaluated row did not overlay the candidate")
    return violations


def main() -> int:
    print(json.dumps({"statuses": sorted(ALLOWED_STATUSES), "stages": STAGE_NAMES}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
