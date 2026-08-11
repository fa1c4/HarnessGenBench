#!/usr/bin/env python3
"""PromeFuzz profile enforcement, normalized result schema, and leakage audit.

This module is imported by both the host-side tests and the container
entrypoint. It must not depend on any library that is unavailable in the
PromeFuzz container venv or the host Python 3 used by pytest.

PromeFuzz is a ``harness_generator`` baseline. ``alpha``, ``paper-faithful``,
and ``reproduction-gamma`` require a real compile database captured from the
pinned FuzzBench build, real link/library context, legitimate consumer
knowledge, and a real semantic embedding provider. ``compat-smoke`` may retain
the synthetic compile database and local hash embeddings for offline wiring
tests only; it is always excluded from the scientific aggregate and is never
selected by default.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

VALID_PROFILES = {"alpha", "paper-faithful", "reproduction-gamma", "reproduction-delta", "reproduction-epsilon", "reproduction-zeta", "compat-smoke"}
VALID_PROTOCOLS = {"blind-project", "api-oracle"}
METHOD_FAITHFUL_PROFILES = {"alpha", "paper-faithful", "reproduction-gamma", "reproduction-delta", "reproduction-epsilon", "reproduction-zeta"}
# Strict reproduction profiles. ``reproduction-zeta`` is the canonical strict
# profile introduced by the reproduction-zeta plan (plan
# ``promefuzz_reproduction_zeta.md``). It is paper-faithful and rejects every
# synthetic/mock/hash fallback and compatibility fallback, plus it forces
# exact FuzzBench compile context, verified link args, consumer cases, and a
# sealed split package. ``reproduction-epsilon`` is the canonical strict
# profile introduced by the reproduction-epsilon plan. It is paper-faithful
# but rejects every synthetic/mock/hash fallback the earlier scaffolding
# allowed. ``reproduction-delta`` remains accepted as a backward-compatible
# alias. ``reproduction-gamma`` remains a method-faithful but non-strict
# alias.
STRICT_REPRODUCTION_PROFILES = {"reproduction-delta", "reproduction-epsilon", "reproduction-zeta"}
# Zeta is the strictest profile: it forces exact FuzzBench compile context,
# verified link args, consumer cases, real embedding, and a sealed split
# package (zeta plan §1).
ZETA_PROFILES = {"reproduction-zeta"}

# Beta plan section 10: allowed run-level statuses for a PromeFuzz
# harness_generator row. ``evaluated`` requires a verified candidate, real
# coverage, nonzero campaign executions, and dynamic API reachability.
STATUS_EVALUATED = "evaluated"
STATUS_QUALITY_FAILURE = "quality_failure"
STATUS_INFRA_FAILURE = "infra_failure"
STATUS_COMPAT_SMOKE_COMPLETED = "compat_smoke_completed"
ALLOWED_BETA_STATUSES = {
    STATUS_EVALUATED,
    STATUS_QUALITY_FAILURE,
    STATUS_INFRA_FAILURE,
    STATUS_COMPAT_SMOKE_COMPLETED,
}
# Evaluator stages that must actually run before a row may be ``evaluated``.
EVALUATION_STAGES = (
    "candidate_overlay",
    "copy_audit",
    "candidate_build",
    "sanitizer_smoke",
    "api_reachability",
    "campaign",
    "coverage",
)

# Flags that are forbidden in method-faithful profiles because they collapse
# PromeFuzz into a compat-smoke no-op: a synthetic compile database, a
# mock/hash embedding provider, and the selected-reference-harness API report.
FORBIDDEN_ALPHA_ENV = {
    "HGB_PROMEFUZZ_SYNTHETIC_COMPILE_DB": "1",
    "PROME_FUZZ_EMBEDDING_LLM_TYPE": "mock",
    "PROME_FUZZ_EMBEDDING_MODEL": "hgb-hash-embedding",
    "HGB_API_SELECTION_MODE": "selected_harness_fallback",
    "HGB_API_SELECTION_MODE_ALT": "selected_harness",
    "HGB_API_REPORT_MODE": "report_first",
    "HGB_API_REPORT_MODE_ALT": "report_only",
}

# Stage names in canonical order for the PromeFuzz harness_generator pipeline.
STAGE_NAMES = [
    "target_prepared",
    "build_context",
    "api_preprocess",
    "knowledge",
    "generation",
    "candidate_overlay",
    "copy_audit",
    "candidate_build",
    "sanitizer_smoke",
    "api_reachability",
    "campaign",
    "coverage",
]


class ProfileError(Exception):
    """Raised when a profile/protocol combination is invalid for alpha."""


def normalize_env_bool(value: str | None, default: str = "0") -> str:
    if value is None:
        return default
    return value.strip() or default


def is_method_faithful(profile: str) -> bool:
    return profile in METHOD_FAITHFUL_PROFILES


def is_compat_smoke(profile: str) -> bool:
    return profile == "compat-smoke"


def _embedding_is_real(value: str) -> bool:
    v = (value or "").strip().lower()
    if not v or v in {"mock", "local", "hash", "hgb-hash-embedding"}:
        return False
    return True


def validate_profile(profile: str, protocol: str, env: dict[str, str] | None = None) -> list[str]:
    """Return a list of violation messages. Empty means valid."""
    env = env or dict(os.environ)
    violations: list[str] = []

    if profile not in VALID_PROFILES:
        violations.append(f"invalid profile: {profile!r}; expected one of {sorted(VALID_PROFILES)}")
        return violations
    if protocol and protocol not in VALID_PROTOCOLS:
        violations.append(f"invalid protocol: {protocol!r}; expected one of {sorted(VALID_PROTOCOLS)}")

    if is_method_faithful(profile):
        for key, bad_value in FORBIDDEN_ALPHA_ENV.items():
            actual = normalize_env_bool(env.get(key))
            if actual == bad_value:
                violations.append(
                    f"{key}={actual} is forbidden in {profile}; "
                    f"method-faithful profiles require a real build context and real embeddings"
                )
        # A mock/hash embedding model is forbidden in alpha/paper-faithful.
        embedding_model = (env.get("PROME_FUZZ_EMBEDDING_MODEL") or "").strip()
        if not _embedding_is_real(embedding_model):
            violations.append(
                f"PROME_FUZZ_EMBEDDING_MODEL={embedding_model!r} is forbidden in {profile}; "
                f"a real semantic embedding service is required (openai-* or ollama-* prefix)"
            )
        embedding_type = (env.get("PROME_FUZZ_EMBEDDING_LLM_TYPE") or "").strip().lower()
        if embedding_type in {"mock", "local", "hash"}:
            violations.append(
                f"PROME_FUZZ_EMBEDDING_LLM_TYPE={embedding_type!r} is forbidden in {profile}; "
                f"only a real embedding provider is allowed"
            )
        # An empty embedding type is forbidden in method-faithful profiles too.
        if embedding_type == "":
            violations.append(
                f"PROME_FUZZ_EMBEDDING_LLM_TYPE is empty in {profile}; "
                f"only a real embedding provider is allowed"
            )
        # Reference-harness leakage is forbidden in blind-project.
        if protocol == "blind-project":
            if normalize_env_bool(env.get("HGB_ALLOW_REFERENCE_USAGE")) == "1":
                violations.append(
                    "HGB_ALLOW_REFERENCE_USAGE=1 is forbidden in blind-project; "
                    "exact reference harnesses are evaluator-only"
                )
            if normalize_env_bool(env.get("HGB_PROMEFUZZ_ALLOW_REFERENCE_HARNESS")) == "1":
                violations.append(
                    "HGB_PROMEFUZZ_ALLOW_REFERENCE_HARNESS=1 is forbidden in blind-project; "
                    "the target reference harness body must never feed build-context capture"
                )

    # Strict reproduction profiles (reproduction-epsilon and its alias
    # reproduction-delta) are the strictest (plan section 1): forbid every
    # synthetic/mock/hash fallback even when an alias env var is set, and reject
    # the selected-harness API modes and report modes.
    if profile in STRICT_REPRODUCTION_PROFILES:
        if normalize_env_bool(env.get("HGB_PROMEFUZZ_SYNTHETIC_COMPILE_DB")) == "1":
            violations.append(
                f"HGB_PROMEFUZZ_SYNTHETIC_COMPILE_DB=1 is forbidden in {profile}; "
                "a real compile database captured from the FuzzBench build is required"
            )
        emb_type = (env.get("PROME_FUZZ_EMBEDDING_LLM_TYPE") or "").strip().lower()
        if emb_type in {"mock", "local", "hash", ""}:
            violations.append(
                f"PROME_FUZZ_EMBEDDING_LLM_TYPE={emb_type!r} is forbidden in {profile}; "
                f"a real semantic embedding provider (openai or ollama) is required"
            )
        emb_model = (env.get("PROME_FUZZ_EMBEDDING_MODEL") or "").strip()
        if not emb_model or emb_model == "hgb-hash-embedding":
            violations.append(
                f"PROME_FUZZ_EMBEDDING_MODEL={emb_model!r} is forbidden in {profile}; "
                f"a real semantic embedding model is required"
            )
        api_mode = (env.get("HGB_API_SELECTION_MODE") or "").strip()
        if api_mode in {"selected_harness", "selected_harness_fallback"}:
            violations.append(
                f"HGB_API_SELECTION_MODE={api_mode} is forbidden in {profile}; "
                f"reference-harness API filtering is evaluator-only"
            )
        report_mode = (env.get("HGB_API_REPORT_MODE") or "").strip()
        if report_mode in {"report_first", "report_only"}:
            violations.append(
                f"HGB_API_REPORT_MODE={report_mode} is forbidden in {profile}; "
                f"the selected-harness API report is evaluator-only"
            )

    # Zeta plan §1: zeta is the strictest profile. It forces exact FuzzBench
    # compile context, verified link args, consumer cases, real embedding, and
    # a sealed split package. These are required env values, not merely
    # forbidden ones.
    if profile in ZETA_PROFILES:
        if normalize_env_bool(env.get("PROMEFUZZ_ALLOW_HASH_EMBEDDING")) == "1":
            violations.append(
                "PROMEFUZZ_ALLOW_HASH_EMBEDDING=1 is forbidden in reproduction-zeta; "
                "a real semantic embedding provider is required"
            )
        if normalize_env_bool(env.get("PROMEFUZZ_ALLOW_SYNTHETIC_COMPILE_DB")) == "1":
            violations.append(
                "PROMEFUZZ_ALLOW_SYNTHETIC_COMPILE_DB=1 is forbidden in reproduction-zeta; "
                "the compile DB must be captured from the exact FuzzBench Docker build"
            )
        if normalize_env_bool(env.get("PROMEFUZZ_ALLOW_EMPTY_LINK_ARGS")) == "1":
            violations.append(
                "PROMEFUZZ_ALLOW_EMPTY_LINK_ARGS=1 is forbidden in reproduction-zeta; "
                "driver_build_args must be nonempty unless the target is verified header-only"
            )
        if normalize_env_bool(env.get("PROMEFUZZ_REQUIRE_CONSUMER_CASES"), "1") != "1":
            violations.append(
                "PROMEFUZZ_REQUIRE_CONSUMER_CASES=1 is required for reproduction-zeta; "
                "consumer/API usage knowledge must be wired into generation"
            )
        build_ctx = (env.get("PROME_FUZZ_BUILD_CONTEXT_METHOD") or "").strip()
        if build_ctx and build_ctx not in {"exact_fuzzbench", "fuzzbench_replay"}:
            violations.append(
                f"PROME_FUZZ_BUILD_CONTEXT_METHOD={build_ctx!r} is forbidden in reproduction-zeta; "
                f"the compile context must come from the exact FuzzBench Docker build"
            )
        if normalize_env_bool(env.get("HGB_TARGET_REQUIRE_SPLIT")) != "1":
            violations.append(
                "HGB_TARGET_REQUIRE_SPLIT=1 is required for reproduction-zeta; "
                "the target package must be physically split into generator/evaluator halves"
            )

    if is_compat_smoke(profile):
        # compat-smoke must always be excluded from aggregate.
        if normalize_env_bool(env.get("HGB_EXCLUDE_FROM_AGGREGATE")) != "1":
            # Not a hard violation of the env, but the result must mark it.
            pass

    return violations


def assert_profile(profile: str, protocol: str, env: dict[str, str] | None = None) -> None:
    violations = validate_profile(profile, protocol, env)
    if violations:
        raise ProfileError("; ".join(violations))


def default_stages() -> dict[str, str]:
    return {name: "pending" for name in STAGE_NAMES}


def mark_stage(stages: dict[str, str], name: str, state: str) -> dict[str, str]:
    if name not in STAGE_NAMES:
        raise ValueError(f"unknown stage: {name}")
    stages[name] = state
    return stages


def result_status_from_stages(stages: dict[str, str]) -> str:
    """Derive a high-level status from stage states.

    Only all-complete yields ``evaluated``. Any failed stage is ``failed``;
    otherwise (partial) it is ``partial_completed`` so it is never silently
    counted as a successful alpha matrix row.
    """
    any_failed = any(state == "failed" for state in stages.values())
    if any_failed:
        return "failed"
    all_completed = all(stages.get(name) == "completed" for name in STAGE_NAMES)
    if all_completed:
        return "evaluated"
    any_running = any(state in {"running", "completed"} for state in stages.values())
    if any_running:
        return "partial_completed"
    return "failed"


def build_result(
    *,
    generator: str = "promefuzz",
    task_family: str = "harness_generator",
    profile: str,
    protocol: str,
    target: str,
    applicability: str = "applicable",
    status: str | None = None,
    stages: dict[str, str] | None = None,
    artifacts: dict[str, Any] | None = None,
    metrics: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
    reference_leakage_audit: dict[str, Any] | None = None,
    reason: str = "",
    method_variant: str = "",
    excluded_from_aggregate: bool = False,
    selected_candidate: dict[str, Any] | None = None,
    candidate_count: int = 0,
    method: dict[str, Any] | None = None,
) -> dict[str, Any]:
    stages = stages if stages is not None else default_stages()
    if status is None:
        status = result_status_from_stages(stages)
    if is_compat_smoke(profile):
        excluded_from_aggregate = True
        if not method_variant:
            method_variant = "compat-smoke"
        # compat-smoke never reaches the scientific ``evaluated`` status.
        if status == STATUS_EVALUATED:
            status = STATUS_COMPAT_SMOKE_COMPLETED
    # reproduction-delta/gamma/epsilon map to the paper-faithful method variant.
    if profile in {"reproduction-gamma", "reproduction-delta", "reproduction-epsilon"} and not method_variant:
        method_variant = "paper-faithful"
    if profile in {"reproduction-gamma", "reproduction-delta", "reproduction-epsilon"} and method_variant == profile:
        method_variant = "paper-faithful"
    return {
        "schema_version": 3,
        "generator": generator,
        "task_family": task_family,
        "profile": profile,
        "protocol": protocol,
        "target": target,
        "applicability": applicability,
        "status": status,
        "reason": reason,
        "stages": stages,
        "artifacts": artifacts or {},
        "metrics": metrics or {},
        "provenance": provenance or {},
        "reference_leakage_audit": reference_leakage_audit or {},
        "method_variant": method_variant or profile,
        "excluded_from_aggregate": excluded_from_aggregate,
        "selected_candidate": selected_candidate or {},
        "candidate_count": candidate_count,
        "method": method or {},
    }


def finalize_status_from_evaluator(
    evaluator_status: str,
    *,
    stages: dict[str, str],
    profile: str,
    coverage_covered_lines: int | None = None,
    campaign_execs_done: int = 0,
    reached_count: int = 0,
    candidate_count: int = 0,
) -> str:
    """Map the shared evaluator status to a PromeFuzz run-level status.

    Per beta plan section 10, ``evaluated`` is only allowed when the evaluator
    produced a verified candidate, real coverage (non-null covered lines),
    ``execs_done > 0``, and ``api_reachability.reached_count > 0``. A
    compile-only candidate can never be ``evaluated``.
    """

    if is_compat_smoke(profile):
        if evaluator_status == STATUS_EVALUATED:
            return STATUS_COMPAT_SMOKE_COMPLETED
        return evaluator_status
    if evaluator_status == STATUS_EVALUATED:
        if candidate_count <= 0:
            return STATUS_QUALITY_FAILURE
        if coverage_covered_lines is None:
            return STATUS_QUALITY_FAILURE
        if int(campaign_execs_done or 0) <= 0:
            return STATUS_QUALITY_FAILURE
        if int(reached_count or 0) <= 0:
            return STATUS_QUALITY_FAILURE
        # Every evaluation stage must be completed.
        if any(stages.get(stage) != "completed" for stage in EVALUATION_STAGES):
            return STATUS_QUALITY_FAILURE
        return STATUS_EVALUATED
    if evaluator_status == STATUS_INFRA_FAILURE:
        return STATUS_INFRA_FAILURE
    # quality_failure, compat_smoke_completed, or any other evaluator state is
    # a quality failure for a method-faithful profile.
    return STATUS_QUALITY_FAILURE


def write_result(result: dict[str, Any], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Leakage audit
# ---------------------------------------------------------------------------

CANARY_PREFIX = "HGB_REF_CANARY_"


def generate_canary_token() -> str:
    """Return a random-ish canary token for reference leakage testing."""
    import time
    return CANARY_PREFIX + hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]


def scan_text_for_canary(text: str, canary: str) -> list[str]:
    """Return positions/contexts where the canary appears in text."""
    hits: list[str] = []
    if not canary or canary not in text:
        return hits
    for match in re.finditer(re.escape(canary), text):
        start = max(0, match.start() - 40)
        end = min(len(text), match.end() + 40)
        hits.append(text[start:end])
    return hits


def audit_leakage(
    generator_input_dir: str | Path,
    canary: str,
    *,
    extra_dirs: list[str | Path] | None = None,
) -> dict[str, Any]:
    """Scan generator input and PromeFuzz outputs for a reference canary token.

    Returns a dict with ``leaked`` (bool) and ``hits`` (list of file/context).
    """
    generator_input_dir = Path(generator_input_dir)
    scan_dirs = [generator_input_dir]
    if extra_dirs:
        scan_dirs.extend(Path(d) for d in extra_dirs)

    hits: list[dict[str, str]] = []
    text_exts = {
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
        ".py", ".sh", ".yaml", ".yml", ".json", ".txt", ".md",
        ".csv", ".tsv", ".log", ".xml", ".html", ".toml",
    }

    for scan_dir in scan_dirs:
        if not scan_dir or not scan_dir.is_dir():
            continue
        for path in sorted(scan_dir.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix.lower() not in text_exts and path.suffix != "":
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for context in scan_text_for_canary(content, canary):
                hits.append({"file": str(path), "context": context})

    return {
        "canary": canary,
        "scanned_dirs": [str(d) for d in scan_dirs if d and d.is_dir()],
        "leaked": len(hits) > 0,
        "hit_count": len(hits),
        "hits": hits[:50],
    }


# ---------------------------------------------------------------------------
# Target overrides and preflight
# ---------------------------------------------------------------------------


def load_target_overrides(metadata_root: str | Path) -> dict[str, Any]:
    path = Path(metadata_root) / "promefuzz_target_overrides.yaml"
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8")
    return _parse_simple_yaml(text)


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Minimal YAML parser for the target overrides file."""
    result: dict[str, Any] = {"targets": {}}
    current_target: str | None = None
    in_targets_section = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0 and stripped.endswith(":"):
            in_targets_section = stripped == "targets:"
            current_target = None
            continue
        if not in_targets_section:
            continue
        m = re.match(r"-\s+(\S+):?\s*$", stripped)
        if m:
            current_target = m.group(1)
            result["targets"][current_target] = {}
            continue
        m = re.match(r"(\S+):\s*$", stripped)
        if m and indent <= 2:
            current_target = m.group(1)
            result["targets"][current_target] = {}
            continue
        if current_target and ":" in stripped:
            key, value = stripped.split(":", 1)
            key = key.strip()
            value = value.strip()
            if value.startswith("[") and value.endswith("]"):
                inner = value[1:-1].strip()
                items = [v.strip().strip("'\"") for v in inner.split(",") if v.strip()]
                result["targets"][current_target][key] = items
            elif value.lower() in {"true", "false"}:
                result["targets"][current_target][key] = value.lower() == "true"
            else:
                result["targets"][current_target][key] = value.strip("'\"")
    return result


def preflight_target(
    target: str,
    overrides: dict[str, Any] | None = None,
    *,
    valuable_targets: list[str] | None = None,
) -> dict[str, Any]:
    """Validate that a target has a preflight decision.

    Every valuable target must produce a concrete decision (``override`` or
    ``default``); a missing decision is a real failure, never a soft skip.
    """
    overrides = overrides or {}
    targets = overrides.get("targets", {})
    entry = targets.get(target)
    if entry is None:
        decision = {
            "target": target,
            "valid": True,
            "decision": "default",
            "reason": "no override needed; standard build-context capture applies",
        }
        if valuable_targets is not None and target not in valuable_targets:
            decision["valid"] = False
            decision["decision"] = "not_valuable"
            decision["reason"] = f"{target} is not in the valuable target set"
        return decision
    language = entry.get("language", "c")
    if language not in {"c", "c++"}:
        return {
            "target": target,
            "valid": False,
            "decision": "not_applicable",
            "reason": f"unsupported language: {language}",
        }
    return {
        "target": target,
        "valid": True,
        "decision": "override",
        "reason": entry.get("reason", "build facts override present"),
        "language": language,
        "candidate_destination": entry.get("candidate_destination", ""),
        "compile_db_capture_method": entry.get("compile_db_capture_method", ""),
        "library_output_glob": entry.get("library_output_glob", ""),
        "build_timeout": entry.get("build_timeout", ""),
        "generation_timeout": entry.get("generation_timeout", ""),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="PromeFuzz profile enforcement and audit")
    sub = parser.add_subparsers(dest="command")

    validate_p = sub.add_parser("validate", help="Validate a profile/protocol/env combination")
    validate_p.add_argument("--profile", required=True)
    validate_p.add_argument("--protocol", default="")
    validate_p.add_argument("--env-file", help="JSON file of env vars")

    audit_p = sub.add_parser("audit", help="Audit generator input for reference canary leakage")
    audit_p.add_argument("--generator-input", required=True)
    audit_p.add_argument("--canary", required=True)
    audit_p.add_argument("--extra-dir", action="append", default=[])

    preflight_p = sub.add_parser("preflight", help="Preflight target override decisions")
    preflight_p.add_argument("--target", required=True)
    preflight_p.add_argument("--metadata-root", default="metadata")

    args = parser.parse_args()
    if args.command == "validate":
        env: dict[str, str] = {}
        if args.env_file:
            env = json.loads(Path(args.env_file).read_text(encoding="utf-8"))
        violations = validate_profile(args.profile, args.protocol, env)
        if violations:
            for v in violations:
                print(f"VIOLATION: {v}", file=sys.stderr)
            return 1
        print("valid")
        return 0
    if args.command == "audit":
        result = audit_leakage(args.generator_input, args.canary, extra_dirs=args.extra_dir)
        print(json.dumps(result, indent=2))
        return 1 if result["leaked"] else 0
    if args.command == "preflight":
        overrides = load_target_overrides(args.metadata_root)
        result = preflight_target(args.target, overrides)
        print(json.dumps(result, indent=2))
        return 0 if result["valid"] else 1
    parser.print_help()
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
