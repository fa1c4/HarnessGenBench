#!/usr/bin/env python3
"""OSS-Fuzz-Gen profile enforcement, normalized result schema, and leakage audit.

This module is imported by both the host-side tests and the container
entrypoint. It must not depend on any library that is unavailable in the
OSS-Fuzz-Gen container venv or the host Python 3 used by pytest.
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

VALID_PROFILES = {"alpha", "paper-faithful", "reproduction-gamma", "compat-smoke"}
VALID_PROTOCOLS = {"blind-project", "target-aware"}
METHOD_FAITHFUL_PROFILES = {"alpha", "paper-faithful", "reproduction-gamma"}

# Introspector modes that satisfy the "real Fuzz Introspector" requirement of
# method-faithful profiles. ``real`` is the reproduction-gamma default; the
# upstream ``remote`` mode is the historical alpha/paper default. ``local`` is
# the compat-smoke shim and is never method-faithful.
REAL_INTROSPECTOR_MODES = {"real", "remote"}

# Flags that are forbidden in method-faithful profiles because they collapse
# OSS-Fuzz-Gen into a compat-smoke no-op: local introspector shim, coverage
# skip, and tiny 1/1/1 budgets.
FORBIDDEN_ALPHA_ENV = {
    "OFG_SKIP_COVERAGE_GAINS": "1",
    "OFG_INTROSPECTOR_MODE": "local",
}

# Flags that are forbidden in reproduction-gamma / paper-faithful because they
# silently relax the paper-faithful contract: falling back to a project YAML
# that may leak the reference answer, or synthesizing a benchmark when the
# real one is bad instead of failing. They may only be enabled with an
# explicit, separately reported variant (never the default).
FORBIDDEN_GAMMA_ENV = {
    "OFG_ALLOW_PROJECT_YAML_FALLBACK": "1",
    "OFG_SYNTHESIZE_ON_BAD_BENCHMARK": "1",
}
FORBIDDEN_ALPHA_BUDGETS = {
    "OFG_NUM_SAMPLES": "1",
    "OFG_NUM_EXP": "1",
    "OFG_NUM_EVA": "1",
}

# Stage names in canonical order for the harness_generator task family.
STAGE_NAMES = [
    "target_prepared",
    "introspector_build",
    "benchmark_synthesized",
    "generation",
    "compilation_repair",
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
                    f"method-faithful profiles require real Introspector and coverage"
                )
        # reproduction-gamma / paper-faithful must not silently relax the
        # paper-faithful contract with project-YAML fallback or bad-benchmark
        # synthesis. These collapse the reproduction into a softer variant and
        # are only allowed in an explicitly reported (non-default) run.
        if profile in {"reproduction-gamma", "paper-faithful"}:
            for key, bad_value in FORBIDDEN_GAMMA_ENV.items():
                actual = normalize_env_bool(env.get(key))
                if actual == bad_value:
                    violations.append(
                        f"{key}={actual} is forbidden in {profile}; "
                        f"it silently relaxes the paper-faithful contract"
                    )
            # reproduction-gamma pins the real introspector mode by default.
            intro_mode = normalize_env_bool(env.get("OFG_INTROSPECTOR_MODE"), "real")
            if intro_mode not in REAL_INTROSPECTOR_MODES:
                violations.append(
                    f"OFG_INTROSPECTOR_MODE={intro_mode} is forbidden in {profile}; "
                    f"expected one of {sorted(REAL_INTROSPECTOR_MODES)} (real Fuzz Introspector)"
                )
        # Tiny 1/1/1 budgets are compat-smoke, not alpha.
        for key, bad_value in FORBIDDEN_ALPHA_BUDGETS.items():
            actual = normalize_env_bool(env.get(key), "0")
            if actual == bad_value:
                violations.append(
                    f"{key}={actual} is a compat-smoke budget and is forbidden in {profile}; "
                    f"alpha requires at least 3 generation samples"
                )
        # Reference-harness leakage is forbidden in blind-project.
        if protocol == "blind-project":
            if normalize_env_bool(env.get("HGB_ALLOW_REFERENCE_USAGE")) == "1":
                violations.append(
                    "HGB_ALLOW_REFERENCE_USAGE=1 is forbidden in blind-project; "
                    "exact reference harnesses are evaluator-only"
                )
            if normalize_env_bool(env.get("OFG_ALLOW_GCS_TARGET_DOWNLOAD")) == "1":
                violations.append(
                    "OFG_ALLOW_GCS_TARGET_DOWNLOAD=1 is forbidden in blind-project; "
                    "the current target answer must not be downloaded"
                )

    if is_compat_smoke(profile):
        # compat-smoke must always be excluded from aggregate.
        if normalize_env_bool(env.get("HGB_EXCLUDE_FROM_AGGREGATE")) != "1":
            violations.append(
                "compat-smoke must set HGB_EXCLUDE_FROM_AGGREGATE=1; "
                "it is never an aggregate-eligible row"
            )

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
    generator: str = "oss-fuzz-gen",
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
) -> dict[str, Any]:
    stages = stages if stages is not None else default_stages()
    if status is None:
        status = result_status_from_stages(stages)
    if is_compat_smoke(profile):
        excluded_from_aggregate = True
        if not method_variant:
            method_variant = "compat-smoke"
    return {
        "schema_version": 2,
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
    }


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
    """Scan generator input and OSS-Fuzz-Gen outputs for a reference canary token.

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
        ".csv", ".tsv", ".log", ".xml", ".html",
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
    path = Path(metadata_root) / "oss_fuzz_gen_target_overrides.yaml"
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

    Returns a dict with ``valid`` (bool) and ``decision`` fields. Every
    valuable target must produce a concrete decision (``override`` or
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
            "reason": "no override needed; standard introspector/build recipe applies",
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
        "introspector_overlay": entry.get("introspector_overlay", ""),
        "compiler": entry.get("compiler", ""),
        "build_timeout": entry.get("build_timeout", ""),
        "fuzz_timeout": entry.get("fuzz_timeout", ""),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="OSS-Fuzz-Gen profile enforcement and audit")
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
