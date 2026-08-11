#!/usr/bin/env python3
"""CKGFuzzer profile enforcement, normalized result schema, and leakage audit.

This module is imported by both the host-side tests and the container
entrypoint. It must not depend on any library that is unavailable in the
CKGFuzzer container venv or the host Python 3 used by pytest.
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
# profile introduced by the reproduction-zeta plan: it is paper-faithful and
# rejects every local/deterministic fallback, every compatibility fallback,
# and additionally forces a sealed split package and a real CodeQL graph.
# ``reproduction-epsilon`` is the strict profile from the reproduction-epsilon
# plan and ``reproduction-delta`` remains accepted as a backward-compatible
# alias. ``reproduction-gamma`` is method-faithful but not strict (it does not
# enforce the epsilon/zeta fail-closed invariants).
STRICT_REPRODUCTION_PROFILES = {"reproduction-delta", "reproduction-epsilon", "reproduction-zeta"}
# Zeta is the strictest profile: it adds fail-closed split-package and
# CodeQL-graph requirements on top of the epsilon strict invariants.
ZETA_PROFILES = {"reproduction-zeta"}

# Flags that are forbidden in method-faithful profiles.
FORBIDDEN_ALPHA_ENV = {
    "CKGFUZZER_LOCAL_API_SUMMARY": "1",
    "CKGFUZZER_LOCAL_API_COMBINATION": "1",
}
FORBIDDEN_ALPHA_FLAGS = ["--skip_check_compilation"]

# Stage names in canonical order.
STAGE_NAMES = [
    "target_prepared",
    "codeql_database",
    "knowledge_graph",
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
                    f"method-faithful profiles require the upstream LLM path"
                )
        if normalize_env_bool(env.get("CKGFUZZER_SKIP_CHECK_COMPILATION")) == "1":
            violations.append(
                f"CKGFUZZER_SKIP_CHECK_COMPILATION=1 is forbidden in {profile}; "
                f"the compile-check/repair loop must run"
            )
        # A mock/local embedding model is forbidden in alpha/paper.
        embedding_model = (env.get("CKGFUZZER_EMBEDDING_MODEL") or "").strip().lower()
        if embedding_model in {"mock", "local", "hgb-hash-embedding", ""}:
            violations.append(
                f"CKGFUZZER_EMBEDDING_MODEL={embedding_model!r} is forbidden in {profile}; "
                f"a real embedding service is required (openai-* or ollama-* prefix)"
            )
        # source_fallback_only must not be permitted in alpha.
        if normalize_env_bool(env.get("CKGFUZZER_ALLOW_SOURCE_FALLBACK")) == "1":
            violations.append(
                f"CKGFUZZER_ALLOW_SOURCE_FALLBACK=1 is forbidden in {profile}; "
                "source-only graph fallback is only allowed in compat-smoke"
            )
        # selected-harness API mode is evaluator-only; a blind generator must
        # never read the reference-derived API list.
        api_mode = (env.get("HGB_API_SELECTION_MODE") or "").strip()
        if api_mode in {"selected_harness", "selected_harness_fallback"}:
            violations.append(
                f"HGB_API_SELECTION_MODE={api_mode} is forbidden in {profile}; "
                "the selected-harness API list is evaluator-only"
            )

    # Strict reproduction profiles (reproduction-epsilon and its alias
    # reproduction-delta) are the strictest: forbid every local fallback the
    # earlier scaffolding allowed, even when an alias env var is set.
    if profile in STRICT_REPRODUCTION_PROFILES:
        for key, bad_value in FORBIDDEN_ALPHA_ENV.items():
            if normalize_env_bool(env.get(key)) == bad_value:
                violations.append(
                    f"{key}={bad_value} is forbidden in {profile}; "
                    f"{profile} requires the upstream LLM path"
                )
        if normalize_env_bool(env.get("CKGFUZZER_SKIP_CHECK_COMPILATION")) == "1":
            violations.append(
                f"CKGFUZZER_SKIP_CHECK_COMPILATION=1 is forbidden in {profile}; "
                "the compile-check/repair loop must run"
            )
        embedding_model = (env.get("CKGFUZZER_EMBEDDING_MODEL") or "").strip().lower()
        if embedding_model in {"mock", "local", "hgb-hash-embedding", ""}:
            violations.append(
                f"CKGFUZZER_EMBEDDING_MODEL={embedding_model!r} is forbidden in {profile}; "
                f"{profile} requires a real embedding service"
            )
        if normalize_env_bool(env.get("CKGFUZZER_ALLOW_SOURCE_FALLBACK")) == "1":
            violations.append(
                f"CKGFUZZER_ALLOW_SOURCE_FALLBACK=1 is forbidden in {profile}; "
                "source-only CodeQL graph fallback is forbidden"
            )

    # Zeta is stricter than epsilon: it additionally forbids the source graph
    # fallback and mock embeddings by name, and requires a sealed split package
    # (zeta plan §1). These are required env values, not merely forbidden ones.
    if profile in ZETA_PROFILES:
        if normalize_env_bool(env.get("CKGFUZZER_SOURCE_GRAPH_FALLBACK")) == "1":
            violations.append(
                "CKGFUZZER_SOURCE_GRAPH_FALLBACK=1 is forbidden in reproduction-zeta; "
                "the CodeQL/code-knowledge graph must be built from the sealed source snapshot"
            )
        if normalize_env_bool(env.get("CKGFUZZER_ALLOW_MOCK_EMBEDDING")) == "1":
            violations.append(
                "CKGFUZZER_ALLOW_MOCK_EMBEDDING=1 is forbidden in reproduction-zeta; "
                "a real embedding service is required"
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
    """Derive a high-level status from stage states."""
    any_failed = any(state == "failed" for state in stages.values())
    if any_failed:
        return "failed"
    all_completed = all(stages.get(name) == "completed" for name in STAGE_NAMES)
    if all_completed:
        return "evaluated"
    any_running = any(state == "running" for state in stages.values())
    if any_running:
        return "partial_completed"
    return "failed"


def build_result(
    *,
    generator: str = "ckgfuzzer",
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
    """Scan generator input and CKG outputs for a reference canary token.

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
        ".csv", ".tsv", ".log", ".ql", ".xml", ".html",
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
# Preflight validation for target overrides
# ---------------------------------------------------------------------------

def load_target_overrides(metadata_root: str | Path) -> dict[str, Any]:
    path = Path(metadata_root) / "ckgfuzzer_target_overrides.yaml"
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8")
    return _parse_simple_yaml(text)


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Minimal YAML parser for the target overrides file.

    Supports top-level ``targets:`` key with per-target mapping entries
    in either ``- target_name:`` or ``  target_name:`` form.
    """
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
        # target entry:  - target_name: OR  target_name:
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


def preflight_target(target: str, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate that a target has a preflight/override decision.

    Returns a dict with ``valid`` (bool) and ``decision`` fields.
    """
    overrides = overrides or {}
    targets = overrides.get("targets", {})
    entry = targets.get(target)
    if entry is None:
        return {
            "target": target,
            "valid": True,
            "decision": "default",
            "reason": "no override needed; standard build recipe applies",
        }
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
        "stub_destination": entry.get("stub_destination", ""),
        "compiler": entry.get("compiler", ""),
        "timeout": entry.get("timeout", ""),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="CKGFuzzer profile enforcement and audit")
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
