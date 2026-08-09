#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat >&2 <<'EOF'
Usage:
  bash scripts/hgb_run_baseline.sh --generator GENERATOR --target TARGET [options]

Options:
  --generator NAME       Baseline generator name.
  --target NAME          FuzzBench target name.
  --profile NAME         Baseline profile (default comes from contract).
  --protocol NAME        Baseline protocol (default comes from contract).
  --run-id ID            Explicit run id.
  --dry-run              Validate contracts without expensive generation.
  --strict               Require the contract strict-success status.
  --layout MODE          Target package layout passed to hgb_generate_harness.sh.
  --save-mode MODE       Save mode passed to hgb_generate_harness.sh.
  --timeout SECONDS      Generation timeout.
EOF
}

generator=""
target=""
profile=""
protocol=""
run_id=""
dry_run=0
strict=0
target_layout="compact"
save_mode="compact"
timeout_seconds="${HGB_GENERATION_TIMEOUT_SECONDS:-10800}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --generator|-g)
      generator="${2:-}"
      shift 2
      ;;
    --target|-t)
      target="${2:-}"
      shift 2
      ;;
    --profile)
      profile="${2:-}"
      shift 2
      ;;
    --protocol)
      protocol="${2:-}"
      shift 2
      ;;
    --run-id)
      run_id="${2:-}"
      shift 2
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    --strict)
      strict=1
      shift
      ;;
    --layout|--target-layout)
      target_layout="${2:-}"
      shift 2
      ;;
    --save-mode)
      save_mode="${2:-}"
      shift 2
      ;;
    --timeout)
      timeout_seconds="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ -n "$generator" && -n "$target" ]] || { usage; exit 64; }
valid_hgb_generator "$generator" || die "unknown generator: $generator"

case "$generator" in
  g2fuzz|elfuzz)
    profile="${profile:-alpha}"
    protocol="${protocol:-paper-native}"
    strict_success="evaluated"
    ;;
  ckgfuzzer)
    profile="${profile:-alpha}"
    protocol="${protocol:-blind-project}"
    strict_success="evaluated"
    ;;
  promefuzz)
    profile="${profile:-alpha}"
    protocol="${protocol:-blind-project}"
    strict_success="evaluated"
    ;;
  oss-fuzz-gen)
    profile="${profile:-alpha}"
    protocol="${protocol:-blind-project}"
    strict_success="evaluated"
    ;;
  *)
    profile="${profile:-alpha}"
    protocol="${protocol:-target-aware}"
    strict_success="completed"
    ;;
esac

export HGB_BASELINE_PROFILE="$profile"
export HGB_BASELINE_PROTOCOL="$protocol"

# Validate profile/protocol combinations before any expensive work.
case "$generator" in
  elfuzz)
    case "$profile" in
      alpha|paper-faithful|reproduction-gamma|reproduction-delta|reproduction-epsilon|compat-smoke) ;;
      *) die_profile "elfuzz: invalid profile: $profile (expected alpha, paper-faithful, reproduction-gamma, reproduction-delta, reproduction-epsilon, or compat-smoke)" ;;
    esac
    case "$protocol" in
      paper-native|extension) ;;
      *) die_profile "elfuzz: invalid protocol: $protocol (expected paper-native or extension)" ;;
    esac
    # reproduction-epsilon is the canonical strict paper-native input-generator
    # profile (epsilon plan shared foundation); reproduction-delta is its
    # backward-compatible alias (plan elfuzz_reproduction_delta.md section 1).
    # reproduction-gamma is kept as a backward-compatible alias. All three
    # forbid a prebuilt ELFUZZ_TARGET_BINARY so the SUT is always built from the
    # exact FuzzBench Dockerfile, require a real coverage replay (never AFL path
    # counters), and require the Docker socket for applicable targets.
    if [[ "$profile" == "reproduction-gamma" || "$profile" == "reproduction-delta" || "$profile" == "reproduction-epsilon" ]]; then
      if [[ -n "${ELFUZZ_TARGET_BINARY:-}" ]]; then
        die "elfuzz/$profile: ELFUZZ_TARGET_BINARY is forbidden; the SUT must be built from the FuzzBench Dockerfile"
      fi
      export ELFUZZ_COVERAGE_REPLAY="${ELFUZZ_COVERAGE_REPLAY:-1}"
      export ELFUZZ_REQUIRE_GPU="${ELFUZZ_REQUIRE_GPU:-1}"
    fi
    # Plan section 1/2: non-text/unsupported targets must return Invalid before
    # Docker image build, TGI, model download, or generation. Classify from the
    # committed manifest before any Docker-socket requirement so an Invalid
    # target never fails on missing Docker. Dry-run skips this (it only
    # validates the profile/protocol combination).
    if [[ "$dry_run" != "1" ]]; then
      elfuzz_cls="$(python3 "$SCRIPT_DIR/../docker/common/elfuzz_target_pipeline.py" classify --target "$target" --metadata-root "$SCRIPT_DIR/../metadata" 2>/dev/null || true)"
      elfuzz_applicability="$(printf '%s' "$elfuzz_cls" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("applicability",""))' 2>/dev/null || true)"
      if [[ "$elfuzz_applicability" == "Invalid" ]]; then
        _inv_id="${run_id:-$(make_timestamp)}"
        _inv_ws="$(workspace_generator_target_run_dir "$generator" "$target" "$_inv_id" "$(repo_root)")"
        ensure_dir "$_inv_ws/logs"
        HGB_BASELINE_PROFILE="$profile" HGB_BASELINE_PROTOCOL="$protocol" \
          python3 "$SCRIPT_DIR/../docker/common/elfuzz_target_pipeline.py" write-invalid \
          --target "$target" --metadata-root "$SCRIPT_DIR/../metadata" --out "$_inv_ws/result.json" >/dev/null
        cp "$_inv_ws/result.json" "$_inv_ws/metadata.json"
        printf 'Invalid: ELFuzz supports text-input targets only\n' >&2
        printf '%s\n' "$_inv_ws"
        exit 0
      fi
      # Applicable strict reproduction (reproduction-delta/epsilon) target: the
      # Docker socket is mandatory to build the native and coverage SUTs from
      # the FuzzBench Docker environment.
      if [[ "$profile" == "reproduction-delta" || "$profile" == "reproduction-epsilon" ]] && [[ ! -S /var/run/docker.sock ]]; then
        die "elfuzz/$profile: a Docker socket is required to build the native and coverage SUTs from the FuzzBench Docker environment"
      fi
    fi
    export HGB_EXCLUDE_FROM_AGGREGATE=0
    [[ "$profile" == "compat-smoke" ]] && export HGB_EXCLUDE_FROM_AGGREGATE=1
    ;;
  ckgfuzzer)
    case "$profile" in
      alpha|paper-faithful|reproduction-gamma|reproduction-delta|reproduction-epsilon|compat-smoke) ;;
      *) die_profile "ckgfuzzer: invalid profile: $profile (expected alpha, paper-faithful, reproduction-gamma, reproduction-delta, reproduction-epsilon, or compat-smoke)" ;;
    esac
    case "$protocol" in
      blind-project|api-oracle) ;;
      *) die_profile "ckgfuzzer: invalid protocol: $protocol (expected blind-project or api-oracle)" ;;
    esac
    # reproduction-epsilon is the canonical strict profile (epsilon plan);
    # reproduction-delta is its backward-compatible alias. Both inherit the
    # alpha/paper-faithful forbiddens and additionally refuse selected-harness
    # API mode and compatibility query rewrite unless the patch is pinned. The
    # env-content guards are "before an LLM call" guards, so a dry run (which
    # makes no LLM/embedding calls) only validates that the profile/protocol
    # combination is accepted.
    if [[ "$dry_run" != "1" ]]; then
      if [[ "$profile" == "alpha" || "$profile" == "paper-faithful" || "$profile" == "reproduction-gamma" || "$profile" == "reproduction-delta" || "$profile" == "reproduction-epsilon" ]]; then
        if [[ "${CKGFUZZER_LOCAL_API_SUMMARY:-0}" == "1" ]]; then
          die "ckgfuzzer/$profile: CKGFUZZER_LOCAL_API_SUMMARY=1 is forbidden; use compat-smoke for local summaries"
        fi
        if [[ "${CKGFUZZER_LOCAL_API_COMBINATION:-0}" == "1" ]]; then
          die "ckgfuzzer/$profile: CKGFUZZER_LOCAL_API_COMBINATION=1 is forbidden; use compat-smoke for local combinations"
        fi
        if [[ "${CKGFUZZER_SKIP_CHECK_COMPILATION:-0}" == "1" ]]; then
          die "ckgfuzzer/$profile: --skip_check_compilation is forbidden; use compat-smoke to skip compilation checking"
        fi
        emb="${CKGFUZZER_EMBEDDING_MODEL:-}"
        if [[ -z "$emb" || "$emb" == "mock" || "$emb" == "local" || "$emb" == "hgb-hash-embedding" ]]; then
          die "ckgfuzzer/$profile: CKGFUZZER_EMBEDDING_MODEL must be a real embedding service (e.g. openai-text-embedding-3-small), not mock/local/hgb-hash-embedding/empty"
        fi
        case "${HGB_API_SELECTION_MODE:-}" in
          selected_harness|selected_harness_fallback) die "ckgfuzzer/$profile: HGB_API_SELECTION_MODE=$HGB_API_SELECTION_MODE is forbidden; reference-harness API filtering is evaluator-only" ;;
        esac
      fi
      # Strict reproduction profiles (reproduction-epsilon and its alias
      # reproduction-delta) forbid the source-only CodeQL graph fallback and
      # unrecorded compatibility query rewrites.
      if [[ "$profile" == "reproduction-delta" || "$profile" == "reproduction-epsilon" ]]; then
        if [[ "${CKGFUZZER_ALLOW_SOURCE_FALLBACK:-0}" == "1" ]]; then
          die "ckgfuzzer/$profile: CKGFUZZER_ALLOW_SOURCE_FALLBACK=1 is forbidden; source-only CodeQL graph fallback is not allowed"
        fi
        if [[ -n "${CKGFUZZER_COMPAT_QUERY_PATCH:-}" && -z "${CKGFUZZER_COMPAT_QUERY_PATCH_PINNED:-}" ]]; then
          die "ckgfuzzer/$profile: a compatibility query rewrite (CKGFUZZER_COMPAT_QUERY_PATCH) is set but not pinned; record method_variant=compatibility_patch and set CKGFUZZER_COMPAT_QUERY_PATCH_PINNED to the pinned file"
        fi
        if [[ -n "${CKGFUZZER_COMPAT_QUERY_PATCH_PINNED:-}" ]]; then
          export HGB_EXCLUDE_FROM_AGGREGATE="${HGB_EXCLUDE_FROM_AGGREGATE:-1}"
        fi
      fi
    fi
    export HGB_EXCLUDE_FROM_AGGREGATE="${HGB_EXCLUDE_FROM_AGGREGATE:-0}"
    [[ "$profile" == "compat-smoke" ]] && export HGB_EXCLUDE_FROM_AGGREGATE=1
    ;;
  promefuzz)
    case "$profile" in
      alpha|paper-faithful|reproduction-gamma|reproduction-delta|reproduction-epsilon|compat-smoke) ;;
      *) die_profile "promefuzz: invalid profile: $profile (expected alpha, paper-faithful, reproduction-gamma, reproduction-delta, reproduction-epsilon, or compat-smoke)" ;;
    esac
    case "$protocol" in
      blind-project|api-oracle) ;;
      *) die_profile "promefuzz: invalid protocol: $protocol (expected blind-project or api-oracle)" ;;
    esac
    # In alpha/paper-faithful/reproduction-gamma, refuse legacy compat env before
    # an LLM call so alpha cannot be silently downgraded to compat-smoke behavior.
    if [[ "$profile" == "alpha" || "$profile" == "paper-faithful" || "$profile" == "reproduction-gamma" ]]; then
      if [[ "${HGB_PROMEFUZZ_SYNTHETIC_COMPILE_DB:-0}" == "1" ]]; then
        die "promefuzz/$profile: HGB_PROMEFUZZ_SYNTHETIC_COMPILE_DB=1 is forbidden; use compat-smoke for the synthetic compile database"
      fi
      emb_type="${PROME_FUZZ_EMBEDDING_LLM_TYPE:-}"
      if [[ -z "$emb_type" || "$emb_type" == "mock" || "$emb_type" == "local" || "$emb_type" == "hash" ]]; then
        die "promefuzz/$profile: PROME_FUZZ_EMBEDDING_LLM_TYPE must be a real embedding provider (openai or ollama), not mock/local/hash/empty"
      fi
      emb_model="${PROME_FUZZ_EMBEDDING_MODEL:-}"
      if [[ -z "$emb_model" || "$emb_model" == "hgb-hash-embedding" ]]; then
        die "promefuzz/$profile: PROME_FUZZ_EMBEDDING_MODEL must be a real semantic embedding model, not hgb-hash-embedding/empty"
      fi
      case "${HGB_API_SELECTION_MODE:-}" in
        selected_harness|selected_harness_fallback) die "promefuzz/$profile: HGB_API_SELECTION_MODE=$HGB_API_SELECTION_MODE is forbidden; reference-harness API filtering is evaluator-only" ;;
      esac
      case "${HGB_API_REPORT_MODE:-}" in
        report_first|report_only) die "promefuzz/$profile: HGB_API_REPORT_MODE=$HGB_API_REPORT_MODE is forbidden; the selected-harness API report is evaluator-only" ;;
      esac
    fi
    # Strict reproduction profiles (reproduction-epsilon and its alias
    # reproduction-delta) are the strictest (plan promefuzz_reproduction_delta.md
    # section 1). They inherit the gamma forbiddens and additionally refuse the
    # synthetic compile DB, empty embedding type/model, and selected-harness API
    # modes. The env-content guards are "before an LLM call" guards, so a dry run
    # (which makes no LLM/embedding calls) only validates that the
    # profile/protocol combination is accepted.
    if [[ "$profile" == "reproduction-delta" || "$profile" == "reproduction-epsilon" ]] && [[ "$dry_run" != "1" ]]; then
      if [[ "${HGB_PROMEFUZZ_SYNTHETIC_COMPILE_DB:-0}" == "1" ]]; then
        die "promefuzz/$profile: HGB_PROMEFUZZ_SYNTHETIC_COMPILE_DB=1 is forbidden; the strict profile requires a real compile database captured from the FuzzBench build"
      fi
      emb_type="${PROME_FUZZ_EMBEDDING_LLM_TYPE:-}"
      if [[ -z "$emb_type" || "$emb_type" == "mock" || "$emb_type" == "local" || "$emb_type" == "hash" ]]; then
        die "promefuzz/$profile: PROME_FUZZ_EMBEDDING_LLM_TYPE must be a real embedding provider (openai or ollama), not mock/local/hash/empty"
      fi
      emb_model="${PROME_FUZZ_EMBEDDING_MODEL:-}"
      if [[ -z "$emb_model" || "$emb_model" == "hgb-hash-embedding" ]]; then
        die "promefuzz/$profile: PROME_FUZZ_EMBEDDING_MODEL must be a real semantic embedding model, not hgb-hash-embedding/empty"
      fi
      case "${HGB_API_SELECTION_MODE:-}" in
        selected_harness|selected_harness_fallback) die "promefuzz/$profile: HGB_API_SELECTION_MODE=$HGB_API_SELECTION_MODE is forbidden; reference-harness API filtering is evaluator-only" ;;
      esac
      case "${HGB_API_REPORT_MODE:-}" in
        report_first|report_only) die "promefuzz/$profile: HGB_API_REPORT_MODE=$HGB_API_REPORT_MODE is forbidden; the selected-harness API report is evaluator-only" ;;
      esac
      export PROME_FUZZ_BUILD_CONTEXT_METHOD="${PROME_FUZZ_BUILD_CONTEXT_METHOD:-fuzzbench_replay}"
    fi
    export HGB_EXCLUDE_FROM_AGGREGATE=0
    [[ "$profile" == "compat-smoke" ]] && export HGB_EXCLUDE_FROM_AGGREGATE=1
    ;;
  oss-fuzz-gen)
    case "$profile" in
      alpha|paper-faithful|reproduction-gamma|reproduction-delta|reproduction-epsilon|compat-smoke) ;;
      *) die_profile "oss-fuzz-gen: invalid profile: $profile (expected alpha, paper-faithful, reproduction-gamma, reproduction-delta, reproduction-epsilon, or compat-smoke)" ;;
    esac
    case "$protocol" in
      blind-project|target-aware) ;;
      *) die_profile "oss-fuzz-gen: invalid protocol: $protocol (expected blind-project or target-aware)" ;;
    esac
    # In alpha/paper-faithful/reproduction-gamma, refuse legacy compat env
    # before an LLM call so the profile cannot be silently downgraded.
    if [[ "$profile" == "alpha" || "$profile" == "paper-faithful" || "$profile" == "reproduction-gamma" ]]; then
      if [[ "${OFG_SKIP_COVERAGE_GAINS:-0}" == "1" ]]; then
        die "oss-fuzz-gen/$profile: OFG_SKIP_COVERAGE_GAINS=1 is forbidden; use compat-smoke to skip coverage"
      fi
      if [[ "${OFG_INTROSPECTOR_MODE:-remote}" == "local" ]]; then
        die "oss-fuzz-gen/$profile: OFG_INTROSPECTOR_MODE=local is forbidden; use compat-smoke for the local shim"
      fi
      if [[ "${OFG_ALLOW_GCS_TARGET_DOWNLOAD:-0}" == "1" ]]; then
        die "oss-fuzz-gen/$profile: OFG_ALLOW_GCS_TARGET_DOWNLOAD=1 is forbidden in blind-project; the target answer must not be downloaded"
      fi
    fi
    # Strict reproduction profiles (reproduction-epsilon and its alias
    # reproduction-delta) are the strictest (plan
    # oss-fuzz-gen_reproduction_delta.md section 1). They inherit the gamma
    # forbiddens and additionally refuse coverage skip, GCS target download,
    # project-YAML fallback, and bad-benchmark synthesis unless an explicit
    # compat variant is recorded and the row is excluded from the aggregate.
    if [[ "$profile" == "reproduction-delta" || "$profile" == "reproduction-epsilon" ]]; then
      if [[ "${OFG_SKIP_COVERAGE_GAINS:-0}" == "1" ]]; then
        die "oss-fuzz-gen/$profile: OFG_SKIP_COVERAGE_GAINS=1 is forbidden; the strict profile requires real coverage gains"
      fi
      if [[ "${OFG_INTROSPECTOR_MODE:-real}" == "local" ]]; then
        die "oss-fuzz-gen/$profile: OFG_INTROSPECTOR_MODE=local is forbidden; the strict profile requires a real Fuzz Introspector report"
      fi
      if [[ "${OFG_ALLOW_GCS_TARGET_DOWNLOAD:-0}" == "1" ]]; then
        die "oss-fuzz-gen/$profile: OFG_ALLOW_GCS_TARGET_DOWNLOAD=1 is forbidden; the current target answer must not be downloaded"
      fi
      if [[ "${OFG_ALLOW_PROJECT_YAML_FALLBACK:-0}" == "1" && "${HGB_EXCLUDE_FROM_AGGREGATE:-0}" != "1" ]]; then
        die "oss-fuzz-gen/$profile: OFG_ALLOW_PROJECT_YAML_FALLBACK=1 is forbidden unless HGB_EXCLUDE_FROM_AGGREGATE=1 and HGB_METHOD_VARIANT=compat_project_yaml_fallback"
      fi
      if [[ "${OFG_SYNTHESIZE_ON_BAD_BENCHMARK:-0}" == "1" && "${HGB_EXCLUDE_FROM_AGGREGATE:-0}" != "1" ]]; then
        die "oss-fuzz-gen/$profile: OFG_SYNTHESIZE_ON_BAD_BENCHMARK=1 is forbidden unless HGB_EXCLUDE_FROM_AGGREGATE=1 and HGB_METHOD_VARIANT=compat_bad_benchmark_synthesis"
      fi
      export OFG_INTROSPECTOR_MODE="${OFG_INTROSPECTOR_MODE:-real}"
    fi
    # reproduction-gamma pins the paper-faithful contract: no project-YAML
    # fallback and no bad-benchmark synthesis by default (plan section 2.3).
    if [[ "$profile" == "reproduction-gamma" ]]; then
      if [[ "${OFG_ALLOW_PROJECT_YAML_FALLBACK:-0}" == "1" ]]; then
        die "oss-fuzz-gen/reproduction-gamma: OFG_ALLOW_PROJECT_YAML_FALLBACK=1 is forbidden by default; record an explicit variant if a fallback is reported"
      fi
      if [[ "${OFG_SYNTHESIZE_ON_BAD_BENCHMARK:-0}" == "1" ]]; then
        die "oss-fuzz-gen/reproduction-gamma: OFG_SYNTHESIZE_ON_BAD_BENCHMARK=1 is forbidden by default; record an explicit variant if synthesis is reported"
      fi
      export OFG_INTROSPECTOR_MODE="${OFG_INTROSPECTOR_MODE:-real}"
    fi
    export HGB_EXCLUDE_FROM_AGGREGATE=0
    [[ "$profile" == "compat-smoke" ]] && export HGB_EXCLUDE_FROM_AGGREGATE=1
    ;;
  g2fuzz)
    case "$profile" in
      alpha|paper-faithful|reproduction-gamma|reproduction-delta|reproduction-epsilon|compat-smoke) ;;
      *) die_profile "g2fuzz: invalid profile: $profile (expected alpha, paper-faithful, reproduction-gamma, reproduction-delta, reproduction-epsilon, or compat-smoke)" ;;
    esac
    case "$protocol" in
      paper-native|extension) ;;
      *) die_profile "g2fuzz: invalid protocol: $protocol (expected paper-native or extension)" ;;
    esac
    # reproduction-epsilon is the canonical strict paper-native profile (epsilon
    # plan shared foundation); reproduction-delta is its backward-compatible alias
    # (plan g2fuzz_reproduction_delta.md section 1); reproduction-gamma is kept
    # as a backward-compatible alias. All three forbid a prebuilt
    # G2FUZZ_TARGET_DIR so the .afl/.cmp/.cov triple is always built from the
    # FuzzBench Docker environment, do not patch G2FUZZ_TRY_NUM down to smoke
    # values, and require a real coverage replay (never AFL paths).
    if [[ "$profile" == "reproduction-gamma" || "$profile" == "reproduction-delta" || "$profile" == "reproduction-epsilon" ]]; then
      if [[ -n "${G2FUZZ_TARGET_DIR:-}" ]]; then
        die "g2fuzz/$profile: G2FUZZ_TARGET_DIR is forbidden; the .afl/.cmp/.cov triple must be built from the FuzzBench Docker environment"
      fi
      # Do not patch G2FUZZ_TRY_NUM down to a smoke value in the strict
      # profiles; a smoke value (1) would weaken the paper-faithful loop.
      if [[ "${G2FUZZ_TRY_NUM:-}" == "1" ]]; then
        die "g2fuzz/$profile: G2FUZZ_TRY_NUM=1 is a smoke value; the strict profiles require the real paper budget (default 3)"
      fi
      # Coverage replay is mandatory in the strict profiles.
      export G2FUZZ_COVERAGE_REPLAY_REQUIRED="${G2FUZZ_COVERAGE_REPLAY_REQUIRED:-1}"
    fi
    # The strictest profiles (reproduction-delta and reproduction-epsilon)
    # require the Docker socket to build the triple from the FuzzBench Docker
    # environment (plan section 1.2). A dry run only validates the
    # profile/protocol combination and never starts Docker.
    if [[ "$profile" == "reproduction-delta" || "$profile" == "reproduction-epsilon" ]] && [[ "$dry_run" != "1" && ! -S /var/run/docker.sock ]]; then
      die "g2fuzz/$profile: a Docker socket is required to build the .afl/.cmp/.cov triple from the FuzzBench Docker environment"
    fi
    export HGB_EXCLUDE_FROM_AGGREGATE=0
    [[ "$profile" == "compat-smoke" ]] && export HGB_EXCLUDE_FROM_AGGREGATE=1
    ;;
esac

# Dry-run fast path: validate the profile/protocol combination and write a
# dry_run_ok result without starting Docker or making any LLM/embedding calls.
# The plan (reproduction-delta section 1) requires a dry run to pass profile
# validation and never start Docker.
if [[ "$dry_run" == "1" ]]; then
  _dry_run_id="${run_id:-$(make_timestamp)}"
  workspace="$(workspace_generator_target_run_dir "$generator" "$target" "$_dry_run_id" "$(repo_root)")"
  ensure_dir "$workspace/logs"
  python3 - "$workspace" "$generator" "$target" "$profile" "$protocol" <<'PY_HGB_DRY_RUN'
import json
import sys
from pathlib import Path
workspace, generator, target, profile, protocol = sys.argv[1:6]
meta = {
    "schema_version": 1,
    "generator": generator,
    "target": target,
    "run_type": "generate-target",
    "capability": "harness_generator",
    "task_family": "harness_generator",
    "profile": profile,
    "protocol": protocol,
    "applicability": "applicable",
    "status": "dry_run_ok",
    "reason": "dry run validated profile/protocol without Docker or LLM calls",
    "exit_code": 0,
}
result = {
    "schema_version": 2,
    "generator": generator,
    "task_family": "harness_generator",
    "profile": profile,
    "protocol": protocol,
    "target": target,
    "applicability": "applicable",
    "status": "dry_run_ok",
    "reason": "dry run validated profile/protocol without Docker or LLM calls",
    "method_variant": "paper-faithful" if profile in ("reproduction-gamma", "reproduction-delta", "reproduction-epsilon") else profile,
    "excluded_from_aggregate": True,
}
Path(workspace, "metadata.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
Path(workspace, "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY_HGB_DRY_RUN
  printf '%s\n' "$workspace"
  exit 0
fi

args=(--generator "$generator" --target "$target" --layout "$target_layout" --save-mode "$save_mode" --timeout "$timeout_seconds")
if [[ -n "$run_id" ]]; then args+=(--run-id "$run_id"); fi
if [[ "$dry_run" == "1" ]]; then args+=(--dry-run); fi

workspace=""
code=0
workspace="$(bash "$SCRIPT_DIR/hgb_generate_harness.sh" "${args[@]}")" || code=$?
if [[ -z "$workspace" ]]; then
  workspace="$(workspace_generator_target_run_dir "$generator" "$target" "${run_id:-unknown}" "$(repo_root)")"
fi

metadata="$workspace/metadata.json"
status="$(extract_json_string status "$metadata")"
# Prefer result.json (schema v2) for the canonical status when available.
result_json="$workspace/result.json"
if [[ -f "$result_json" ]]; then
  result_status="$(extract_json_string status "$result_json")"
  if [[ -n "$result_status" ]]; then
    status="$result_status"
  fi
  applicability="$(extract_json_string applicability "$result_json")"
  reason="$(extract_json_string reason "$result_json")"
else
  applicability="$(extract_json_string applicability "$metadata")"
  reason="$(extract_json_string reason "$metadata")"
fi
if [[ -z "$status" ]]; then
  status="missing_metadata"
fi

if [[ "$strict" == "1" ]]; then
  if [[ "$dry_run" == "1" && "$status" == "dry_run_ok" ]]; then
    printf '%s\n' "$workspace"
    exit 0
  fi
  if [[ "$status" == "not_applicable" && "$applicability" == "Invalid" ]]; then
    printf '%s\n' "$workspace"
    exit 0
  fi
  if [[ "$status" != "$strict_success" ]]; then
    printf 'Baseline strict check failed: generator=%s target=%s status=%s expected=%s reason=%s workspace=%s\n' \
      "$generator" "$target" "$status" "$strict_success" "${reason:-unknown}" "$workspace" >&2
    if [[ "$code" -eq 0 ]]; then code=1; fi
    exit "$code"
  fi
fi

printf '%s\n' "$workspace"
exit "$code"
