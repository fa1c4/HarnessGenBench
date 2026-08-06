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
  ckgfuzzer)
    case "$profile" in
      alpha|paper-faithful|compat-smoke) ;;
      *) die "ckgfuzzer: invalid profile: $profile (expected alpha, paper-faithful, or compat-smoke)" ;;
    esac
    case "$protocol" in
      blind-project|api-oracle) ;;
      *) die "ckgfuzzer: invalid protocol: $protocol (expected blind-project or api-oracle)" ;;
    esac
    # In alpha/paper-faithful, refuse legacy compat env before an LLM call.
    if [[ "$profile" == "alpha" || "$profile" == "paper-faithful" ]]; then
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
      if [[ -z "$emb" || "$emb" == "mock" || "$emb" == "local" ]]; then
        die "ckgfuzzer/$profile: CKGFUZZER_EMBEDDING_MODEL must be a real embedding service (e.g. openai-text-embedding-3-small), not mock/local/empty"
      fi
    fi
    export HGB_EXCLUDE_FROM_AGGREGATE=0
    [[ "$profile" == "compat-smoke" ]] && export HGB_EXCLUDE_FROM_AGGREGATE=1
    ;;
  promefuzz)
    case "$profile" in
      alpha|paper-faithful|compat-smoke) ;;
      *) die "promefuzz: invalid profile: $profile (expected alpha, paper-faithful, or compat-smoke)" ;;
    esac
    case "$protocol" in
      blind-project|api-oracle) ;;
      *) die "promefuzz: invalid protocol: $protocol (expected blind-project or api-oracle)" ;;
    esac
    # In alpha/paper-faithful, refuse legacy compat env before an LLM call so
    # alpha cannot be silently downgraded to compat-smoke behavior.
    if [[ "$profile" == "alpha" || "$profile" == "paper-faithful" ]]; then
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
    export HGB_EXCLUDE_FROM_AGGREGATE=0
    [[ "$profile" == "compat-smoke" ]] && export HGB_EXCLUDE_FROM_AGGREGATE=1
    ;;
  oss-fuzz-gen)
    case "$profile" in
      alpha|paper-faithful|compat-smoke) ;;
      *) die "oss-fuzz-gen: invalid profile: $profile (expected alpha, paper-faithful, or compat-smoke)" ;;
    esac
    case "$protocol" in
      blind-project|target-aware) ;;
      *) die "oss-fuzz-gen: invalid protocol: $protocol (expected blind-project or target-aware)" ;;
    esac
    # In alpha/paper-faithful, refuse legacy compat env before an LLM call.
    if [[ "$profile" == "alpha" || "$profile" == "paper-faithful" ]]; then
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
    export HGB_EXCLUDE_FROM_AGGREGATE=0
    [[ "$profile" == "compat-smoke" ]] && export HGB_EXCLUDE_FROM_AGGREGATE=1
    ;;
esac

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
