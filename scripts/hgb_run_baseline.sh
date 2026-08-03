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
  *)
    profile="${profile:-alpha}"
    protocol="${protocol:-target-aware}"
    strict_success="completed"
    ;;
esac

export HGB_BASELINE_PROFILE="$profile"
export HGB_BASELINE_PROTOCOL="$protocol"

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
if [[ -z "$status" ]]; then
  status="missing_metadata"
fi

if [[ "$strict" == "1" ]]; then
  if [[ "$dry_run" == "1" && "$status" == "dry_run_ok" ]]; then
    printf '%s\n' "$workspace"
    exit 0
  fi
  applicability="$(extract_json_string applicability "$metadata")"
  if [[ "$status" == "not_applicable" && "$applicability" == "Invalid" ]]; then
    printf '%s\n' "$workspace"
    exit 0
  fi
  if [[ "$status" != "$strict_success" ]]; then
    reason="$(extract_json_string reason "$metadata")"
    printf 'Baseline strict check failed: generator=%s target=%s status=%s expected=%s reason=%s workspace=%s\n' \
      "$generator" "$target" "$status" "$strict_success" "${reason:-unknown}" "$workspace" >&2
    if [[ "$code" -eq 0 ]]; then code=1; fi
    exit "$code"
  fi
fi

printf '%s\n' "$workspace"
exit "$code"
