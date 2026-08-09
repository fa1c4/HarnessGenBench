#!/usr/bin/env bash
set -euo pipefail

# CKGFuzzer reproduction-epsilon valuable-target matrix runner (plan
# ckggfuzzer_reproduction_epsilon.md CKG-6). This is a thin wrapper over
# hgb_generate_matrix.sh that accepts the plan's canonical command:
#
#   bash scripts/hgb_run_baseline_matrix.sh \
#     --generator ckgfuzzer \
#     --profile reproduction-epsilon \
#     --protocol blind-project \
#     --targets valuable \
#     --campaign-seconds "$HGB_CAMPAIGN_SECONDS"
#
# It translates ``--generator`` (singular) to ``--generators`` and
# ``--campaign-seconds`` to the ``HGB_CAMPAIGN_SECONDS`` environment variable
# consumed by the lower-level generator wrapper, then delegates to
# hgb_generate_matrix.sh which runs every (generator, target) pair through
# hgb_generate_harness.sh and collects the machine-readable matrix.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

generators=""
profile=""
protocol=""
targets=""
extra_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --generator|--generators)
      generators="${2:-}"
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
    --targets|--target-set)
      targets="${2:-}"
      shift 2
      ;;
    --campaign-seconds)
      export HGB_CAMPAIGN_SECONDS="${2:-}"
      shift 2
      ;;
    -h|--help)
      cat >&2 <<'EOF'
Usage:
  bash scripts/hgb_run_baseline_matrix.sh --generator GENERATOR --targets LIST|all|valuable|deduped [options]

Options:
  --generator NAME         Baseline generator name (ckgfuzzer).
  --profile NAME           Baseline profile (e.g. reproduction-epsilon).
  --protocol NAME          Baseline protocol (e.g. blind-project).
  --targets VALUE          Comma list, all, valuable, or deduped.
  --campaign-seconds N     Per-target campaign budget (exported as HGB_CAMPAIGN_SECONDS).
  Any other option is forwarded to hgb_generate_matrix.sh (--dry-run, --strict,
  --parallel-worker N, --layout, --save-mode, --run-id, ...).
EOF
      exit 0
      ;;
    *)
      extra_args+=("$1")
      shift
      ;;
  esac
done

[[ -n "$generators" ]] || die_profile "hgb_run_baseline_matrix.sh: --generator is required"
[[ -n "$targets" ]] || die_profile "hgb_run_baseline_matrix.sh: --targets is required"

matrix_args=(--generators "$generators" --targets "$targets")
[[ -n "$profile" ]] && matrix_args+=(--profile "$profile")
[[ -n "$protocol" ]] && matrix_args+=(--protocol "$protocol")
if [[ ${#extra_args[@]} -gt 0 ]]; then
  matrix_args+=("${extra_args[@]}")
fi

exec bash "$SCRIPT_DIR/hgb_generate_matrix.sh" "${matrix_args[@]}"
