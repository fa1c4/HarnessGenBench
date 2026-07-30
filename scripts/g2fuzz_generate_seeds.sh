#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat >&2 <<"EOF"
Usage:
  bash scripts/g2fuzz_generate_seeds.sh [TARGET]

Compatibility wrapper around hgb_run_baseline.sh. The default target is
libpng_libpng_read_fuzzer and the profile is compat-smoke unless overridden by
HGB_BASELINE_PROFILE.
EOF
}

main() {
  local target profile
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi
  target="${1:-libpng_libpng_read_fuzzer}"
  profile="${HGB_BASELINE_PROFILE:-compat-smoke}"
  bash "$SCRIPT_DIR/hgb_run_baseline.sh" \
    --generator g2fuzz \
    --target "$target" \
    --profile "$profile" \
    --protocol "${HGB_BASELINE_PROTOCOL:-paper-native}"
}
main "$@"
