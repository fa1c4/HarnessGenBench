#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat >&2 <<"EOF"
Usage:
  bash scripts/g2fuzz_smoke_afl.sh [TARGET]

Compatibility wrapper around the staged G2Fuzz baseline pipeline. The .afl/.cmp
target pair is auto-built from the pinned FuzzBench target inside the G2Fuzz
image; a host-provided pair may still be supplied via G2FUZZ_TARGET_DIR as an
optional override.
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
