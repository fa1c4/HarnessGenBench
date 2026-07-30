#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat >&2 <<"EOF"
Usage:
  bash scripts/g2fuzz_smoke_afl.sh [TARGET]

Compatibility wrapper around the staged G2Fuzz baseline pipeline. If
G2FUZZ_TARGET_DIR points at host-built .afl/.cmp binaries, hgb_run_baseline.sh
mounts that directory at /g2fuzz-target-pair and sets the container-visible
G2FUZZ_TARGET_DIR to that path.
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
