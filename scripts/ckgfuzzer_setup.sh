#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

main() {
  local root image
  root="$(repo_root)"
  load_hgb_config
  ensure_artifacts_present "$root" "ckgfuzzer"
  image="$(hgb_build_image "ckgfuzzer" "ckgfuzzer" "$root")"
  log "CKGFuzzer Docker image ready: $image"
}
main "$@"
