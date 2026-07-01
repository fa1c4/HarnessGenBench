#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

main() {
  local root image
  root="$(repo_root)"
  load_hgb_config
  ensure_artifacts_present "$root" "g2fuzz" "g2fuzz-data"
  image="$(hgb_build_image "g2fuzz" "g2fuzz" "$root")"
  log "G2FUZZ Docker image ready: $image"
}
main "$@"
