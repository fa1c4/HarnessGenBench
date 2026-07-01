#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

main() {
  local root image workspace code
  root="$(repo_root)"
  load_hgb_config
  ensure_artifacts_present "$root" "g2fuzz" "g2fuzz-data"
  image="$(hgb_image_name "g2fuzz" "g2fuzz" "$root")"
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    bash "$SCRIPT_DIR/g2fuzz_setup.sh"
  fi
  workspace="$(workspace_run_dir "g2fuzz" "$(make_timestamp)" "$root")"
  ensure_dir "$workspace/logs"
  code=0
  run_hgb_container "$image" "$workspace" "generate-seeds"  || code=$?
  bash "$SCRIPT_DIR/g2fuzz_collect_report.sh" "$workspace" >/dev/null 2>&1 || true
  if [[ "$code" -ne 0 ]]; then
    printf 'G2FUZZ seed generation smoke recorded exit code %s. Run directory: %s
' "$code" "$workspace" >&2
    exit "$code"
  fi
  log "G2FUZZ seed generation smoke completed: $workspace"
}
main "$@"
