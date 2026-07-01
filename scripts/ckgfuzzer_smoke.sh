#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

main() {
  local root image workspace code
  root="$(repo_root)"
  load_hgb_config
  ensure_artifacts_present "$root" "ckgfuzzer"
  image="$(hgb_image_name "ckgfuzzer" "ckgfuzzer" "$root")"
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    bash "$SCRIPT_DIR/ckgfuzzer_setup.sh"
  fi
  workspace="$(workspace_run_dir "ckgfuzzer" "$(make_timestamp)" "$root")"
  ensure_dir "$workspace/logs"
  code=0
  run_hgb_container "$image" "$workspace" "smoke"  || code=$?
  bash "$SCRIPT_DIR/ckgfuzzer_collect_report.sh" "$workspace" >/dev/null 2>&1 || true
  if [[ "$code" -ne 0 ]]; then
    printf 'CKGFuzzer smoke recorded exit code %s. Run directory: %s
' "$code" "$workspace" >&2
    exit "$code"
  fi
  log "CKGFuzzer smoke completed: $workspace"
}
main "$@"
