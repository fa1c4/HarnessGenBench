#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

main() {
  local root image workspace code
  root="$(repo_root)"
  load_hgb_config
  ensure_artifacts_present "$root" "promefuzz"
  image="$(hgb_image_name "promefuzz" "promefuzz" "$root")"
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    bash "$SCRIPT_DIR/promefuzz_build_docker.sh"
  fi
  workspace="$(workspace_run_dir "promefuzz" "$(make_timestamp)" "$root")"
  ensure_dir "$workspace/logs"
  code=0
  run_hgb_container "$image" "$workspace" "smoke-pugixml"  || code=$?
  bash "$SCRIPT_DIR/promefuzz_collect_report.sh" "$workspace" >/dev/null 2>&1 || true
  if [[ "$code" -ne 0 ]]; then
    printf 'PromeFuzz smoke recorded exit code %s. Run directory: %s
' "$code" "$workspace" >&2
    exit "$code"
  fi
  log "PromeFuzz smoke completed: $workspace"
}
main "$@"
