#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

main() {
  local root image workspace code
  root="$(repo_root)"
  load_hgb_config
  ensure_artifacts_present "$root" "oss-fuzz-gen"
  image="$(hgb_image_name "oss-fuzz-gen" "oss-fuzz-gen" "$root")"
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    bash "$SCRIPT_DIR/oss_fuzz_gen_setup.sh"
  fi
  workspace="$(workspace_run_dir "oss-fuzz-gen" "$(make_timestamp)" "$root")"
  ensure_dir "$workspace/logs"
  code=0
  run_hgb_container "$image" "$workspace" "smoke" -v /var/run/docker.sock:/var/run/docker.sock || code=$?
  bash "$SCRIPT_DIR/oss_fuzz_gen_collect_report.sh" "$workspace" >/dev/null 2>&1 || true
  if [[ "$code" -ne 0 ]]; then
    printf 'OSS-Fuzz-Gen smoke recorded exit code %s. Run directory: %s
' "$code" "$workspace" >&2
    exit "$code"
  fi
  log "OSS-Fuzz-Gen smoke completed: $workspace"
}
main "$@"
