#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

main() {
  local root image workspace
  root="$(repo_root)"
  load_hgb_config
  ensure_artifacts_present "$root" "elfuzz"
  image="$(hgb_image_name "elfuzz" "elfuzz" "$root")"
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    bash "$SCRIPT_DIR/elfuzz_pull_image.sh"
  fi
  case "${1:---smoke}" in
    --smoke|smoke)
      bash "$SCRIPT_DIR/elfuzz_smoke_jsoncpp.sh"
      ;;
    --shell)
      workspace="$(workspace_run_dir "elfuzz" "shell_$(make_timestamp)" "$root")"
      ensure_dir "$workspace"
      docker run --rm --init -it \
        -e API_KEY -e BASE_URL -e MODEL -e OPENAI_API_KEY -e OPENAI_BASE_URL -e OPENAI_MODEL \
        -e HGB_HOST_UID="$(id -u)" -e HGB_HOST_GID="$(id -g)" \
        -v "$workspace:/workspace" \
        "$image" bash -lc 'while true; do sleep 3600; done'
      ;;
    *)
      die "Usage: bash scripts/elfuzz_start_container.sh [--smoke|--shell]"
      ;;
  esac
}
main "$@"
