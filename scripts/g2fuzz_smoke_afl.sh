#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

main() {
  local root image workspace seed_run code
  local -a extra_mount
  root="$(repo_root)"
  load_hgb_config
  ensure_artifacts_present "$root" "g2fuzz" "g2fuzz-data"
  image="$(hgb_image_name "g2fuzz" "g2fuzz" "$root")"
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    bash "$SCRIPT_DIR/g2fuzz_setup.sh"
  fi
  seed_run="${1:-}"
  if [[ -z "$seed_run" ]]; then
    seed_run="$(latest_workspace_run "g2fuzz" "$root")"
  fi
  extra_mount=()
  if [[ -n "$seed_run" ]]; then
    [[ "$seed_run" = /* ]] || seed_run="$root/$seed_run"
    if [[ -d "$seed_run" ]]; then
      extra_mount=(-e G2FUZZ_SEED_RUN=/seed-run -v "$seed_run:/seed-run:ro")
    fi
  fi
  workspace="$(workspace_run_dir "g2fuzz" "afl_$(make_timestamp)" "$root")"
  ensure_dir "$workspace/logs"
  code=0
  docker run --rm --init \
    -e API_KEY -e BASE_URL -e MODEL -e OPENAI_API_KEY -e OPENAI_BASE_URL -e OPENAI_MODEL \
    -e HGB_HOST_UID="$(id -u)" -e HGB_HOST_GID="$(id -g)" \
    -e G2FUZZ_PROGRAM -e G2FUZZ_AFL_TIMEOUT_SECONDS -e G2FUZZ_MEMORY_MB -e G2FUZZ_REQUIRE_TARGET_BINARIES -e G2FUZZ_TARGET_DIR \
    -v "$workspace:/workspace" \
    "${extra_mount[@]}" \
    "$image" smoke-afl || code=$?
  bash "$SCRIPT_DIR/g2fuzz_collect_report.sh" "$workspace" >/dev/null 2>&1 || true
  if [[ "$code" -ne 0 ]]; then
    printf 'G2FUZZ AFL smoke recorded exit code %s. Run directory: %s\n' "$code" "$workspace" >&2
    exit "$code"
  fi
  log "G2FUZZ AFL smoke completed: $workspace"
}
main "$@"
