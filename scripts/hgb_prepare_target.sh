#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat >&2 <<'EOF'
Usage:
  bash scripts/hgb_prepare_target.sh TARGET
  bash scripts/hgb_prepare_target.sh --target TARGET [--run-id ID] [--output PATH] [--layout compact|full] [--force]
EOF
}

target=""
run_id=""
output=""
layout="compact"
force=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target|-t)
      target="${2:-}"
      shift 2
      ;;
    --run-id)
      run_id="${2:-}"
      shift 2
      ;;
    --output)
      output="${2:-}"
      shift 2
      ;;
    --layout)
      layout="${2:-}"
      shift 2
      ;;
    --force)
      force=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      die "unknown option: $1"
      ;;
    *)
      if [[ -z "$target" ]]; then
        target="$1"
        shift
      else
        die "unexpected argument: $1"
      fi
      ;;
  esac
done

[[ -n "$target" ]] || { usage; exit 64; }
[[ "$layout" == "compact" || "$layout" == "full" ]] || die "--layout must be compact or full"

root="$(repo_root)"
load_hgb_config
export HGB_TARGET_PACKAGE_CACHE_DIR="${HGB_TARGET_PACKAGE_CACHE_DIR:-$(hgb_workspace_dir "$root")/target-package-cache}"
if [[ ! -d "$(artifact_dir fuzzbench "$root")/.git" ]]; then
  log "FuzzBench artifact missing; running scripts/clone_artifacts.sh"
  bash "$root/scripts/clone_artifacts.sh"
fi

run_id="${run_id:-$(make_timestamp)}"
if [[ -z "$output" ]]; then
  output="$(hgb_workspace_dir "$root")/targets/$target/$run_id"
fi

prepare_args=(package "$target" --output "$output" --layout "$layout")
[[ "$force" == "1" ]] && prepare_args+=(--force)
python3 "$SCRIPT_DIR/hgb_targets.py" "${prepare_args[@]}"
