#!/usr/bin/env bash
set -euo pipefail

repo_root() {
  git rev-parse --show-toplevel
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

require_cmd() {
  local cmd="${1:-}"
  [[ -n "$cmd" ]] || die "require_cmd needs a command name"
  command -v "$cmd" >/dev/null 2>&1 || die "Required command not found: $cmd"
}

make_timestamp() {
  date -u +'%Y%m%dT%H%M%SZ'
}

ensure_dir() {
  local dir="${1:-}"
  [[ -n "$dir" ]] || die "ensure_dir needs a directory path"
  mkdir -p "$dir"
}

load_env() {
  local root env_file
  root="$(repo_root)"
  env_file="$root/.env"

  if [[ -f "$env_file" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$env_file"
    set +a
  fi
}
