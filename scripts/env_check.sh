#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

main() {
  local required optional cmd
  required=(git python3 docker make timeout)
  optional=(jq cmake ninja clang gcc c++filt)

  log "Checking required dependencies"
  for cmd in "${required[@]}"; do
    require_cmd "$cmd"
    log "found required command: $cmd"
  done

  if command -v pip3 >/dev/null 2>&1; then
    log "found required Python package installer: pip3"
  elif python3 -m pip --version >/dev/null 2>&1; then
    log "found required Python package installer: python3 -m pip"
  else
    die "Required Python package installer not found: pip3 or python3 -m pip"
  fi

  log "Checking optional dependencies"
  for cmd in "${optional[@]}"; do
    if command -v "$cmd" >/dev/null 2>&1; then
      log "found optional command: $cmd"
    else
      printf 'WARNING: optional command not found: %s\n' "$cmd" >&2
    fi
  done

  if command -v docker >/dev/null 2>&1 && ! docker info >/dev/null 2>&1; then
    printf 'WARNING: docker is installed, but the daemon is not reachable by this user.\n' >&2
  fi

  log "Environment check complete"
}

main "$@"
