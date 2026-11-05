#!/usr/bin/env bash
set -euo pipefail

# Manual recovery for HGB-owned /tmp directories left by a direct host run.
# Docker --tmpfs mounts are released by Docker when the container stops.
execute=0
min_age_minutes=60
usage() {
  printf 'Usage: %s [--execute] [--min-age-minutes N]\n' "$0" >&2
  printf 'Lists stale /tmp/hgb-campaign-* directories; --execute removes them.\n' >&2
}
while (($#)); do
  case "$1" in
    --execute) execute=1; shift ;;
    --min-age-minutes)
      [[ "${2:-}" =~ ^[0-9]+$ ]] || { usage; exit 64; }
      min_age_minutes="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 64 ;;
  esac
done

while IFS= read -r -d '' candidate; do
  [[ -d "$candidate" && ! -L "$candidate" ]] || continue
  [[ "$(stat -c %u -- "$candidate")" == "$(id -u)" ]] || continue
  pid_file="$candidate/owner.pid"
  if [[ -f "$pid_file" ]]; then
    read -r owner_pid < "$pid_file" || true
    if [[ "${owner_pid:-}" =~ ^[0-9]+$ ]] && kill -0 "$owner_pid" 2>/dev/null; then
      printf 'active: %s (pid %s)\n' "$candidate" "$owner_pid"
      continue
    fi
  fi
  if ((execute)); then
    rm -rf -- "$candidate"
    printf 'removed: %s\n' "$candidate"
  else
    printf 'would remove: %s\n' "$candidate"
  fi
done < <(find /tmp -mindepth 1 -maxdepth 1 -type d -name 'hgb-campaign-*' -mmin "+$min_age_minutes" -print0)
