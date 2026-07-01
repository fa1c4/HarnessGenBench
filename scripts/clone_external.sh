#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
printf 'scripts/clone_external.sh is deprecated; use scripts/clone_artifacts.sh. Running clone_artifacts now.\n' >&2
exec bash "$SCRIPT_DIR/clone_artifacts.sh" "$@"
