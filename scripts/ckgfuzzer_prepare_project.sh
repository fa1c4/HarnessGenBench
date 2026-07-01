#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

main() {
  printf 'CKGFuzzer project preparation now happens inside the Docker smoke entrypoint.\n' >&2
  printf 'Running scripts/ckgfuzzer_smoke.sh to create a workspace sample project.\n' >&2
  exec bash "$SCRIPT_DIR/ckgfuzzer_smoke.sh"
}
main "$@"
