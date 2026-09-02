#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat >&2 <<"EOF"
Usage:
  bash scripts/g2fuzz_build_toolchain.sh

Populates the built G2Fuzz AFL++ toolchain (afl-clang-fast, afl-clang-fast++,
afl-fuzz, instrumentation libraries) into the host artifacts/g2fuzz checkout.

At runtime the generator container bind-mounts the host checkout read-only over
/opt/hgb/artifacts/g2fuzz, shadowing the copy built inside the Docker image.
The host checkout must therefore carry the compiled toolchain. The binaries are
extracted from the pinned generator image (built from the same commit as the
checkout), which guarantees glibc/ABI compatibility with the container runtime;
host-built binaries must not be used because the host glibc can be newer than
the image glibc.

The script is idempotent: it exits early when the checkout already contains an
executable toolchain.
EOF
}

g2fuzz_toolchain_present() {
  local artifact="$1"
  [[ -x "$artifact/afl-clang-fast" ]] &&
    [[ -x "$artifact/afl-clang-fast++" ]] &&
    [[ -x "$artifact/afl-cc" ]] &&
    [[ -x "$artifact/afl-fuzz" ]]
}

main() {
  local root artifact image code
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi
  root="$(repo_root)"
  require_docker
  artifact="$(artifact_dir g2fuzz "$root")"
  [[ -d "$artifact/.git" ]] || die "G2Fuzz artifact checkout missing: $artifact"
  if g2fuzz_toolchain_present "$artifact"; then
    log "G2Fuzz toolchain already present in $artifact; nothing to do"
    return 0
  fi
  image="$(hgb_image_name "g2fuzz" "g2fuzz" "$root")"
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    log "building generator image $image"
    image="$(hgb_build_image "g2fuzz" "g2fuzz" "$root")"
  fi
  if ! docker run --rm --entrypoint /bin/bash "$image" -lc \
    'test -x /opt/hgb/artifacts/g2fuzz/afl-clang-fast && test -x /opt/hgb/artifacts/g2fuzz/afl-clang-fast++ && test -x /opt/hgb/artifacts/g2fuzz/afl-cc && test -x /opt/hgb/artifacts/g2fuzz/afl-fuzz'; then
    die "image $image does not contain a built G2Fuzz AFL++ toolchain; rebuild it with: bash scripts/g2fuzz_setup.sh"
  fi
  log "extracting built G2Fuzz toolchain from $image into $artifact"
  docker run --rm \
    -v "$artifact:/out:rw" \
    --entrypoint rsync \
    "$image" -a --exclude=.git /opt/hgb/artifacts/g2fuzz/ /out/
  if ! g2fuzz_toolchain_present "$artifact"; then
    die "toolchain extraction failed; afl-clang-fast/afl-fuzz are still not executable in $artifact"
  fi
  log "G2Fuzz toolchain ready in $artifact"
}
main "$@"
