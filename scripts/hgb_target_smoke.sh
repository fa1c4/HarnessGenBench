#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

target="${1:-${TARGET:-}}"
[[ -n "$target" ]] || die "usage: bash scripts/hgb_target_smoke.sh TARGET"

pkg="$(bash "$SCRIPT_DIR/hgb_prepare_target.sh" "$target")"
manifest="$pkg/target_manifest.json"
[[ -f "$manifest" ]] || die "target_manifest.json missing from $pkg"
[[ -f "$pkg/fuzzbench_benchmark/build.sh" ]] || die "build.sh missing from $pkg"

project="$(extract_json_string project "$manifest")"
fuzz_target="$(extract_json_string fuzz_target "$manifest")"
[[ -n "$project" ]] || die "project missing in $manifest"
[[ -n "$fuzz_target" ]] || die "fuzz_target missing in $manifest"

printf '%s\n' "$pkg"
