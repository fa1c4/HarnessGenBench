#!/usr/bin/env bash
# Build one PromeFuzz candidate through the selected FuzzBench target recipe.
#
# The upstream direct clang command has no target objects/libraries, so it can
# accept a harness that only compiles.  This wrapper overlays the candidate at
# the manifest-selected native harness path and requires build.sh to produce
# the declared fuzz target.  Calls are serialized because PromeFuzz sanitizes
# candidates concurrently but a FuzzBench build script owns shared OUT/WORK.
set -euo pipefail

candidate_source="${1:?missing candidate source}"
candidate_binary="${2:?missing candidate binary destination}"
template_root="${PROME_FUZZ_NATIVE_SOURCE_TEMPLATE:?missing native source template}"
native_root="${PROME_FUZZ_NATIVE_BUILD_ROOT:?missing native build root}"
native_destination="${PROME_FUZZ_NATIVE_HARNESS_DESTINATION:?missing native harness destination}"
fuzz_target="${PROME_FUZZ_NATIVE_FUZZ_TARGET:?missing fuzz target}"
build_timeout="${PROME_FUZZ_NATIVE_BUILD_TIMEOUT_SECONDS:-900}"
lock_timeout="${PROME_FUZZ_NATIVE_LOCK_TIMEOUT_SECONDS:-${build_timeout}}"

[[ -f "$candidate_source" ]] || { echo "PromeFuzz candidate source is missing: $candidate_source" >&2; exit 64; }
[[ -d "$template_root" ]] || { echo "PromeFuzz native source template is missing: $template_root" >&2; exit 65; }
case "$native_destination" in
  /src/*) relative_destination="${native_destination#/src/}" ;;
  *) echo "unsafe native harness destination: $native_destination" >&2; exit 66 ;;
esac
[[ -n "$relative_destination" && "$relative_destination" != *".."* ]] || { echo "unsafe native harness destination: $native_destination" >&2; exit 66; }

mkdir -p "$native_root"
exec 9>"$native_root/build.lock"
flock -w "$lock_timeout" 9 || { echo "timed out waiting for PromeFuzz native target build lock" >&2; exit 124; }

run_source="$native_root/src"
run_out="$native_root/out"
run_work="$native_root/work"
rm -rf "$run_source" "$run_out" "$run_work"
mkdir -p "$run_source" "$run_out" "$run_work"
cp -a "$template_root/." "$run_source/"

native_source="$run_source/$relative_destination"
mkdir -p "$(dirname "$native_source")"
cp "$candidate_source" "$native_source"
[[ -f "$run_source/build.sh" ]] || { echo "native source template lacks build.sh" >&2; exit 67; }

export SRC="$run_source"
export OUT="$run_out"
export WORK="$run_work"
export FUZZING_ENGINE="${FUZZING_ENGINE:-libfuzzer}"
export SANITIZER="${SANITIZER:-address}"
export ARCHITECTURE="${ARCHITECTURE:-x86_64}"
export CC="${CC:-clang}"
export CXX="${CXX:-clang++}"
export LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}"
export FUZZER_LIB="${FUZZER_LIB:--fsanitize=fuzzer}"
export CFLAGS="${CFLAGS:-} -pthread"
export CXXFLAGS="${CXXFLAGS:-} -pthread"

echo "PromeFuzz native build: $native_source -> $OUT/$fuzz_target" >&2
timeout "$build_timeout" bash "$run_source/build.sh"
native_binary="$OUT/$fuzz_target"
[[ -f "$native_binary" && -x "$native_binary" ]] || {
  echo "native build did not produce executable fuzz target: $native_binary" >&2
  exit 68
}
mkdir -p "$(dirname "$candidate_binary")"
cp "$native_binary" "$candidate_binary"
chmod +x "$candidate_binary"
