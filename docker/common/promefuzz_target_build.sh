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

build_workdir_relative="${PROME_FUZZ_NATIVE_BUILD_WORKDIR_RELATIVE:-}"
smoke_run="${PROME_FUZZ_NATIVE_SMOKE_RUN:-1}"
run_timeout="${PROME_FUZZ_NATIVE_RUN_TIMEOUT_SECONDS:-15}"
build_log_dir="${PROME_FUZZ_NATIVE_BUILD_LOG_DIR:-}"
run_log_dir="${PROME_FUZZ_NATIVE_RUN_LOG_DIR:-}"
container_src_root="${PROME_FUZZ_NATIVE_CONTAINER_SRC_ROOT:-/src}"
container_seed_root="${PROME_FUZZ_NATIVE_CONTAINER_SEED_ROOT:-/opt/seeds}"
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
case "$container_src_root" in
  /*) ;;
  *) echo "native container source root must be absolute: $container_src_root" >&2; exit 66 ;;
esac
if [[ -e "$container_src_root" && ! -L "$container_src_root" ]]; then
  echo "native container source root already exists and is not a symlink: $container_src_root" >&2
  exit 67
fi
mkdir -p "$(dirname "$container_src_root")"
if [[ -d "$run_source/seeds" ]]; then
  case "$container_seed_root" in
    /*) ;;
    *) echo "native container seed root must be absolute: $container_seed_root" >&2; exit 66 ;;
  esac
  if [[ -e "$container_seed_root" && ! -L "$container_seed_root" ]]; then
    echo "native container seed root already exists and is not a symlink: $container_seed_root" >&2
    exit 67
  fi
  mkdir -p "$(dirname "$container_seed_root")"
  ln -sfn "$run_source/seeds" "$container_seed_root"
fi
ln -sfn "$run_source" "$container_src_root"


build_workdir="$run_source"
if [[ -n "$build_workdir_relative" ]]; then
  case "$build_workdir_relative" in
    /*|..|../*|*/../*|*/..)
      echo "unsafe native build working directory: $build_workdir_relative" >&2
      exit 66
      ;;
  esac
  build_workdir="$run_source/$build_workdir_relative"
fi
[[ -d "$build_workdir" ]] || {
  echo "native build working directory does not exist: $build_workdir" >&2
  exit 67
}

native_source="$run_source/$relative_destination"
mkdir -p "$(dirname "$native_source")"
cp "$candidate_source" "$native_source"
[[ -f "$run_source/build.sh" ]] || { echo "native source template lacks build.sh" >&2; exit 67; }
while IFS= read -r archive; do
  case "$archive" in
    *.tar.xz)
      archive_dir="${archive%.tar.xz}"
      if [[ -d "$run_source/$archive_dir" && ! -e "$run_source/$archive" ]]; then
        echo "PromeFuzz recreating archived recipe context: $archive" >&2
        tar -C "$run_source" -cJf "$run_source/$archive" "$archive_dir"
      fi
      ;;
  esac
done < <(grep -Eo '[A-Za-z0-9][A-Za-z0-9._+-]*\.tar\.xz' "$run_source/build.sh" | sort -u)

export SRC="$run_source"
export OUT="$run_out"
export WORK="$run_work"
export FUZZING_ENGINE="${FUZZING_ENGINE:-libfuzzer}"
export FUZZER="${FUZZER:-libfuzzer}"
export SANITIZER="${SANITIZER:-address}"
export ARCHITECTURE="${ARCHITECTURE:-x86_64}"
export CC="${CC:-clang}"
export CXX="${CXX:-clang++}"
export LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}"
export FUZZER_LIB="${FUZZER_LIB:--fsanitize=fuzzer}"
export CFLAGS="${CFLAGS:-} -pthread"
export CXXFLAGS="${CXXFLAGS:-} -pthread -Wno-register"

candidate_name="$(basename "$candidate_source")"
candidate_name="${candidate_name%.*}"
candidate_name="$(printf '%s' "$candidate_name" | tr -cs 'A-Za-z0-9._-' '_')"
[[ -n "$candidate_name" ]] || candidate_name="candidate"
build_log=""
if [[ -n "$build_log_dir" ]]; then
  mkdir -p "$build_log_dir"
  build_log="$build_log_dir/$candidate_name.log"
fi

echo "PromeFuzz native build: $native_source -> $OUT/$fuzz_target (workdir: $build_workdir)" >&2
build_status=0
# Do not put the build in an `if !` condition: Bash disables errexit for
# commands in a conditional list, which lets a FuzzBench script with `-e` run
# past a failed build step. Report the child shell's status ourselves instead.
set +e
if [[ -n "$build_log" ]]; then
  (cd "$build_workdir" && timeout "$build_timeout" bash -eu "$run_source/build.sh") >"$build_log" 2>&1
  build_status=$?
else
  (cd "$build_workdir" && timeout "$build_timeout" bash -eu "$run_source/build.sh")
  build_status=$?
fi
set -e
if [[ "$build_status" -ne 0 ]]; then
  if [[ -n "$build_log" ]]; then
    cat "$build_log" >&2
  fi
  exit 68
fi
native_binary="$OUT/$fuzz_target"
[[ -f "$native_binary" && -x "$native_binary" ]] || {
  echo "native build did not produce executable fuzz target: $native_binary" >&2
  exit 68
}
mkdir -p "$(dirname "$candidate_binary")"
if [[ "$smoke_run" == "1" ]]; then
  smoke_input_dir="$native_root/smoke-inputs"
  mkdir -p "$smoke_input_dir"
  : >"$smoke_input_dir/empty"
  run_log=""
  if [[ -n "$run_log_dir" ]]; then
    mkdir -p "$run_log_dir"
    run_log="$run_log_dir/$candidate_name.log"
  fi
  echo "PromeFuzz native smoke run: $native_binary" >&2
  if [[ -n "$run_log" ]]; then
    if ! timeout "$run_timeout" "$native_binary" -runs=1 "$smoke_input_dir/empty" >"$run_log" 2>&1; then
      cat "$run_log" >&2
      exit 69
    fi
  else
    timeout "$run_timeout" "$native_binary" -runs=1 "$smoke_input_dir/empty"
  fi
fi

cp "$native_binary" "$candidate_binary"
chmod +x "$candidate_binary"
