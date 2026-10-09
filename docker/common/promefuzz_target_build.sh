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
# Reuse the staged project tree between sanitization attempts so large targets
# (curl, freetype2, openssl, libxml2, systemd) do not pay a full configure/make
# rebuild for every generated driver. The tree is staged once per run; each call
# only overwrites the candidate at its native path and re-runs the build script,
# which then rebuilds incrementally. The expected output binary is removed before
# the build so the non-fatal-recovery path can never accept a stale binary.
template_marker="$native_root/.hgb_template_staged"
# Stage the project tree once per run and reuse it for every sanitization
# attempt. Never delete a pre-existing tree: interrupt-prone build scripts can
# leave directories that make `rm -rf` fail ("Directory not empty") under
# `set -e`, which aborts the whole run. Reusing/merging is safe because each
# call overwrites the candidate at its native path and re-runs the build.
if [[ ! -d "$run_source" ]]; then
  mkdir -p "$run_source" "$run_out" "$run_work"
  cp -a "$template_root/." "$run_source/"
fi
mkdir -p "$run_source" "$run_out" "$run_work"
touch "$template_marker"
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
# Some recipes enable -Werror and -Wdocumentation, which fails on newer clang
# for upstream doxygen comments. Wrap the compilers so the suppression is
# appended last and cannot be re-enabled by a target's own flags.
compiler_shim_dir="${native_root}/compiler-shims"
mkdir -p "$compiler_shim_dir"
# The shipped clang libFuzzer runtime is built against libstdc++; some recipes
# (php) configure themselves with -stdlib=libc++ and then fail to link the
# engine's std::__cxx11 symbols. Translate libc++ to libstdc++ so every object
# (and the engine) uses one consistent standard library.
write_compiler_shim() {
  local real_compiler="$1" dest="$2"
  cat >"$dest" <<SHIM
#!/bin/bash
out=()
for a in "\$@"; do
  case "\$a" in
    -stdlib=libc++) out+=(-stdlib=libstdc++) ;;
    -lc++) out+=(-lstdc++) ;;
    *) out+=("\$a") ;;
  esac
done
exec ${real_compiler} "\${out[@]}" ${PROME_FUZZ_EXTRA_LDFLAGS:-} -Wno-documentation -Wno-error=documentation -Wno-error=missing-prototypes ${PROME_FUZZ_EXTRA_LIBS:-}
SHIM
  chmod +x "$dest"
}
write_compiler_shim /usr/bin/clang "$compiler_shim_dir/clang"
write_compiler_shim /usr/bin/clang++ "$compiler_shim_dir/clang++"
chmod +x "$compiler_shim_dir/clang" "$compiler_shim_dir/clang++"
# Many FuzzBench build scripts `mkdir <dir>` unconditionally before use. With a
# reused staged tree (incremental rebuilds) that dies under `set -e` with
# "File exists", so the sanitizer can never finalize a driver. Force `mkdir -p`
# through a shim on PATH so re-builds are idempotent.
cat >"$compiler_shim_dir/mkdir" <<'MKDIR_SHIM'
#!/bin/bash
exec /bin/mkdir -p "$@"
MKDIR_SHIM
chmod +x "$compiler_shim_dir/mkdir"
# Recipe build scripts sometimes `rm -rf` a tree that a reused build left in a
# state where GNU rm reports "Directory not empty" (overlay/NFS, busy entries).
# Never let a cleanup step abort the build: force recursive+force and ignore the
# residual status.
cat >"$compiler_shim_dir/rm" <<'RM_SHIM'
#!/bin/bash
exec /bin/rm -rf "$@" 2>/dev/null || true
RM_SHIM
chmod +x "$compiler_shim_dir/rm"
export PATH="$compiler_shim_dir:$PATH"
export CC="${CC:-$compiler_shim_dir/clang}"
export CXX="${CXX:-$compiler_shim_dir/clang++}"
export LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}"
export FUZZER_LIB="${FUZZER_LIB:--fsanitize=fuzzer}"
# Make the project root and the native harness's project include/src dirs
# resolvable so candidates using project-relative includes still compile.
# Scoped to the native project only: adding every sibling source tree (e.g.
# libjpeg's 3.0.x/3.1.x/main branches) shadows branch-specific headers.
project_include_args=(-I"$run_source")
native_dest="${PROME_FUZZ_NATIVE_HARNESS_DESTINATION:-}"
case "$native_dest" in
  /src/*)
    native_first="${native_dest#/src/}"
    native_first="${native_first%%/*}"
    native_project_root="$run_source/$native_first"
    if [[ -n "$native_first" && -d "$native_project_root" ]]; then
      project_include_args+=(-I"$native_project_root")
      for sub in include inc src; do
        [[ -d "$native_project_root/$sub" ]] && project_include_args+=(-I"$native_project_root/$sub")
      done
    fi
    ;;
esac
project_include_flags="${project_include_args[*]}"
export CFLAGS="${CFLAGS:-} -pthread ${project_include_flags} ${PROME_FUZZ_EXTRA_CFLAGS:-}"
export CXXFLAGS="${CXXFLAGS:-} -pthread -Wno-register ${project_include_flags} ${PROME_FUZZ_EXTRA_CXXFLAGS:-}"
export LIBS="${LIBS:-} ${PROME_FUZZ_EXTRA_LIBS:-}"
export LDFLAGS="${LDFLAGS:-} ${PROME_FUZZ_EXTRA_LDFLAGS:-}"
export PIP_BREAK_SYSTEM_PACKAGES="${PIP_BREAK_SYSTEM_PACKAGES:-1}"
export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"

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
# Drop any binary from a previous reused-tree candidate so a failed rebuild is
# never masked by a stale artifact.
rm -f "$run_out/$fuzz_target"
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
  # Some FuzzBench recipes fail only on an unrelated fuzz target or in a
  # trailing post-build step (for example copying a seed corpus zip that the
  # FuzzBench infra would otherwise synthesize). If the expected fuzz binary was
  # produced by this build, continue: the evaluator supplies its own campaign
  # corpus.
  recovered=""
  if [[ -f "$OUT/$fuzz_target" && -x "$OUT/$fuzz_target" ]]; then
    recovered="$OUT/$fuzz_target"
  else
    recovered="$(find "$OUT" "$run_source" -maxdepth 5 -type f -name "$fuzz_target" -perm -u+x 2>/dev/null | head -1 || true)"
  fi
  if [[ -n "$recovered" ]]; then
    echo "PromeFuzz native build: build.sh exited $build_status but produced $recovered; continuing after non-fatal build failure" >&2
    if [[ "$recovered" != "$OUT/$fuzz_target" ]]; then
      cp "$recovered" "$OUT/$fuzz_target" 2>/dev/null || true
    fi
  else
    if [[ -n "$build_log" ]]; then
      cat "$build_log" >&2
    fi
    exit 68
  fi
fi
native_binary="$OUT/$fuzz_target"
[[ -f "$native_binary" && -x "$native_binary" ]] || {
  echo "native build did not produce executable fuzz target: $native_binary" >&2
  exit 68
}
mkdir -p "$(dirname "$candidate_binary")"
if [[ "$smoke_run" == "1" ]]; then
  # Some FuzzBench recipes (systemd in particular) link the fuzz binary to a
  # shared library built under WORK without installing it in the loader path.
  # Resolve only libraries that ldd reports missing; keep the recipe's own
  # build tree as the source of truth.
  while IFS= read -r missing_library; do
    [[ -n "$missing_library" ]] || continue
    library_path="$(find "$run_source" "$run_work" "$run_out" -name "$missing_library" -print -quit 2>/dev/null || true)"
    if [[ -n "$library_path" && -f "$library_path" ]]; then
      export LD_LIBRARY_PATH="$(dirname "$library_path")${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    fi
  done < <(ldd "$native_binary" 2>/dev/null | awk '$2 == "=>" && $3 == "not" {print $1}')
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
