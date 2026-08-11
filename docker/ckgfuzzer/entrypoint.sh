#!/usr/bin/env bash
set -euo pipefail

artifact=/opt/hgb/artifacts/ckgfuzzer
workspace=/workspace
# shellcheck source=/opt/hgb/bin/llm_provider.sh
source /opt/hgb/bin/llm_provider.sh
hgb_resolve_llm_provider

fix_workspace_permissions() {
  if [[ -n "${HGB_HOST_UID:-}" && -n "${HGB_HOST_GID:-}" ]] && command -v chown >/dev/null 2>&1; then
    chown -R "${HGB_HOST_UID}:${HGB_HOST_GID}" "$workspace" 2>/dev/null || true
  fi
}
trap fix_workspace_permissions EXIT
mode="${1:-smoke}"
mkdir -p "$workspace/logs" "$workspace/generated" "$workspace/project/hgb-sample"
json_escape() { local v="${1:-}"; v="${v//\\/\\\\}"; v="${v//\"/\\\"}"; v="${v//$'\n'/\\n}"; printf '%s' "$v"; }
count_files() { local d="$1"; shift || true; [[ -d "$d" ]] || { printf '0'; return 0; }; find "$d" "$@" 2>/dev/null | wc -l | tr -d ' '; }
commit() { git -C "$artifact" rev-parse HEAD 2>/dev/null || printf unknown; }
add_codeql_to_path() {
  local dir="${1:-}" candidate
  [[ -n "$dir" ]] || return 0
  for candidate in "$dir" "$dir/codeql"; do
    if [[ -x "$candidate/codeql" && ! -d "$candidate/codeql" ]]; then
      export PATH="$candidate:$PATH"
      return 0
    fi
  done
}
ckg_codeql_version() {
  if command -v codeql >/dev/null 2>&1; then
    local first_line=''
    IFS= read -r first_line < <(codeql version 2>/dev/null || true)
    printf '%s' "$first_line"
  else
    printf 'unavailable'
  fi
}
write_sample() {
  local d="$workspace/project/hgb-sample"
  mkdir -p "$d/test_usage"
  cat >"$d/sample.h" <<'EOF'
#ifndef HGB_SAMPLE_H
#define HGB_SAMPLE_H
#include <stddef.h>
#include <stdint.h>
int hgb_parse_record(const uint8_t *data, size_t size);
uint32_t hgb_record_checksum(const uint8_t *data, size_t size);
#endif
EOF
  cat >"$d/sample.c" <<'EOF'
#include "sample.h"
uint32_t hgb_record_checksum(const uint8_t *data, size_t size) {
  uint32_t acc = 2166136261u;
  if (!data) return 0;
  for (size_t i = 0; i < size; ++i) { acc ^= data[i]; acc *= 16777619u; }
  return acc;
}
int hgb_parse_record(const uint8_t *data, size_t size) {
  if (!data || size < 4) return 0;
  if (data[0] != 'H' || data[1] != 'G' || data[2] != 'B') return 0;
  uint8_t declared = data[3];
  if ((size_t)declared > size - 4) return -1;
  return (int)(hgb_record_checksum(data + 4, declared) & 0x7fffffffU);
}
EOF
  cat >"$d/test_usage/example_usage.c" <<'EOF'
#include "../sample.h"
#include <stdint.h>
int main(void) {
  const uint8_t data[] = {'H', 'G', 'B', 3, 'o', 'k', '!'};
  return hgb_parse_record(data, sizeof(data)) < 0;
}
EOF
  cat >"$d/api_list.json" <<'EOF'
[
  "hgb_parse_record",
  "hgb_record_checksum"
]
EOF
  cat >"$d/build.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
out="${TMPDIR:-/tmp}/hgb_sample_usage"
cc -Wall -Wextra -I"$SCRIPT_DIR" \
  "$SCRIPT_DIR/sample.c" \
  "$SCRIPT_DIR/test_usage/example_usage.c" \
  -o "$out"
"$out"
EOF
  chmod +x "$d/build.sh"
}
summary() {
  local status="$1" reason="$2" build_code="$3" gen_code="$4"
  {
    printf '# HarnessGenBench CKGFuzzer Summary\n\n'
    printf -- '- Run directory: `%s`\n' "$workspace"
    printf -- '- Upstream commit: `%s`\n' "$(commit)"
    printf -- '- Project: `hgb-sample`\n'
    printf -- '- Model: `%s`\n' "${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
    printf -- '- Status: `%s`\n' "$status"
    printf -- '- Sample build exit code: `%s`\n' "$build_code"
    printf -- '- Generation exit code: `%s`\n' "$gen_code"
    printf -- '- Generated driver candidates: %s\n' "$(count_files "$workspace" -type f \( -name 'driver_*.c' -o -name '*fuzz*.c' -o -name '*fuzz*.cc' \))"
    printf -- '- Top failure reason: %s\n' "$reason"
    printf '\n## Logs\n\n'
    find "$workspace/logs" -type f 2>/dev/null | sort | sed "s#^$workspace/##" | sed 's/^/- `/' | sed 's/$/`/'
  } >"$workspace/HGB_SUMMARY.md"
}
metadata() {
  local status="$1" reason="$2" build_code="$3" gen_code="$4"
  {
    printf '{\n'
    printf '  "fuzzer": "ckgfuzzer",\n'
    printf '  "status": "%s",\n' "$(json_escape "$status")"
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$(commit)")"
    printf '  "project": "hgb-sample",\n'
    printf '  "model": "%s",\n' "$(json_escape "${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}")"
    printf '  "api_key_present": %s,\n' "$([[ -n "${OPENAI_API_KEY:-${API_KEY:-}}" ]] && printf true || printf false)"
    printf '  "sample_build_exit_code": %s,\n' "$build_code"
    printf '  "generation_exit_code": %s,\n' "$gen_code"
    printf '  "reason": "%s",\n' "$(json_escape "$reason")"
    printf '  "command_file": "%s",\n' "$(json_escape "$workspace/command.txt")"
    printf '  "log_dir": "%s"\n' "$(json_escape "$workspace/logs")"
    printf '}\n'
  } >"$workspace/metadata.json"
}

if [[ "$mode" == "generate-target" ]]; then
  # shellcheck source=/opt/hgb/bin/target_contract.sh
  source /opt/hgb/bin/target_contract.sh
  export HGB_GENERATOR="${HGB_GENERATOR:-ckgfuzzer}"
  export HGB_GENERATOR_ARTIFACT_DIR="$artifact"
  export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
  export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
  export OPENAI_MODEL="${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
  export HGB_LLM_REQUEST_TIMEOUT_SECONDS="${HGB_LLM_REQUEST_TIMEOUT_SECONDS:-900}"
  export CKGFUZZER_LLM_REQUEST_TIMEOUT_SECONDS="${CKGFUZZER_LLM_REQUEST_TIMEOUT_SECONDS:-$HGB_LLM_REQUEST_TIMEOUT_SECONDS}"
  export CKGFUZZER_LLM_MAX_RETRIES="${CKGFUZZER_LLM_MAX_RETRIES:-3}"
  # --- Profile and protocol resolution ---
  export HGB_PROFILE="${HGB_BASELINE_PROFILE:-${HGB_PROFILE:-alpha}}"
  export HGB_PROTOCOL="${HGB_BASELINE_PROTOCOL:-${HGB_PROTOCOL:-blind-project}}"
  ckg_profile="$HGB_PROFILE"
  ckg_protocol="$HGB_PROTOCOL"
  case "$ckg_profile" in
    alpha|paper-faithful|reproduction-gamma|reproduction-delta|reproduction-epsilon|reproduction-zeta|compat-smoke) ;;
    *) hgb_write_common_metadata failed "invalid CKGFuzzer profile: $ckg_profile" 64 harness_generator; exit 64 ;;
  esac
  case "$ckg_protocol" in
    blind-project|api-oracle) ;;
    *) hgb_write_common_metadata failed "invalid CKGFuzzer protocol: $ckg_protocol" 64 harness_generator; exit 64 ;;
  esac
  # Method-faithful profiles forbid compat fallbacks even if legacy env is set.
  if [[ "$ckg_profile" == "alpha" || "$ckg_profile" == "paper-faithful" || "$ckg_profile" == "reproduction-gamma" || "$ckg_profile" == "reproduction-delta" || "$ckg_profile" == "reproduction-epsilon" || "$ckg_profile" == "reproduction-zeta" ]]; then
    if [[ "${CKGFUZZER_LOCAL_API_SUMMARY:-0}" == "1" ]]; then
      hgb_write_common_metadata failed "CKGFUZZER_LOCAL_API_SUMMARY=1 is forbidden in $ckg_profile" 64 harness_generator; exit 64
    fi
    if [[ "${CKGFUZZER_LOCAL_API_COMBINATION:-0}" == "1" ]]; then
      hgb_write_common_metadata failed "CKGFUZZER_LOCAL_API_COMBINATION=1 is forbidden in $ckg_profile" 64 harness_generator; exit 64
    fi
    if [[ "${CKGFUZZER_SKIP_CHECK_COMPILATION:-0}" == "1" ]]; then
      hgb_write_common_metadata failed "--skip_check_compilation is forbidden in $ckg_profile" 64 harness_generator; exit 64
    fi
    ckg_emb="${CKGFUZZER_EMBEDDING_MODEL:-}"
    if [[ -z "$ckg_emb" || "$ckg_emb" == "mock" || "$ckg_emb" == "local" || "$ckg_emb" == "hgb-hash-embedding" ]]; then
      hgb_write_common_metadata failed "CKGFUZZER_EMBEDDING_MODEL must be a real embedding service in $ckg_profile, not mock/local/hgb-hash-embedding/empty" 64 harness_generator; exit 64
    fi
    # Strict reproduction profiles (reproduction-zeta and its backward
    # compatible aliases reproduction-epsilon and reproduction-delta) forbid
    # source-only CodeQL graph fallback and selected-harness API mode.
    if [[ "$ckg_profile" == "reproduction-delta" || "$ckg_profile" == "reproduction-epsilon" || "$ckg_profile" == "reproduction-zeta" ]]; then
      if [[ "${CKGFUZZER_ALLOW_SOURCE_FALLBACK:-0}" == "1" ]]; then
        hgb_write_common_metadata failed "CKGFUZZER_ALLOW_SOURCE_FALLBACK=1 is forbidden in $ckg_profile; source-only CodeQL graph fallback is not allowed" 64 harness_generator; exit 64
      fi
      case "${HGB_API_SELECTION_MODE:-}" in
        selected_harness|selected_harness_fallback)
          hgb_write_common_metadata failed "HGB_API_SELECTION_MODE=${HGB_API_SELECTION_MODE} is forbidden in $ckg_profile; reference-harness API filtering is evaluator-only" 64 harness_generator; exit 64 ;;
      esac
    fi
    # reproduction-zeta is the strictest profile (zeta plan §1): force the
    # CodeQL graph to be built from the sealed source snapshot, forbid mock
    # embeddings, and require the target package to be physically split. No
    # compatibility fallbacks are permitted.
    if [[ "$ckg_profile" == "reproduction-zeta" ]]; then
      if [[ "${CKGFUZZER_SOURCE_GRAPH_FALLBACK:-0}" == "1" ]]; then
        hgb_write_common_metadata failed "CKGFUZZER_SOURCE_GRAPH_FALLBACK=1 is forbidden in reproduction-zeta; the CodeQL graph must be built from the sealed source snapshot" 64 harness_generator; exit 64
      fi
      if [[ "${CKGFUZZER_ALLOW_MOCK_EMBEDDING:-0}" == "1" ]]; then
        hgb_write_common_metadata failed "CKGFUZZER_ALLOW_MOCK_EMBEDDING=1 is forbidden in reproduction-zeta; a real embedding service is required" 64 harness_generator; exit 64
      fi
      export CKGFUZZER_SOURCE_GRAPH_FALLBACK=0
      export CKGFUZZER_ALLOW_MOCK_EMBEDDING=0
      export HGB_TARGET_REQUIRE_SPLIT=1
    fi
    # Force upstream LLM paths in method-faithful profiles.
    export CKGFUZZER_LOCAL_API_SUMMARY=0
    export CKGFUZZER_LOCAL_API_COMBINATION=0
    ckg_method_faithful=1
  else
    # compat-smoke: allow deterministic/mock fallbacks.
    export CKGFUZZER_LOCAL_API_SUMMARY="${CKGFUZZER_LOCAL_API_SUMMARY:-1}"
    export CKGFUZZER_LOCAL_API_COMBINATION="${CKGFUZZER_LOCAL_API_COMBINATION:-1}"
    export HGB_EXCLUDE_FROM_AGGREGATE=1
    ckg_method_faithful=0
  fi
  # Initialize stage tracking.
  hgb_result_init_stages "$workspace/stages.json"
  hgb_result_set_stage "$workspace/stages.json" target_prepared completed
  # --- API selection defaults depend on protocol ---
  if [[ "$ckg_protocol" == "blind-project" ]]; then
    # In blind-project, APIs are discovered from public headers, source
    # declarations, project docs, and protocol-allowed examples/tests.
    # Never read the selected-harness-APIs report or reference harnesses.
    export HGB_API_SELECTION_MODE="${HGB_API_SELECTION_MODE:-public_headers}"
    export HGB_SELECTED_API_REPORT=""
    export HGB_API_REPORT_MODE=""
  elif [[ "$ckg_protocol" == "api-oracle" ]]; then
    # In api-oracle, accept only independently declared API names/signatures
    # from declared_api.json. The report is still not the reference harness.
    export HGB_API_SELECTION_MODE="${HGB_API_SELECTION_MODE:-declared_api}"
    export HGB_SELECTED_API_REPORT="${HGB_SELECTED_API_REPORT:-}"
    export HGB_API_REPORT_MODE="${HGB_API_REPORT_MODE:-}"
  else
    export HGB_API_SELECTION_MODE="${HGB_API_SELECTION_MODE:-public_headers}"
    export HGB_SELECTED_API_REPORT=""
    export HGB_API_REPORT_MODE=""
  fi
  export HGB_SELECTED_API_MAX="${HGB_SELECTED_API_MAX:-8}"
  export HGB_SELECTED_API_FALLBACK_MAX="${HGB_SELECTED_API_FALLBACK_MAX:-4}"
  mkdir -p "$workspace/logs" "$workspace/generated_harnesses"
  add_codeql_to_path "${HGB_CODEQL_DIR:-}"
  add_codeql_to_path /opt/codeql
  hgb_require_target_package
  target_name="${HGB_TARGET:-$(hgb_target_manifest_value target)}"
  project="${HGB_TARGET_PROJECT:-$(hgb_target_manifest_value project)}"
  fuzz_target="${HGB_TARGET_FUZZ_TARGET:-$(hgb_target_manifest_value fuzz_target)}"
  safe_target="$(printf '%s' "$target_name" | sed 's/[^A-Za-z0-9_]/_/g')"
  ckg_project="hgb_${safe_target}"
  ckg_root=/fuzzing_llm_engine
  ckg_db="$ckg_root/external_database/$ckg_project"
  ckg_proj="$artifact/fuzzing_llm_engine/projects/$ckg_project"
  ckg_shared="${HGB_CKG_DOCKER_SHARED:-/docker_shared}"
  rm -rf "$ckg_db" "$ckg_proj"
  mkdir -p "$ckg_db/test" "$ckg_proj" "$ckg_shared" "$ckg_shared/codeqldb"
  if [[ "$ckg_shared" != "/docker_shared" ]]; then
    rm -rf /docker_shared 2>/dev/null || true
    ln -s "$ckg_shared" /docker_shared 2>/dev/null || true
  fi
  if [[ -d "$artifact/docker_shared" ]]; then
    cp -a "$artifact/docker_shared/." "$ckg_shared/" 2>/dev/null || true
  fi
  rm -rf "$artifact/docker_shared" 2>/dev/null || true
  ln -s "$ckg_shared" "$artifact/docker_shared" 2>/dev/null || true
  cat >"$ckg_shared/change_owner.sh" <<'EOF_CHANGE_OWNER'
#!/usr/bin/env bash
set -euo pipefail
target_path="${1:-}"
[[ -n "$target_path" ]] || exit 0
owner_uid="${HGB_HOST_UID:-$(id -u)}"
owner_gid="${HGB_HOST_GID:-$(id -g)}"
chown -R "$owner_uid:$owner_gid" "$target_path" 2>/dev/null || true
printf 'Changed ownership of %s to %s:%s.\n' "$target_path" "$owner_uid" "$owner_gid"
EOF_CHANGE_OWNER
  chmod +x "$ckg_shared/change_owner.sh"
  cat >"$ckg_shared/wrapper.sh" <<'EOF_CKG_WRAPPER'
#!/usr/bin/env bash
set -uo pipefail
project="${1:-}"
[[ -n "$project" ]] || project="${HGB_CKG_PROJECT:-hgb_target}"
export SRC="${SRC:-/src/$project}"
export OUT="${OUT:-/out}"
export WORK="${WORK:-/work}"
export CC="${CC:-clang}"
export CXX="${CXX:-clang++}"
export CFLAGS="${CFLAGS:--g -O0}"
export CXXFLAGS="${CXXFLAGS:--g -O0}"
export LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE:-}"
export HGB_CKG_BUILD_DIR="${HGB_CKG_BUILD_DIR:-$SRC}"
mkdir -p "$OUT" "$WORK" "$WORK/hgb-codeql-objects"
marker="/src/fuzzing_os/hgb_compiled_units_${project}.txt"
printf '0\n' >"$marker"
run_build=0
if [[ -x /target/fuzzbench_benchmark/build.sh ]]; then
  echo "[hgb-codeql] replaying /target/fuzzbench_benchmark/build.sh with SRC=$SRC and build dir=$HGB_CKG_BUILD_DIR"
  (cd "$HGB_CKG_BUILD_DIR" && bash /target/fuzzbench_benchmark/build.sh) || run_build=$?
elif [[ -x /src/build.sh ]]; then
  echo "[hgb-codeql] replaying /src/build.sh with SRC=$SRC and build dir=$HGB_CKG_BUILD_DIR"
  (cd "$HGB_CKG_BUILD_DIR" && bash /src/build.sh) || run_build=$?
elif [[ -x "$SRC/build.sh" ]]; then
  echo "[hgb-codeql] replaying $SRC/build.sh"
  (cd "$HGB_CKG_BUILD_DIR" && bash "$SRC/build.sh") || run_build=$?
fi
count=0
include_args=(-I"$SRC")
while IFS= read -r -d '' include_dir; do
  include_args+=("-I$include_dir")
done < <(find "$SRC" -maxdepth 3 -type d -name include -print0 2>/dev/null | sort -z)
while IFS= read -r -d '' src_file; do
  case "$src_file" in
    *.c) compiler="$CC"; std="-std=c11" ;;
    *) compiler="$CXX"; std="-std=c++17" ;;
  esac
  obj="$WORK/hgb-codeql-objects/${count}.o"
  if "$compiler" $std "${include_args[@]}" -D_FORTIFY_SOURCE=0 -c "$src_file" -o "$obj" >/dev/null 2>&1; then
    count=$((count + 1))
    printf '%s\n' "$count" >"$marker"
  fi
done < <(find "$SRC" -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' \) -print0 2>/dev/null | sort -z)
echo "[hgb-codeql] fallback compiled $count translation units"
build_artifact="$(find "$HGB_CKG_BUILD_DIR" "$SRC" "$OUT" "$WORK" -type f \( -name '*.o' -o -name '*.lo' -o -name '*.a' -o -name '*.so' -o -name '*.so.*' -o -name '*.dylib' -o -name '*.dll' \) -print -quit 2>/dev/null || true)"
if [[ -n "$build_artifact" ]]; then
  echo "[hgb-codeql] build replay produced compiled artifact: $build_artifact"
fi
if [[ "$count" -gt 0 || "$run_build" -eq 0 || -n "$build_artifact" ]]; then
  exit 0
fi
exit "$run_build"
EOF_CKG_WRAPPER
  chmod +x "$ckg_shared/wrapper.sh"
  if command -v codeql >/dev/null 2>&1; then
    codeql_bin="$(command -v codeql)"
    codeql_home="$(dirname "$codeql_bin")"
    if [[ ! -x "$ckg_shared/codeql/codeql" ]]; then
      rm -rf "$ckg_shared/codeql"
      mkdir -p "$ckg_shared/codeql"
      cp -a "$codeql_home/." "$ckg_shared/codeql/" 2>/dev/null || ln -sf "$codeql_bin" "$ckg_shared/codeql/codeql"
    fi
  fi
  if [[ -d "$ckg_shared/qlpacks/cpp_queries" ]]; then
    for ql_template in \
      "$ckg_shared/qlpacks/cpp_queries/extract_call_graph_template.ql" \
      "$ckg_shared/qlpacks/cpp_queries/extract_call_graph_template_fast.ql"; do
      [[ -f "$ql_template" ]] || continue
      cat >"$ql_template" <<'EOF_CKG_CALL_GRAPH_QL'
import cpp

predicate directCall(Function caller, Function callee) {
  exists(FunctionCall fc |
    fc.getEnclosingFunction() = caller and
    fc.getTarget() = callee
  )
}

predicate virtualCall(Function caller, Function callee) {
  exists(Call vc |
    vc.getEnclosingFunction() = caller and
    vc.getTarget() = callee and
    exists(MemberFunction mf |
      mf = callee and
      exists(MemberFunction base |
        base = mf.getAnOverriddenFunction*() and
        base.isVirtual()
      )
    )
  )
}

predicate edges(Function caller, Function callee) {
  directCall(caller, callee) or virtualCall(caller, callee)
}

predicate reachableWithDepth(Function src, Function dest, int depth) {
  depth = 1 and edges(src, dest)
  or
  depth in [2..5] and
  exists(Function mid |
    edges(src, mid) and
    reachableWithDepth(mid, dest, depth - 1)
  )
}

predicate isEntryPoint(Function f) {
  f.hasName("main") or
  f.hasName("ENTRY_FNC") or
  exists(Function func |
    func = f and
    (
      exists(Class c |
        c.getAMember() = func and
        func.getName() = c.getName()
      ) or
      not exists(Class c | c.getAMember() = func)
    )
  )
}

from Function start, Function end, Location start_loc, Location end_loc, int depth
where
  isEntryPoint(start) and
  depth in [1..5] and
  reachableWithDepth(start, end, depth) and
  start_loc = start.getLocation() and
  end_loc = end.getLocation()
select
  start as caller,
  end as callee,
  start.getFile() as caller_src,
  end.getFile() as callee_src,
  start_loc.getStartLine() as start_body_start_line,
  start_loc.getEndLine() as start_body_end_line,
  end_loc.getStartLine() as end_body_start_line,
  end_loc.getEndLine() as end_body_end_line,
  start.getName() as caller_signature,
  start.getParameterString() as caller_parameter_string,
  start.getType() as caller_return_type,
  start.getUnspecifiedType() as caller_return_type_inferred,
  end.getName() as callee_signature,
  end.getParameterString() as callee_parameter_string,
  end.getType() as callee_return_type,
  end.getUnspecifiedType() as callee_return_type_inferred
EOF_CKG_CALL_GRAPH_QL
    done
  fi
  ckg_analysis_src="$ckg_shared/source_code/$ckg_project"
  export CKGFUZZER_SOURCE_ROOT="$ckg_analysis_src"
  ckg_stage_metadata="$workspace/ckg_stage.json"
  ckg_build_dir="$(python3 /opt/hgb/bin/ckgfuzzer_stage_project.py \
    --target-root /target \
    --project-dir "$ckg_proj" \
    --analysis-dir "$ckg_analysis_src" \
    --project-name "$ckg_project" \
    --metadata "$ckg_stage_metadata")"
  if [[ ! -f "$ckg_proj/build.sh" ]]; then
    cat >"$ckg_proj/build.sh" <<'EOF_CKG_STUB_BUILD'
#!/usr/bin/env bash
set -euo pipefail
: "${SRC:=$(pwd)}"
: "${OUT:=/out}"
: "${WORK:=/work}"
mkdir -p "$OUT" "$WORK"
exit 0
EOF_CKG_STUB_BUILD
    chmod +x "$ckg_proj/build.sh"
  fi
  cat >"$ckg_proj/Dockerfile" <<EOF_CKG_DOCKERFILE
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build make pkg-config clang git ca-certificates \
    autoconf automake libtool meson python3 python3-pip zlib1g-dev libssl-dev libxml2-dev \
    zip ruby rake bison nasm subversion libgcrypt-dev wget \
  && rm -rf /var/lib/apt/lists/*
ENV SRC=/src/$ckg_project
ENV HGB_CKG_BUILD_DIR=$ckg_build_dir
ENV OUT=/out
ENV WORK=/work
ENV CC=clang
ENV CXX=clang++
ENV CFLAGS=-g
ENV CXXFLAGS=-g
ENV LIB_FUZZING_ENGINE=
RUN mkdir -p /out /work
COPY . /src/$ckg_project/
COPY build.sh /src/build.sh
WORKDIR $ckg_build_dir
EOF_CKG_DOCKERFILE
  if [[ "$(hgb_count_files "$ckg_proj" -type f)" == "0" ]]; then
    hgb_soft_skip source_input_missing 'target package does not contain source files for CKGFuzzer API extraction' harness_generator
  fi
  # Generator/evaluator isolation: in blind-project the CKGFuzzer process
  # must never see the exact target reference harness. HGB_TARGET_REFERENCE_DIR
  # is not exported by the host runner in blind-project; enforce the same
  # contract inside the container regardless of legacy flags.
  if [[ "$ckg_protocol" == "blind-project" || -z "${HGB_TARGET_REFERENCE_DIR:-}" ]]; then
    if [[ -d /target/reference_harnesses ]]; then
      printf 'WARNING: /target/reference_harnesses exists but blind-project isolation forbids reading it; ignoring\n' >"$workspace/logs/reference_isolation.log"
    fi
    cat >"$ckg_db/test/hgb_neutral_usage.c" <<'EOF_CKG_USAGE'
#include <stdint.h>
int main(void) { const uint8_t data[] = {0}; return (int)data[0]; }
EOF_CKG_USAGE
  elif [[ "${HGB_ALLOW_REFERENCE_USAGE:-0}" == "1" && -n "${HGB_TARGET_REFERENCE_DIR:-}" && -d "${HGB_TARGET_REFERENCE_DIR}" ]]; then
    cp -a "${HGB_TARGET_REFERENCE_DIR}/." "$ckg_db/test/" 2>/dev/null || true
  else
    cat >"$ckg_db/test/hgb_neutral_usage.c" <<'EOF_CKG_USAGE'
#include <stdint.h>
int main(void) { const uint8_t data[] = {0}; return (int)data[0]; }
EOF_CKG_USAGE
  fi

  api_selection_metadata="$workspace/api_selection.json"
  selected_reference_dir="/target/reference_harnesses/selected"
  ckg_api_extract_args=(
    --source /target/source_input
    --out "$ckg_db/api_list.json"
    --max "${CKGFUZZER_MAX_APIS:-${HGB_SELECTED_API_MAX:-8}}"
    --fallback-max "${HGB_SELECTED_API_FALLBACK_MAX:-4}"
    --selection-mode "${HGB_API_SELECTION_MODE:-public_headers}"
    --project "$project"
    --target-name "$target_name"
    --fuzz-target "$fuzz_target"
    --selection-metadata "$api_selection_metadata"
  )
  # In blind-project, do not pass reference-dir or api-report: APIs are
  # discovered from public headers, source declarations, and docs only.
  if [[ "$ckg_protocol" != "blind-project" ]]; then
    ckg_api_extract_args+=(--reference-dir "$selected_reference_dir")
    if [[ -n "${HGB_SELECTED_API_REPORT:-}" ]]; then
      ckg_api_extract_args+=(--api-report "$HGB_SELECTED_API_REPORT")
    fi
    if [[ -n "${HGB_API_REPORT_MODE:-}" ]]; then
      ckg_api_extract_args+=(--report-mode "$HGB_API_REPORT_MODE")
    fi
    ckg_api_extract_args+=(--allow-name-only-report-apis)
  fi
  api_count="$(python3 /opt/hgb/bin/extract_api_list.py \
    "${ckg_api_extract_args[@]}" \
    2>"$workspace/logs/api_extract.log" || printf '0')"
  api_count="${api_count##*$'\n'}"
  export CKGFUZZER_SELECTED_API_LIST="$ckg_db/api_list.json"
  if ! ckg_program_language="$(python3 /opt/hgb/bin/ckgfuzzer_target_harness.py \
    --target-root /target --fuzz-target "$fuzz_target" --field language 2>"$workspace/logs/native_harness.log")"; then
    # In blind-project split mode the sanitized generator manifest does not
    # carry selected_reference_harness_files, so the native-harness resolver
    # cannot determine the language.  Infer it from the source_input files
    # instead of soft-skipping: the generator needs the language tag for its
    # config but must not read evaluator-only reference harness metadata.
    ckg_lang_script="$workspace/logs/ckg_infer_language.py"
    mkdir -p "$(dirname "$ckg_lang_script")"
    cat >"$ckg_lang_script" <<'PY_CKG_LANG_INFER'
import sys
from pathlib import Path
root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/target/source_input")
if not root.is_dir():
    print("c")
    sys.exit(0)
cpp = any(p.suffix.lower() in {".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp"} for p in root.rglob("*") if p.is_file())
print("c++" if cpp else "c")
PY_CKG_LANG_INFER
    ckg_program_language="$(python3 "$ckg_lang_script" /target/source_input 2>/dev/null || printf 'c')"
    if [[ -z "$ckg_program_language" ]]; then
      ckg_program_language="c"
    fi
    printf 'Inferred CKGFuzzer program_language=%s from source_input (native harness resolver unavailable in blind mode)\n' "$ckg_program_language" >>"$workspace/logs/native_harness.log"
  fi
  case "$ckg_program_language" in
    c|c++) ;;
    *) hgb_soft_skip ckg_native_harness_unresolved "unsupported native harness language: $ckg_program_language" harness_generator ;;
  esac
  if [[ "$ckg_method_faithful" == "1" ]]; then
    ckg_embedding_default="openai-text-embedding-3-small"
  else
    ckg_embedding_default="mock"
  fi
  cat >"$ckg_db/config.yaml" <<EOF_CKG_CONFIG
config:
  project_name: "$ckg_project"
  program_language: "$ckg_program_language"
  fuzz_projects_dir: "$ckg_db/"
  work_dir: "$artifact/"
  shared_dir: "$ckg_shared/"
  report_target_dir: "$ckg_proj"
  time_budget: "${CKGFUZZER_FUZZ_TIME_BUDGET:-5m}"
  headers:
    - <stdint.h>
    - <stddef.h>
    - <stdlib.h>
    - <string.h>
project_name: "$ckg_project"
api_key: "${OPENAI_API_KEY:-}"
base_url: "${OPENAI_BASE_URL:-}"
model: "${OPENAI_MODEL:-}"
llm_coder:
  model: "${OPENAI_MODEL:-gpt-4o-mini}"
  api_key: "${OPENAI_API_KEY:-}"
  base_url: "${OPENAI_BASE_URL:-}"
  temperature: 0.0
  request_timeout: ${CKGFUZZER_LLM_REQUEST_TIMEOUT_SECONDS:-900}
  max_retries: ${CKGFUZZER_LLM_MAX_RETRIES:-3}
llm_analyzer:
  model: "${OPENAI_MODEL:-gpt-4o-mini}"
  api_key: "${OPENAI_API_KEY:-}"
  base_url: "${OPENAI_BASE_URL:-}"
  temperature: 0.0
  request_timeout: ${CKGFUZZER_LLM_REQUEST_TIMEOUT_SECONDS:-900}
  max_retries: ${CKGFUZZER_LLM_MAX_RETRIES:-3}
llm_embedding:
  model: "${CKGFUZZER_EMBEDDING_MODEL:-$ckg_embedding_default}"
  api_key: "${CKGFUZZER_EMBEDDING_API_KEY:-${OPENAI_API_KEY:-}}"
  base_url: "${CKGFUZZER_EMBEDDING_BASE_URL:-${OPENAI_BASE_URL:-}}"
llm_code_embedding:
  model: "${CKGFUZZER_EMBEDDING_MODEL:-$ckg_embedding_default}"
  api_key: "${CKGFUZZER_EMBEDDING_API_KEY:-${OPENAI_API_KEY:-}}"
  base_url: "${CKGFUZZER_EMBEDDING_BASE_URL:-${OPENAI_BASE_URL:-}}"
source_dir: "$ckg_analysis_src"
output_dir: "$workspace/generated_harnesses"
build_command: "bash /target/fuzzbench_benchmark/build.sh"
EOF_CKG_CONFIG
  printf 'CKGFuzzer project: %s\nlanguage: %s\napi_list: %s\nconfig: %s\n' "$ckg_project" "$ckg_program_language" "$ckg_db/api_list.json" "$ckg_db/config.yaml" >"$workspace/command.txt"
  if [[ "${api_count:-0}" == "0" ]]; then
    hgb_soft_skip no_api_candidates 'no C/C++ API candidates were extracted from target source_input' harness_generator
  fi
  if [[ "${HGB_DRY_RUN:-0}" == "1" ]]; then
    hgb_write_common_metadata dry_run_ok 'dry run prepared CKGFuzzer project config and API list' 0 harness_generator
    hgb_write_common_summary dry_run_ok 'dry run prepared CKGFuzzer project config and API list' harness_generator
    exit 0
  fi
  if ! hgb_api_key_present; then
    printf 'OPENAI_API_KEY is not set; CKGFuzzer target generation skipped.\n' >"$workspace/logs/generation.log"
    hgb_write_common_metadata missing_api_key 'OPENAI_API_KEY is not set' 2 harness_generator
    hgb_write_common_summary missing_api_key 'OPENAI_API_KEY is not set' harness_generator
    exit 2
  fi
  if [[ "${CKGFUZZER_SKIP_CODEQL:-0}" != "1" ]] && ! command -v codeql >/dev/null 2>&1; then
    hgb_soft_skip missing_codeql 'CodeQL CLI is not available; rebuild the CKGFuzzer image with HGB_INSTALL_CODEQL=1, set HGB_CODEQL_DIR, or set CKGFUZZER_SKIP_CODEQL=1 to bypass this check' harness_generator
  fi
  repo_py="$(find "$artifact" -name repo.py -type f 2>/dev/null | head -n 1 || true)"
  preproc_py="$(find "$artifact" -name preproc.py -type f 2>/dev/null | head -n 1 || true)"
  fuzzing_py="$(find "$artifact" -name fuzzing.py -type f 2>/dev/null | head -n 1 || true)"
  if [[ -z "$repo_py" || -z "$preproc_py" || -z "$fuzzing_py" ]]; then
    hgb_soft_skip upstream_cli_not_found 'could not find repo.py, preproc.py, and fuzzing.py in the CKGFuzzer artifact' harness_generator
  fi
  python3 - "$repo_py" <<'PY_CKG_REPO_PATCH'
from pathlib import Path
import re
import sys
path = Path(sys.argv[1])
text = path.read_text()
for required_import in ("import json\n", "import os\n", "import sys\n"):
    if required_import not in text:
        text = required_import + text
old = """        eggs = [ (api[0].strip(), api[1].strip(), self.database_db, self.output_results_folder, self.shared_llm_dir) for api in src_api ]
        logger.info(f"Total number of API to be processed: {len(eggs)}")
"""
new = """        eggs = [ (api[0].strip(), api[1].strip(), self.database_db, self.output_results_folder, self.shared_llm_dir) for api in src_api ]
        selected_api_names = []
        selected_api_path = os.environ.get("CKGFUZZER_SELECTED_API_LIST", "")
        if selected_api_path and os.path.isfile(selected_api_path):
            try:
                selected_raw = json.load(open(selected_api_path))
                for item in selected_raw:
                    if isinstance(item, str):
                        selected_api_names.append(item)
                    elif isinstance(item, dict) and item.get("name"):
                        selected_api_names.append(str(item.get("name")))
            except Exception as exc:
                logger.warning(f"Failed to load HGB selected API list {selected_api_path}: {exc}")
        if selected_api_names:
            selected_keys = [name.split("::")[-1].lower() for name in selected_api_names]
            matched = []
            used = set()
            for wanted in selected_keys:
                for egg in eggs:
                    key = egg[0].split("::")[-1].lower()
                    if key == wanted and id(egg) not in used:
                        matched.append(egg)
                        used.add(id(egg))
                        break
            if matched:
                logger.info(f"Filtered API call graph processing from {len(eggs)} to {len(matched)} HGB-selected APIs: {selected_api_names}")
                eggs = matched
            else:
                logger.warning(f"No extracted source definitions matched HGB-selected APIs: {selected_api_names}")
                eggs = []
        max_apis = int(os.environ.get("CKGFUZZER_MAX_CALL_GRAPH_APIS", "8") or "0")
        if max_apis > 0 and len(eggs) > max_apis:
            logger.info(f"Limiting API call graph processing from {len(eggs)} to {max_apis} for HGB integration.")
            eggs = eggs[:max_apis]
        logger.info(f"Total number of API to be processed: {len(eggs)}")
"""
if old in text:
    text = text.replace(old, new, 1)
cleanup_pattern = re.compile(
    r"""        for i in tqdm\(range\(pool_num\)\):
            shutil\.copytree\(self\.database_db, f'\{self\.database_db\}_\{i\}', dirs_exist_ok=True\)
            queue_id\.put\(i\)

        with Pool\(pool_num\) as pool:[ \t]*
            results = list\(tqdm\(pool\.imap\(RepositoryAgent\.handle_extract_api_call_graph_multiple_path, eggs\), total=len\(eggs\), desc='Processing transactions'\)\)[ \t]*
[ \t]*
        for i in range\(pool_num\):
            shutil\.rmtree\(f'\{self\.database_db\}_\{i\}'\)
"""
)
new_cleanup = """        try:
            for i in tqdm(range(pool_num)):
                shutil.copytree(self.database_db, f'{self.database_db}_{i}', dirs_exist_ok=True)
                queue_id.put(i)

            with Pool(pool_num) as pool:
                results = list(tqdm(pool.imap(RepositoryAgent.handle_extract_api_call_graph_multiple_path, eggs), total=len(eggs), desc='Processing transactions'))
        finally:
            for i in range(pool_num):
                shutil.rmtree(f'{self.database_db}_{i}', ignore_errors=True)
"""
text = cleanup_pattern.sub(new_cleanup, text, count=1)
path.write_text(text)
PY_CKG_REPO_PATCH
  python3 - "$repo_py" <<'PY_CKG_REPO_DOCKER_MOUNT_PATCH'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = """        # Run the Docker container with the CodeQL command
        command = [
            'docker', 'run', '--rm',
            '-v', f'{args.shared_llm_dir}:/src/fuzzing_os',
            '-t', image_name,
            '/bin/bash', '-c', codeql_command
        ]
"""
new = """        # Run the Docker container with the CodeQL command. HGB exposes
        # the prepared target package to the inner Docker run when available.
        command = [
            'docker', 'run', '--rm',
            '-v', f'{args.shared_llm_dir}:/src/fuzzing_os',
        ]
        target_package_host = os.environ.get('HGB_TARGET_PACKAGE_HOST')
        if target_package_host:
            command.extend(['-v', f'{target_package_host}:/target:ro'])
        elif os.path.isdir('/target'):
            command.extend(['-v', '/target:/target:ro'])
        if sys.stdin.isatty() and sys.stdout.isatty():
            command.extend(['-t'])
        command.extend([
            image_name,
            '/bin/bash', '-c', codeql_command
        ])
"""
if old in text and "'/target:/target:ro'" not in text:
    text = text.replace(old, new, 1)
old_success = """        if f"Successfully created database at /src/fuzzing_os/codeqldb/{args.project_name}" in result.stdout:
            with open(f'{args.shared_llm_dir}/codeqldb/{args.project_name}/.successfully_created', 'w') as f:
                f.write('')
            logger.info(result.stdout)
            logger.info(f"Confirmed Successfully created database at /src/fuzzing_os/codeqldb/{args.project_name}")
        else:
            print(result.stdout)
            print(result.stderr)
            assert False, f"Failed to create database at /src/fuzzing_os/codeqldb/{args.project_name}"
"""
new_success = """        success_message = f"Successfully created database at /src/fuzzing_os/codeqldb/{args.project_name}"
        combined_output = (result.stdout or "") + "\\n" + (result.stderr or "")
        database_dir = f'{args.shared_llm_dir}/codeqldb/{args.project_name}'
        database_created = result.returncode == 0 and (success_message in combined_output or os.path.isdir(database_dir))
        if database_created:
            with open(f'{database_dir}/.successfully_created', 'w') as f:
                f.write('')
            if result.stdout:
                logger.info(result.stdout)
            if result.stderr:
                logger.info(result.stderr)
            logger.info(f"Confirmed Successfully created database at /src/fuzzing_os/codeqldb/{args.project_name}")
        else:
            print(result.stdout)
            print(result.stderr)
            logger.error(f"CodeQL database create exited {result.returncode} for {args.project_name}")
            assert False, f"Failed to create database at /src/fuzzing_os/codeqldb/{args.project_name}"
"""
if old_success in text and "database_created = result.returncode == 0" not in text:
    text = text.replace(old_success, new_success, 1)
path.write_text(text)
PY_CKG_REPO_DOCKER_MOUNT_PATCH
  python3 - "$artifact" <<'PY_CKG_RUNTIME_DOCKER_PATCH'
from pathlib import Path
import re
import sys
root = Path(sys.argv[1])
check_path = root / "fuzzing_llm_engine/utils/check_gen_fuzzer.py"
if check_path.exists():
    text = check_path.read_text()
    if "import sys\n" not in text:
        text = "import sys\n" + text
    old = """  command = [
      'docker', 'exec', '-u', 'root','-it', project_name+"_check" ]
  command.extend(run_args)
"""
    new = """  command = ['docker', 'exec', '-u', 'root']
  if sys.stdin.isatty() and sys.stdout.isatty():
    command.extend(['-i', '-t'])
  command.append(project_name+"_check")
  command.extend(run_args)
"""
    if old in text:
        text = text.replace(old, new, 1)
    old = """  except subprocess.CalledProcessError as e:
    if print_output:
      return e.output.decode('utf-8', errors='replace')
"""
    new = """  except subprocess.CalledProcessError as e:
    if print_output:
      return e.output.decode('utf-8', errors='replace')
    return f"ERROR: docker exec failed with exit code {e.returncode}"
"""
    if old in text:
        text = text.replace(old, new, 1)
    check_path.write_text(text)

run_path = root / "fuzzing_llm_engine/roles/run_fuzzer.py"
if run_path.exists():
    text = run_path.read_text()
    replacements = [
        (
            r'''build_fuzzer_result =  run\(run_args\)[ \t]*
        logger\.info\(f"compile \{fuzz_driver_file\}, result \{build_fuzzer_result\}"\)''',
            """build_fuzzer_result =  run(run_args)
        if not isinstance(build_fuzzer_result, str):
            build_fuzzer_result = f"ERROR: non-string result from build_fuzzer_file: {build_fuzzer_result!r}"
        logger.info(f"compile {fuzz_driver_file}, result {build_fuzzer_result}")""",
        ),
        (
            r'''run_fuzzer_result =  run\(run_args\)[ \t]*
            logger\.info\(f"run_fuzzer \{fuzz_driver_file\}, result \{run_fuzzer_result\}"\)''',
            """run_fuzzer_result =  run(run_args)
            if not isinstance(run_fuzzer_result, str):
                run_fuzzer_result = f"ERROR: non-string result from run_fuzzer: {run_fuzzer_result!r}"
            logger.info(f"run_fuzzer {fuzz_driver_file}, result {run_fuzzer_result}")""",
        ),
        (
            r'''build_fuzzer_result =  run\(run_args\)[ \t]*
                        logger\.info\(f"compile \{fuzz_driver_file\}, result \{build_fuzzer_result\}"\)''',
            """build_fuzzer_result =  run(run_args)
                        if not isinstance(build_fuzzer_result, str):
                            build_fuzzer_result = f"ERROR: non-string result from build_fuzzer_file: {build_fuzzer_result!r}"
                        logger.info(f"compile {fuzz_driver_file}, result {build_fuzzer_result}")""",
        ),
        (
            r'''run_fuzzer_result =  run\(run_args\)[ \t]*
                        logger\.info\(f"run_fuzzer \{fuzz_driver_file\}, result \{run_fuzzer_result\}"\)''',
            """run_fuzzer_result =  run(run_args)
                        if not isinstance(run_fuzzer_result, str):
                            run_fuzzer_result = f"ERROR: non-string result from run_fuzzer: {run_fuzzer_result!r}"
                        logger.info(f"run_fuzzer {fuzz_driver_file}, result {run_fuzzer_result}")""",
        ),
    ]
    for pattern, replacement in replacements:
        if replacement not in text:
            text = re.sub(pattern, lambda _match: replacement, text, count=1)
    run_path.write_text(text)

fix_path = root / "fuzzing_llm_engine/roles/compilation_fix_agent.py"
if fix_path.exists():
    text = fix_path.read_text()
    pattern = r'''                result =  run\(run_args\)[ \t]*
            logger\.info\(f"check_compilation \{file\}, result:\\n \{result\}"\)
            if "error:" not in result:
'''
    replacement = """                result =  run(run_args)
            if not isinstance(result, str):
                result = f"ERROR: non-string result from check_compilation: {result!r}"
            logger.info(f"check_compilation {file}, result:\\n {result}")
            lowered_result = result.lower()
            if "error:" not in lowered_result and "input device is not a tty" not in lowered_result and "error" not in lowered_result:
"""
    if replacement not in text:
        text = re.sub(pattern, lambda _match: replacement, text, count=1)
    fix_path.write_text(text)
PY_CKG_RUNTIME_DOCKER_PATCH
  get_model_py="$(find "$artifact" -path '*/models/get_model.py' -type f 2>/dev/null | head -n 1 || true)"
  if [[ -n "$get_model_py" ]]; then
    CKG_METHOD_FAITHFUL="$ckg_method_faithful" python3 - "$get_model_py" <<'PY_CKG_MODEL_PATCH'
from pathlib import Path
import os
import sys
path = Path(sys.argv[1])
text = path.read_text()
method_faithful = os.environ.get("CKG_METHOD_FAITHFUL", "0") == "1"
if not method_faithful:
    if "from llama_index.core.embeddings import MockEmbedding" not in text:
        text = text.replace(
            "from llama_index.embeddings.ollama import OllamaEmbedding\n",
            "from llama_index.embeddings.ollama import OllamaEmbedding\nfrom llama_index.core.embeddings import MockEmbedding\n",
            1,
        )
start = text.find("def get_embedding_model(")
if start != -1:
    if method_faithful:
        replacement = ('def get_embedding_model(llm_config=None, device=\'cuda:1\'):\n'
            '    if llm_config is None:\n'
            '        raise AssertionError("HGB alpha/paper-faithful requires a configured embedding service; MockEmbedding is forbidden")\n'
            '    model_name = llm_config[\'model\']\n'
            '    if model_name.startswith("mock") or model_name.startswith("local"):\n'
            '        raise AssertionError(f"HGB alpha/paper-faithful forbids mock/local embedding model: {model_name}")\n'
            '    if model_name.startswith("openai"):\n'
            '        model_name = model_name.replace("openai-", "").strip()\n'
            '        return OpenAIEmbedding(model=model_name, api_key=llm_config["api_key"], api_base=llm_config.get("base_url") or None)\n'
            '    if model_name.startswith("ollama"):\n'
            '        model_name = model_name.replace("ollama-", "").strip()\n'
            '        return OllamaEmbedding(model_name=model_name, base_url=llm_config["base_url"], ollama_additional_kwargs={"mirostat": 0})\n'
            '    assert False, f"Non-support Emb Model Name, The LLM config is {llm_config}. Please use Ollama, or OpenAI embeddings"\n')
    else:
        replacement = ('def get_embedding_model(llm_config=None, device=\'cuda:1\'):\n'
            '    if llm_config is None:\n'
            '        return MockEmbedding(embed_dim=384)\n'
            '    model_name = llm_config[\'model\']\n'
            '    if model_name.startswith("mock") or model_name.startswith("local"):\n'
            '        return MockEmbedding(embed_dim=int(llm_config.get("dimensions", 384)))\n'
            '    if model_name.startswith("openai"):\n'
            '        model_name = model_name.replace("openai-", "").strip()\n'
            '        return OpenAIEmbedding(model=model_name, api_key=llm_config["api_key"], api_base=llm_config.get("base_url") or None)\n'
            '    if model_name.startswith("ollama"):\n'
            '        model_name = model_name.replace("ollama-", "").strip()\n'
            '        return OllamaEmbedding(model_name=model_name, base_url=llm_config["base_url"], ollama_additional_kwargs={"mirostat": 0})\n'
            '    assert False, f"Non-support Emb Model Name, The LLM config is {llm_config}. Please use mock/local, Ollama, or OpenAI embeddings"\n')
    text = text[:start] + replacement
path.write_text(text)
PY_CKG_MODEL_PATCH
  fi
  fuzzing_py_for_patch="$(find "$artifact" -path '*/fuzzing.py' -type f 2>/dev/null | head -n 1 || true)"
  if [[ -n "$fuzzing_py_for_patch" ]]; then
    python3 - "$fuzzing_py_for_patch" <<'PY_CKG_FUZZING_PATCH'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
log_old = '    logger.info(f"Init LLM Models, config {config}")'
log_new = '    safe_config = yaml.safe_load(yaml.safe_dump(config))\n    for section in ("llm_coder", "llm_analyzer", "llm_embedding", "llm_code_embedding"):\n        if isinstance(safe_config.get(section), dict) and safe_config[section].get("api_key"):\n            safe_config[section]["api_key"] = "***"\n    if safe_config.get("api_key"):\n        safe_config["api_key"] = "***"\n    logger.info(f"Init LLM Models, config {safe_config}")'
if log_old in text:
    text = text.replace(log_old, log_new, 1)
old = '    # set default LLM settings\n    Settings.llm = get_model(None)\n    Settings.embed_model = get_embedding_model(None, device=\'cuda:1\')\n    logger.info(f"Init Default LLM Model and Embedding Model, LLM config: { Settings.llm.metadata } \\n Embed config: {Settings.embed_model}")'
new = '    # Reuse configured HGB models instead of upstream default Ollama/HuggingFace settings.\n    Settings.llm = llm_analyzer\n    Settings.embed_model = llm_embedding\n    logger.info(f"Init Default LLM Model and Embedding Model, LLM config: { Settings.llm.metadata } \\n Embed config: {Settings.embed_model}")'
if old in text:
    text = text.replace(old, new, 1)
path.write_text(text)
PY_CKG_FUZZING_PATCH
  fi
  if [[ -n "$fuzzing_py_for_patch" ]]; then
    python3 - "$fuzzing_py_for_patch" <<'PY_CKG_SUMMARY_PATCH'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = """    if args.summary_api:
        logger.info("Generate API Summary")
        plan_agent.summarize_code()
        api_combine_dir = os.path.join(fuzz_projects_dir, "api_combine")
        os.makedirs(api_combine_dir, exist_ok=True)
        shutil.copy2(api_summary_file, os.path.join(api_combine_dir, os.path.basename(api_summary_file)))
        logger.info(f"Copied {api_summary_file} to {api_combine_dir}/{os.path.basename(api_summary_file)}")
        api_list = plan_agent.extract_api_list()
"""
new = """    if args.summary_api:
        logger.info("Generate API Summary")
        if os.environ.get("CKGFUZZER_LOCAL_API_SUMMARY", "1") != "0":
            max_summary_apis = int(os.environ.get("CKGFUZZER_MAX_SUMMARY_APIS", "4") or "0")
            src_api_code_for_summary = json.load(open(api_code_file))
            selected_names = list(src_api_code_for_summary.keys())
            if max_summary_apis > 0:
                selected_names = selected_names[:max_summary_apis]
            local_summary = {"hgb_local_summary": {"file_summary": "Deterministic HGB local summary generated from extracted API names and source excerpts."}}
            for api_name in selected_names:
                excerpt = str(src_api_code_for_summary.get(api_name, ""))[:1200].replace("\\n", " ")
                local_summary["hgb_local_summary"][api_name] = f"Local HGB summary for {api_name}. Source excerpt: {excerpt}"
            os.makedirs(os.path.dirname(api_summary_file), exist_ok=True)
            json.dump(local_summary, open(api_summary_file, "w"), indent=2)
            logger.info(f"Wrote deterministic HGB API summaries for {len(selected_names)} APIs. Set CKGFUZZER_LOCAL_API_SUMMARY=0 to use upstream LLM summaries.")
        else:
            plan_agent.summarize_code()
        api_combine_dir = os.path.join(fuzz_projects_dir, "api_combine")
        os.makedirs(api_combine_dir, exist_ok=True)
        shutil.copy2(api_summary_file, os.path.join(api_combine_dir, os.path.basename(api_summary_file)))
        logger.info(f"Copied {api_summary_file} to {api_combine_dir}/{os.path.basename(api_summary_file)}")
        api_list = plan_agent.extract_api_list()
"""
if old in text and "CKGFUZZER_LOCAL_API_SUMMARY" not in text:
    text = text.replace(old, new, 1)
path.write_text(text)
PY_CKG_SUMMARY_PATCH
  fi
  planner_py_for_patch="$(find "$artifact" -path '*/roles/planner.py' -type f 2>/dev/null | head -n 1 || true)"
  if [[ -n "$planner_py_for_patch" ]]; then
    python3 - "$planner_py_for_patch" <<'PY_CKG_PLANNER_PATCH'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
if "import os\n" not in text:
    text = text.replace("import pandas as pd\n", "import os\nimport pandas as pd\n", 1)
old = """    def api_combination(self, api_list):
        api_combination = []

        Settings.llm = self.llm
"""
new = """    def api_combination(self, api_list):
        api_combination = []

        if os.environ.get("CKGFUZZER_LOCAL_API_COMBINATION", "1") != "0":
            max_size = max(1, int(os.environ.get("CKGFUZZER_MAX_COMBINATION_SIZE", "3") or "1"))
            max_apis = int(os.environ.get("CKGFUZZER_MAX_PLANNER_APIS", "4") or "0")
            planned_apis = list(api_list)
            if max_apis > 0 and len(planned_apis) > max_apis:
                planned_apis = planned_apis[:max_apis]
            all_apis = list(api_list)
            for api in planned_apis:
                combo = [api]
                for candidate in all_apis:
                    if candidate != api and candidate not in combo:
                        combo.append(candidate)
                    if len(combo) >= max_size:
                        break
                api_combination.append(combo)
                self.update_api_usage_count(combo)
            logger.info(f"Using local HGB API combinations for {len(api_combination)} APIs. Set CKGFUZZER_LOCAL_API_COMBINATION=0 to use the upstream LLM planner.")
            return api_combination

        Settings.llm = self.llm
"""
if old in text and "CKGFUZZER_LOCAL_API_COMBINATION" not in text:
    text = text.replace(old, new, 1)
old = """    def generate_single_api_combination(self, api, api_combine, low_coverage_apis):
        api_list = self.extract_api_list()

        Settings.llm=self.llm
"""
new = """    def generate_single_api_combination(self, api, api_combine, low_coverage_apis):
        api_list = self.extract_api_list()

        if os.environ.get("CKGFUZZER_LOCAL_API_COMBINATION", "1") != "0":
            max_size = max(1, int(os.environ.get("CKGFUZZER_MAX_COMBINATION_SIZE", "3") or "1"))
            combo = []
            for candidate in list(api_combine or []) + [api] + list(low_coverage_apis or []) + list(api_list):
                if candidate and candidate not in combo:
                    combo.append(candidate)
                if len(combo) >= max_size:
                    break
            return combo or [api]

        Settings.llm=self.llm
"""
if old in text:
    text = text.replace(old, new, 1)
path.write_text(text)
PY_CKG_PLANNER_PATCH
  fi
  python3 - "$artifact" <<'PY_CKG_HF_IMPORT_PATCH'
from pathlib import Path
import sys
root = Path(sys.argv[1])
hf_import = "from llama_index.embeddings.huggingface import HuggingFaceEmbedding\n"
for rel in (
    "fuzzing_llm_engine/roles/compilation_fix_agent.py",
    "fuzzing_llm_engine/rag/kg.py",
):
    path = root / rel
    if path.exists():
        text = path.read_text()
        text = text.replace(hf_import, "")
        path.write_text(text)
path = root / "fuzzing_llm_engine/models/get_model.py"
if path.exists():
    text = path.read_text()
    text = text.replace(hf_import, "")
    old = '    if llm_config is None:\n        return HuggingFaceEmbedding(model_name="BAAI/bge-small-en-v1.5",device=device)'
    new = '    if llm_config is None:\n        from llama_index.embeddings.huggingface import HuggingFaceEmbedding\n        return HuggingFaceEmbedding(model_name="BAAI/bge-small-en-v1.5",device=device)'
    if old in text:
        text = text.replace(old, new, 1)
    path.write_text(text)
PY_CKG_HF_IMPORT_PATCH
  python3 - "$artifact" <<'PY_CKG_LLM_TRACE_PATCH'
from pathlib import Path
import sys
root = Path(sys.argv[1])
get_model_path = root / "fuzzing_llm_engine/models/get_model.py"
if get_model_path.exists():
    text = get_model_path.read_text()
    if "class HGBOpenAILike" not in text:
        trace_block = '''
import sys as _hgb_trace_sys
_hgb_trace_sys.path.insert(0, "/opt/hgb/bin")
try:
    import hgb_llm_trace as _hgb_llm_trace
except Exception as _hgb_trace_exc:
    _hgb_llm_trace = None
    print(f"HGB_LLM_TRACE: CKGFuzzer OpenAILike tracing unavailable: {_hgb_trace_exc}", file=_hgb_trace_sys.stderr)


class HGBOpenAILike(OpenAILike):
    # Supported subclass hook; do not mutate Pydantic model methods.
    def complete(self, prompt, *args, **kwargs):
        parent_complete = super().complete
        if _hgb_llm_trace is None:
            return parent_complete(prompt, *args, **kwargs)
        return _hgb_llm_trace.trace_call(
            lambda: parent_complete(prompt, *args, **kwargs),
            stage="ckgfuzzer",
            provider="openai-compatible",
            operation="complete",
            model=str(getattr(self, "model", "")),
            request={"prompt": prompt, "args": args, "kwargs": kwargs},
        )

    def chat(self, messages, *args, **kwargs):
        parent_chat = super().chat
        if _hgb_llm_trace is None:
            return parent_chat(messages, *args, **kwargs)
        return _hgb_llm_trace.trace_call(
            lambda: parent_chat(messages, *args, **kwargs),
            stage="ckgfuzzer",
            provider="openai-compatible",
            operation="chat",
            model=str(getattr(self, "model", "")),
            request={"messages": messages, "args": args, "kwargs": kwargs},
        )
'''
        text = text.replace("import os\n", "import os\n" + trace_block, 1)
    text = text.replace(
        "temperature=llm_config[\"temperature\"] )",
        "temperature=llm_config[\"temperature\"], timeout=float(llm_config.get(\"request_timeout\", 900)), max_retries=int(llm_config.get(\"max_retries\", 3)) )",
    )
    text = text.replace(
        "temperature=llm_config[\"temperature\"])",
        "temperature=llm_config[\"temperature\"], timeout=float(llm_config.get(\"request_timeout\", 900)), max_retries=int(llm_config.get(\"max_retries\", 3)))",
    )
    text = text.replace("return OpenAILike(", "return HGBOpenAILike(")
    get_model_path.write_text(text)
openai_path = root / "fuzzing_llm_engine/models/openai.py"
if openai_path.exists():
    text = openai_path.read_text()
    if "import hgb_llm_trace" not in text:
        text = text.replace("from openai.types.chat import ChatCompletion\n", "from openai.types.chat import ChatCompletion\nimport sys\nsys.path.insert(0, \"/opt/hgb/bin\")\ntry:\n    import hgb_llm_trace\nexcept Exception:\n    hgb_llm_trace = None\n", 1)
    old = '''        response: ChatCompletion = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            **kwargs
        )'''
    new = '''        request = {"model": self.model_name, "messages": messages, **kwargs}
        if hgb_llm_trace is not None:
            response: ChatCompletion = hgb_llm_trace.trace_call(
                lambda: self.client.chat.completions.create(**request),
                stage="ckgfuzzer",
                provider="openai-compatible",
                operation="chat.completions.create",
                model=self.model_name,
                request=request,
            )
        else:
            response: ChatCompletion = self.client.chat.completions.create(**request)'''
    if old in text and "hgb_llm_trace.trace_call" not in text:
        text = text.replace(old, new, 1)
    openai_path.write_text(text)
PY_CKG_LLM_TRACE_PATCH
  ckg_runtime_patch_log="$workspace/logs/runtime_patch.log"
  if ! python3 /opt/hgb/bin/ckgfuzzer_runtime_patch.py "$artifact" >"$ckg_runtime_patch_log" 2>&1; then
    cat "$ckg_runtime_patch_log" >&2 || true
    hgb_write_common_metadata failed 'CKGFuzzer deterministic runtime patch failed' 1 harness_generator
    hgb_write_common_summary failed 'CKGFuzzer deterministic runtime patch failed' harness_generator
    exit 1
  fi
  ckg_patch_compile_candidates=(
    "$artifact/fuzzing_llm_engine/roles/compilation_fix_agent.py"
    "$artifact/fuzzing_llm_engine/roles/run_fuzzer.py"
    "$artifact/fuzzing_llm_engine/utils/check_gen_fuzzer.py"
    "$artifact/fuzzing_llm_engine/rag/code_base.py"
    "$artifact/fuzzing_llm_engine/rag/kg.py"
    "$artifact/fuzzing_llm_engine/repo/preproc.py"
    "$artifact/fuzzing_llm_engine/fuzzing.py"
  )
  ckg_patch_compile_files=()
  for ckg_patch_compile_file in "${ckg_patch_compile_candidates[@]}"; do
    if [[ -f "$ckg_patch_compile_file" ]]; then
      ckg_patch_compile_files+=("$ckg_patch_compile_file")
    fi
  done
  if [[ "${#ckg_patch_compile_files[@]}" -gt 0 ]]; then
    ckg_patch_compile_log="$workspace/logs/runtime_patch_py_compile.log"
    if ! python3 -m py_compile "${ckg_patch_compile_files[@]}" >"$ckg_patch_compile_log" 2>&1; then
      cat "$ckg_patch_compile_log" >&2 || true
      hgb_write_common_metadata failed 'CKGFuzzer runtime patch produced invalid Python syntax' 1 harness_generator
      hgb_write_common_summary failed 'CKGFuzzer runtime patch produced invalid Python syntax' harness_generator
      exit 1
    fi
  fi
  ckg_compile_call_graph_templates() {
    local ql_template ql_log
    for ql_template in \
      "$ckg_shared/qlpacks/cpp_queries/extract_call_graph_template.ql" \
      "$ckg_shared/qlpacks/cpp_queries/extract_call_graph_template_fast.ql"; do
      [[ -f "$ql_template" ]] || continue
      ql_log="$workspace/logs/$(basename "$ql_template").compile.log"
      if ! codeql query compile "$ql_template" >"$ql_log" 2>&1; then
        printf 'CodeQL query compile failed: %s\n' "$ql_template" >&2
        return 1
      fi
    done
  }
  if [[ "${CKGFUZZER_SKIP_CODEQL:-0}" != "1" ]] && ! ckg_compile_call_graph_templates; then
    hgb_write_common_metadata failed 'ckg_codeql_query_invalid: call-graph QL did not compile' 7 harness_generator
    hgb_write_common_summary failed 'ckg_codeql_query_invalid: call-graph QL did not compile' harness_generator
    exit 7
  fi
  cleanup_ckg_codeql_shards() {
    if [[ -d "$ckg_shared/codeqldb" ]]; then
      find "$ckg_shared/codeqldb" -maxdepth 1 -mindepth 1 -type d -name "${ckg_project}_*" -exec rm -rf {} + 2>/dev/null || true
    fi
  }
  cleanup_ckg_check_container() {
    if [[ "${CKGFUZZER_KEEP_CHECK_CONTAINER:-0}" == "1" ]]; then
      return 0
    fi
    if command -v docker >/dev/null 2>&1; then
      docker rm -f "${ckg_project}_check" >/dev/null 2>&1 || true
    fi
  }
  compact_ckg_workspace() {
    cleanup_ckg_codeql_shards
    cleanup_ckg_check_container
    if [[ "${HGB_SAVE_MODE:-compact}" == "compact" ]]; then
      rm -rf "$ckg_shared/codeql" "$ckg_shared/codeqldb" "$ckg_shared/source_code" 2>/dev/null || true
    fi
  }
  ckg_codeql_cache_status=disabled
  ckg_codeql_cache_reason='cache disabled'
  ckg_codeql_cache_key=''
  ckg_codeql_cache_path=''
  ckg_codeql_cache_key_json="$workspace/ckgfuzzer_codeql_cache_key.json"
  ckg_codeql_cache_enabled="${CKGFUZZER_CODEQL_CACHE:-1}"
  ckg_codeql_cache_refresh="${CKGFUZZER_CODEQL_CACHE_REFRESH:-0}"
  ckg_codeql_cache_root="${HGB_CKG_CODEQL_CACHE_DIR:-}"

  ckg_codeql_cache_required_present() {
    local base="$1" call_graph_csv='' call_graph_ok=''
    [[ -s "$base/api_list.json" ]] || return 1
    [[ -s "$base/codebase/api/src_api.json" ]] || return 1
    [[ -d "$base/codebase/call_graph" ]] || return 1
    call_graph_csv="$(find "$base/codebase/call_graph" -maxdepth 1 -type f -name '*.csv' -print -quit 2>/dev/null || true)"
    call_graph_ok="$(find "$base/codebase/call_graph" -maxdepth 1 -type f -name '*.ok' -print -quit 2>/dev/null || true)"
    [[ -n "$call_graph_csv" && -n "$call_graph_ok" ]] || return 1
    [[ -s "$base/api_summary/api_with_summary.json" ]] || return 1
    [[ -s "$base/src/src_api_code.json" ]] || return 1
    [[ -s "$base/api_combine/combined_call_graph.csv" ]] || return 1
    return 0
  }

  ckg_codeql_cache_make_key() {
    CKG_CACHE_KEY_JSON="$ckg_codeql_cache_key_json" \
    CKG_CACHE_API_LIST="$ckg_db/api_list.json" \
    CKG_CACHE_SHARED_DIR="$ckg_shared" \
    CKG_CACHE_CODEQL_VERSION="$(ckg_codeql_version)" \
    CKG_CACHE_PROJECT_NAME="$ckg_project" \
    CKG_CACHE_TARGET="$target_name" \
    CKG_CACHE_PROJECT="$project" \
    CKG_CACHE_FUZZ_TARGET="$fuzz_target" \
    python3 - <<'PY_CKG_CACHE_KEY'
import hashlib
import json
import os
from pathlib import Path


def file_hash(path):
    path = Path(path)
    if not path.is_file():
        return "missing"
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

manifest_path = Path(os.environ.get("HGB_TARGET_MANIFEST", "/target/target_manifest.json"))
try:
    manifest = json.loads(manifest_path.read_text())
except Exception:
    manifest = {}
shared_dir = Path(os.environ["CKG_CACHE_SHARED_DIR"])
query_files = {
    "extract_call_graph_sh": shared_dir / "qlpacks/cpp_queries/extract_call_graph.sh",
    "extract_call_graph_template": shared_dir / "qlpacks/cpp_queries/extract_call_graph_template.ql",
    "extract_call_graph_template_fast": shared_dir / "qlpacks/cpp_queries/extract_call_graph_template_fast.ql",
    "wrapper": shared_dir / "wrapper.sh",
}
payload = {
    "schema_version": 2,
    "target": os.environ.get("CKG_CACHE_TARGET", ""),
    "project": os.environ.get("CKG_CACHE_PROJECT", ""),
    "fuzz_target": os.environ.get("CKG_CACHE_FUZZ_TARGET", ""),
    "ckgfuzzer_project": os.environ.get("CKG_CACHE_PROJECT_NAME", ""),
    "fuzzbench_commit": manifest.get("fuzzbench_commit", ""),
    "target_source_commit": manifest.get("commit", ""),
    "source_layout": manifest.get("source_layout", ""),
    "source_file_count": manifest.get("source_file_count", ""),
    "generator_commit": os.environ.get("HGB_GENERATOR_COMMIT", ""),
    "codeql_version": os.environ.get("CKG_CACHE_CODEQL_VERSION", ""),
    "selected_api_list_hash": file_hash(os.environ["CKG_CACHE_API_LIST"]),
    "max_call_graph_apis": os.environ.get("CKGFUZZER_MAX_CALL_GRAPH_APIS", "8"),
    "query_hashes": {name: file_hash(path) for name, path in sorted(query_files.items())},
}
serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
Path(os.environ["CKG_CACHE_KEY_JSON"]).write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n")
print(hashlib.sha256(serialized.encode("utf-8")).hexdigest())
PY_CKG_CACHE_KEY
  }

  ckg_codeql_cache_init() {
    if [[ "$ckg_codeql_cache_enabled" != "1" ]]; then
      ckg_codeql_cache_status=disabled
      ckg_codeql_cache_reason='CKGFUZZER_CODEQL_CACHE is disabled'
      return 0
    fi
    if [[ -z "$ckg_codeql_cache_root" ]]; then
      ckg_codeql_cache_status=disabled
      ckg_codeql_cache_reason='HGB_CKG_CODEQL_CACHE_DIR is not mounted'
      return 0
    fi
    mkdir -p "$ckg_codeql_cache_root/$ckg_project" 2>/dev/null || true
    ckg_codeql_cache_key="$(ckg_codeql_cache_make_key 2>/dev/null | tail -n 1 || true)"
    if [[ -z "$ckg_codeql_cache_key" ]]; then
      ckg_codeql_cache_status=disabled
      ckg_codeql_cache_reason='failed to compute cache key'
      return 0
    fi
    ckg_codeql_cache_path="$ckg_codeql_cache_root/$ckg_project/$ckg_codeql_cache_key"
    if [[ "$ckg_codeql_cache_refresh" == "1" ]]; then
      ckg_codeql_cache_status=refresh
      ckg_codeql_cache_reason='CKGFUZZER_CODEQL_CACHE_REFRESH requested'
    else
      ckg_codeql_cache_status=miss
      ckg_codeql_cache_reason='no completed cache entry found'
    fi
  }

  ckg_codeql_cache_validate_entry() {
    local entry="$1"
    [[ -f "$entry/.complete" ]] || { ckg_codeql_cache_reason='cache entry missing .complete sentinel'; return 1; }
    [[ -f "$entry/metadata.json" ]] || { ckg_codeql_cache_reason='cache entry missing metadata.json'; return 1; }
    if ! python3 - "$entry/metadata.json" "$ckg_codeql_cache_key" <<'PY_CKG_CACHE_VALIDATE'
import json
import sys
try:
    data = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(1)
sys.exit(0 if data.get("schema_version") == 2 and data.get("cache_key") == sys.argv[2] else 1)
PY_CKG_CACHE_VALIDATE
    then
      ckg_codeql_cache_reason='cache metadata key mismatch'
      return 1
    fi
    ckg_codeql_cache_required_present "$entry/data" || { ckg_codeql_cache_reason='cache entry is missing required CodeQL/preproc files'; return 1; }
    if ! python3 /opt/hgb/bin/ckgfuzzer_cache.py validate --root "$entry/data" --project "$ckg_project" --source-root "$ckg_analysis_src" --portable >"$workspace/logs/codeql_cache_validate.log" 2>&1; then
      ckg_codeql_cache_reason='cache entry is non-portable, oversized, or invalid'
      return 1
    fi
    return 0
  }

  ckg_codeql_cache_try_restore() {
    [[ "$ckg_codeql_cache_enabled" == "1" && -n "$ckg_codeql_cache_path" ]] || return 1
    if [[ "$ckg_codeql_cache_refresh" == "1" ]]; then
      return 1
    fi
    if [[ ! -e "$ckg_codeql_cache_path" ]]; then
      ckg_codeql_cache_status=miss
      ckg_codeql_cache_reason='no completed cache entry found'
      return 1
    fi
    if ! ckg_codeql_cache_validate_entry "$ckg_codeql_cache_path"; then
      ckg_codeql_cache_status=invalid
      return 1
    fi
    rm -rf "$ckg_db/codebase" "$ckg_db/api_summary" "$ckg_db/src" "$ckg_db/api_combine" 2>/dev/null || true
    if ! cp -a "$ckg_codeql_cache_path/data/." "$ckg_db/"; then
      ckg_codeql_cache_status=invalid
      ckg_codeql_cache_reason='failed to restore cache entry into CKG database'
      return 1
    fi
    if ! python3 /opt/hgb/bin/ckgfuzzer_cache.py rebase --root "$ckg_db" --project "$ckg_project" --source-root "$ckg_analysis_src" >"$workspace/logs/codeql_cache_rebase.log" 2>&1 \
      || ! python3 /opt/hgb/bin/ckgfuzzer_cache.py validate --root "$ckg_db" --project "$ckg_project" --source-root "$ckg_analysis_src" >"$workspace/logs/codeql_cache_resolved_validate.log" 2>&1; then
      rm -rf "$ckg_db/codebase" "$ckg_db/api_summary" "$ckg_db/src" "$ckg_db/api_combine" 2>/dev/null || true
      ckg_codeql_cache_status=invalid
      ckg_codeql_cache_reason='cache paths could not be rebased to the current source tree'
      return 1
    fi
    ckg_codeql_cache_status=hit
    ckg_codeql_cache_reason='restored completed CodeQL/preproc data from portable cache'
    printf 'CKGFuzzer CodeQL cache hit: %s\n' "$ckg_codeql_cache_path" >"$workspace/logs/repo.log"
    printf 'CKGFuzzer preproc cache hit: %s\n' "$ckg_codeql_cache_path" >"$workspace/logs/preproc.log"
    return 0
  }

  ckg_codeql_cache_find_previous_candidate() {
    local search_root="${HGB_CKG_PREVIOUS_WORKSPACE_ROOT:-}"
    [[ -d "$search_root" ]] || return 1
    python3 - "$search_root" "$target_name" "$ckg_project" "$ckg_codeql_cache_key" <<'PY_CKG_CACHE_PREVIOUS'
import hashlib
import json
import sys
from pathlib import Path

search_root = Path(sys.argv[1])
target_name = sys.argv[2]
ckg_project = sys.argv[3]
current_key = sys.argv[4]


def key_from_json(path):
    try:
        payload = json.loads(path.read_text())
    except Exception:
        return ""
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def required_present(base):
    required_files = [
        "api_list.json",
        "codebase/api/src_api.json",
        "api_summary/api_with_summary.json",
        "src/src_api_code.json",
        "api_combine/combined_call_graph.csv",
    ]
    if not all((base / item).is_file() and (base / item).stat().st_size > 0 for item in required_files):
        return False
    call_graph_dir = base / "codebase/call_graph"
    if not call_graph_dir.is_dir():
        return False
    return (
        any(path.is_file() and path.stat().st_size > 0 for path in call_graph_dir.glob("*.csv"))
        and any(path.is_file() for path in call_graph_dir.glob("*.ok"))
    )


def candidate_data_dirs(run_dir):
    return [
        run_dir / "ckgfuzzer_codeql_cache/data",
        run_dir / "codeql_cache/data",
        run_dir / "ckg_db",
        run_dir / "external_database" / ckg_project,
        run_dir / "fuzzing_llm_engine/external_database" / ckg_project,
    ]

metadata_files = []
target_dir = search_root / "ckgfuzzer" / target_name
if target_dir.is_dir():
    metadata_files.extend(target_dir.glob("*/metadata.json"))
else:
    metadata_files.extend((search_root / "ckgfuzzer").glob("*/*/metadata.json"))

candidates = []
for metadata_path in metadata_files:
    run_dir = metadata_path.parent
    try:
        metadata = json.loads(metadata_path.read_text())
    except Exception:
        continue
    if str(metadata.get("repo_exit_code", "")) != "0" or str(metadata.get("preproc_exit_code", "")) != "0":
        continue
    metadata_key = str(metadata.get("ckgfuzzer_codeql_cache_key", ""))
    key_file = run_dir / "ckgfuzzer_codeql_cache_key.json"
    if not metadata_key and key_file.is_file():
        metadata_key = key_from_json(key_file)
    if metadata_key != current_key:
        continue
    for data_dir in candidate_data_dirs(run_dir):
        if required_present(data_dir):
            try:
                mtime = metadata_path.stat().st_mtime
            except OSError:
                mtime = 0
            candidates.append((mtime, str(data_dir)))
            break

if not candidates:
    sys.exit(1)
print(sorted(candidates, reverse=True)[0][1])
PY_CKG_CACHE_PREVIOUS
  }

  ckg_codeql_cache_write_entry() {
    local source_dir="$1"
    local source_note="${2:-}"
    local parent lock tmp
    ckg_codeql_cache_required_present "$source_dir" || return 1
    parent="$(dirname "$ckg_codeql_cache_path")"
    lock="$ckg_codeql_cache_path.lock"
    tmp="$ckg_codeql_cache_path.tmp.$$"
    if ! mkdir -p "$parent" 2>/dev/null; then
      ckg_codeql_cache_status=invalid
      ckg_codeql_cache_reason='failed to create cache parent directory'
      return 1
    fi
    if ! mkdir "$lock" 2>/dev/null; then
      ckg_codeql_cache_reason='another process is storing this cache key'
      return 2
    fi
    rm -rf "$tmp" 2>/dev/null || true
    if mkdir -p "$tmp/data" \
      && cp -a "$source_dir/api_list.json" "$tmp/data/" \
      && cp -a "$source_dir/codebase" "$tmp/data/" \
      && cp -a "$source_dir/api_summary" "$tmp/data/" \
      && cp -a "$source_dir/src" "$tmp/data/" \
      && cp -a "$source_dir/api_combine" "$tmp/data/" \
      && cp -f "$ckg_codeql_cache_key_json" "$tmp/key.json"; then
      if ! python3 /opt/hgb/bin/ckgfuzzer_cache.py normalize --root "$tmp/data" --project "$ckg_project" --source-root "$ckg_analysis_src" >"$workspace/logs/codeql_cache_normalize.log" 2>&1 \
        || ! python3 /opt/hgb/bin/ckgfuzzer_cache.py validate --root "$tmp/data" --project "$ckg_project" --source-root "$ckg_analysis_src" --portable >"$workspace/logs/codeql_cache_store_validate.log" 2>&1; then
        ckg_codeql_cache_reason='current CodeQL/preproc output is non-portable, oversized, or invalid'
        rm -rf "$tmp" 2>/dev/null || true
        rmdir "$lock" 2>/dev/null || true
        return 1
      fi
      if ! CKG_CACHE_METADATA="$tmp/metadata.json" \
        CKG_CACHE_KEY="$ckg_codeql_cache_key" \
        CKG_CACHE_PROJECT="$ckg_project" \
        CKG_CACHE_TARGET="$target_name" \
        CKG_CACHE_SOURCE="$source_note" \
        CKG_CACHE_CODEQL_VERSION="$(ckg_codeql_version)" \
        CKG_CACHE_CREATED_AT="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        python3 - <<'PY_CKG_CACHE_WRITE_METADATA'
import json
import os
from pathlib import Path
metadata = {
    "schema_version": 2,
    "cache_key": os.environ["CKG_CACHE_KEY"],
    "ckgfuzzer_project": os.environ["CKG_CACHE_PROJECT"],
    "target": os.environ["CKG_CACHE_TARGET"],
    "codeql_version": os.environ["CKG_CACHE_CODEQL_VERSION"],
    "created_at": os.environ["CKG_CACHE_CREATED_AT"],
}
if os.environ.get("CKG_CACHE_SOURCE"):
    metadata["source"] = os.environ["CKG_CACHE_SOURCE"]
Path(os.environ["CKG_CACHE_METADATA"]).write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
PY_CKG_CACHE_WRITE_METADATA
      then
        rm -rf "$tmp" 2>/dev/null || true
        rmdir "$lock" 2>/dev/null || true
        return 1
      fi
    fi
    if [[ -f "$tmp/metadata.json" ]] \
      && touch "$tmp/.complete" \
      && rm -rf "$ckg_codeql_cache_path" 2>/dev/null \
      && mv "$tmp" "$ckg_codeql_cache_path"; then
      rmdir "$lock" 2>/dev/null || true
      return 0
    fi
    rm -rf "$tmp" 2>/dev/null || true
    rmdir "$lock" 2>/dev/null || true
    return 1
  }

  ckg_codeql_cache_import_previous_workspace() {
    [[ "$ckg_codeql_cache_enabled" == "1" && -n "$ckg_codeql_cache_path" ]] || return 1
    [[ "$ckg_codeql_cache_refresh" != "1" ]] || return 1
    [[ ! -e "$ckg_codeql_cache_path" ]] || return 1
    local candidate
    candidate="$(ckg_codeql_cache_find_previous_candidate 2>/dev/null | tail -n 1 || true)"
    if [[ -z "$candidate" ]]; then
      ckg_codeql_cache_status=miss
      ckg_codeql_cache_reason='no completed cache entry or matching previous workspace data found'
      return 1
    fi
    if ckg_codeql_cache_write_entry "$candidate" "$candidate"; then
      printf 'Imported CKGFuzzer CodeQL cache from previous workspace data: %s\n' "$candidate" >"$workspace/logs/codeql_cache_import.log"
      ckg_codeql_cache_status=stored
      ckg_codeql_cache_reason='imported completed CodeQL/preproc data from previous workspace'
      return 0
    fi
    ckg_codeql_cache_status=invalid
    ckg_codeql_cache_reason='failed to import completed CodeQL/preproc data from previous workspace'
    return 1
  }

  ckg_codeql_cache_store() {
    [[ "$ckg_codeql_cache_enabled" == "1" && -n "$ckg_codeql_cache_path" ]] || return 0
    ckg_codeql_cache_required_present "$ckg_db" || {
      ckg_codeql_cache_status=invalid
      ckg_codeql_cache_reason='current CodeQL/preproc output is incomplete; not storing cache'
      return 0
    }
    if ckg_codeql_cache_write_entry "$ckg_db" ''; then
      ckg_codeql_cache_status=stored
      ckg_codeql_cache_reason='stored completed CodeQL/preproc data in cache'
    elif [[ "$ckg_codeql_cache_reason" != 'another process is storing this cache key' ]]; then
      ckg_codeql_cache_status=invalid
      ckg_codeql_cache_reason='failed to store completed CodeQL/preproc data in cache'
    fi
  }

  ckg_input_args=()
  if [[ "${CKGFUZZER_GEN_INPUT:-0}" == "1" ]]; then
    ckg_input_args+=(--gen_input)
  else
    ckg_input_args+=(--skip_gen_input)
  fi
  # In alpha/paper-faithful, use upstream compilation checking (no
  # --skip_check_compilation). compat-smoke may skip it.
  ckg_compilation_args=()
  if [[ "$ckg_method_faithful" != "1" ]]; then
    ckg_compilation_args+=(--skip_check_compilation)
  fi
  {
    printf 'cd %q && python %q --project_name %q --shared_llm_dir %q --saved_dir %q --src_api --call_graph
' "$(dirname "$repo_py")" "$repo_py" "$ckg_project" "$ckg_shared" "$ckg_db/codebase"
    printf 'python %q --project_name %q --src_api_file_path %q
' "$preproc_py" "$ckg_project" "$ckg_db"
    printf 'python %q --yaml %q --gen_driver --summary_api' "$fuzzing_py" "$ckg_db/config.yaml"
    if [[ "${#ckg_compilation_args[@]}" -gt 0 ]]; then
      printf ' %q' "${ckg_compilation_args[@]}"
    fi
    printf ' %q' "${ckg_input_args[@]}"
    printf '
'
  } >"$workspace/command.txt"
  code=0
  failed_stage=none
  repo_code=0
  preproc_code=not_run
  fuzzing_code=not_run
  analysis_mode=codeql
  analysis_fallback_reason=''
  source_fallback_recovered_body_count=0
  ckg_codeql_cache_restored=0
  ckg_codeql_cache_init
  if ckg_codeql_cache_try_restore; then
    ckg_codeql_cache_restored=1
    repo_code=0
    preproc_code=0
  elif ckg_codeql_cache_import_previous_workspace && ckg_codeql_cache_try_restore; then
    ckg_codeql_cache_restored=1
    repo_code=0
    preproc_code=0
  fi
  if [[ "$ckg_codeql_cache_restored" != "1" ]]; then
    (cd "$(dirname "$repo_py")" && timeout "${HGB_GENERATION_TIMEOUT_SECONDS:-10800}" python "$repo_py" --project_name "$ckg_project" --shared_llm_dir "$ckg_shared" --saved_dir "$ckg_db/codebase" --src_api --call_graph) >"$workspace/logs/repo.log" 2>&1 || repo_code=$?
    cleanup_ckg_codeql_shards
    if [[ "$repo_code" != "0" ]]; then
      code="$repo_code"
      if grep -Eqi 'Error executing CodeQL query|codeql query (compile|run)|duplicate variables|Query compilation failed' "$workspace/logs/repo.log"; then
        failed_stage=analysis
      else
        failed_stage=repo
      fi
    elif [[ "${CKGFUZZER_SKIP_CODEQL:-0}" != "1" ]]; then
      call_graph_ok="$(find "$ckg_db/codebase/call_graph" -maxdepth 1 -type f -name '*.ok' -print -quit 2>/dev/null || true)"
      if [[ -z "$call_graph_ok" ]]; then
        if [[ "$ckg_method_faithful" == "1" ]]; then
          # In alpha/paper-faithful, an empty CodeQL graph is a hard failure.
          # Do not continue to generation with a source-only fallback.
          code=2
          failed_stage=repo
          analysis_mode=source_fallback_only
          analysis_fallback_reason='CodeQL produced no selected-API call-graph artifact; alpha/paper-faithful does not allow source-only fallback'
          printf 'CKGFuzzer: %s\n' "$analysis_fallback_reason" >>"$workspace/logs/repo.log"
          hgb_result_set_stage "$workspace/stages.json" knowledge_graph failed
        else
          # compat-smoke: CKGFuzzer can omit valid APIs whose definitions use
          # syntax it does not parse. The preprocessor has a source-recovery
          # path for this case, so let it run first.
          analysis_mode=source_fallback_only
          analysis_fallback_reason='CodeQL produced no selected-API call-graph artifact; using source recovery with an empty graph'
          mkdir -p "$ckg_db/codebase/call_graph"
          printf '%s\n' 'caller,callee,caller_src,callee_src,start_body_start_line,start_body_end_line,end_body_start_line,end_body_end_line,caller_signature,caller_parameter_string,caller_return_type,caller_return_type_inferred,callee_signature,callee_parameter_string,callee_return_type,callee_return_type_inferred' >"$ckg_db/codebase/call_graph/hgb_source_fallback_call_graph.csv"
          printf '%s\n' "$analysis_mode" >"$ckg_db/codebase/call_graph/hgb_analysis_mode"
          printf 'CKGFuzzer: %s\n' "$analysis_fallback_reason" >>"$workspace/logs/repo.log"
        fi
      elif [[ -f "$ckg_shared/hgb_compiled_units_${ckg_project}.txt" ]]; then
        compiled_units="$(cat "$ckg_shared/hgb_compiled_units_${ckg_project}.txt" 2>/dev/null || printf '0')"
        if [[ "${compiled_units:-0}" == "0" && ! -f "$ckg_shared/codeqldb/$ckg_project/.successfully_created" ]]; then
          code=2
          failed_stage=repo
          hgb_result_set_stage "$workspace/stages.json" codeql_database failed
        fi
      fi
      # Graph validation: require non-empty function and call-edge data.
      if [[ "$code" == "0" && "$failed_stage" == "none" ]]; then
        hgb_result_set_stage "$workspace/stages.json" codeql_database completed
        ckg_graph_csv_size="$(find "$ckg_db/codebase/call_graph" -maxdepth 1 -type f -name '*.csv' -exec wc -c {} + 2>/dev/null | tail -n 1 | awk '{print $1}' || printf '0')"
        ckg_src_api_size="$(wc -c < "$ckg_db/codebase/api/src_api.json" 2>/dev/null || printf '0')"
        if [[ "${ckg_graph_csv_size:-0}" -le 1 || "${ckg_src_api_size:-0}" -le 2 ]]; then
          if [[ "$ckg_method_faithful" == "1" ]]; then
            code=2
            failed_stage=repo
            analysis_fallback_reason='ckg_graph_validation_failed: CodeQL graph has empty function or call-edge data'
            printf 'CKGFuzzer: %s (csv_size=%s, src_api_size=%s)\n' "$analysis_fallback_reason" "$ckg_graph_csv_size" "$ckg_src_api_size" >>"$workspace/logs/repo.log"
            hgb_result_set_stage "$workspace/stages.json" knowledge_graph failed
          fi
        else
          hgb_result_set_stage "$workspace/stages.json" knowledge_graph completed
        fi
        # Count CodeQL graph nodes (unique functions) and edges (call rows)
        # for the result schema (plan section 5/6).
        ckg_codeql_graph_nodes=0
        ckg_codeql_graph_edges=0
        ckg_graph_csv="$(find "$ckg_db/codebase/call_graph" -maxdepth 1 -type f -name '*.csv' -print -quit 2>/dev/null || true)"
        if [[ -s "$ckg_graph_csv" ]]; then
          ckg_codeql_graph_edges="$(python3 - "$ckg_graph_csv" <<'PY_CKG_GRAPH_COUNT' 2>/dev/null || printf '0'
import csv
import sys
edges = 0
nodes = set()
with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
    reader = csv.reader(f)
    for row in reader:
        if not row:
            continue
        if row[0] in ("caller", ""):
            continue
        edges += 1
        if len(row) > 1 and row[1]:
            nodes.add(row[1])
        if row[0]:
            nodes.add(row[0])
print(edges)
PY_CKG_GRAPH_COUNT
)"
          ckg_codeql_graph_nodes="$(python3 - "$ckg_graph_csv" <<'PY_CKG_GRAPH_NODES' 2>/dev/null || printf '0'
import csv
import sys
nodes = set()
with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
    reader = csv.reader(f)
    for row in reader:
        if not row:
            continue
        if row[0] in ("caller", ""):
            continue
        if len(row) > 1 and row[1]:
            nodes.add(row[1])
        if row[0]:
            nodes.add(row[0])
print(len(nodes))
PY_CKG_GRAPH_NODES
)"
        fi
      fi
    fi
    if [[ "$code" == "0" ]]; then
      preproc_code=0
      timeout "${HGB_GENERATION_TIMEOUT_SECONDS:-10800}" python "$preproc_py" --project_name "$ckg_project" --src_api_file_path "$ckg_db" >"$workspace/logs/preproc.log" 2>&1 || preproc_code=$?
      if [[ "$preproc_code" != "0" ]]; then
        code="$preproc_code"
        failed_stage=preproc
      else
        resolved_api_count="$(jq 'length' "$ckg_db/src/src_api_code.json" 2>/dev/null || printf '0')"
        if [[ "${resolved_api_count:-0}" -eq 0 ]]; then
          preproc_code=3
          code=3
          failed_stage=preproc
        else
          mkdir -p "$ckg_db/api_combine"
          if [[ ! -s "$ckg_db/api_combine/combined_call_graph.csv" ]]; then
            printf '%s
' 'caller,callee,caller_src,callee_src,start_body_start_line,start_body_end_line,end_body_start_line,end_body_end_line,caller_signature,caller_parameter_string,caller_return_type,caller_return_type_inferred,callee_signature,callee_parameter_string,callee_return_type,callee_return_type_inferred' >"$ckg_db/api_combine/combined_call_graph.csv"
          fi
          if [[ "$analysis_mode" == source_fallback_only ]]; then
            source_fallback_recovered_body_count="$(PYTHONPATH="/opt/hgb/bin${PYTHONPATH:+:$PYTHONPATH}" python3 - "$ckg_db/api_list.json" "$ckg_db/src/src_api_code.json" <<'PY_CKG_SOURCE_FALLBACK_BODIES'
import json
import sys
from pathlib import Path

from ckgfuzzer_api_recovery import recovered_body_count

try:
    selected = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    recovered = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
except Exception:
    print(0)
    raise SystemExit(0)

# Macro/declaration recovery is useful context but is not sufficient to
# replace a missing definition in source_fallback_only mode.
print(recovered_body_count(selected, recovered))
PY_CKG_SOURCE_FALLBACK_BODIES
)"
            if [[ "${source_fallback_recovered_body_count:-0}" -eq 0 ]]; then
              preproc_code=3
              code=3
              failed_stage=preproc
            else
              printf '{"analysis_mode":"source_fallback_only","recovered_body_count":%s}\n' "$source_fallback_recovered_body_count" >"$ckg_db/analysis_mode.json"
              ckg_codeql_cache_status=not_cached
              ckg_codeql_cache_reason='source_fallback_only output is intentionally excluded from the CodeQL cache'
            fi
          else
            ckg_codeql_cache_store
          fi
        fi
      fi
    fi
  fi
  if [[ "$code" == "0" ]]; then
    fuzzing_code=0
    rm -f "$workspace/verified_harnesses.json"
    export HGB_CKG_EXTERNAL_VERIFIER=1
    cleanup_ckg_check_container
    timeout "${HGB_GENERATION_TIMEOUT_SECONDS:-10800}" python "$fuzzing_py" --yaml "$ckg_db/config.yaml" --gen_driver --summary_api "${ckg_compilation_args[@]}" "${ckg_input_args[@]}" >"$workspace/logs/fuzzing.log" 2>&1 || fuzzing_code=$?
    cleanup_ckg_check_container
    if [[ "$fuzzing_code" != "0" ]]; then
      code="$fuzzing_code"
      failed_stage=fuzzing
      hgb_result_set_stage "$workspace/stages.json" generation failed
      hgb_result_set_stage "$workspace/stages.json" compilation_repair failed
    else
      hgb_result_set_stage "$workspace/stages.json" generation completed
      hgb_result_set_stage "$workspace/stages.json" compilation_repair completed
    fi
  fi
  if [[ "$fuzzing_code" != "not_run" ]]; then
    n=0
    while IFS= read -r generated; do
      case "$generated" in
        "$workspace/generated_harnesses"/*|"$ckg_db/test"/*) continue ;;
      esac
      n=$((n + 1))
      cp "$generated" "$workspace/generated_harnesses/${n}_$(basename "$generated")" 2>/dev/null || true
    done < <(find "$ckg_db" -type f \( -name 'driver_*.c' -o -name 'driver_*.cc' -o -name 'driver_*.cpp' -o -name '*fuzz*.c' -o -name '*fuzz*.cc' -o -name '*fuzz*.cpp' \) 2>/dev/null | sort)
  fi
  generated_harness_count="$(count_files "$workspace/generated_harnesses" -type f)"
  candidate_verification_dir="$workspace/candidate_verification"
  # reproduction-zeta restores the CKGFuzzer compile-check/repair loop evidence
  # (zeta plan §3): --skip_check_compilation never appears in the command trace
  # for method-faithful profiles, and every repair attempt is saved under
  # repair/attempt_N/ with candidate source, compile log, and LLM trace.
  if [[ "$ckg_profile" == "reproduction-zeta" ]] && [[ "$fuzzing_code" != "not_run" ]]; then
    ckg_repair_dir="$workspace/repair"
    mkdir -p "$ckg_repair_dir"
    ckg_repair_attempt=1
    ckg_repair_attempt_dir="$ckg_repair_dir/attempt_${ckg_repair_attempt}"
    mkdir -p "$ckg_repair_attempt_dir"
    [[ -f "$workspace/logs/fuzzing.log" ]] && cp -f "$workspace/logs/fuzzing.log" "$ckg_repair_attempt_dir/compile.log" 2>/dev/null || true
    [[ -f "${HGB_LLM_TRACE_DIR:-$workspace/api_traces}/llm_api_samples.jsonl" ]] && cp -f "${HGB_LLM_TRACE_DIR:-$workspace/api_traces}/llm_api_samples.jsonl" "$ckg_repair_attempt_dir/llm_trace.jsonl" 2>/dev/null || true
    ckg_repair_first_candidate="$(find "$workspace/generated_harnesses" -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' \) -print -quit 2>/dev/null || true)"
    [[ -n "$ckg_repair_first_candidate" && -f "$ckg_repair_first_candidate" ]] && cp -f "$ckg_repair_first_candidate" "$ckg_repair_attempt_dir/candidate.c" 2>/dev/null || true
    ckg_repair_rounds="$(grep -cE 'check_compilation|compilation_fix|repair|Retry|attempt' "$workspace/logs/fuzzing.log" 2>/dev/null || printf '0')"
    while [[ "$ckg_repair_rounds" -gt 1 ]] && [[ "$ckg_repair_attempt" -lt "$ckg_repair_rounds" ]]; do
      ckg_repair_attempt=$((ckg_repair_attempt + 1))
      ckg_repair_attempt_dir="$ckg_repair_dir/attempt_${ckg_repair_attempt}"
      mkdir -p "$ckg_repair_attempt_dir"
      [[ -f "$workspace/logs/fuzzing.log" ]] && cp -f "$workspace/logs/fuzzing.log" "$ckg_repair_attempt_dir/compile.log" 2>/dev/null || true
    done
  fi
  candidate_verification_file="$candidate_verification_dir/results.json"
  verification_code=not_run
  verification_ran=false
  verified_harness_count=0
  verification_context_mode=''
  evaluator_status=''
  evaluator_execs_done=0
  evaluator_cov_lines=''
  if [[ "${generated_harness_count:-0}" -gt 0 ]]; then
    # Reject candidates with no LLVMFuzzerTestOneInput (or no fuzz-driver
    # equivalent accepted by FuzzBench).  Only candidates that define a
    # libFuzzer entry point are forwarded to the evaluator.
    hgb_filtered_dir="$workspace/generated_harnesses_filtered"
    rm -rf "$hgb_filtered_dir"
    mkdir -p "$hgb_filtered_dir"
    filtered_count=0
    while IFS= read -r -d '' cand; do
      if grep -qE 'LLVMFuzzerTestOneInput' "$cand" 2>/dev/null; then
        filtered_count=$((filtered_count + 1))
        cp "$cand" "$hgb_filtered_dir/${filtered_count}_$(basename "$cand")" 2>/dev/null || true
      fi
    done < <(find "$workspace/generated_harnesses" -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' \) -print0 2>/dev/null)
    if [[ "$filtered_count" -gt 0 ]]; then
      rm -rf "$workspace/generated_harnesses"
      mv "$hgb_filtered_dir" "$workspace/generated_harnesses"
      generated_harness_count="$filtered_count"
    else
      generated_harness_count=0
    fi
  fi
  if [[ "${generated_harness_count:-0}" -gt 0 ]]; then
    if [[ "$ckg_method_faithful" == "1" ]]; then
      # reproduction-gamma / paper-faithful / alpha: route candidates directly
      # into the split-aware shared evaluator.  The old build-only verifier is
      # NOT invoked before evaluation; in blind mode /target is generator_input
      # only and the old verifier cannot find fuzzbench_benchmark, which would
      # block the split-package reproduction loop.
      # Collect method-faithful stage evidence (reproduction-delta section 6).
      ckg_method_dir="$workspace/ckgfuzzer/method"
      mkdir -p "$ckg_method_dir"
      [[ -d "$ckg_db" ]] && printf '{"path":"%s","version":"%s"}\n' "$(hgb_json_escape "$ckg_db")" "$(hgb_json_escape "$(ckg_codeql_version)")" >"$ckg_method_dir/codeql_db.json"
      [[ -f "$ckg_db/api_list.json" ]] && cp -f "$ckg_db/api_list.json" "$ckg_method_dir/api_list.json" 2>/dev/null || true
      [[ -f "$ckg_db/api_summary/api_with_summary.json" ]] && cp -f "$ckg_db/api_summary/api_with_summary.json" "$ckg_method_dir/api_summaries.jsonl" 2>/dev/null || true
      [[ -d "$ckg_db/api_combine" ]] && cat "$ckg_db/api_combine"/*.csv 2>/dev/null >"$ckg_method_dir/api_combinations.jsonl" || true
      [[ -f "$workspace/logs/fuzzing.log" ]] && cp -f "$workspace/logs/fuzzing.log" "$ckg_method_dir/compile_repair_log.jsonl" 2>/dev/null || true
      [[ -d "${HGB_LLM_TRACE_DIR:-$workspace/api_traces}" ]] && cat "${HGB_LLM_TRACE_DIR:-$workspace/api_traces}"/llm_api_samples.jsonl 2>/dev/null >"$ckg_method_dir/llm_trace.jsonl" || true
      # reproduction-zeta records the additional CKG evidence required by the
      # zeta plan §2: the CodeQL database path, query_results.json, api_plan.json,
      # and llm_trace.jsonl under a ckg/ directory in the run workspace.
      if [[ "$ckg_profile" == "reproduction-zeta" ]]; then
        ckg_evidence_dir="$workspace/ckg"
        mkdir -p "$ckg_evidence_dir"
        [[ -d "$ckg_db" ]] && printf '{"path":"%s","version":"%s"}\n' "$(hgb_json_escape "$ckg_db")" "$(hgb_json_escape "$(ckg_codeql_version)")" >"$ckg_evidence_dir/codeql_database.json"
        [[ -f "$ckg_method_dir/codeql_db.json" ]] && cp -f "$ckg_method_dir/codeql_db.json" "$ckg_evidence_dir/codeql_database.json" 2>/dev/null || true
        # CodeQL query results (graph nodes/edges) recorded as query_results.json.
        if [[ "${ckg_codeql_graph_nodes_final:-0}" -gt 0 || "${ckg_codeql_graph_edges_final:-0}" -gt 0 ]]; then
          printf '{"nodes":%s,"edges":%s}\n' "${ckg_codeql_graph_nodes_final:-0}" "${ckg_codeql_graph_edges_final:-0}" >"$ckg_evidence_dir/query_results.json"
        fi
        [[ -f "$ckg_db/api_list.json" ]] && cp -f "$ckg_db/api_list.json" "$ckg_evidence_dir/api_plan.json" 2>/dev/null || true
        [[ -f "$ckg_method_dir/llm_trace.jsonl" ]] && cp -f "$ckg_method_dir/llm_trace.jsonl" "$ckg_evidence_dir/llm_trace.jsonl" 2>/dev/null || true
      fi
      # Strict reproduction profiles (reproduction-zeta and its backward
      # compatible aliases reproduction-epsilon and reproduction-delta): require
      # nonzero method evidence before evaluation.
      if [[ "$ckg_profile" == "reproduction-delta" || "$ckg_profile" == "reproduction-epsilon" || "$ckg_profile" == "reproduction-zeta" ]]; then
        ckg_method_missing=0
        for ckg_evidence in codeql_db.json api_list.json api_summaries.jsonl api_combinations.jsonl llm_trace.jsonl; do
          if [[ ! -s "$ckg_method_dir/$ckg_evidence" ]]; then
            printf '%s: missing method evidence %s\n' "$ckg_profile" "$ckg_evidence" >>"$workspace/logs/method_evidence.log"
            ckg_method_missing=1
          fi
        done
        if [[ "$ckg_method_missing" == "1" ]]; then
          code=9
          failed_stage=method_evidence
          status=failed
          reason="ckg_method_evidence_missing: $ckg_profile requires codeql_db/api_list/api_summaries/api_combinations/llm_trace evidence before evaluation"
          hgb_result_set_stage "$workspace/stages.json" generation failed
          hgb_write_common_metadata "$status" "$reason" "$code" harness_generator
          hgb_write_common_summary "$status" "$reason" harness_generator
          exit "$code"
        fi
        # CodeQL database must have nonzero query results (graph nodes/edges).
        if [[ "${ckg_codeql_graph_nodes_final:-0}" -le 0 && "${ckg_codeql_graph_edges_final:-0}" -le 0 ]]; then
          code=9
          failed_stage=method_evidence
          status=failed
          reason="ckg_method_evidence_missing: $ckg_profile requires nonzero CodeQL graph query results"
          hgb_result_set_stage "$workspace/stages.json" knowledge_graph failed
          hgb_write_common_metadata "$status" "$reason" "$code" harness_generator
          hgb_write_common_summary "$status" "$reason" harness_generator
          exit "$code"
        fi
      fi
      verification_ran=true
      verification_code=0
      verified_harness_count="$generated_harness_count"
      hgb_result_set_stage "$workspace/stages.json" candidate_build pending
      evaluator_root="${HGB_EVALUATOR_ROOT:-/target}"
      evaluator_dir="$workspace/evaluation"
      evaluator_code=0
      ckg_evaluator_args=(
        --generator ckgfuzzer
        --target-root /target
        --evaluator-root "$evaluator_root"
        --candidates "$workspace/generated_harnesses"
        --work-dir "$evaluator_dir"
        --project "$ckg_project"
        --fuzz-target "$fuzz_target"
        --profile "$ckg_profile"
        --protocol "$ckg_protocol"
        --campaign-seconds "${HGB_CAMPAIGN_SECONDS:-300}"
        --strict
      )
      # Strict reproduction profiles (reproduction-zeta and its backward
      # compatible aliases reproduction-epsilon and reproduction-delta) build a
      # separate coverage-instrumented image so an address/libFuzzer image is
      # never reused for source-based coverage.
      [[ "$ckg_profile" == "reproduction-delta" || "$ckg_profile" == "reproduction-epsilon" || "$ckg_profile" == "reproduction-zeta" ]] && ckg_evaluator_args+=(--build-coverage-image)
      # reproduction-zeta additionally runs the native coverage control so the
      # runtime coverage diff is reported (zeta plan §5/§6).
      [[ "$ckg_profile" == "reproduction-zeta" ]] && ckg_evaluator_args+=(--run-native-control)
      timeout "${HGB_CKG_EVALUATOR_TIMEOUT_SECONDS:-14400}" \
        python3 /opt/hgb/bin/hgb_harness_evaluator.py \
          "${ckg_evaluator_args[@]}" \
          >"$workspace/logs/harness_evaluator.log" 2>&1 || evaluator_code=$?
      evaluator_result="$evaluator_dir/result.json"
      if [[ -f "$evaluator_result" ]]; then
        # The evaluator drives candidate_build through coverage; mirror all
        # evaluation stages from the evaluator result so a build-only success
        # never marks campaign/coverage completed.
        for stage in candidate_build sanitizer_smoke api_reachability campaign coverage; do
          stage_state="$(jq -r --arg s "$stage" '.stages[$s] // "pending"' "$evaluator_result" 2>/dev/null || printf pending)"
          hgb_result_set_stage "$workspace/stages.json" "$stage" "$stage_state"
        done
        evaluator_status="$(jq -r '.status // ""' "$evaluator_result" 2>/dev/null || printf '')"
        evaluator_execs_done="$(jq -r '.metrics.campaign.execs_done // 0' "$evaluator_result" 2>/dev/null || printf 0)"
        evaluator_cov_lines="$(jq -r '.metrics.coverage.line_coverage.covered // empty' "$evaluator_result" 2>/dev/null || true)"
        # Record the selected candidate as the verified harness list so the
        # status derivation below does not treat a successful evaluation as
        # "no verified harness".
        jq '[.selected_candidate // empty] | map(select(. != null and . != {}))' "$evaluator_result" >"$workspace/verified_harnesses.json" 2>/dev/null || printf '[]\n' >"$workspace/verified_harnesses.json"
        verified_harness_count="$(jq 'length' "$workspace/verified_harnesses.json" 2>/dev/null || printf '0')"
      else
        for stage in candidate_build sanitizer_smoke api_reachability campaign coverage; do
          hgb_result_set_stage "$workspace/stages.json" "$stage" failed
        done
        evaluator_status=''
        evaluator_execs_done=0
        evaluator_cov_lines=''
        printf '[]\n' >"$workspace/verified_harnesses.json"
        if [[ "$code" -eq 0 ]]; then
          code=6
          failed_stage=evaluator
        fi
      fi
    else
      # compat-smoke: optional legacy build-only verifier path, excluded from
      # the scientific aggregate (method_variant=compat_smoke).
      verification_code=0
      # reproduction-delta/gamma/epsilon (and alpha/paper-faithful) must never
      # invoke the old build-only verifier before the shared evaluator. This
      # branch is only reached for compat-smoke; fail closed if a method-faithful
      # profile reaches here.
      if [[ "$ckg_profile" == "reproduction-delta" || "$ckg_profile" == "reproduction-epsilon" || "$ckg_profile" == "reproduction-zeta" || "$ckg_profile" == "reproduction-gamma" || "$ckg_profile" == "alpha" || "$ckg_profile" == "paper-faithful" ]]; then
        hgb_write_common_metadata failed "ckgfuzzer/$ckg_profile must not invoke the old build-only verifier; the shared evaluator is the only accepted path" 6 harness_generator
        hgb_write_common_summary failed "ckgfuzzer/$ckg_profile must not invoke the old build-only verifier" harness_generator
        exit 6
      fi
      timeout "${CKGFUZZER_CANDIDATE_VERIFY_TIMEOUT_SECONDS:-7200}" \
        python3 /opt/hgb/bin/ckgfuzzer_candidate_verifier.py \
          --target-root /target \
          --candidates "$workspace/generated_harnesses" \
          --work-dir "$candidate_verification_dir" \
          --fuzz-target "$fuzz_target" \
          --timeout-seconds "${CKGFUZZER_CANDIDATE_BUILD_TIMEOUT_SECONDS:-1800}" \
          >"$workspace/logs/candidate_verification.log" 2>&1 || verification_code=$?
      if [[ -f "$candidate_verification_file" ]]; then
        verification_ran="$(jq -r '.verification_ran // false' "$candidate_verification_file" 2>/dev/null || printf false)"
        verification_context_mode="$(jq -r '.verification_context.mode // ""' "$candidate_verification_file" 2>/dev/null || printf '')"
        jq '.verified_candidates // []' "$candidate_verification_file" >"$workspace/verified_harnesses.json" 2>/dev/null || printf '[]\n' >"$workspace/verified_harnesses.json"
        verified_harness_count="$(jq '(.verified_candidates // []) | length' "$candidate_verification_file" 2>/dev/null || printf '0')"
      else
        printf '[]\n' >"$workspace/verified_harnesses.json"
      fi
      if [[ "$verification_code" != "0" || "$verification_ran" != "true" ]]; then
        code=6
        if [[ "$verification_context_mode" == "verification_context_unreproducible" ]]; then
          failed_stage=verification_context
        else
          failed_stage=verification
        fi
        hgb_result_set_stage "$workspace/stages.json" candidate_build failed
      else
        hgb_result_set_stage "$workspace/stages.json" candidate_build completed
        # Beta plan §6: sanitizer_smoke, api_reachability, campaign, and coverage
        # are set ONLY from the full harness evaluator output. A candidate that
        # merely compiled must never mark these stages completed.
        evaluator_root="${HGB_EVALUATOR_ROOT:-/target}"
        evaluator_dir="$workspace/evaluation"
        evaluator_code=0
        timeout "${HGB_CKG_EVALUATOR_TIMEOUT_SECONDS:-14400}" \
          python3 /opt/hgb/bin/hgb_harness_evaluator.py \
            --generator ckgfuzzer \
            --target-root /target \
            --evaluator-root "$evaluator_root" \
            --candidates "$workspace/generated_harnesses" \
            --work-dir "$evaluator_dir" \
            --project "$ckg_project" \
            --fuzz-target "$fuzz_target" \
            --profile "$ckg_profile" \
            --campaign-seconds "${HGB_CAMPAIGN_SECONDS:-300}" \
            --strict \
            >"$workspace/logs/harness_evaluator.log" 2>&1 || evaluator_code=$?
        evaluator_result="$evaluator_dir/result.json"
        if [[ -f "$evaluator_result" ]]; then
          for stage in sanitizer_smoke api_reachability campaign coverage; do
            stage_state="$(jq -r --arg s "$stage" '.stages[$s] // "pending"' "$evaluator_result" 2>/dev/null || printf pending)"
            hgb_result_set_stage "$workspace/stages.json" "$stage" "$stage_state"
          done
          evaluator_status="$(jq -r '.status // ""' "$evaluator_result" 2>/dev/null || printf '')"
          evaluator_execs_done="$(jq -r '.metrics.campaign.execs_done // 0' "$evaluator_result" 2>/dev/null || printf 0)"
          evaluator_cov_lines="$(jq -r '.metrics.coverage.line_coverage.covered // empty' "$evaluator_result" 2>/dev/null || true)"
        else
          for stage in sanitizer_smoke api_reachability campaign coverage; do
            hgb_result_set_stage "$workspace/stages.json" "$stage" failed
          done
          evaluator_status=''
          evaluator_execs_done=0
          evaluator_cov_lines=''
        fi
      fi
    fi
  else
    printf '[]\n' >"$workspace/verified_harnesses.json"
  fi
  # Beta plan §7: status is derived from evaluator output. ``evaluated`` is
  # only allowed when the evaluator produced a per-candidate JSON, overlaid the
  # candidate, recorded execs_done > 0, and measured real coverage. A build-only
  # success is never ``evaluated``.
  status=evaluated
  reason=none
  if [[ -n "${evaluator_status:-}" ]]; then
    case "$evaluator_status" in
      evaluated)
        if [[ -z "${evaluator_cov_lines:-}" || "${evaluator_execs_done:-0}" -le 0 ]]; then
          status=quality_failure
          reason='ckg_evaluator_incomplete: evaluated claimed without coverage or execs_done>0'
        else
          status=evaluated
        fi
        ;;
      quality_failure) status=quality_failure; reason='ckg_quality_failure: no candidate passed build/smoke/reachability/campaign/coverage' ;;
      infra_failure) status=infra_failure; reason='ckg_infra_failure: evaluator tooling failed' ;;
      compat_smoke_completed) status=compat_smoke_completed; reason='compat-smoke completed (excluded from aggregate)' ;;
      *) status=quality_failure; reason="ckg_evaluator_status=${evaluator_status}" ;;
    esac
  fi
  if [[ "$code" -ne 0 ]]; then
    status=failed
    reason="CKGFuzzer $failed_stage stage exited $code"
    if [[ "$failed_stage" == "preproc" && "$code" == "3" ]]; then
      reason='ckg_selected_api_unresolved: CKGFuzzer could not recover source for any selected API'
    elif [[ "$failed_stage" == "analysis" ]]; then
      reason='ckg_codeql_analysis_failed: call-graph extraction failed; no empty graph was accepted'
    elif [[ "$failed_stage" == "verification" ]]; then
      status=infra_failed
      reason='ckg_verification_infra_failed: candidate compile/link verification did not run; inspect candidate_verification results and logs'
    elif [[ "$failed_stage" == "verification_context" ]]; then
      status=not_applicable
      reason='ckg_verification_context_unreproducible: target dependency source is not pinned; generated candidates were not evaluated against a moving source tree'
    fi
    if [[ "$failed_stage" == "repo" && -f "$workspace/logs/repo.log" ]]; then
      if grep -Eqi 'No source code was seen|did not process any source|No source code was seen during the build|hgb-codeql.*fallback compiled 0' "$workspace/logs/repo.log"; then
        reason='ckg_no_compilable_sources: CKGFuzzer CodeQL database build saw no C/C++ source after target build replay; inspect repo.log and target build scripts'
      elif [[ "$code" == "124" ]] && grep -Eqi 'Processing transactions|Starting evaluation of cpp-queries|codeql query run|Extracting call graph' "$workspace/logs/repo.log"; then
        reason='ckg_codeql_call_graph_timeout: CKGFuzzer CodeQL call-graph extraction timed out; reduce CKGFUZZER_MAX_CALL_GRAPH_APIS or inspect selected API filtering'
      elif [[ "$code" == "124" ]] && grep -Eqi 'copy_source_code_fromDocker|Extracting source code from the repository|source_code' "$workspace/logs/repo.log"; then
        reason='ckg_source_copy_timeout: CKGFuzzer timed out while copying source from the synthetic Docker image'
      fi
    fi
    if [[ "$failed_stage" == "fuzzing" && -f "$workspace/logs/fuzzing.log" ]]; then
      if grep -q 'openai.NotFoundError: Error code: 404' "$workspace/logs/fuzzing.log"; then
        reason='CKGFuzzer embedding API returned 404; set CKGFUZZER_EMBEDDING_MODEL and embedding base/API key to a compatible embeddings endpoint'
      elif grep -qi 'AuthenticationError\|PermissionDeniedError\|Error code: 401\|Error code: 403\|invalid api key' "$workspace/logs/fuzzing.log"; then
        reason='CKGFuzzer LLM API key or embedding credentials were rejected; verify base URL, model, and API key before rerunning'
      elif grep -qi 'ofg_empty_llm_response\|empty response\|NoneType.*split' "$workspace/logs/fuzzing.log"; then
        reason='CKGFuzzer LLM API returned empty response content before harness generation'
      elif grep -qi 'APITimeoutError\|ReadTimeout\|The read operation timed out\|Request timed out' "$workspace/logs/fuzzing.log"; then
        reason='CKGFuzzer LLM API request timed out before harness generation; reduce API caps or increase CKGFUZZER_LLM_REQUEST_TIMEOUT_SECONDS/HGB_LLM_REQUEST_TIMEOUT_SECONDS'
      elif grep -qi 'Connection refused.*11434\|Failed to establish.*11434' "$workspace/logs/fuzzing.log"; then
        reason='CKGFuzzer embedding service is unavailable at localhost:11434; start Ollama or configure CKGFUZZER_EMBEDDING_MODEL/base URL'
      elif grep -qi 'input device is not a TTY\|non-string result from run_fuzzer\|non-string result from build_fuzzer_file\|TypeError: argument of type' "$workspace/logs/fuzzing.log"; then
        reason='ckg_docker_noninteractive_compile_check: CKGFuzzer Docker compile/run check failed in non-interactive mode or returned a non-string result'
      elif grep -q "ModuleNotFoundError: No module named" "$workspace/logs/fuzzing.log"; then
        missing_mod="$(sed -n "s/.*ModuleNotFoundError: No module named '\\([^']*\\)'.*/\1/p" "$workspace/logs/fuzzing.log" | tail -n 1)"
        reason="CKGFuzzer missing Python dependency${missing_mod:+: $missing_mod}"
      fi
    fi
  fi
  generated_harness_count="$(count_files "$workspace/generated_harnesses" -type f)"
  verified_harness_count="$(jq 'length' "$workspace/verified_harnesses.json" 2>/dev/null || printf '0')"
  if [[ "$code" -eq 0 && "${generated_harness_count:-0}" -eq 0 ]]; then
    code=4
    fuzzing_code=4
    failed_stage=fuzzing
    status=failed
    reason='ckg_no_harness_generated: CKGFuzzer exited successfully without producing a harness candidate'
  elif [[ "$code" -eq 0 && "${verified_harness_count:-0}" -eq 0 ]]; then
    code=5
    fuzzing_code=5
    failed_stage=fuzzing
    status=failed
    reason='ckg_no_verified_harness: no generated harness passed compilation verification'
  fi
  if [[ "$code" -ne 0 && "$failed_stage" == "fuzzing" && "${generated_harness_count:-0}" -gt 0 ]]; then
    if [[ "${verified_harness_count:-0}" -gt 0 ]]; then
      status=partial_completed
      reason="CKGFuzzer fuzzing stage exited $code after producing candidates, but $verified_harness_count passed independent compile/link verification"
    else
      status=failed
      reason="CKGFuzzer fuzzing stage exited $code after producing $generated_harness_count candidates; verification did not establish a valid harness"
    fi
  fi
  compact_ckg_workspace
  # --- Reference leakage audit ---
  # If the host placed a canary token in the evaluator-only reference source
  # (HGB_REF_CANARY), scan all CKG generator inputs and outputs to prove it
  # never reached prompts, logs, API lists, summaries, or candidates.
  ckg_leakage_audit='{}'
  if [[ -n "${HGB_REF_CANARY:-}" ]]; then
    ckg_leakage_audit="$(python3 /opt/hgb/bin/ckgfuzzer_profile.py audit \
      --generator-input /target/source_input \
      --canary "$HGB_REF_CANARY" \
      --extra-dir "$workspace" \
      --extra-dir "$ckg_db" 2>/dev/null || printf '{"leaked":true,"error":"audit_failed"}')"
    if printf '%s' "$ckg_leakage_audit" | grep -q '"leaked": *true'; then
      printf 'Reference leakage audit FAILED: canary token found in CKG generator data\n' >"$workspace/logs/leakage_audit.log"
      printf '%s\n' "$ckg_leakage_audit" >>"$workspace/logs/leakage_audit.log"
      if [[ "$code" -eq 0 ]]; then
        code=8
        status=failed
        reason='ckg_reference_leakage: canary token from evaluator-only reference source reached CKG generator data'
        failed_stage=leakage_audit
      fi
    else
      printf 'Reference leakage audit passed: no canary leakage detected\n' >"$workspace/logs/leakage_audit.log"
    fi
  fi
  # --- Candidate reference-copy audit (plan section 4.4 / 5) ---
  # Compare the selected candidate to evaluator-only reference harnesses
  # *after* generation.  This never runs before generation and never writes
  # reference contents into generator-visible directories.
  ckg_candidate_audit='{"contains_reference_canary":false,"near_duplicate_reference":false,"exact_copy":false}'
  ckg_candidate_path=''
  ckg_candidate_sha256=''
  ckg_selected_candidate_json='{}'
  if [[ -f "$workspace/evaluation/result.json" ]]; then
    ckg_selected_candidate_json="$(jq '.selected_candidate // {}' "$workspace/evaluation/result.json" 2>/dev/null || printf '{}')"
    ckg_candidate_path="$(printf '%s' "$ckg_selected_candidate_json" | jq -r '.candidate_path // ""' 2>/dev/null || true)"
  fi
  if [[ -z "$ckg_candidate_path" && "${generated_harness_count:-0}" -gt 0 ]]; then
    ckg_candidate_path="$(find "$workspace/generated_harnesses" -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' \) -print -quit 2>/dev/null || true)"
  fi
  if [[ -n "$ckg_candidate_path" && -f "$ckg_candidate_path" ]]; then
    ckg_candidate_sha256="$(sha256sum "$ckg_candidate_path" | awk '{print $1}' 2>/dev/null || true)"
    ckg_eval_ref_dir="${HGB_EVALUATOR_ROOT:-/evaluator}/reference_harnesses"
    if [[ -d "$ckg_eval_ref_dir" ]]; then
      ckg_audit_script="$workspace/logs/ckg_candidate_audit.py"
      mkdir -p "$(dirname "$ckg_audit_script")"
      cat >"$ckg_audit_script" <<'PY_CKG_CAND_AUDIT'
import json
import sys
from pathlib import Path
sys.path.insert(0, "/opt/hgb/bin")
try:
    from hgb_split_context import audit_candidate_reference_copy
except Exception:
    print(json.dumps({"contains_reference_canary": False, "near_duplicate_reference": False, "exact_copy": False}))
    sys.exit(0)
candidate = Path(sys.argv[1])
ref_dir = Path(sys.argv[2])
canary = sys.argv[3] if len(sys.argv) > 3 else ""
result = audit_candidate_reference_copy(candidate, ref_dir, canary=canary)
print(json.dumps(result, sort_keys=True))
PY_CKG_CAND_AUDIT
      ckg_candidate_audit="$(PYTHONPATH="/opt/hgb/bin${PYTHONPATH:+:$PYTHONPATH}" python3 "$ckg_audit_script" "$ckg_candidate_path" "$ckg_eval_ref_dir" "${HGB_REF_CANARY:-}" 2>/dev/null || printf '%s' "$ckg_candidate_audit")"
    fi
  fi
  # Report API summary/combination mode and compilation repair attempts.
  if [[ "$ckg_method_faithful" == "1" ]]; then
    ckg_api_summary_mode='llm'
    ckg_api_combination_mode='llm'
  else
    ckg_api_summary_mode='local'
    ckg_api_combination_mode='local'
  fi
  ckg_repair_attempts="$(grep -cE 'check_compilation|compilation_fix|repair' "$workspace/logs/fuzzing.log" 2>/dev/null || printf '0')"
  ckg_repair_attempts="${ckg_repair_attempts:-0}"
  ckg_codeql_graph_nodes_final="${ckg_codeql_graph_nodes:-0}"
  ckg_codeql_graph_edges_final="${ckg_codeql_graph_edges:-0}"
  # initial_candidate_compiled: true when the first generated candidate
  # compiled cleanly with no repair rounds (zeta plan §6).
  if [[ "$fuzzing_code" == "0" && "$ckg_repair_attempts" -le 0 ]]; then
    ckg_initial_candidate_compiled=true
  else
    ckg_initial_candidate_compiled=false
  fi
  ckg_candidate_block="$(printf '{"path":"%s","sha256":"%s","contains_reference_canary":%s,"near_duplicate_reference":%s}' \
    "$(hgb_json_escape "$ckg_candidate_path")" "$(hgb_json_escape "$ckg_candidate_sha256")" \
    "$(printf '%s' "$ckg_candidate_audit" | jq -r '.contains_reference_canary // false' 2>/dev/null || printf false)" \
    "$(printf '%s' "$ckg_candidate_audit" | jq -r '.near_duplicate_reference // false' 2>/dev/null || printf false)")"
  ckg_block="$(printf '{"codeql_database":"%s","codeql_graph_nodes":%s,"codeql_graph_edges":%s,"api_summary_mode":"%s","api_combination_mode":"%s","compilation_repair_attempts":%s,"initial_candidate_compiled":%s}' \
    "$(hgb_json_escape "$ckg_db")" "$ckg_codeql_graph_nodes_final" "$ckg_codeql_graph_edges_final" \
    "$ckg_api_summary_mode" "$ckg_api_combination_mode" "$ckg_repair_attempts" "$ckg_initial_candidate_compiled")"
  api_selection_extra="$(hgb_api_selection_metadata_json "$api_selection_metadata")"
  extra=$(printf '%s  "ckgfuzzer_project": "%s",
  "ckgfuzzer_shared_dir": "%s",
  "ckgfuzzer_profile": "%s",
  "ckgfuzzer_protocol": "%s",
  "ckgfuzzer_method_faithful": %s,
  "api_candidate_count": %s,
  "generated_harness_count": %s,
  "verified_harness_count": %s,
  "candidate_verification_ran": %s,
  "candidate_verification_exit_code": "%s",
  "candidate_verification_file": "%s",
  "llm_request_timeout_seconds": "%s",
  "llm_max_retries": "%s",
  "api_selection_metadata": "%s",
  "command_file": "%s",
  "failed_stage": "%s",
  "repo_exit_code": "%s",
  "preproc_exit_code": "%s",
  "fuzzing_exit_code": "%s",
  "analysis_mode": "%s",
  "analysis_fallback_reason": "%s",
  "source_fallback_recovered_body_count": %s,
  "codeql_version": "%s",
  "codeql_graph_nodes": %s,
  "codeql_graph_edges": %s,
  "ckgfuzzer_codeql_cache_status": "%s",
  "ckgfuzzer_codeql_cache_key": "%s",
  "ckgfuzzer_codeql_cache_path": "%s",
  "ckgfuzzer_codeql_cache_reason": "%s",
  "candidate": %s,
  "ckgfuzzer": %s,
  "method": {"ckgfuzzer": %s},
  "reference_leakage_audit": %s' "$api_selection_extra" "$(hgb_json_escape "$ckg_project")" "$(hgb_json_escape "$ckg_shared")" "$(hgb_json_escape "$ckg_profile")" "$(hgb_json_escape "$ckg_protocol")" "$ckg_method_faithful" "${api_count:-0}" "${generated_harness_count:-0}" "${verified_harness_count:-0}" "$verification_ran" "$(hgb_json_escape "$verification_code")" "$(hgb_json_escape "$candidate_verification_file")" "$(hgb_json_escape "${CKGFUZZER_LLM_REQUEST_TIMEOUT_SECONDS:-900}")" "$(hgb_json_escape "${CKGFUZZER_LLM_MAX_RETRIES:-3}")" "$(hgb_json_escape "$api_selection_metadata")" "$(hgb_json_escape "$workspace/command.txt")" "$(hgb_json_escape "$failed_stage")" "$(hgb_json_escape "$repo_code")" "$(hgb_json_escape "$preproc_code")" "$(hgb_json_escape "$fuzzing_code")" "$(hgb_json_escape "$analysis_mode")" "$(hgb_json_escape "$analysis_fallback_reason")" "${source_fallback_recovered_body_count:-0}" "$(hgb_json_escape "$(ckg_codeql_version)")" "$ckg_codeql_graph_nodes_final" "$ckg_codeql_graph_edges_final" "$(hgb_json_escape "$ckg_codeql_cache_status")" "$(hgb_json_escape "$ckg_codeql_cache_key")" "$(hgb_json_escape "$ckg_codeql_cache_path")" "$(hgb_json_escape "$ckg_codeql_cache_reason")" "$ckg_candidate_block" "$ckg_block" "$ckg_block" "$ckg_leakage_audit")
  hgb_write_common_metadata "$status" "$reason" "$code" harness_generator "$extra"
  hgb_write_common_summary "$status" "$reason" harness_generator
  exit "$code"
fi
[[ "$mode" == "smoke" ]] || { echo "unknown mode: $mode" >&2; exit 64; }
export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
export OPENAI_MODEL="${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
write_sample
printf 'bash /workspace/project/hgb-sample/build.sh\n' >"$workspace/command.txt"
build_code=0
bash "$workspace/project/hgb-sample/build.sh" >"$workspace/logs/sample_build.log" 2>&1 || build_code=$?
gen_code=0
reason=none
status=completed
if [[ -z "$OPENAI_API_KEY" ]]; then
  printf 'OPENAI_API_KEY is not set; CKGFuzzer LLM generation skipped after sample preparation.\n' >"$workspace/logs/generation.log"
  gen_code=2
  status=missing_api_key
  reason='OPENAI_API_KEY is not set'
else
  printf 'CKGFuzzer artifact present. Full generation command is upstream-version dependent; wrapper smoke prepared the project and environment.\n' >"$workspace/logs/generation.log"
fi
metadata "$status" "$reason" "$build_code" "$gen_code"
summary "$status" "$reason" "$build_code" "$gen_code"
[[ "$build_code" -eq 0 && "$gen_code" -eq 0 ]]
