#!/usr/bin/env bash
set -euo pipefail

artifact=/opt/hgb/artifacts/ckgfuzzer
workspace=/workspace

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
  mkdir -p "$workspace/logs" "$workspace/generated_harnesses"
  add_codeql_to_path "${HGB_CODEQL_DIR:-}"
  add_codeql_to_path /opt/codeql
  hgb_require_target_package
  target_name="${HGB_TARGET:-$(hgb_target_manifest_value target)}"
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
mkdir -p "$OUT" "$WORK" "$WORK/hgb-codeql-objects"
marker="/src/fuzzing_os/hgb_compiled_units_${project}.txt"
printf '0\n' >"$marker"
run_build=0
if [[ -x /target/fuzzbench_benchmark/build.sh ]]; then
  echo "[hgb-codeql] replaying /target/fuzzbench_benchmark/build.sh with SRC=$SRC"
  (cd "$SRC" && bash /target/fuzzbench_benchmark/build.sh) || run_build=$?
elif [[ -x /src/build.sh ]]; then
  echo "[hgb-codeql] replaying /src/build.sh with SRC=$SRC"
  (cd "$SRC" && bash /src/build.sh) || run_build=$?
elif [[ -x "$SRC/build.sh" ]]; then
  echo "[hgb-codeql] replaying $SRC/build.sh"
  (cd "$SRC" && bash "$SRC/build.sh") || run_build=$?
fi
count=0
while IFS= read -r -d '' src_file; do
  case "$src_file" in
    *.c) compiler="$CC"; std="-std=c11" ;;
    *) compiler="$CXX"; std="-std=c++17" ;;
  esac
  obj="$WORK/hgb-codeql-objects/${count}.o"
  if "$compiler" $std -I"$SRC" -D_FORTIFY_SOURCE=0 -c "$src_file" -o "$obj" >/dev/null 2>&1; then
    count=$((count + 1))
    printf '%s\n' "$count" >"$marker"
  fi
done < <(find "$SRC" -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' \) -print0 2>/dev/null | sort -z)
echo "[hgb-codeql] fallback compiled $count translation units"
if [[ "$count" -gt 0 || "$run_build" -eq 0 ]]; then
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
  if [[ -d /target/source_input ]]; then
    mapfile -t source_roots < <(find /target/source_input -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
    if [[ "${#source_roots[@]}" -eq 1 && -f "${source_roots[0]}/CMakeLists.txt" ]]; then
      cp -a "${source_roots[0]}/." "$ckg_proj/" 2>/dev/null || true
      repo_leaf="$(basename "${source_roots[0]}")"
      if [[ ! -e "$ckg_proj/$repo_leaf" ]]; then
        ln -s . "$ckg_proj/$repo_leaf" 2>/dev/null || true
      fi
    else
      cp -a /target/source_input/. "$ckg_proj/" 2>/dev/null || true
    fi
  fi
  if [[ -f /target/fuzzbench_benchmark/build.sh ]]; then
    cp /target/fuzzbench_benchmark/build.sh "$ckg_proj/build.sh" 2>/dev/null || true
    chmod +x "$ckg_proj/build.sh" 2>/dev/null || true
  fi
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
  && rm -rf /var/lib/apt/lists/*
ENV SRC=/src/$ckg_project
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
WORKDIR /src/$ckg_project
EOF_CKG_DOCKERFILE
  if [[ "$(hgb_count_files "$ckg_proj" -type f)" == "0" ]]; then
    hgb_soft_skip source_input_missing 'target package does not contain source files for CKGFuzzer API extraction' harness_generator
  fi
  if [[ "${HGB_ALLOW_REFERENCE_USAGE:-0}" == "1" && -d /target/reference_harnesses ]]; then
    cp -a /target/reference_harnesses/. "$ckg_db/test/" 2>/dev/null || true
  else
    cat >"$ckg_db/test/hgb_neutral_usage.c" <<'EOF_CKG_USAGE'
#include <stdint.h>
int main(void) { const uint8_t data[] = {0}; return (int)data[0]; }
EOF_CKG_USAGE
  fi

  api_count="$(python3 /opt/hgb/bin/extract_api_list.py --source /target/source_input --out "$ckg_db/api_list.json" --max 200 2>"$workspace/logs/api_extract.log" || printf '0')"
  api_count="${api_count##*$'\n'}"
  cat >"$ckg_db/config.yaml" <<EOF_CKG_CONFIG
config:
  project_name: "$ckg_project"
  program_language: "c++"
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
  request_timeout: 3600
llm_analyzer:
  model: "${OPENAI_MODEL:-gpt-4o-mini}"
  api_key: "${OPENAI_API_KEY:-}"
  base_url: "${OPENAI_BASE_URL:-}"
  temperature: 0.0
  request_timeout: 3600
llm_embedding:
  model: "${CKGFUZZER_EMBEDDING_MODEL:-mock}"
  api_key: "${CKGFUZZER_EMBEDDING_API_KEY:-${OPENAI_API_KEY:-}}"
  base_url: "${CKGFUZZER_EMBEDDING_BASE_URL:-${OPENAI_BASE_URL:-}}"
llm_code_embedding:
  model: "${CKGFUZZER_EMBEDDING_MODEL:-mock}"
  api_key: "${CKGFUZZER_EMBEDDING_API_KEY:-${OPENAI_API_KEY:-}}"
  base_url: "${CKGFUZZER_EMBEDDING_BASE_URL:-${OPENAI_BASE_URL:-}}"
source_dir: "$ckg_proj"
output_dir: "$workspace/generated_harnesses"
build_command: "bash /target/fuzzbench_benchmark/build.sh"
EOF_CKG_CONFIG
  printf 'CKGFuzzer project: %s\napi_list: %s\nconfig: %s\n' "$ckg_project" "$ckg_db/api_list.json" "$ckg_db/config.yaml" >"$workspace/command.txt"
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
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = """        eggs = [ (api[0].strip(), api[1].strip(), self.database_db, self.output_results_folder, self.shared_llm_dir) for api in src_api ]
        logger.info(f"Total number of API to be processed: {len(eggs)}")
"""
new = """        eggs = [ (api[0].strip(), api[1].strip(), self.database_db, self.output_results_folder, self.shared_llm_dir) for api in src_api ]
        max_apis = int(os.environ.get("CKGFUZZER_MAX_CALL_GRAPH_APIS", "8") or "0")
        if max_apis > 0 and len(eggs) > max_apis:
            logger.info(f"Limiting API call graph processing from {len(eggs)} to {max_apis} for HGB integration.")
            eggs = eggs[:max_apis]
        logger.info(f"Total number of API to be processed: {len(eggs)}")
"""
if old in text:
    path.write_text(text.replace(old, new, 1))
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
        command.extend([
            '-t', image_name,
            '/bin/bash', '-c', codeql_command
        ])
"""
if old in text and "'/target:/target:ro'" not in text:
    text = text.replace(old, new, 1)
path.write_text(text)
PY_CKG_REPO_DOCKER_MOUNT_PATCH
  get_model_py="$(find "$artifact" -path '*/models/get_model.py' -type f 2>/dev/null | head -n 1 || true)"
  if [[ -n "$get_model_py" ]]; then
    python3 - "$get_model_py" <<'PY_CKG_MODEL_PATCH'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
if "from llama_index.core.embeddings import MockEmbedding" not in text:
    text = text.replace(
        "from llama_index.embeddings.ollama import OllamaEmbedding\n",
        "from llama_index.embeddings.ollama import OllamaEmbedding\nfrom llama_index.core.embeddings import MockEmbedding\n",
        1,
    )
start = text.find("def get_embedding_model(")
if start != -1:
    replacement = 'def get_embedding_model(llm_config=None, device=\'cuda:1\'):\n    if llm_config is None:\n        return MockEmbedding(embed_dim=384)\n    model_name = llm_config[\'model\']\n    if model_name.startswith("mock") or model_name.startswith("local"):\n        return MockEmbedding(embed_dim=int(llm_config.get("dimensions", 384)))\n    if model_name.startswith("openai"):\n        model_name = model_name.replace("openai-", "").strip()\n        return OpenAIEmbedding(model=model_name, api_key=llm_config["api_key"], api_base=llm_config.get("base_url") or None)\n    if model_name.startswith("ollama"):\n        model_name = model_name.replace("ollama-", "").strip()\n        return OllamaEmbedding(model_name=model_name, base_url=llm_config["base_url"], ollama_additional_kwargs={"mirostat": 0})\n    assert False, f"Non-support Emb Model Name, The LLM config is {llm_config}. Please use mock/local, Ollama, or OpenAI embeddings"\n'
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
  ckg_input_args=()
  if [[ "${CKGFUZZER_GEN_INPUT:-0}" == "1" ]]; then
    ckg_input_args+=(--gen_input)
  else
    ckg_input_args+=(--skip_gen_input)
  fi
  {
    printf 'cd %q && python %q --project_name %q --shared_llm_dir %q --saved_dir %q --src_api --call_graph
' "$(dirname "$repo_py")" "$repo_py" "$ckg_project" "$ckg_shared" "$ckg_db/codebase"
    printf 'python %q --project_name %q --src_api_file_path %q
' "$preproc_py" "$ckg_project" "$ckg_db"
    printf 'python %q --yaml %q --gen_driver --summary_api --check_compilation' "$fuzzing_py" "$ckg_db/config.yaml"
    printf ' %q' "${ckg_input_args[@]}"
    printf '
'
  } >"$workspace/command.txt"
  code=0
  failed_stage=none
  repo_code=0
  preproc_code=not_run
  fuzzing_code=not_run
  (cd "$(dirname "$repo_py")" && timeout "${HGB_GENERATION_TIMEOUT_SECONDS:-900}" python "$repo_py" --project_name "$ckg_project" --shared_llm_dir "$ckg_shared" --saved_dir "$ckg_db/codebase" --src_api --call_graph) >"$workspace/logs/repo.log" 2>&1 || repo_code=$?
  if [[ "$repo_code" != "0" ]]; then
    code="$repo_code"
    failed_stage=repo
  elif [[ "${CKGFUZZER_SKIP_CODEQL:-0}" != "1" && -f "$ckg_shared/hgb_compiled_units_${ckg_project}.txt" ]]; then
    compiled_units="$(cat "$ckg_shared/hgb_compiled_units_${ckg_project}.txt" 2>/dev/null || printf '0')"
    if [[ "${compiled_units:-0}" == "0" && ! -f "$ckg_shared/codeqldb/$ckg_project/.successfully_created" ]]; then
      code=2
      failed_stage=repo
    fi
  fi
  if [[ "$code" == "0" ]]; then
    preproc_code=0
    timeout "${HGB_GENERATION_TIMEOUT_SECONDS:-900}" python "$preproc_py" --project_name "$ckg_project" --src_api_file_path "$ckg_db" >"$workspace/logs/preproc.log" 2>&1 || preproc_code=$?
    if [[ "$preproc_code" != "0" ]]; then
      code="$preproc_code"
      failed_stage=preproc
    else
      mkdir -p "$ckg_db/api_combine"
      if [[ ! -s "$ckg_db/api_combine/combined_call_graph.csv" ]]; then
        printf '%s
' 'caller,callee,caller_src,callee_src,start_body_start_line,start_body_end_line,end_body_start_line,end_body_end_line,caller_signature,caller_parameter_string,caller_return_type,caller_return_type_inferred,callee_signature,callee_parameter_string,callee_return_type,callee_return_type_inferred' >"$ckg_db/api_combine/combined_call_graph.csv"
      fi
    fi
  fi
  if [[ "$code" == "0" ]]; then
    fuzzing_code=0
    timeout "${HGB_GENERATION_TIMEOUT_SECONDS:-900}" python "$fuzzing_py" --yaml "$ckg_db/config.yaml" --gen_driver --summary_api --check_compilation "${ckg_input_args[@]}" >"$workspace/logs/fuzzing.log" 2>&1 || fuzzing_code=$?
    if [[ "$fuzzing_code" != "0" ]]; then
      code="$fuzzing_code"
      failed_stage=fuzzing
    fi
  fi
  n=0
  while IFS= read -r generated; do
    n=$((n + 1))
    cp "$generated" "$workspace/generated_harnesses/${n}_$(basename "$generated")" 2>/dev/null || true
  done < <(find "$ckg_proj" "$ckg_db" "$ckg_shared" -type f \( -name 'driver_*.c' -o -name '*fuzz*.c' -o -name '*fuzz*.cc' -o -name '*fuzz*.cpp' \) 2>/dev/null | sort)
  status=completed
  reason=none
  if [[ "$code" -ne 0 ]]; then
    status=failed
    reason="CKGFuzzer $failed_stage stage exited $code"
    if [[ "$failed_stage" == "repo" && -f "$workspace/logs/repo.log" ]]; then
      if grep -Eqi 'No source code was seen|did not process any source|No source code was seen during the build|hgb-codeql.*fallback compiled 0' "$workspace/logs/repo.log"; then
        reason='ckg_no_compilable_sources: CKGFuzzer CodeQL database build saw no C/C++ source after target build replay; inspect repo.log and target build scripts'
      fi
    fi
    if [[ "$failed_stage" == "fuzzing" && -f "$workspace/logs/fuzzing.log" ]]; then
      if grep -q 'openai.NotFoundError: Error code: 404' "$workspace/logs/fuzzing.log"; then
        reason='CKGFuzzer embedding API returned 404; set CKGFUZZER_EMBEDDING_MODEL and embedding base/API key to a compatible embeddings endpoint'
      elif grep -qi 'Connection refused.*11434\|Failed to establish.*11434' "$workspace/logs/fuzzing.log"; then
        reason='CKGFuzzer embedding service is unavailable at localhost:11434; start Ollama or configure CKGFUZZER_EMBEDDING_MODEL/base URL'
      elif grep -q "ModuleNotFoundError: No module named" "$workspace/logs/fuzzing.log"; then
        missing_mod="$(sed -n "s/.*ModuleNotFoundError: No module named '\\([^']*\\)'.*/\1/p" "$workspace/logs/fuzzing.log" | tail -n 1)"
        reason="CKGFuzzer missing Python dependency${missing_mod:+: $missing_mod}"
      fi
    fi
  fi
  generated_harness_count="$(count_files "$workspace/generated_harnesses" -type f)"
  if [[ "$code" -ne 0 && "${generated_harness_count:-0}" -gt 0 ]]; then
    status=partial_completed
    reason="CKGFuzzer $failed_stage stage exited $code after producing $generated_harness_count harness candidates"
  fi
  extra=$(printf '  "ckgfuzzer_project": "%s",\n  "ckgfuzzer_shared_dir": "%s",\n  "api_candidate_count": %s,\n  "command_file": "%s",\n  "failed_stage": "%s",\n  "repo_exit_code": "%s",\n  "preproc_exit_code": "%s",\n  "fuzzing_exit_code": "%s",\n  "codeql_version": "%s"' "$(hgb_json_escape "$ckg_project")" "$(hgb_json_escape "$ckg_shared")" "${api_count:-0}" "$(hgb_json_escape "$workspace/command.txt")" "$(hgb_json_escape "$failed_stage")" "$(hgb_json_escape "$repo_code")" "$(hgb_json_escape "$preproc_code")" "$(hgb_json_escape "$fuzzing_code")" "$(hgb_json_escape "$(ckg_codeql_version)")")
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
