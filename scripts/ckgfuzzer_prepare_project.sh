#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

json_escape() {
  local value="${1:-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "$value"
}

find_complete_upstream_project() {
  local upstream_dir="$1"
  local wanted="${2:-auto}"
  local config project_dir project
  while IFS= read -r config; do
    project_dir="$(dirname "$config")"
    project="$(basename "$project_dir")"
    if [[ "$wanted" != "auto" && "$wanted" != "$project" ]]; then
      continue
    fi
    if [[ -f "$project_dir/api_list.json" && -d "$project_dir/test" && -f "$upstream_dir/fuzzing_llm_engine/projects/$project/Dockerfile" ]]; then
      printf '%s\n' "$project"
      return 0
    fi
  done < <(find "$upstream_dir/fuzzing_llm_engine/external_database" -mindepth 2 -maxdepth 2 -name config.yaml -type f 2>/dev/null | sort)
  return 1
}

write_sample_sources() {
  local sample_dir="$1"
  ensure_dir "$sample_dir/test_usage"
  cat >"$sample_dir/README.md" <<'EOF'
# CKGFuzzer Sample Project

This tiny C library validates the HarnessGenBench CKGFuzzer wrapper when upstream examples are missing `api_list.json`.
EOF
  cat >"$sample_dir/sample.h" <<'EOF'
#ifndef HGB_SAMPLE_H
#define HGB_SAMPLE_H
#include <stddef.h>
#include <stdint.h>
int hgb_parse_record(const uint8_t *data, size_t size);
uint32_t hgb_record_checksum(const uint8_t *data, size_t size);
#endif
EOF
  cat >"$sample_dir/sample.c" <<'EOF'
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
  cat >"$sample_dir/test_usage/example_usage.c" <<'EOF'
#include "../sample.h"
#include <stdint.h>
int main(void) {
  const uint8_t data[] = {'H', 'G', 'B', 3, 'o', 'k', '!'};
  return hgb_parse_record(data, sizeof(data)) < 0;
}
EOF
  cat >"$sample_dir/api_list.json" <<'EOF'
[
  "hgb_parse_record",
  "hgb_record_checksum"
]
EOF
  cat >"$sample_dir/build.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
cc -Wall -Wextra -I. sample.c test_usage/example_usage.c -o /tmp/hgb_sample_usage
/tmp/hgb_sample_usage
EOF
  chmod +x "$sample_dir/build.sh"
}

copy_shared_support() {
  local upstream_dir="$1"
  local shared_dir="$2"
  ensure_dir "$shared_dir"
  cp -a "$upstream_dir/docker_shared/wrapper.sh" "$shared_dir/wrapper.sh"
  cat >"$shared_dir/change_owner.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
target="${1:-}"
if [[ -n "$target" && -e "$target" ]]; then
  chown -R "$(id -u):$(id -g)" "$target" 2>/dev/null || true
fi
EOF
  chmod +x "$shared_dir/change_owner.sh"
  if [[ ! -e "$shared_dir/qlpacks" ]]; then
    cp -a "$upstream_dir/docker_shared/qlpacks" "$shared_dir/qlpacks"
  fi
  if [[ -e "$upstream_dir/docker_shared/codeql" && ! -e "$shared_dir/codeql" ]]; then
    cp -a "$upstream_dir/docker_shared/codeql" "$shared_dir/codeql"
  fi
}

write_preseeded_api_db() {
  local database_dir="$1"
  ensure_dir "$database_dir/codebase/api"
  ensure_dir "$database_dir/codebase/call_graph"
  cat >"$database_dir/codebase/api/src_api.json" <<'EOF'
{
  "src": {
    "/src/hgb-sample/sample.c": {
      "fn_def_list": [
        {
          "fn_meta": {"identifier": "hgb_parse_record", "parameters": {"data": "const uint8_t *", "size": "size_t"}, "return_type": "int"},
          "fn_code": "int hgb_parse_record(const uint8_t *data, size_t size) { if (!data || size < 4) return 0; if (data[0] != 'H' || data[1] != 'G' || data[2] != 'B') return 0; uint8_t declared = data[3]; if ((size_t)declared > size - 4) return -1; return (int)(hgb_record_checksum(data + 4, declared) & 0x7fffffffU); }"
        },
        {
          "fn_meta": {"identifier": "hgb_record_checksum", "parameters": {"data": "const uint8_t *", "size": "size_t"}, "return_type": "uint32_t"},
          "fn_code": "uint32_t hgb_record_checksum(const uint8_t *data, size_t size) { uint32_t acc = 2166136261u; if (!data) return 0; for (size_t i = 0; i < size; ++i) { acc ^= data[i]; acc *= 16777619u; } return acc; }"
        }
      ],
      "fn_declaraion": [],
      "class_node_list": [],
      "struct_node_list": [],
      "include_list": ["sample.h"],
      "global_variables": [],
      "enumerate_node_list": []
    }
  },
  "head": {
    "/src/hgb-sample/sample.h": {
      "fn_def_list": [],
      "fn_declaraion": [
        {"fn_meta": {"identifier": "hgb_parse_record"}, "fn_code": "int hgb_parse_record(const uint8_t *data, size_t size);"},
        {"fn_meta": {"identifier": "hgb_record_checksum"}, "fn_code": "uint32_t hgb_record_checksum(const uint8_t *data, size_t size);"}
      ],
      "class_node_list": [],
      "struct_node_list": [],
      "include_list": [],
      "global_variables": [],
      "enumerate_node_list": []
    }
  }
}
EOF
  cat >"$database_dir/codebase/call_graph/_src_hgb-sample_sample.c@hgb_parse_record_call_graph.csv" <<'EOF'
caller,callee
hgb_parse_record,hgb_record_checksum
EOF
  cat >"$database_dir/codebase/call_graph/_src_hgb-sample_sample.c@hgb_record_checksum_call_graph.csv" <<'EOF'
caller,callee
hgb_record_checksum,hgb_record_checksum
EOF
}

safe_link() {
  local target="$1"
  local link_path="$2"
  if [[ -L "$link_path" ]]; then
    ln -sfn "$target" "$link_path"
  elif [[ -e "$link_path" ]]; then
    die "$link_path already exists and is not a symlink; refusing to replace it"
  else
    ln -s "$target" "$link_path"
  fi
}

main() {
  local root upstream_dir requested project workspace engine_ws database_dir project_dir shared_dir sample_dir selected_env metadata_file
  root="$(repo_root)"
  load_env

  upstream_dir="$root/external/CKGFuzzer"
  [[ -d "$upstream_dir/.git" ]] || die "Missing $upstream_dir. Run: bash scripts/ckgfuzzer_setup.sh"

  requested="${CKGFUZZER_PROJECT:-auto}"
  project=""
  if project="$(find_complete_upstream_project "$upstream_dir" "$requested")"; then
    log "Using complete upstream CKGFuzzer example: $project"
  else
    if [[ "$requested" != "auto" && "$requested" != "hgb-sample" ]]; then
      die "Requested CKGFUZZER_PROJECT=$requested does not have config.yaml + api_list.json + tests in upstream checkout"
    fi
    project="hgb-sample"
    log "No complete upstream example found; preparing local sample project: $project"
  fi

  workspace="$root/${HGB_RESULTS_DIR:-results}/ckgfuzzer/workspace/$project"
  engine_ws="$workspace/fuzzing_llm_engine"
  database_dir="$engine_ws/external_database/$project"
  project_dir="$engine_ws/projects/$project"
  shared_dir="$workspace/docker_shared"
  sample_dir="$root/repro/ckgfuzzer/sample_project"
  ensure_dir "$database_dir/test"
  ensure_dir "$project_dir"
  ensure_dir "$shared_dir"
  ensure_dir "$workspace/logs"

  if [[ "$project" == "hgb-sample" ]]; then
    write_sample_sources "$sample_dir"
    cp -a "$sample_dir/sample.h" "$sample_dir/sample.c" "$project_dir/"
    cp -a "$sample_dir/sample.h" "$sample_dir/sample.c" "$database_dir/test/"
    cp -a "$sample_dir/test_usage/example_usage.c" "$database_dir/test/"
    cp -a "$sample_dir/api_list.json" "$database_dir/api_list.json"
    cat >"$project_dir/project.yaml" <<'EOF'
homepage: "https://example.invalid/hgb-sample"
language: c
primary_contact: "harnessgenbench@example.invalid"
sanitizers:
  - address
main_repo: "local"
EOF
    cat >"$project_dir/Dockerfile" <<EOF
FROM gcr.io/oss-fuzz-base/base-builder
COPY . /src/$project
WORKDIR /src/$project
COPY build.sh \$SRC/
EOF
    cat >"$project_dir/build.sh" <<'EOF'
#!/bin/bash -eu
$CC $CFLAGS -I/src/hgb-sample -c /src/hgb-sample/sample.c -o /tmp/hgb_sample.o
ar rcs /tmp/libhgb_sample.a /tmp/hgb_sample.o
EOF
    chmod +x "$project_dir/build.sh"
    write_preseeded_api_db "$database_dir"
  fi

  copy_shared_support "$upstream_dir" "$shared_dir"

  local openai_base_url ollama_base_url model
  openai_base_url="${OPENAI_BASE_URL:-https://api.openai.com/v1}"
  ollama_base_url="${CKGFUZZER_OLLAMA_BASE_URL:-http://127.0.0.1:11434}"
  model="${CKGFUZZER_MODEL:-${OPENAI_MODEL:-gpt-4o-mini}}"
  sed \
    -e "s#@PROJECT@#$project#g" \
    -e "s#@FUZZ_PROJECTS_DIR@#$database_dir/#g" \
    -e "s#@WORK_DIR@#$workspace/#g" \
    -e "s#@SHARED_DIR@#$shared_dir/#g" \
    -e "s#@OPENAI_BASE_URL@#$openai_base_url#g" \
    -e "s#@OLLAMA_BASE_URL@#$ollama_base_url#g" \
    -e "s#@MODEL@#$model#g" \
    "$sample_dir/config.yaml.template" >"$database_dir/config.yaml"

  ensure_dir "$upstream_dir/fuzzing_llm_engine/projects"
  ensure_dir "$upstream_dir/fuzzing_llm_engine/external_database"
  if [[ "$project" == "hgb-sample" ]]; then
    safe_link "$project_dir" "$upstream_dir/fuzzing_llm_engine/projects/$project"
    safe_link "$database_dir" "$upstream_dir/fuzzing_llm_engine/external_database/$project"
  fi

  selected_env="$root/${HGB_RESULTS_DIR:-results}/ckgfuzzer/selected_project.env"
  ensure_dir "$(dirname "$selected_env")"
  cat >"$selected_env" <<EOF
CKGFUZZER_PROJECT=$project
CKGFUZZER_WORKSPACE=$workspace
CKGFUZZER_DATABASE_DIR=$database_dir
CKGFUZZER_PROJECT_DIR=$project_dir
CKGFUZZER_SHARED_DIR=$shared_dir
CKGFUZZER_CONFIG=$database_dir/config.yaml
EOF

  metadata_file="$workspace/metadata.json"
  {
    printf '{\n'
    printf '  "project": "%s",\n' "$(json_escape "$project")"
    printf '  "workspace": "%s",\n' "$(json_escape "$workspace")"
    printf '  "database_dir": "%s",\n' "$(json_escape "$database_dir")"
    printf '  "project_dir": "%s",\n' "$(json_escape "$project_dir")"
    printf '  "shared_dir": "%s",\n' "$(json_escape "$shared_dir")"
    printf '  "config": "%s",\n' "$(json_escape "$database_dir/config.yaml")"
    printf '  "source": "%s"\n' "$(json_escape "$sample_dir")"
    printf '}\n'
  } >"$metadata_file"

  log "Prepared CKGFuzzer workspace at $workspace"
  log "Selected project metadata: $selected_env"
}

main "$@"
