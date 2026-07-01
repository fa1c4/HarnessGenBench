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
  hgb_require_target_package
  target_name="${HGB_TARGET:-$(hgb_target_manifest_value target)}"
  safe_target="$(printf '%s' "$target_name" | sed 's/[^A-Za-z0-9_]/_/g')"
  ckg_project="hgb_${safe_target}"
  ckg_root=/fuzzing_llm_engine
  ckg_db="$ckg_root/external_database/$ckg_project"
  ckg_proj="$ckg_root/projects/$ckg_project"
  rm -rf "$ckg_db" "$ckg_proj"
  mkdir -p "$ckg_db/test" "$ckg_proj" /docker_shared
  if [[ -d /target/source_input ]]; then
    cp -a /target/source_input/. "$ckg_proj/" 2>/dev/null || true
  fi
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
project_name: "$ckg_project"
api_key: "${OPENAI_API_KEY:-}"
base_url: "${OPENAI_BASE_URL:-}"
model: "${OPENAI_MODEL:-}"
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
    hgb_soft_skip missing_codeql 'CodeQL CLI is not available in the CKGFuzzer image; set CKGFUZZER_SKIP_CODEQL=1 to bypass this check' harness_generator
  fi
  repo_py="$(find "$artifact" -name repo.py -type f 2>/dev/null | head -n 1 || true)"
  preproc_py="$(find "$artifact" -name preproc.py -type f 2>/dev/null | head -n 1 || true)"
  fuzzing_py="$(find "$artifact" -name fuzzing.py -type f 2>/dev/null | head -n 1 || true)"
  if [[ -z "$repo_py" || -z "$preproc_py" || -z "$fuzzing_py" ]]; then
    hgb_soft_skip upstream_cli_not_found 'could not find repo.py, preproc.py, and fuzzing.py in the CKGFuzzer artifact' harness_generator
  fi
  {
    printf 'cd %q && python %q --project_name %q --shared_llm_dir /docker_shared --saved_dir %q --src_api --call_graph\n' "$(dirname "$repo_py")" "$repo_py" "$ckg_project" "$ckg_db/codebase"
    printf 'python %q --project_name %q --src_api_file_path %q\n' "$preproc_py" "$ckg_project" "$ckg_db"
    printf 'python %q --yaml %q --gen_driver --summary_api --check_compilation --gen_input\n' "$fuzzing_py" "$ckg_db/config.yaml"
  } >"$workspace/command.txt"
  code=0
  (cd "$(dirname "$repo_py")" && timeout "${HGB_GENERATION_TIMEOUT_SECONDS:-900}" python "$repo_py" --project_name "$ckg_project" --shared_llm_dir /docker_shared --saved_dir "$ckg_db/codebase" --src_api --call_graph) >"$workspace/logs/repo.log" 2>&1 || code=$?
  if [[ "$code" == "0" ]]; then
    timeout "${HGB_GENERATION_TIMEOUT_SECONDS:-900}" python "$preproc_py" --project_name "$ckg_project" --src_api_file_path "$ckg_db" >"$workspace/logs/preproc.log" 2>&1 || code=$?
  fi
  if [[ "$code" == "0" ]]; then
    timeout "${HGB_GENERATION_TIMEOUT_SECONDS:-900}" python "$fuzzing_py" --yaml "$ckg_db/config.yaml" --gen_driver --summary_api --check_compilation --gen_input >"$workspace/logs/fuzzing.log" 2>&1 || code=$?
  fi
  n=0
  while IFS= read -r generated; do
    n=$((n + 1))
    cp "$generated" "$workspace/generated_harnesses/${n}_$(basename "$generated")" 2>/dev/null || true
  done < <(find "$ckg_root" "$artifact" -type f \( -name 'driver_*.c' -o -name '*fuzz*.c' -o -name '*fuzz*.cc' -o -name '*fuzz*.cpp' \) 2>/dev/null | sort)
  status=completed
  reason=none
  if [[ "$code" -ne 0 ]]; then
    status=failed
    reason="CKGFuzzer upstream command exited $code"
  fi
  extra=$(printf '  "ckgfuzzer_project": "%s",\n  "api_candidate_count": %s,\n  "command_file": "%s"' "$(hgb_json_escape "$ckg_project")" "${api_count:-0}" "$(hgb_json_escape "$workspace/command.txt")")
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
