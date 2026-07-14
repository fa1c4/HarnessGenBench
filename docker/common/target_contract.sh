#!/usr/bin/env bash
set -euo pipefail

hgb_json_escape() {
  local value="${1:-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "$value"
}

hgb_count_files() {
  local dir="$1"
  shift || true
  if [[ ! -d "$dir" ]]; then
    printf '0\n'
    return 0
  fi
  find "$dir" "$@" 2>/dev/null | wc -l | tr -d ' '
}


hgb_count_generated_harness_files() {
  local dir="$1"
  local count
  count="$(hgb_count_files "$dir" -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' -o -name '*.fuzz_target' \))"
  if [[ "${count:-0}" == "0" ]]; then
    count="$(hgb_count_files "$dir" -type f ! -name '*.build_script' ! -name '*build*script*')"
  fi
  printf '%s\n' "${count:-0}"
}

hgb_count_generated_build_scripts() {
  local dir="$1"
  hgb_count_files "$dir" -type f \( -name '*.build_script' -o -name '*build*script*' \)
}

hgb_count_generated_log_candidates() {
  local dir="$1"
  hgb_count_files "$dir" -type f -name 'log_candidate_*'
}

hgb_target_manifest_value() {
  local key="$1"
  local manifest="${HGB_TARGET_MANIFEST:-/target/target_manifest.json}"
  [[ -f "$manifest" ]] || return 0
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$manifest" "$key" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as f:
    value = json.load(f).get(sys.argv[2], "")
if isinstance(value, (list, dict)):
    print(json.dumps(value))
else:
    print(value)
PY
  else
    sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$manifest" | head -n 1
  fi
}

hgb_api_key_present() {
  [[ -n "${OPENAI_API_KEY:-${API_KEY:-}}" ]]
}

hgb_trace_summary_value() {
  local key="$1"
  local dir="${2:-${HGB_LLM_TRACE_DIR:-${workspace:-/workspace}/api_traces}}"
  local summary="$dir/summary.json"
  [[ -f "$summary" ]] || { printf '0\n'; return 0; }
  python3 - "$summary" "$key" <<'PY_HGB_TRACE_SUMMARY'
import json
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        value = json.load(f).get(sys.argv[2], 0)
except Exception:
    value = 0
try:
    print(int(value))
except Exception:
    print(0)
PY_HGB_TRACE_SUMMARY
}

hgb_trace_summary_string() {
  local key="$1"
  local dir="${2:-${HGB_LLM_TRACE_DIR:-${workspace:-/workspace}/api_traces}}"
  local default="${3:-}"
  local summary="$dir/summary.json"
  [[ -f "$summary" ]] || { printf '%s\n' "$default"; return 0; }
  python3 -c 'import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        data = json.load(f)
    value = data.get(sys.argv[2], sys.argv[3])
except Exception:
    value = sys.argv[3]
if value is None:
    value = sys.argv[3]
if isinstance(value, (dict, list)):
    print(json.dumps(value, sort_keys=True))
else:
    print(str(value))' "$summary" "$key" "$default"
}

hgb_fix_workspace_permissions() {
  local workspace="${workspace:-/workspace}"
  if [[ -n "${HGB_HOST_UID:-}" && -n "${HGB_HOST_GID:-}" ]] && command -v chown >/dev/null 2>&1; then
    chown -R "${HGB_HOST_UID}:${HGB_HOST_GID}" "$workspace" 2>/dev/null || true
  fi
}

hgb_generator_commit() {
  if [[ -n "${HGB_GENERATOR_COMMIT:-}" ]]; then
    printf '%s' "$HGB_GENERATOR_COMMIT"
    return 0
  fi
  local artifact="${HGB_GENERATOR_ARTIFACT_DIR:-${artifact:-}}"
  if [[ -n "$artifact" && -d "$artifact/.git" ]]; then
    git -C "$artifact" rev-parse HEAD 2>/dev/null || printf 'unknown'
  else
    printf 'unknown'
  fi
}

hgb_write_common_metadata() {
  local status="$1"
  local reason="$2"
  local exit_code="${3:-0}"
  local capability="${4:-harness_generator}"
  local extra_json="${5:-}"
  local workspace="${workspace:-/workspace}"
  local manifest="${HGB_TARGET_MANIFEST:-/target/target_manifest.json}"
  local harness_count build_script_count log_candidate_count input_count api_key_bool llm_provider llm_base_url trace_path trace_file trace_rate trace_total trace_sample
  mkdir -p "$workspace/logs" "$workspace/generated_harnesses" "$workspace/generated_inputs"
  harness_count="$(hgb_count_generated_harness_files "$workspace/generated_harnesses")"
  build_script_count="$(hgb_count_generated_build_scripts "$workspace/generated_harnesses")"
  log_candidate_count="$(hgb_count_generated_log_candidates "$workspace/generated_harnesses")"
  input_count="$(hgb_count_files "$workspace/generated_inputs" -type f)"
  if hgb_api_key_present; then api_key_bool=true; else api_key_bool=false; fi
  llm_provider="${HGB_LLM_PROVIDER_RESOLVED:-${HGB_LLM_PROVIDER:-custom}}"
  llm_base_url="${OPENAI_BASE_URL:-${BASE_URL:-}}"
  trace_path="${HGB_LLM_TRACE_DIR:-$workspace/api_traces}"
  trace_file="$(hgb_trace_summary_string trace_file "$trace_path" "$trace_path/llm_api_samples.jsonl")"
  trace_rate="$(hgb_trace_summary_string sample_rate "$trace_path" "${HGB_LLM_TRACE_SAMPLE_RATE:-10}")"
  trace_total="$(hgb_trace_summary_value total_count "$trace_path")"
  trace_sample="$(hgb_trace_summary_value sample_count "$trace_path")"
  {
    printf '{\n'
    printf '  "schema_version": 1,\n'
    printf '  "generator": "%s",\n' "$(hgb_json_escape "${HGB_GENERATOR:-unknown}")"
    printf '  "target": "%s",\n' "$(hgb_json_escape "${HGB_TARGET:-$(hgb_target_manifest_value target)}")"
    printf '  "run_type": "generate-target",\n'
    printf '  "save_mode": "%s",\n' "$(hgb_json_escape "${HGB_SAVE_MODE:-compact}")"
    printf '  "capability": "%s",\n' "$(hgb_json_escape "$capability")"
    printf '  "status": "%s",\n' "$(hgb_json_escape "$status")"
    printf '  "reason": "%s",\n' "$(hgb_json_escape "$reason")"
    printf '  "exit_code": %s,\n' "$exit_code"
    printf '  "api_key_present": %s,\n' "$api_key_bool"
    printf '  "llm_provider": "%s",\n' "$(hgb_json_escape "$llm_provider")"
    printf '  "llm_base_url": "%s",\n' "$(hgb_json_escape "$llm_base_url")"
    printf '  "model": "%s",\n' "$(hgb_json_escape "${OPENAI_MODEL:-${MODEL:-}}")"
    printf '  "target_manifest": "%s",\n' "$(hgb_json_escape "$manifest")"
    printf '  "fuzzbench_commit": "%s",\n' "$(hgb_json_escape "$(hgb_target_manifest_value fuzzbench_commit)")"
    printf '  "generator_commit": "%s",\n' "$(hgb_json_escape "$(hgb_generator_commit)")"
    printf '  "project": "%s",\n' "$(hgb_json_escape "${HGB_TARGET_PROJECT:-$(hgb_target_manifest_value project)}")"
    printf '  "fuzz_target": "%s",\n' "$(hgb_json_escape "${HGB_TARGET_FUZZ_TARGET:-$(hgb_target_manifest_value fuzz_target)}")"
    printf '  "generated_harness_count": %s,\n' "$harness_count"
    printf '  "generated_build_script_count": %s,\n' "$build_script_count"
    printf '  "generated_log_candidate_count": %s,\n' "$log_candidate_count"
    printf '  "generated_input_count": %s,\n' "$input_count"
    printf '  "log_dir": "%s",\n' "$(hgb_json_escape "$workspace/logs")"
    printf '  "api_trace_dir": "%s",\n' "$(hgb_json_escape "$trace_path")"
    printf '  "api_trace_file": "%s",\n' "$(hgb_json_escape "$trace_file")"
    printf '  "api_trace_sample_rate": "%s",\n' "$(hgb_json_escape "$trace_rate")"
    printf '  "api_trace_total_count": %s,\n' "${trace_total:-0}"
    printf '  "api_trace_sample_count": %s' "${trace_sample:-0}"
    if [[ -n "$extra_json" ]]; then
      printf ',\n%s\n' "$extra_json"
    else
      printf '\n'
    fi
    printf '}\n'
  } >"$workspace/metadata.json"
}

hgb_write_common_summary() {
  local status="$1"
  local reason="$2"
  local capability="${3:-harness_generator}"
  local workspace="${workspace:-/workspace}"
  local trace_path trace_file trace_rate
  {
    printf '# HarnessGenBench Target Run Summary\n\n'
    printf -- '- Generator: `%s`\n' "${HGB_GENERATOR:-unknown}"
    printf -- '- Target: `%s`\n' "${HGB_TARGET:-$(hgb_target_manifest_value target)}"
    printf -- '- Project: `%s`\n' "${HGB_TARGET_PROJECT:-$(hgb_target_manifest_value project)}"
    printf -- '- Fuzz target: `%s`\n' "${HGB_TARGET_FUZZ_TARGET:-$(hgb_target_manifest_value fuzz_target)}"
    printf -- '- Capability: `%s`\n' "$capability"
    printf -- '- Status: `%s`\n' "$status"
    printf -- '- API key present: `%s`\n' "$(hgb_api_key_present && printf true || printf false)"
    printf -- '- LLM provider: `%s`\n' "${HGB_LLM_PROVIDER_RESOLVED:-${HGB_LLM_PROVIDER:-custom}}"
    printf -- '- LLM base URL: `%s`\n' "${OPENAI_BASE_URL:-${BASE_URL:-}}"
    printf -- '- Model: `%s`\n' "${OPENAI_MODEL:-${MODEL:-}}"
    printf -- '- Generated harnesses: `%s`\n' "$(hgb_count_generated_harness_files "$workspace/generated_harnesses")"
    printf -- '- Generated build scripts: `%s`\n' "$(hgb_count_generated_build_scripts "$workspace/generated_harnesses")"
    printf -- '- Generated inputs: `%s`\n' "$(hgb_count_files "$workspace/generated_inputs" -type f)"
    trace_path="${HGB_LLM_TRACE_DIR:-$workspace/api_traces}"
    trace_file="$(hgb_trace_summary_string trace_file "$trace_path" "$trace_path/llm_api_samples.jsonl")"
    trace_rate="$(hgb_trace_summary_string sample_rate "$trace_path" "${HGB_LLM_TRACE_SAMPLE_RATE:-10}")"
    printf -- '- API trace dir: `%s`\n' "$trace_path"
    printf -- '- API trace file: `%s`\n' "$trace_file"
    printf -- '- API trace sample rate: `%s`\n' "$trace_rate"
    printf -- '- API trace calls/samples: `%s/%s`\n' "$(hgb_trace_summary_value total_count "$trace_path")" "$(hgb_trace_summary_value sample_count "$trace_path")"
    printf -- '- Top failure reason: %s\n' "$reason"
    printf '\n## Logs\n\n'
    find "$workspace/logs" -type f 2>/dev/null | sort | sed "s#^$workspace/##" | sed 's/^/- `/' | sed 's/$/`/'
  } >"$workspace/HGB_SUMMARY.md"
}

hgb_require_target_package() {
  local workspace="${workspace:-/workspace}"
  local target_root="${HGB_TARGET_PACKAGE:-/target}"
  local missing=0
  mkdir -p "$workspace/logs" "$workspace/generated_harnesses" "$workspace/generated_inputs"
  for path in \
    "$target_root/target_manifest.json" \
    "$target_root/fuzzbench_benchmark/benchmark.yaml" \
    "$target_root/fuzzbench_benchmark/build.sh"; do
    if [[ ! -e "$path" ]]; then
      printf 'missing required target package path: %s\n' "$path" >>"$workspace/logs/target_contract.log"
      missing=1
    fi
  done
  if [[ "$missing" == "1" ]]; then
    hgb_write_common_metadata target_package_missing 'target package is missing required files' 66 "${HGB_CAPABILITY:-harness_generator}"
    hgb_write_common_summary target_package_missing 'target package is missing required files' "${HGB_CAPABILITY:-harness_generator}"
    exit 66
  fi
}

hgb_soft_skip() {
  local status="$1"
  local reason="$2"
  local capability="${3:-${HGB_CAPABILITY:-harness_generator}}"
  hgb_write_common_metadata "$status" "$reason" 0 "$capability"
  hgb_write_common_summary "$status" "$reason" "$capability"
  exit 0
}

hgb_api_selection_metadata_json() {
  local file="${1:-}"
  python3 - "$file" <<'PY_HGB_API_SELECTION_METADATA'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1] else None
try:
    data = json.loads(path.read_text(encoding="utf-8")) if path and path.is_file() else {}
except (OSError, json.JSONDecodeError):
    data = {}

def emit(key, value):
    print(f'  "{key}": {json.dumps(value)},')

selected = data.get("selected_api_names") or data.get("api_candidate_names") or []
emit("api_selection_source", data.get("api_selection_source", "unknown"))
emit("api_report_mode", data.get("report_mode", ""))
emit("api_report_path", data.get("api_report_path", ""))
emit("api_report_row_found", bool(data.get("api_report_row_found")))
emit("api_report_source_field", data.get("api_report_source_field", ""))
emit("api_report_target", data.get("api_report_target", ""))
emit("api_selection_fallback_used", bool(data.get("fallback_used")))
emit("api_candidate_names", selected if isinstance(selected, list) else [])
PY_HGB_API_SELECTION_METADATA
}

