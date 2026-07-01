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
  local harness_count input_count api_key_bool
  mkdir -p "$workspace/logs" "$workspace/generated_harnesses" "$workspace/generated_inputs"
  harness_count="$(hgb_count_files "$workspace/generated_harnesses" -type f)"
  input_count="$(hgb_count_files "$workspace/generated_inputs" -type f)"
  if hgb_api_key_present; then api_key_bool=true; else api_key_bool=false; fi
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
    printf '  "model": "%s",\n' "$(hgb_json_escape "${OPENAI_MODEL:-${MODEL:-}}")"
    printf '  "target_manifest": "%s",\n' "$(hgb_json_escape "$manifest")"
    printf '  "fuzzbench_commit": "%s",\n' "$(hgb_json_escape "$(hgb_target_manifest_value fuzzbench_commit)")"
    printf '  "generator_commit": "%s",\n' "$(hgb_json_escape "$(hgb_generator_commit)")"
    printf '  "project": "%s",\n' "$(hgb_json_escape "${HGB_TARGET_PROJECT:-$(hgb_target_manifest_value project)}")"
    printf '  "fuzz_target": "%s",\n' "$(hgb_json_escape "${HGB_TARGET_FUZZ_TARGET:-$(hgb_target_manifest_value fuzz_target)}")"
    printf '  "generated_harness_count": %s,\n' "$harness_count"
    printf '  "generated_input_count": %s,\n' "$input_count"
    printf '  "log_dir": "%s"' "$(hgb_json_escape "$workspace/logs")"
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
  {
    printf '# HarnessGenBench Target Run Summary\n\n'
    printf -- '- Generator: `%s`\n' "${HGB_GENERATOR:-unknown}"
    printf -- '- Target: `%s`\n' "${HGB_TARGET:-$(hgb_target_manifest_value target)}"
    printf -- '- Project: `%s`\n' "${HGB_TARGET_PROJECT:-$(hgb_target_manifest_value project)}"
    printf -- '- Fuzz target: `%s`\n' "${HGB_TARGET_FUZZ_TARGET:-$(hgb_target_manifest_value fuzz_target)}"
    printf -- '- Capability: `%s`\n' "$capability"
    printf -- '- Status: `%s`\n' "$status"
    printf -- '- API key present: `%s`\n' "$(hgb_api_key_present && printf true || printf false)"
    printf -- '- Generated harnesses: `%s`\n' "$(hgb_count_files "$workspace/generated_harnesses" -type f)"
    printf -- '- Generated inputs: `%s`\n' "$(hgb_count_files "$workspace/generated_inputs" -type f)"
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
