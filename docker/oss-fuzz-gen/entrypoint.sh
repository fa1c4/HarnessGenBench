#!/usr/bin/env bash
set -euo pipefail

artifact=/opt/hgb/artifacts/oss-fuzz-gen
python=/opt/hgb/venv/bin/python
workspace=/workspace

fix_workspace_permissions() {
  if [[ -n "${HGB_HOST_UID:-}" && -n "${HGB_HOST_GID:-}" ]] && command -v chown >/dev/null 2>&1; then
    chown -R "${HGB_HOST_UID}:${HGB_HOST_GID}" "$workspace" 2>/dev/null || true
  fi
}
trap fix_workspace_permissions EXIT
mode="${1:-smoke}"
mkdir -p "$workspace/logs"

json_escape() { local v="${1:-}"; v="${v//\\/\\\\}"; v="${v//\"/\\\"}"; v="${v//$'\n'/\\n}"; printf '%s' "$v"; }
count_files() { local d="$1"; shift || true; [[ -d "$d" ]] || { printf '0'; return 0; }; find "$d" "$@" 2>/dev/null | wc -l | tr -d ' '; }
commit() { git -C "$artifact" rev-parse HEAD 2>/dev/null || printf unknown; }
summary() {
  local status="$1" exit_code="$2" reason="$3"
  {
    printf '# HarnessGenBench OSS-Fuzz-Gen Summary\n\n'
    printf -- '- Run directory: `%s`\n' "$workspace"
    printf -- '- Upstream commit: `%s`\n' "$(commit)"
    printf -- '- Status: `%s`\n' "$status"
    printf -- '- Exit code: `%s`\n' "$exit_code"
    printf -- '- Benchmark: `%s`\n' "${OFG_BENCHMARK:-tinyxml2}"
    printf -- '- Model: `%s`\n' "${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
    printf -- '- Generated harness candidates: %s\n' "$(count_files "$workspace" -type f \( -name '*fuzz*.cc' -o -name '*fuzz*.cpp' -o -name '*fuzz*.c' \))"
    printf -- '- Top failure reason: %s\n' "$reason"
    printf '\n## Logs\n\n'
    find "$workspace/logs" -type f 2>/dev/null | sort | sed "s#^$workspace/##" | sed 's/^/- `/' | sed 's/$/`/'
  } >"$workspace/HGB_SUMMARY.md"
}
metadata() {
  local status="$1" exit_code="$2" reason="$3" command_file="$4" log_file="$5" benchmark_yaml="$6"
  {
    printf '{\n'
    printf '  "fuzzer": "oss-fuzz-gen",\n'
    printf '  "status": "%s",\n' "$(json_escape "$status")"
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$(commit)")"
    printf '  "benchmark": "%s",\n' "$(json_escape "${OFG_BENCHMARK:-tinyxml2}")"
    printf '  "benchmark_yaml": "%s",\n' "$(json_escape "$benchmark_yaml")"
    printf '  "model": "%s",\n' "$(json_escape "${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}")"
    printf '  "api_key_present": %s,\n' "$([[ -n "${OPENAI_API_KEY:-${API_KEY:-}}" ]] && printf true || printf false)"
    printf '  "exit_code": %s,\n' "$exit_code"
    printf '  "reason": "%s",\n' "$(json_escape "$reason")"
    printf '  "command_file": "%s",\n' "$(json_escape "$command_file")"
    printf '  "log_file": "%s"\n' "$(json_escape "$log_file")"
    printf '}\n'
  } >"$workspace/metadata.json"
}

[[ "$mode" == "smoke" ]] || { echo "unknown mode: $mode" >&2; exit 64; }
export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
export OPENAI_MODEL="${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
benchmark="${OFG_BENCHMARK:-tinyxml2}"
benchmark_yaml=""
if [[ -d "$artifact/benchmark-sets" ]]; then
  benchmark_yaml="$(find "$artifact/benchmark-sets" -type f \( -name '*.yaml' -o -name '*.yml' \) \( -iname "*$benchmark*" -o -exec grep -Il "$benchmark" {} \; \) 2>/dev/null | sort | head -n 1 || true)"
fi
help_file="$workspace/logs/help.txt"
run_log="$workspace/logs/run.log"
command_file="$workspace/command.txt"
(cd "$artifact" && "$python" run_all_experiments.py --help) >"$help_file" 2>&1 || true
if [[ -z "$benchmark_yaml" ]]; then
  printf 'Could not locate benchmark YAML for %s\n' "$benchmark" >"$run_log"
  printf 'locate benchmark yaml\n' >"$command_file"
  metadata missing_benchmark 2 'benchmark YAML not found' "$command_file" "$run_log" "$benchmark_yaml"
  summary missing_benchmark 2 'benchmark YAML not found'
  exit 2
fi
if [[ -z "$OPENAI_API_KEY" ]]; then
  printf 'OPENAI_API_KEY is not set; OSS-Fuzz-Gen smoke not launched.\n' >"$run_log"
  printf 'python run_all_experiments.py -y %q --model %q --run-timeout %q --work-dir %q\n' "$benchmark_yaml" "$OPENAI_MODEL" "${OFG_RUN_TIMEOUT:-300}" "$workspace/ofg-work" >"$command_file"
  metadata missing_api_key 2 'OPENAI_API_KEY is not set' "$command_file" "$run_log" "$benchmark_yaml"
  summary missing_api_key 2 'OPENAI_API_KEY is not set'
  exit 2
fi
cmd=("$python" run_all_experiments.py -y "$benchmark_yaml" --model "$OPENAI_MODEL" --run-timeout "${OFG_RUN_TIMEOUT:-300}" --work-dir "$workspace/ofg-work")
printf '%q ' "${cmd[@]}" >"$command_file"; printf '\n' >>"$command_file"
code=0
(cd "$artifact" && timeout "${OFG_TOTAL_TIMEOUT_SECONDS:-600}" "${cmd[@]}") >"$run_log" 2>&1 || code=$?
status=completed; reason=none
[[ "$code" -eq 0 ]] || { status=failed; reason="run_all_experiments exited $code"; }
metadata "$status" "$code" "$reason" "$command_file" "$run_log" "$benchmark_yaml"
summary "$status" "$code" "$reason"
exit "$code"
