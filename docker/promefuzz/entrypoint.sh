#!/usr/bin/env bash
set -euo pipefail

artifact=/opt/hgb/artifacts/promefuzz
python=/opt/hgb/venv/bin/python
workspace=/workspace

fix_workspace_permissions() {
  if [[ -n "${HGB_HOST_UID:-}" && -n "${HGB_HOST_GID:-}" ]] && command -v chown >/dev/null 2>&1; then
    chown -R "${HGB_HOST_UID}:${HGB_HOST_GID}" "$workspace" 2>/dev/null || true
  fi
}
trap fix_workspace_permissions EXIT
mode="${1:-smoke-pugixml}"
mkdir -p "$workspace/logs" "$workspace/artifacts" /run/hgb
json_escape() { local v="${1:-}"; v="${v//\\/\\\\}"; v="${v//\"/\\\"}"; v="${v//$'\n'/\\n}"; printf '%s' "$v"; }
count_files() { local d="$1"; shift || true; [[ -d "$d" ]] || { printf '0'; return 0; }; find "$d" "$@" 2>/dev/null | wc -l | tr -d ' '; }
commit() { git -C "$artifact" rev-parse HEAD 2>/dev/null || printf unknown; }
write_config() {
  local cfg=/run/hgb/promefuzz_config.toml
  if [[ -f "$artifact/config.template.toml" ]]; then
    cp "$artifact/config.template.toml" "$cfg"
  else
    printf '[llm]\n' >"$cfg"
  fi
  cat >>"$cfg" <<EOF

# HarnessGenBench runtime-only LLM configuration. Not mounted to host.
[llm.hgb_cloud]
llm_type = "openai"
base_url = "${OPENAI_BASE_URL:-${BASE_URL:-https://api.openai.com/v1}}"
api_key = "${OPENAI_API_KEY:-${API_KEY:-}}"
model = "${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
EOF
  printf '%s\n' "$cfg"
}
summary() {
  local status="$1" code="$2" reason="$3"
  {
    printf '# HarnessGenBench PromeFuzz Summary\n\n'
    printf -- '- Run directory: `%s`\n' "$workspace"
    printf -- '- Upstream commit: `%s`\n' "$(commit)"
    printf -- '- Target: `pugixml`\n'
    printf -- '- Status: `%s`\n' "$status"
    printf -- '- Exit code: `%s`\n' "$code"
    printf -- '- API key present: `%s`\n' "$([[ -n "${OPENAI_API_KEY:-${API_KEY:-}}" ]] && printf true || printf false)"
    printf -- '- Generated fuzz-driver count: %s\n' "$(count_files "$workspace" -type f \( -name 'fuzz_driver_*.c' -o -name 'fuzz_driver_*.cc' -o -name 'fuzz_driver_*.cpp' \))"
    printf -- '- Top failure reason: %s\n' "$reason"
    printf '\n## Logs\n\n'
    find "$workspace/logs" -type f 2>/dev/null | sort | sed "s#^$workspace/##" | sed 's/^/- `/' | sed 's/$/`/'
  } >"$workspace/HGB_SUMMARY.md"
}
metadata() {
  local status="$1" code="$2" reason="$3" cfg="$4"
  {
    printf '{\n'
    printf '  "fuzzer": "promefuzz",\n'
    printf '  "status": "%s",\n' "$(json_escape "$status")"
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$(commit)")"
    printf '  "target": "pugixml",\n'
    printf '  "api_key_present": %s,\n' "$([[ -n "${OPENAI_API_KEY:-${API_KEY:-}}" ]] && printf true || printf false)"
    printf '  "runtime_config": "%s",\n' "$(json_escape "$cfg")"
    printf '  "exit_code": %s,\n' "$code"
    printf '  "reason": "%s",\n' "$(json_escape "$reason")"
    printf '  "command_file": "%s",\n' "$(json_escape "$workspace/command.txt")"
    printf '  "log_file": "%s"\n' "$(json_escape "$workspace/logs/run.log")"
    printf '}\n'
  } >"$workspace/metadata.json"
}
[[ "$mode" == "smoke-pugixml" || "$mode" == "smoke" ]] || { echo "unknown mode: $mode" >&2; exit 64; }
export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
export OPENAI_MODEL="${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
cfg="$(write_config)"
(cd "$artifact" && ("$python" PromeFuzz.py --help || python3 PromeFuzz.py --help)) >"$workspace/logs/help.txt" 2>&1 || true
printf 'PromeFuzz runtime config: /run/hgb/promefuzz_config.toml (not mounted)\n' >"$workspace/command.txt"
if [[ -z "$OPENAI_API_KEY" ]]; then
  printf 'OPENAI_API_KEY is not set; PromeFuzz pugixml smoke not launched.\n' >"$workspace/logs/run.log"
  metadata missing_api_key 2 'OPENAI_API_KEY is not set' "$cfg"
  summary missing_api_key 2 'OPENAI_API_KEY is not set'
  exit 2
fi
code=0
(cd "$artifact" && timeout "${PROMEFUZZ_STAGE_TIMEOUT_SECONDS:-600}" "$python" PromeFuzz.py --config "$cfg" --help) >"$workspace/logs/run.log" 2>&1 || code=$?
status=completed; reason=none
[[ "$code" -eq 0 ]] || { status=failed; reason="PromeFuzz command exited $code"; }
metadata "$status" "$code" "$reason" "$cfg"
summary "$status" "$code" "$reason"
exit "$code"
