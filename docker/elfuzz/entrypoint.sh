#!/usr/bin/env bash
set -euo pipefail

workspace=/workspace

fix_workspace_permissions() {
  if [[ -n "${HGB_HOST_UID:-}" && -n "${HGB_HOST_GID:-}" ]] && command -v chown >/dev/null 2>&1; then
    chown -R "${HGB_HOST_UID}:${HGB_HOST_GID}" "$workspace" 2>/dev/null || true
  fi
}
trap fix_workspace_permissions EXIT
mode="${1:-smoke-jsoncpp}"
mkdir -p "$workspace/logs" "$workspace/artifacts"
json_escape() { local v="${1:-}"; v="${v//\\/\\\\}"; v="${v//\"/\\\"}"; v="${v//$'\n'/\\n}"; printf '%s' "$v"; }
stage_exit() { [[ -f "$workspace/logs/$1.exit" ]] && cat "$workspace/logs/$1.exit" || printf not_run; }
run_stage() {
  local stage="$1"; shift
  local code=0
  printf '%q ' "$@" >"$workspace/logs/$stage.cmd"; printf '\n' >>"$workspace/logs/$stage.cmd"
  timeout "${ELFUZZ_STAGE_TIMEOUT_SECONDS:-900}" "$@" >"$workspace/logs/$stage.log" 2>&1 || code=$?
  printf '%s\n' "$code" >"$workspace/logs/$stage.exit"
  return 0
}
summary() {
  local status="$1" reason="$2"
  {
    printf '# HarnessGenBench ELFuzz Summary\n\n'
    printf -- '- Run directory: `%s`\n' "$workspace"
    printf -- '- Target: `%s`\n' "${ELFUZZ_TARGET:-jsoncpp}"
    printf -- '- Status: `%s`\n' "$status"
    printf -- '- Setup status: `%s`\n' "$(stage_exit setup)"
    printf -- '- Synthesis status: `%s`\n' "$(stage_exit synth)"
    printf -- '- Seed production status: `%s`\n' "$(stage_exit produce)"
    printf -- '- AFL++ status: `%s`\n' "$(stage_exit afl)"
    printf -- '- Top failure reason: %s\n' "$reason"
    printf '\n## Logs\n\n'
    find "$workspace/logs" -type f 2>/dev/null | sort | sed "s#^$workspace/##" | sed 's/^/- `/' | sed 's/$/`/'
  } >"$workspace/HGB_SUMMARY.md"
}
metadata() {
  local status="$1" reason="$2"
  {
    printf '{\n'
    printf '  "fuzzer": "elfuzz",\n'
    printf '  "status": "%s",\n' "$(json_escape "$status")"
    printf '  "target": "%s",\n' "$(json_escape "${ELFUZZ_TARGET:-jsoncpp}")"
    printf '  "setup": "%s",\n' "$(json_escape "$(stage_exit setup)")"
    printf '  "synth": "%s",\n' "$(json_escape "$(stage_exit synth)")"
    printf '  "produce": "%s",\n' "$(json_escape "$(stage_exit produce)")"
    printf '  "afl": "%s",\n' "$(json_escape "$(stage_exit afl)")"
    printf '  "reason": "%s",\n' "$(json_escape "$reason")"
    printf '  "command_file": "%s",\n' "$(json_escape "$workspace/command.txt")"
    printf '  "log_dir": "%s"\n' "$(json_escape "$workspace/logs")"
    printf '}\n'
  } >"$workspace/metadata.json"
}
[[ "$mode" == "smoke-jsoncpp" || "$mode" == "smoke" ]] || { echo "unknown mode: $mode" >&2; exit 64; }
target="${ELFUZZ_TARGET:-jsoncpp}"
printf 'elfuzz smoke-jsoncpp target=%s\n' "$target" >"$workspace/command.txt"
if ! command -v elfuzz >/dev/null 2>&1; then
  printf 'elfuzz CLI not found in image.\n' >"$workspace/logs/help.txt"
  metadata missing_cli 'elfuzz CLI not found in image'
  summary missing_cli 'elfuzz CLI not found in image'
  exit 127
fi
elfuzz --help >"$workspace/logs/help.txt" 2>&1 || true
if [[ "${ELFUZZ_HELP_ONLY:-0}" == "1" ]]; then
  metadata help_only none
  summary help_only none
  exit 0
fi
run_stage setup bash -lc 'printf "y\n" | elfuzz setup'
if [[ "$(stage_exit setup)" == "0" && "${ELFUZZ_SKIP_DOWNLOAD:-0}" != "1" ]]; then
  run_stage download elfuzz download
else
  printf 'download skipped\n' >"$workspace/logs/download.log"; printf '0\n' >"$workspace/logs/download.exit"
fi
if [[ -n "${HF_TOKEN:-}" ]]; then
  run_stage hf_config bash -lc 'elfuzz config --set tgi.huggingface_token "$HF_TOKEN" >/dev/null 2>&1'
else
  printf 'HF_TOKEN is not set; skipped.\n' >"$workspace/logs/hf_config.log"; printf '0\n' >"$workspace/logs/hf_config.exit"
fi
run_stage synth elfuzz synth -T fuzzer.elfuzz --use-small-model --tgi-waiting "${ELFUZZ_TGI_WAITING_SECONDS:-120}" --evolution-iterations "${ELFUZZ_EVOLUTION_ITERATIONS:-1}" "$target"
run_stage produce elfuzz produce -T elfuzz --time "${ELFUZZ_PRODUCE_SECONDS:-60}" "$target"
run_stage afl elfuzz run rq1.afl --fuzzers elfuzz --repeat 1 --time "${ELFUZZ_AFL_SECONDS:-300}" "$target"
status=completed; reason=none
for s in setup synth produce afl; do
  c="$(stage_exit "$s")"
  if [[ "$c" != "0" ]]; then status=failed; reason="stage $s exited $c"; break; fi
done
metadata "$status" "$reason"
summary "$status" "$reason"
[[ "$status" == completed ]]
