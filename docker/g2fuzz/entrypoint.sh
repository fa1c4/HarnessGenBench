#!/usr/bin/env bash
set -euo pipefail

artifact=/opt/hgb/artifacts/g2fuzz
data_artifact=/opt/hgb/artifacts/g2fuzz-data
python=/opt/hgb/venv/bin/python
if [[ ! -x "$python" ]]; then
  python="$(command -v python3)"
fi
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
mode="${1:-generate-seeds}"
mkdir -p "$workspace/logs" "$workspace/config" "$workspace/artifacts"
json_escape() { local v="${1:-}"; v="${v//\\/\\\\}"; v="${v//\"/\\\"}"; v="${v//$'\n'/\\n}"; printf '%s' "$v"; }
count_files() { local d="$1"; shift || true; [[ -d "$d" ]] || { printf '0'; return 0; }; find "$d" "$@" 2>/dev/null | wc -l | tr -d ' '; }
extract_json_string() { local key="$1" file="$2"; [[ -f "$file" ]] || return 0; sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$file" | head -n 1; }
commit() { git -C "$artifact" rev-parse HEAD 2>/dev/null || printf unknown; }
data_commit() { git -C "$data_artifact" rev-parse HEAD 2>/dev/null || printf unknown; }
write_g2fuzz_preseeds() {
  local target="$1" formats="$2" seed_dir="$3"
  mkdir -p "$seed_dir"
  if [[ "$target" == *harfbuzz* || ",$formats," == *TTF* || ",$formats," == *OTF* || ",$formats," == *TTC* ]]; then
    python3 - "$seed_dir" <<'PY_G2_PRESEED'
from pathlib import Path
import sys
seed_dir = Path(sys.argv[1])
seed_dir.mkdir(parents=True, exist_ok=True)
seeds = {
    "hgb_minimal.ttf": bytes.fromhex("000100000000000000000000"),
    "hgb_minimal.otf": b"OTTO" + b"\x00" * 8,
    "hgb_minimal.ttc": b"ttcf\x00\x01\x00\x00\x00\x00\x00\x00",
}
for name, data in seeds.items():
    path = seed_dir / name
    if not path.exists():
        path.write_bytes(data)
PY_G2_PRESEED
  fi
  local copied=0
  while IFS= read -r corpus_file && [[ "$copied" -lt "${G2FUZZ_MAX_PRESEEDED_CORPUS_FILES:-32}" ]]; do
    cp "$corpus_file" "$seed_dir/hgb_corpus_${copied}_$(basename "$corpus_file")" 2>/dev/null || true
    copied=$((copied + 1))
  done < <(find /target -type f \( -path '*/corpus/*' -o -path '*/seeds/*' -o -path '*/seed_corpus/*' \) -size -1048576c 2>/dev/null | sort)
}
patch_g2fuzz_program_gen() {
  local py="$artifact/program_gen.py"
  [[ -f "$py" ]] || return 0
  python3 - "$py" <<'PY_G2_PROGRAM_PATCH'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
text = text.replace(
    'feature_analysis(model, file_format, tmp_path, seeds_path, generators, output_path, 3)',
    'feature_analysis(model, file_format, tmp_path, seeds_path, generators, output_path, int(os.environ.get("G2FUZZ_TRY_NUM", "3") or "3"))',
)
text = text.replace(
    'feature_analysis(model, file_format, tmp_path, seeds_path, generators, output_path, 1)',
    'feature_analysis(model, file_format, tmp_path, seeds_path, generators, output_path, int(os.environ.get("G2FUZZ_TRY_NUM", "3") or "3"))',
)
llm_path = path.parent / "py_utils" / "llm_utils.py"
if llm_path.exists():
    llm_text = llm_path.read_text()
    timeout_expr = "float(os.environ.get(\"G2FUZZ_LLM_REQUEST_TIMEOUT_SECONDS\", os.environ.get(\"HGB_LLM_REQUEST_TIMEOUT_SECONDS\", \"1200\")))"
    llm_text = llm_text.replace(
        "OpenAI(api_key=OPENAI_KEY)",
        f"OpenAI(api_key=OPENAI_KEY, timeout={timeout_expr})",
    )
    if "hgb_llm_trace" not in llm_text:
        llm_text = f"""from openai import OpenAI
import os
import sys

sys.path.insert(0, \"/opt/hgb/bin\")
try:
    import hgb_llm_trace
except Exception as exc:  # noqa: BLE001 - tracing is best-effort.
    hgb_llm_trace = None
    print(f\"HGB_LLM_TRACE: G2FUZZ tracing unavailable: {{exc}}\", file=sys.stderr)

with open('openai_key.txt', 'r') as file:
    key = file.read().strip()

OPENAI_KEY = key


def _client():
    timeout = float(os.environ.get(\"G2FUZZ_LLM_REQUEST_TIMEOUT_SECONDS\", os.environ.get(\"HGB_LLM_REQUEST_TIMEOUT_SECONDS\", \"1200\")))
    base_url = os.environ.get(\"OPENAI_BASE_URL\") or os.environ.get(\"BASE_URL\") or None
    return OpenAI(api_key=OPENAI_KEY, base_url=base_url, timeout=timeout)


def _create(model, messages, temperature):
    client = _client()
    request = {{\"model\": model, \"messages\": messages, \"temperature\": temperature}}
    if hgb_llm_trace is not None:
        response = hgb_llm_trace.trace_call(
            lambda: client.chat.completions.create(**request),
            stage=\"g2fuzz\",
            provider=\"openai-compatible\",
            operation=\"chat.completions.create\",
            model=model,
            request=request,
        )
    else:
        response = client.chat.completions.create(**request)
    return response.choices[0].message.content


def llm(model, prompt, temperature):
    return _create(model, [{{\"role\": \"user\", \"content\": prompt}}], temperature)


def llm_messages(model, messages, temperature):
    return _create(model, messages, temperature)


if __name__ == \"__main__\":
    print(llm(\"gpt-4o-mini-2024-07-18\", \"hi\", 0.0))
"""
    llm_path.write_text(llm_text)
path.write_text(text)
PY_G2_PROGRAM_PATCH
}
select_program() {
  "$python" - "$artifact/program_to_format.json" "${G2FUZZ_PROGRAM:-auto}" <<'PYSEL'
import json, sys
from pathlib import Path
programs=json.loads(Path(sys.argv[1]).read_text())
requested=sys.argv[2]
if requested != 'auto':
    if requested not in programs:
        raise SystemExit(f'unknown G2FUZZ program: {requested}')
    program=requested
else:
    program='jhead' if 'jhead' in programs else next(iter(programs))
print(program)
print(','.join(programs[program]))
PYSEL
}
write_seed_summary() {
  local status="$1" code="$2" reason="$3" program="$4" formats="$5" seeds="$6" generators="$7"
  {
    printf '# HarnessGenBench G2FUZZ Summary\n\n'
    printf -- '- Run directory: `%s`\n' "$workspace"
    printf -- '- Upstream commit: `%s`\n' "$(commit)"
    printf -- '- Data commit: `%s`\n' "$(data_commit)"
    printf -- '- Selected target: `%s`\n' "$program"
    printf -- '- Selected format(s): `%s`\n' "$formats"
    printf -- '- Model: `%s`\n' "${G2FUZZ_MODEL:-${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}}"
    printf -- '- Status: `%s`\n' "$status"
    printf -- '- Generated seed count: %s\n' "$seeds"
    printf -- '- Generator count: %s\n' "$generators"
    printf -- '- AFL run status: `not_run`\n'
    printf -- '- Top failure reason: %s\n' "$reason"
    printf '\n## Logs\n\n'
    find "$workspace/logs" -type f 2>/dev/null | sort | sed "s#^$workspace/##" | sed 's/^/- `/' | sed 's/$/`/'
  } >"$workspace/HGB_SUMMARY.md"
}
write_seed_metadata() {
  local status="$1" code="$2" reason="$3" program="$4" formats="$5" seeds="$6" generators="$7" output_dir="$8"
  {
    printf '{\n'
    printf '  "fuzzer": "g2fuzz",\n'
    printf '  "run_type": "seed_generation",\n'
    printf '  "status": "%s",\n' "$(json_escape "$status")"
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$(commit)")"
    printf '  "data_commit": "%s",\n' "$(json_escape "$(data_commit)")"
    printf '  "program": "%s",\n' "$(json_escape "$program")"
    printf '  "formats": "%s",\n' "$(json_escape "$formats")"
    printf '  "model": "%s",\n' "$(json_escape "${G2FUZZ_MODEL:-${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}}")"
    printf '  "api_key_present": %s,\n' "$([[ -n "${OPENAI_API_KEY:-${API_KEY:-}}" ]] && printf true || printf false)"
    printf '  "generated_seed_count": %s,\n' "$seeds"
    printf '  "generator_count": %s,\n' "$generators"
    printf '  "program_gen_exit_code": %s,\n' "$code"
    printf '  "reason": "%s",\n' "$(json_escape "$reason")"
    printf '  "output_dir": "%s",\n' "$(json_escape "$output_dir")"
    printf '  "data_repo_comparison_path": "%s",\n' "$(json_escape "$data_artifact/unifuzz/G2FUZZ_GPT35/$program")"
    printf '  "command_file": "%s",\n' "$(json_escape "$workspace/command.txt")"
    printf '  "log_file": "%s"\n' "$(json_escape "$workspace/logs/program_gen.log")"
    printf '}\n'
  } >"$workspace/metadata.json"
}
find_target_pair() {
  local program="$1" d
  for d in ${G2FUZZ_TARGET_DIR:-} "$workspace/targets/$program" "$artifact"; do
    [[ -n "$d" ]] || continue
    if [[ -x "$d/$program.afl" && -x "$d/$program.cmp" ]]; then
      printf '%s\n%s\n' "$d/$program.afl" "$d/$program.cmp"
      return 0
    fi
  done
  return 1
}
write_afl_summary() {
  local status="$1" code="$2" reason="$3" program="$4" queue="$5" crashes="$6" hangs="$7"
  {
    printf '# HarnessGenBench G2FUZZ Summary\n\n'
    printf -- '- Run directory: `%s`\n' "$workspace"
    printf -- '- Upstream commit: `%s`\n' "$(commit)"
    printf -- '- Selected target: `%s`\n' "$program"
    printf -- '- Status: `%s`\n' "$status"
    printf -- '- AFL run status: `%s`\n' "$code"
    printf -- '- AFL queue/crash/hang counts: queue=%s, crashes=%s, hangs=%s\n' "$queue" "$crashes" "$hangs"
    printf -- '- Top failure reason: %s\n' "$reason"
    printf '\n## Logs\n\n'
    find "$workspace" -maxdepth 3 -type f \( -name '*.log' -o -name 'TARGET_BUILD_MISSING.md' \) 2>/dev/null | sort | sed "s#^$workspace/##" | sed 's/^/- `/' | sed 's/$/`/'
  } >"$workspace/HGB_SUMMARY.md"
}
write_afl_metadata() {
  local status="$1" code="$2" reason="$3" program="$4" queue="$5" crashes="$6" hangs="$7" seed_run="$8"
  {
    printf '{\n'
    printf '  "fuzzer": "g2fuzz",\n'
    printf '  "run_type": "afl_smoke",\n'
    printf '  "status": "%s",\n' "$(json_escape "$status")"
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$(commit)")"
    printf '  "program": "%s",\n' "$(json_escape "$program")"
    printf '  "seed_run": "%s",\n' "$(json_escape "$seed_run")"
    printf '  "afl_exit_code": %s,\n' "$code"
    printf '  "queue_count": %s,\n' "$queue"
    printf '  "crash_count": %s,\n' "$crashes"
    printf '  "hang_count": %s,\n' "$hangs"
    printf '  "reason": "%s",\n' "$(json_escape "$reason")"
    printf '  "command_file": "%s",\n' "$(json_escape "$workspace/command.txt")"
    printf '  "log_file": "%s"\n' "$(json_escape "$workspace/logs/afl.log")"
    printf '}\n'
  } >"$workspace/metadata.json"
}


if [[ "$mode" == "generate-target" ]]; then
  # shellcheck source=/opt/hgb/bin/target_contract.sh
  source /opt/hgb/bin/target_contract.sh
  export HGB_GENERATOR="${HGB_GENERATOR:-g2fuzz}"
  export HGB_GENERATOR_ARTIFACT_DIR="$artifact"
  export HGB_CAPABILITY=input_generator
  export HGB_TASK_FAMILY=input_generator
  export HGB_BASELINE_PROFILE="${HGB_BASELINE_PROFILE:-alpha}"
  export HGB_BASELINE_PROTOCOL="${HGB_BASELINE_PROTOCOL:-paper-native}"
  export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
  export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
  export OPENAI_MODEL="${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
  export HGB_LLM_REQUEST_TIMEOUT_SECONDS="${HGB_LLM_REQUEST_TIMEOUT_SECONDS:-1200}"
  export G2FUZZ_LLM_REQUEST_TIMEOUT_SECONDS="${G2FUZZ_LLM_REQUEST_TIMEOUT_SECONDS:-$HGB_LLM_REQUEST_TIMEOUT_SECONDS}"
  mkdir -p "$workspace/logs" "$workspace/generated_inputs" "$workspace/config"
  hgb_require_target_package
  patch_g2fuzz_program_gen
  target_name="${HGB_TARGET:-$(hgb_target_manifest_value target)}"
  dry_run_arg=()
  if [[ "${HGB_DRY_RUN:-0}" == "1" ]]; then
    dry_run_arg=(--dry-run)
  fi
  exec "$python" /opt/hgb/bin/g2fuzz_target_pipeline.py full \
    --workspace "$workspace" \
    --target "$target_name" \
    --target-package "${HGB_TARGET_PACKAGE:-/target}" \
    --artifact-dir "$artifact" \
    --metadata-root /opt/hgb/metadata \
    --profile "$HGB_BASELINE_PROFILE" \
    --protocol "$HGB_BASELINE_PROTOCOL" \
    "${dry_run_arg[@]}"
fi
case "$mode" in
  generate-seeds|smoke)
    mapfile -t selected < <(select_program)
    program="${selected[0]}"
    formats="${selected[1]}"
    model="${G2FUZZ_MODEL:-${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}}"
    output_dir="$workspace/${program}_output"
    write_g2fuzz_preseeds "$program" "$formats" "$output_dir/default/gen_seeds"
    patch_g2fuzz_program_gen
    runtime=/run/hgb/g2fuzz-runtime
    mkdir -p "$runtime" "$workspace/config"
    cp "$artifact/program_to_format.json" "$runtime/program_to_format.json"
    cp "$artifact/program_to_format.json" "$workspace/config/program_to_format.json"
    "$python" - "$runtime/model_setting.json" "$model" <<'PYMODEL'
import json, sys
with open(sys.argv[1], 'w') as f:
    json.dump({'model': [sys.argv[2]]}, f, indent=2)
    f.write('\n')
PYMODEL
    cp "$runtime/model_setting.json" "$workspace/config/model_setting.json"
    printf '%q ' "$python" "$artifact/program_gen.py" --output "$output_dir" --program "$program" >"$workspace/command.txt"; printf '\n' >>"$workspace/command.txt"
    export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
    export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
    export HGB_LLM_REQUEST_TIMEOUT_SECONDS="${HGB_LLM_REQUEST_TIMEOUT_SECONDS:-1200}"
    export G2FUZZ_LLM_REQUEST_TIMEOUT_SECONDS="${G2FUZZ_LLM_REQUEST_TIMEOUT_SECONDS:-$HGB_LLM_REQUEST_TIMEOUT_SECONDS}"
    if [[ -z "$OPENAI_API_KEY" ]]; then
      printf 'OPENAI_API_KEY is not set. No credential file was created.\n' >"$workspace/logs/program_gen.log"
      write_seed_metadata missing_api_key 2 'OPENAI_API_KEY is not set' "$program" "$formats" 0 0 "$output_dir"
      write_seed_summary missing_api_key 2 'OPENAI_API_KEY is not set' "$program" "$formats" 0 0
      exit 2
    fi
    printf '%s\n' "$OPENAI_API_KEY" >"$runtime/openai_key.txt"
    chmod 600 "$runtime/openai_key.txt"
    code=0
    (cd "$runtime" && timeout "${G2FUZZ_PER_FORMAT_TIMEOUT_SECONDS:-${G2FUZZ_TIMEOUT_SECONDS:-300}}" "$python" "$artifact/program_gen.py" --output "$output_dir" --program "$program") >"$workspace/logs/program_gen.log" 2>&1 || code=$?
    rm -f "$runtime/openai_key.txt"
    seeds="$(count_files "$output_dir/default/gen_seeds" -type f)"
    generators="$(count_files "$output_dir/default/generators" -type f)"
    status=completed; reason=none
    program_gen_code="$code"
    if [[ "$program_gen_code" -eq 124 && "$seeds" -gt 0 ]]; then
      status=partial_completed
      reason="program_gen timed out after generating $seeds seeds"
      code=0
    elif [[ "$program_gen_code" -ne 0 ]]; then
      status=failed
      reason="program_gen exited $program_gen_code"
      if grep -qi 'AuthenticationError\|PermissionDeniedError\|Error code: 401\|Error code: 403\|invalid api key' "$workspace/logs/program_gen.log"; then
        reason='G2Fuzz LLM API credentials were rejected; verify base URL, model, and API key before rerunning'
      elif grep -qi 'ofg_empty_llm_response\|empty response\|NoneType.*split' "$workspace/logs/program_gen.log"; then
        reason='G2Fuzz LLM API returned empty response content before saving generated inputs'
      elif grep -qi 'APITimeoutError\|ReadTimeout\|The read operation timed out\|Request timed out' "$workspace/logs/program_gen.log"; then
        reason='G2Fuzz LLM API request timed out before saving generated inputs; reduce G2FUZZ_MAX_FORMATS/G2FUZZ_TRY_NUM or increase G2FUZZ_LLM_REQUEST_TIMEOUT_SECONDS/HGB_LLM_REQUEST_TIMEOUT_SECONDS'
      fi
    fi
    write_seed_metadata "$status" "$program_gen_code" "$reason" "$program" "$formats" "$seeds" "$generators" "$output_dir"
    write_seed_summary "$status" "$program_gen_code" "$reason" "$program" "$formats" "$seeds" "$generators"
    exit "$code"
    ;;
  smoke-afl)
    if [[ -z "${HGB_TARGET:-}" || ! -d "${HGB_TARGET_PACKAGE:-/target}" ]]; then
      echo "smoke-afl is now a compatibility alias for generate-target; set HGB_TARGET and HGB_TARGET_PACKAGE or use scripts/g2fuzz_smoke_afl.sh TARGET" >&2
      exit 64
    fi
    exec "$0" generate-target
    ;;
  *) echo "unknown mode: $mode" >&2; exit 64 ;;
esac
