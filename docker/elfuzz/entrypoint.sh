#!/usr/bin/env bash
set -euo pipefail

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
mode="${1:-smoke-jsoncpp}"
mkdir -p "$workspace/logs" "$workspace/artifacts"
json_escape() { local v="${1:-}"; v="${v//\\/\\\\}"; v="${v//\"/\\\"}"; v="${v//$'\n'/\\n}"; printf '%s' "$v"; }
count_files() { local d="$1"; shift || true; [[ -d "$d" ]] || { printf '0'; return 0; }; find "$d" "$@" 2>/dev/null | wc -l | tr -d ' '; }

find_elfuzz_project_root() {
  local candidate
  for candidate in "${ELFUZZ_PROJECT_ROOT:-}" /home/appuser/elmfuzz /elfuzz /opt/hgb/artifacts/elfuzz; do
    [[ -n "$candidate" && -f "$candidate/cli/main.py" ]] || continue
    printf '%s\n' "$candidate"
    return 0
  done
  return 1
}
ELFUZZ_PROJECT_ROOT="$(find_elfuzz_project_root || true)"
export ELFUZZ_PROJECT_ROOT

patch_elfuzz_trace() {
  local py="$ELFUZZ_PROJECT_ROOT/genvariants_parallel.py"
  [[ -f "$py" ]] || return 0
  python3 - "$py" <<'PY_ELFUZZ_TRACE_PATCH'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
if "import hgb_llm_trace" not in text:
    if "import requests\n" in text:
        text = text.replace(
            "import requests\n",
            "import requests\nimport sys\nsys.path.insert(0, \"/opt/hgb/bin\")\ntry:\n    import hgb_llm_trace\nexcept Exception as exc:\n    hgb_llm_trace = None\n    print(f\"HGB_LLM_TRACE: ELFuzz tracing unavailable: {exc}\", file=sys.stderr)\n",
            1,
        )
old = "    return requests.post(f'{ENDPOINT}/generate', json=data).json()"
new = """    request = {'url': f'{ENDPOINT}/generate', 'json': data}
    if hgb_llm_trace is not None:
        return hgb_llm_trace.trace_call(
            lambda: requests.post(request['url'], json=data).json(),
            stage='elfuzz',
            provider='tgi',
            operation='generate',
            model=os.environ.get('ELFUZZ_MODEL', os.environ.get('MODEL', '')),
            request=request,
        )
    return requests.post(request['url'], json=data).json()"""
if old in text and "stage='elfuzz'" not in text:
    text = text.replace(old, new, 1)
path.write_text(text)
PY_ELFUZZ_TRACE_PATCH
}

patch_elfuzz_cleanup() {
  local py="$ELFUZZ_PROJECT_ROOT/cli/pre_experiments.py"
  [[ -f "$py" ]] || return 0
  python3 - "$py" <<'PY_ELFUZZ_CLEANUP_PATCH'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = '        subprocess.run(["sudo", "docker", "stop", "tgi-server"], check=True, cwd=PROJECT_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)'
new = '        try:\n            subprocess.run(["sudo", "docker", "stop", "tgi-server"], check=False, cwd=PROJECT_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n        except Exception as exc:\n            print(f"[HGB] ignoring tgi-server cleanup failure: {exc}")'
if old in text and "ignoring tgi-server cleanup failure" not in text:
    path.write_text(text.replace(old, new, 1))
PY_ELFUZZ_CLEANUP_PATCH
}

patch_elfuzz_sibling_paths() {
  local getcov="$ELFUZZ_PROJECT_ROOT/getcov_fuzzbench.py"
  [[ -f "$getcov" ]] || return 0
  python3 - "$getcov" "$ELFUZZ_PROJECT_ROOT/start_tgi_servers.sh" "$ELFUZZ_PROJECT_ROOT/start_tgi_servers_debug.sh" <<'PY_ELFUZZ_SIBLING_PATH_PATCH'
from pathlib import Path
import sys

getcov = Path(sys.argv[1])
text = getcov.read_text()
old = "        prefix = '/tmp/host/fuzzdata/'"
new = "        prefix = os.environ.get('ELFUZZ_HOST_SHARED_DIR', '/tmp/host/fuzzdata/')"
if old in text:
    getcov.write_text(text.replace(old, new, 1))

for raw_path in sys.argv[2:]:
    path = Path(raw_path)
    if not path.is_file():
        continue
    text = path.read_text()
    old = "volume=./tmp/fastdata/hfcache/transformers/"
    new = "volume=${ELFUZZ_TGI_CACHE_DIR:-./tmp/fastdata/hfcache/transformers/}\\nmkdir -p \"$volume\""
    if old in text:
        path.write_text(text.replace(old, new, 1))
PY_ELFUZZ_SIBLING_PATH_PATCH
}

if [[ "$mode" == "generate-target" ]]; then
  # shellcheck source=/opt/hgb/bin/target_contract.sh
  source /opt/hgb/bin/target_contract.sh
  export HGB_GENERATOR="${HGB_GENERATOR:-elfuzz}"
  export HGB_GENERATOR_ARTIFACT_DIR="/opt/hgb/artifacts/elfuzz"
  export HGB_CAPABILITY=input_generator
  export HGB_TASK_FAMILY=input_generator
  export HGB_BASELINE_PROFILE="${HGB_BASELINE_PROFILE:-alpha}"
  export HGB_BASELINE_PROTOCOL="${HGB_BASELINE_PROTOCOL:-paper-native}"
  export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
  export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
  export OPENAI_MODEL="${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
  export HGB_LLM_REQUEST_TIMEOUT_SECONDS="${HGB_LLM_REQUEST_TIMEOUT_SECONDS:-1200}"
  export ELFUZZ_LLM_REQUEST_TIMEOUT_SECONDS="${ELFUZZ_LLM_REQUEST_TIMEOUT_SECONDS:-$HGB_LLM_REQUEST_TIMEOUT_SECONDS}"
  mkdir -p "$workspace/logs"
  hgb_require_target_package
  target_name="${HGB_TARGET:-$(hgb_target_manifest_value target)}"
  patch_elfuzz_cleanup
  patch_elfuzz_trace
  patch_elfuzz_sibling_paths
  python=/opt/hgb/venv/bin/python
  if [[ ! -x "$python" ]]; then
    python="$(command -v python3)"
  fi
  dry_run_arg=()
  if [[ "${HGB_DRY_RUN:-0}" == "1" ]]; then
    dry_run_arg=(--dry-run)
  fi
  exec "$python" /opt/hgb/bin/elfuzz_target_pipeline.py full \
    --workspace "$workspace" \
    --target "$target_name" \
    --target-package "${HGB_TARGET_PACKAGE:-/target}" \
    --artifact-dir /opt/hgb/artifacts/elfuzz \
    --metadata-root /opt/hgb/metadata \
    --profile "$HGB_BASELINE_PROFILE" \
    --protocol "$HGB_BASELINE_PROTOCOL" \
    "${dry_run_arg[@]}"
fi

# Legacy smoke mode (compatibility only; not the alpha matrix path).
stage_exit() { [[ -f "$workspace/logs/$1.exit" ]] && cat "$workspace/logs/$1.exit" || printf not_run; }
run_stage() {
  local stage="$1"; shift
  local code=0
  printf '%q ' "$@" >"$workspace/logs/$stage.cmd"; printf '\n' >>"$workspace/logs/$stage.cmd"
  timeout "${ELFUZZ_STAGE_TIMEOUT_SECONDS:-900}" "$@" >"$workspace/logs/$stage.log" 2>&1 || code=$?
  printf '%s\n' "$code" >"$workspace/logs/$stage.exit"
  return 0
}
smoke_metadata() {
  local status="$1" reason="$2"
  {
    printf '{\n'
    printf '  "fuzzer": "elfuzz",\n'
    printf '  "task_family": "input_generator",\n'
    printf '  "status": "%s",\n' "$(json_escape "$status")"
    printf '  "target": "%s",\n' "$(json_escape "${ELFUZZ_TARGET:-jsoncpp}")"
    printf '  "setup": "%s",\n' "$(json_escape "$(stage_exit setup)")"
    printf '  "synth": "%s",\n' "$(json_escape "$(stage_exit synth)")"
    printf '  "produce": "%s",\n' "$(json_escape "$(stage_exit produce)")"
    printf '  "afl": "%s",\n' "$(json_escape "$(stage_exit afl)")"
    printf '  "reason": "%s",\n' "$(json_escape "$reason")"
    printf '  "log_dir": "%s"\n' "$(json_escape "$workspace/logs")"
    printf '}\n'
  } >"$workspace/metadata.json"
  {
    printf '# HarnessGenBench ELFuzz Summary\n\n'
    printf -- '- Run directory: `%s`\n' "$workspace"
    printf -- '- Target: `%s`\n' "${ELFUZZ_TARGET:-jsoncpp}"
    printf -- '- Status: `%s`\n' "$status"
    printf -- '- Top failure reason: %s\n' "$reason"
  } >"$workspace/HGB_SUMMARY.md"
}

[[ "$mode" == "smoke-jsoncpp" || "$mode" == "smoke" ]] || { echo "unknown mode: $mode" >&2; exit 64; }
target="${ELFUZZ_TARGET:-jsoncpp}"
printf 'elfuzz smoke-jsoncpp target=%s\n' "$target" >"$workspace/command.txt"
if ! command -v elfuzz >/dev/null 2>&1; then
  printf 'elfuzz CLI not found in image.\n' >"$workspace/logs/help.txt"
  smoke_metadata missing_cli 'elfuzz CLI not found in image'
  exit 127
fi
elfuzz --help >"$workspace/logs/help.txt" 2>&1 || true
if [[ "${ELFUZZ_HELP_ONLY:-0}" == "1" ]]; then
  smoke_metadata help_only none
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
patch_elfuzz_trace
run_stage synth elfuzz synth -T fuzzer.elfuzz --use-small-model --tgi-waiting "${ELFUZZ_TGI_WAITING_SECONDS:-120}" --evolution-iterations "${ELFUZZ_EVOLUTION_ITERATIONS:-1}" "$target"
run_stage produce elfuzz produce -T elfuzz --time "${ELFUZZ_PRODUCE_SECONDS:-60}" "$target"
run_stage afl elfuzz run rq1.afl --fuzzers elfuzz --repeat 1 --time "${ELFUZZ_AFL_SECONDS:-300}" "$target"
status=completed; reason=none
for s in setup synth produce afl; do
  c="$(stage_exit "$s")"
  if [[ "$c" != "0" ]]; then status=failed; reason="stage $s exited $c"; break; fi
done
smoke_metadata "$status" "$reason"
[[ "$status" == completed ]]
