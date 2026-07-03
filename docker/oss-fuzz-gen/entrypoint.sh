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
json_file_value() {
  local file="$1" key="$2"
  "$python" - "$file" "$key" <<'PY_JSON_VALUE'
import json
import sys
try:
    with open(sys.argv[1], encoding='utf-8') as f:
        value = json.load(f).get(sys.argv[2], '')
except (OSError, json.JSONDecodeError):
    value = ''
if isinstance(value, (dict, list)):
    print(json.dumps(value))
else:
    print(value)
PY_JSON_VALUE
}
commit() { git -C "$artifact" rev-parse HEAD 2>/dev/null || printf unknown; }
oss_fuzz_checkout_ready() {
  local dir="$1"
  [[ -d "$dir/.git" && -f "$dir/infra/helper.py" ]]
}
materialize_oss_fuzz_checkout() {
  local source_dir="${OFG_OSS_FUZZ_DIR:-/opt/hgb/oss-fuzz}"
  local run_dir="${OFG_OSS_FUZZ_RUN_DIR:-$workspace/oss-fuzz}"
  rm -rf "$run_dir"
  mkdir -p "$(dirname "$run_dir")"
  if oss_fuzz_checkout_ready "$source_dir"; then
    rsync -a --delete "$source_dir/" "$run_dir/"
  elif [[ "${OFG_ALLOW_RUNTIME_CLONE:-0}" == "1" ]]; then
    git clone --depth 1 "${OFG_OSS_FUZZ_REPO:-https://github.com/google/oss-fuzz.git}" "$run_dir" >"$workspace/logs/oss_fuzz_checkout.log" 2>&1 || true
  fi
  oss_fuzz_checkout_ready "$run_dir" || return 1
  printf '%s' "$run_dir"
}
prepare_oss_fuzz_venv() {
  local oss_fuzz_dir="$1"
  local venv_target="${OFG_OSS_FUZZ_VENV:-/opt/hgb/venv}"
  if [[ -x "$venv_target/bin/python3" || -x "$venv_target/bin/python" ]]; then
    rm -rf "$oss_fuzz_dir/venv"
    ln -s "$venv_target" "$oss_fuzz_dir/venv"
    return 0
  fi
  printf 'ofg_oss_fuzz_dependency_setup_failed: missing OSS-Fuzz helper venv at %s
' "$venv_target" >&2
  return 1
}
ofg_llm_preflight() {
  local log_file="$1"
  [[ "${OFG_LLM_PREFLIGHT:-1}" == "1" ]] || return 0
  "$python" - >"$log_file" 2>&1 <<'PY_OFG_PREFLIGHT'
import os
import sys
import openai

api_key = os.getenv('OPENAI_API_KEY') or os.getenv('API_KEY') or os.getenv('DEEPSEEK_API_KEY')
model = os.getenv('OPENAI_MODEL') or os.getenv('MODEL') or 'gpt-4o-mini'
kwargs = {'api_key': api_key, 'timeout': float(os.getenv('OFG_LLM_REQUEST_TIMEOUT_SECONDS', '600'))}
base_url = os.getenv('OPENAI_BASE_URL') or os.getenv('BASE_URL')
if base_url:
    kwargs['base_url'] = base_url
max_retries = os.getenv('OFG_LLM_MAX_RETRIES', '0')
try:
    kwargs['max_retries'] = int(max_retries)
except ValueError:
    print(f'Invalid OFG_LLM_MAX_RETRIES: {max_retries}')
    sys.exit(1)
try:
    client = openai.OpenAI(**kwargs)
    client.chat.completions.create(
        model=model,
        messages=[{'role': 'user', 'content': 'Return OK.'}],
        max_tokens=1,
        temperature=0,
    )
except Exception as exc:
    print(f'{type(exc).__name__}: {exc}')
    sys.exit(1)
print('llm_preflight_ok')
PY_OFG_PREFLIGHT
}
classify_ofg_failure() {
  local code="$1" log_file="$2"
  if [[ -f "$log_file" ]]; then
    if grep -Eiq 'ModuleNotFoundError: No module named .pkg_resources.|No module named .pkg_resources.|pkg_resources' "$log_file"; then
      printf 'ofg_oss_fuzz_dependency_setup_failed: OSS-Fuzz-Gen Python environment is missing pkg_resources'
      return 0
    fi
    if grep -Eiq 'ofg_benchmark_trim_failed|ModuleNotFoundError: No module named .yaml.|benchmark trim failed' "$log_file"; then
      printf 'ofg_benchmark_trim_failed: OSS-Fuzz-Gen benchmark YAML trimming failed'
      return 0
    fi
    if grep -Eiq 'AuthenticationError|Authentication Fails|401 Authorization Required|HTTP/1\.1 401|Error code: 401|PermissionDeniedError|Error code: 403|invalid api key' "$log_file"; then
      printf 'ofg_invalid_api_key: OpenAI-compatible API key was rejected'
      return 0
    fi
    if grep -Eiq 'ofg_empty_llm_response|LLM returned empty response|NoneType.*split|expected non-empty LLM response' "$log_file"; then
      printf 'ofg_empty_llm_response: OpenAI-compatible endpoint returned empty response content'
      return 0
    fi
    if grep -Eiq 'TLS handshake timeout|net/http: TLS handshake timeout|docker pull.*timed out|Client\.Timeout exceeded|context deadline exceeded' "$log_file"; then
      printf 'ofg_docker_pull_timeout: Docker image pull timed out while preparing the OSS-Fuzz project image'
      return 0
    fi
    if grep -Eiq 'ofg_project_image_build_failed|Failed to build image for|Failed to build project image' "$log_file"; then
      printf 'ofg_project_image_build_failed: OSS-Fuzz project image build failed during harness validation'
      return 0
    fi
    if [[ "$code" == "124" ]] && grep -Eiq '===== ROUND .* Recompile|Recompile|fixing build' "$log_file"; then
      printf 'ofg_recompile_timeout: OSS-Fuzz-Gen timed out while recompiling or repairing the generated harness'
      return 0
    fi
    if grep -Eiq 'APITimeoutError|ReadTimeout|The read operation timed out|Request timed out|timed out while requesting|LLM request timeout' "$log_file"; then
      printf 'ofg_llm_request_timeout: OpenAI-compatible LLM request timed out'
      return 0
    fi
    if grep -Eiq 'Invalid n value' "$log_file"; then
      printf 'deepseek_invalid_n: DeepSeek rejected the OpenAI n parameter'
      return 0
    fi
    if grep -Eiq 'invalid_request_error' "$log_file"; then
      printf 'ofg_nonretryable_llm_request: OpenAI-compatible endpoint rejected the request'
      return 0
    fi
    if grep -Eiq 'Bad model type' "$log_file"; then
      printf 'OSS-Fuzz-Gen unsupported model type'
      return 0
    fi
    if grep -Eiq 'docker\.sock: connect: no such file or directory|Cannot connect to the Docker daemon|failed to connect to the docker API' "$log_file"; then
      printf 'ofg_docker_unavailable: Docker socket is unavailable and source fallback did not satisfy OSS-Fuzz-Gen'
      return 0
    fi
    if grep -Eiq 'permission denied|read-only file system|cannot create' "$log_file"; then
      printf 'OSS-Fuzz-Gen workspace write/setup failed'
      return 0
    fi
    if grep -Eiq 'ofg_oss_fuzz_dependency_setup_failed|pip install|requirements\.txt|subprocess\.CalledProcessError.*pip|No matching distribution|Failed building wheel|error: subprocess-exited-with-error' "$log_file"; then
      printf 'ofg_oss_fuzz_dependency_setup_failed: OSS-Fuzz helper dependency setup failed'
      return 0
    fi
    if grep -Eiq 'docker.*not found' "$log_file"; then
      printf 'ofg_docker_unavailable: Docker command is unavailable and source fallback did not satisfy OSS-Fuzz-Gen'
      return 0
    fi
    if grep -Eiq 'missing_oss_fuzz_checkout|OSS-Fuzz checkout is unavailable|no valid OSS-Fuzz checkout|No such file or directory.*infra/helper\.py|FileNotFoundError.*infra/helper\.py' "$log_file"; then
      printf 'missing_oss_fuzz_checkout: OSS-Fuzz checkout is unavailable or invalid; rebuild the image with OFG_INSTALL_OSS_FUZZ=1 or set OFG_OSS_FUZZ_DIR'
      return 0
    fi
    if grep -Eiq 'Querying FuzzIntrospector API' "$log_file" && [[ "$code" == "124" ]]; then
      printf 'ofg_introspector_timeout: OSS-Fuzz-Gen timed out while querying Fuzz Introspector'
      return 0
    fi
    if grep -Eiq 'one_prompt_prototyper|chat.completions|LLM API Error' "$log_file" && [[ "$code" == "124" ]]; then
      printf 'ofg_llm_request_timeout: OpenAI-compatible LLM request timed out or exceeded row budget'
      return 0
    fi
    if grep -Eiq 'Exception while running experiment|Traceback' "$log_file"; then
      printf 'OSS-Fuzz-Gen experiment exception before harness generation'
      return 0
    fi
  fi
  if [[ "$code" == "124" ]]; then
    printf 'OSS-Fuzz-Gen timed out'
    return 0
  fi
  printf 'run_all_experiments exited %s' "$code"
}
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


if [[ "$mode" == "generate-target" ]]; then
  # shellcheck source=/opt/hgb/bin/target_contract.sh
  source /opt/hgb/bin/target_contract.sh
  export HGB_GENERATOR="${HGB_GENERATOR:-oss-fuzz-gen}"
  export HGB_GENERATOR_ARTIFACT_DIR="$artifact"
  export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
  export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
  export OPENAI_MODEL="${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
  export OFG_SKIP_COVERAGE_GAINS="${OFG_SKIP_COVERAGE_GAINS:-1}"
  export OFG_NUM_SAMPLES="${OFG_NUM_SAMPLES:-1}"
  export OFG_NUM_EXP="${OFG_NUM_EXP:-1}"
  export OFG_NUM_EVA="${OFG_NUM_EVA:-1}"
  export OFG_INTROSPECTOR_MODE="${OFG_INTROSPECTOR_MODE:-local}"
  export OFG_REQUIRE_BENCHMARK_TRIM="${OFG_REQUIRE_BENCHMARK_TRIM:-1}"
  export OFG_LLM_PREFLIGHT="${OFG_LLM_PREFLIGHT:-1}"
  export OFG_LLM_REQUEST_TIMEOUT_SECONDS="${OFG_LLM_REQUEST_TIMEOUT_SECONDS:-600}"
  export OFG_LLM_MAX_RETRIES="${OFG_LLM_MAX_RETRIES:-0}"
  export LLM_NUM_EXP="${LLM_NUM_EXP:-$OFG_NUM_EXP}"
  export LLM_NUM_EVA="${LLM_NUM_EVA:-$OFG_NUM_EVA}"
  mkdir -p "$workspace/logs" "$workspace/generated_harnesses"
  hgb_require_target_package
  project="${HGB_TARGET_PROJECT:-$(hgb_target_manifest_value project)}"
  fuzz_target="${HGB_TARGET_FUZZ_TARGET:-$(hgb_target_manifest_value fuzz_target)}"
  target_name="${HGB_TARGET:-$(hgb_target_manifest_value target)}"

  synthesize_benchmark_yaml() {
    local out_yaml="$1"
    local api_json="$workspace/ofg_api_candidates.json"
    local api_count
    api_count="$(python3 /opt/hgb/bin/extract_api_list.py --details --source /target/source_input --out "$api_json" --max "${OFG_SYNTH_MAX_APIS:-5}" 2>"$workspace/logs/ofg_api_extract.log" || printf '0')"
    api_count="${api_count##*$'\n'}"
    if [[ "${api_count:-0}" == "0" ]]; then
      return 1
    fi
    python3 - "$api_json" "$out_yaml" "$project" "$fuzz_target" "$target_name" <<'PY_OFG_YAML'
import json
import sys
from pathlib import Path
api_json, out_yaml, project, fuzz_target, target_name = sys.argv[1:]
max_functions = int(__import__('os').environ.get('OFG_MAX_BENCHMARK_FUNCTIONS', '1'))
records = json.loads(Path(api_json).read_text(encoding='utf-8'))[:max(1, max_functions)]
source = Path('/target/source_input')
cpp_exts = {'.cc', '.cpp', '.cxx', '.hpp', '.hh', '.hxx'}
c_exts = {'.c', '.h'}
cpp_count = sum(1 for p in source.rglob('*') if p.suffix.lower() in cpp_exts)
c_count = sum(1 for p in source.rglob('*') if p.suffix.lower() in c_exts)
language = 'c++' if cpp_count >= c_count else 'c'
ref = None
ref_root = Path('/target/reference_harnesses')
if ref_root.exists():
    for candidate in sorted(ref_root.rglob('*')):
        if candidate.is_file() and candidate.suffix.lower() in {'.c', '.cc', '.cpp', '.cxx'}:
            ref = candidate
            break
target_path = str(ref) if ref else f'/src/{project}/{fuzz_target or target_name}.cc'
functions = []
for record in records:
    name = record.get('name')
    signature = record.get('signature') or f"{record.get('return_type', 'int')} {name}()"
    if not name or name in {'void', 'main'}:
        continue
    functions.append({
        'name': name,
        'params': record.get('params') or [],
        'return_type': record.get('return_type') or 'int',
        'signature': signature,
    })
if not functions:
    raise SystemExit(1)
with open(out_yaml, 'w', encoding='utf-8') as f:
    json.dump({
        'functions': functions,
        'language': language,
        'project': project,
        'target_name': fuzz_target or target_name,
        'target_path': target_path,
    }, f, indent=2)
    f.write('\n')
PY_OFG_YAML
  }

  if [[ "${HGB_DRY_RUN:-0}" == "1" ]]; then
    printf 'oss-fuzz-gen generate-target dry-run for %s\n' "$target_name" >"$workspace/command.txt"
    hgb_write_common_metadata dry_run_ok 'dry run validated target package' 0 harness_generator
    hgb_write_common_summary dry_run_ok 'dry run validated target package' harness_generator
    exit 0
  fi

  if ! hgb_api_key_present; then
    printf 'OPENAI_API_KEY is not set; OSS-Fuzz-Gen target generation skipped.\n' >"$workspace/logs/run.log"
    hgb_write_common_metadata missing_api_key 'OPENAI_API_KEY is not set' 2 harness_generator
    hgb_write_common_summary missing_api_key 'OPENAI_API_KEY is not set' harness_generator
    exit 2
  fi

  benchmark_yaml="${OFG_BENCHMARK_YAML:-}"
  benchmark_original_function_count=0
  benchmark_trimmed_function_count=0
  benchmark_original_test_file_count=0
  benchmark_trimmed_test_file_count=0
  benchmark_match_kind="none"
  selected_yaml_project=""
  selected_yaml_target_name=""
  benchmark_candidate_count=0
  if [[ -n "$benchmark_yaml" ]]; then
    if [[ ! -f "$benchmark_yaml" ]]; then
      printf 'Provided OFG_BENCHMARK_YAML does not exist: %s\n' "$benchmark_yaml" >"$workspace/logs/benchmark_yaml.log"
      extra=$(printf '  "benchmark_yaml": "%s",\n  "benchmark_match_kind": "explicit_missing",\n  "offline_coverage_mode": "%s"' "$(hgb_json_escape "$benchmark_yaml")" "$(hgb_json_escape "$OFG_SKIP_COVERAGE_GAINS")")
      hgb_write_common_metadata failed 'Provided OFG_BENCHMARK_YAML does not exist' 66 harness_generator "$extra"
      hgb_write_common_summary failed 'Provided OFG_BENCHMARK_YAML does not exist' harness_generator
      exit 66
    fi
    benchmark_match_kind="explicit_override"
  elif [[ -d "$artifact/benchmark-sets" ]]; then
    selection_json="$workspace/ofg_benchmark_selection.json"
    selector_args=(--benchmark-sets-dir "$artifact/benchmark-sets" --project "$project" --fuzz-target "$fuzz_target" --target-name "$target_name" --out "$selection_json")
    if [[ "${OFG_ALLOW_PROJECT_YAML_FALLBACK:-0}" == "1" ]]; then
      selector_args+=(--allow-project-fallback)
    fi
    if python3 /opt/hgb/bin/ofg_select_benchmark.py "${selector_args[@]}" >"$workspace/logs/benchmark_yaml.log" 2>&1; then
      benchmark_yaml="$(json_file_value "$selection_json" path)"
    fi
    if [[ -f "$selection_json" ]]; then
      benchmark_match_kind="$(json_file_value "$selection_json" benchmark_match_kind)"
      selected_yaml_project="$(json_file_value "$selection_json" selected_yaml_project)"
      selected_yaml_target_name="$(json_file_value "$selection_json" selected_yaml_target_name)"
      benchmark_candidate_count="$(json_file_value "$selection_json" candidate_count)"
      benchmark_candidate_count="${benchmark_candidate_count:-0}"
    fi
  fi
  if [[ -z "$benchmark_yaml" ]]; then
    generated_yaml="$workspace/ofg_benchmark.yaml"
    if synthesize_benchmark_yaml "$generated_yaml"; then
      benchmark_yaml="$generated_yaml"
      benchmark_match_kind="synthesized"
      selected_yaml_project="$project"
      selected_yaml_target_name="${fuzz_target:-$target_name}"
      printf 'Generated OSS-Fuzz-Gen benchmark YAML for project=%s target=%s: %s\n' "$project" "$target_name" "$benchmark_yaml" >"$workspace/logs/benchmark_yaml.log"
    else
      printf 'No compatible OSS-Fuzz-Gen benchmark YAML found for project=%s target=%s, and no API candidates could be extracted.\n' "$project" "$target_name" >"$workspace/logs/benchmark_yaml.log"
      hgb_soft_skip no_api_candidates 'OSS-Fuzz-Gen could not find or synthesize a benchmark YAML because no API candidates were extracted' harness_generator
    fi
  fi

  if [[ -n "$benchmark_yaml" && "${OFG_MAX_BENCHMARK_FUNCTIONS:-1}" != "0" ]]; then
    trimmed_yaml="$workspace/ofg_benchmark.trimmed.yaml"
    trim_metadata="$workspace/ofg_benchmark_trim.json"
    if "$python" /opt/hgb/bin/ofg_trim_benchmark.py --in "$benchmark_yaml" --out "$trimmed_yaml" --max-functions "${OFG_MAX_BENCHMARK_FUNCTIONS:-1}" --metadata "$trim_metadata" >>"$workspace/logs/benchmark_yaml.log" 2>&1; then
      benchmark_yaml="$trimmed_yaml"
      benchmark_original_function_count="$(json_file_value "$trim_metadata" original_function_count)"
      benchmark_trimmed_function_count="$(json_file_value "$trim_metadata" trimmed_function_count)"
      benchmark_original_test_file_count="$(json_file_value "$trim_metadata" original_test_file_count)"
      benchmark_trimmed_test_file_count="$(json_file_value "$trim_metadata" trimmed_test_file_count)"
    elif [[ "${OFG_REQUIRE_BENCHMARK_TRIM:-1}" == "1" ]]; then
      printf 'ofg_benchmark_trim_failed: failed to trim %s
' "$benchmark_yaml" >>"$workspace/logs/benchmark_yaml.log"
      extra=$(printf '  "benchmark_yaml": "%s",
  "benchmark_match_kind": "%s",
  "benchmark_trim_log": "%s"' "$(hgb_json_escape "$benchmark_yaml")" "$(hgb_json_escape "$benchmark_match_kind")" "$(hgb_json_escape "$workspace/logs/benchmark_yaml.log")")
      hgb_write_common_metadata failed 'ofg_benchmark_trim_failed: OSS-Fuzz-Gen benchmark YAML trimming failed' 65 harness_generator "$extra"
      hgb_write_common_summary failed 'ofg_benchmark_trim_failed: OSS-Fuzz-Gen benchmark YAML trimming failed' harness_generator
      exit 65
    fi
  fi

  oss_fuzz_dir=""
  if ! oss_fuzz_dir="$(materialize_oss_fuzz_checkout)"; then
    printf 'missing_oss_fuzz_checkout: no valid OSS-Fuzz checkout at OFG_OSS_FUZZ_DIR=%s and runtime clone is disabled or failed.
' "${OFG_OSS_FUZZ_DIR:-/opt/hgb/oss-fuzz}" >"$workspace/logs/oss_fuzz_checkout.log"
    hgb_write_common_metadata missing_oss_fuzz_checkout 'missing_oss_fuzz_checkout: OSS-Fuzz checkout is unavailable or invalid; rebuild the image with OFG_INSTALL_OSS_FUZZ=1 or set OFG_OSS_FUZZ_DIR' 2 harness_generator
    hgb_write_common_summary missing_oss_fuzz_checkout 'missing_oss_fuzz_checkout: OSS-Fuzz checkout is unavailable or invalid; rebuild the image with OFG_INSTALL_OSS_FUZZ=1 or set OFG_OSS_FUZZ_DIR' harness_generator
    exit 2
  fi
  if ! prepare_oss_fuzz_venv "$oss_fuzz_dir" >"$workspace/logs/oss_fuzz_venv.log" 2>&1; then
    hgb_write_common_metadata failed 'ofg_oss_fuzz_dependency_setup_failed: missing OSS-Fuzz helper venv' 65 harness_generator
    hgb_write_common_summary failed 'ofg_oss_fuzz_dependency_setup_failed: missing OSS-Fuzz helper venv' harness_generator
    exit 65
  fi
  if ! ofg_llm_preflight "$workspace/logs/llm_preflight.log"; then
    reason="$(classify_ofg_failure 1 "$workspace/logs/llm_preflight.log")"
    hgb_write_common_metadata failed "$reason" 65 harness_generator
    hgb_write_common_summary failed "$reason" harness_generator
    exit 65
  fi
  mkdir -p "$workspace/pip-cache"
  cmd=("$python" /opt/hgb/bin/ofg_run_wrapper.py --artifact "$artifact" -- --model "$OPENAI_MODEL" -y "$benchmark_yaml" --oss-fuzz-dir "$oss_fuzz_dir" --run-timeout "${OFG_RUN_TIMEOUT:-300}" --num-samples "${OFG_NUM_SAMPLES:-1}" --work-dir "$workspace/ofg-work")
  printf '%q ' "${cmd[@]}" >"$workspace/command.txt"; printf '\n' >>"$workspace/command.txt"
  code=0
  (cd "$artifact" && PIP_CACHE_DIR="$workspace/pip-cache" timeout "${HGB_GENERATION_TIMEOUT_SECONDS:-10800}" "${cmd[@]}") >"$workspace/logs/run.log" 2>&1 || code=$?
  if [[ -d "$workspace/ofg-work" ]]; then
    n=0
    while IFS= read -r generated; do
      n=$((n + 1))
      cp "$generated" "$workspace/generated_harnesses/${n}_$(basename "$generated")" 2>/dev/null || true
    done < <(find "$workspace/ofg-work" -type f \( -path '*/fixed_targets/*' -o -path '*/raw_targets/*' \) \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' \) 2>/dev/null | sort)
  fi
  if [[ "${HGB_SAVE_MODE:-compact}" == "compact" ]]; then
    rm -rf "$workspace/ofg-work" "$workspace/pip-cache" "$workspace/oss-fuzz"
  fi
  status=completed
  reason=none
  if [[ "$code" -ne 0 ]]; then
    status=failed
    reason="$(classify_ofg_failure "$code" "$workspace/logs/run.log")"
  elif [[ "$(hgb_count_files "$workspace/generated_harnesses" -type f)" == "0" ]] && grep -Eiq 'Bad model type|Exception while running experiment|Traceback' "$workspace/logs/run.log"; then
    code=1
    status=failed
    reason="$(classify_ofg_failure "$code" "$workspace/logs/run.log")"
  fi
  if [[ "$status" == "failed" && "$benchmark_match_kind" == "exact_project" && -n "$selected_yaml_target_name" && "$selected_yaml_target_name" != "$fuzz_target" && "$selected_yaml_target_name" != "$target_name" ]]; then
    case "$reason" in
      'OSS-Fuzz-Gen timed out'|'OSS-Fuzz-Gen experiment exception before harness generation')
        reason="ofg_bad_benchmark_fallback: selected project-level YAML target $selected_yaml_target_name for requested target ${fuzz_target:-$target_name}"
        ;;
    esac
  fi
  target_source_status="$(hgb_target_manifest_value source_status)"
  target_source_file_count="$(hgb_target_manifest_value source_file_count)"
  target_source_file_count="${target_source_file_count:-0}"
  target_source_fallback_statuses="$(hgb_target_manifest_value source_fallback_statuses)"
  target_source_fallback_statuses="${target_source_fallback_statuses:-[]}"
  extra=$(printf '  "benchmark_yaml": "%s",
  "benchmark_match_kind": "%s",
  "selected_yaml_project": "%s",
  "selected_yaml_target_name": "%s",
  "benchmark_candidate_count": %s,
  "benchmark_original_function_count": %s,
  "benchmark_trimmed_function_count": %s,
  "benchmark_original_test_file_count": %s,
  "benchmark_trimmed_test_file_count": %s,
  "offline_coverage_mode": "%s",
  "introspector_mode": "%s",
  "ofg_num_samples": %s,
  "ofg_num_exp": %s,
  "ofg_num_eva": %s,
  "target_source_status": "%s",
  "target_source_file_count": %s,
  "target_source_fallback_statuses": %s,
  "command_file": "%s",
  "log_file": "%s",
  "oss_fuzz_dir": "%s",
  "pip_cache_dir": "%s"' "$(hgb_json_escape "$benchmark_yaml")" "$(hgb_json_escape "$benchmark_match_kind")" "$(hgb_json_escape "$selected_yaml_project")" "$(hgb_json_escape "$selected_yaml_target_name")" "$benchmark_candidate_count" "${benchmark_original_function_count:-0}" "${benchmark_trimmed_function_count:-0}" "${benchmark_original_test_file_count:-0}" "${benchmark_trimmed_test_file_count:-0}" "$(hgb_json_escape "$OFG_SKIP_COVERAGE_GAINS")" "$(hgb_json_escape "$OFG_INTROSPECTOR_MODE")" "${OFG_NUM_SAMPLES:-1}" "${OFG_NUM_EXP:-1}" "${OFG_NUM_EVA:-1}" "$(hgb_json_escape "$target_source_status")" "$target_source_file_count" "$target_source_fallback_statuses" "$(hgb_json_escape "$workspace/command.txt")" "$(hgb_json_escape "$workspace/logs/run.log")" "$(hgb_json_escape "$oss_fuzz_dir")" "$(hgb_json_escape "$workspace/pip-cache")")
  hgb_write_common_metadata "$status" "$reason" "$code" harness_generator "$extra"
  hgb_write_common_summary "$status" "$reason" harness_generator
  exit "$code"
fi
[[ "$mode" == "smoke" ]] || { echo "unknown mode: $mode" >&2; exit 64; }
export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
export OPENAI_MODEL="${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
export OFG_SKIP_COVERAGE_GAINS="${OFG_SKIP_COVERAGE_GAINS:-1}"
export OFG_NUM_SAMPLES="${OFG_NUM_SAMPLES:-1}"
export OFG_NUM_EXP="${OFG_NUM_EXP:-1}"
export OFG_NUM_EVA="${OFG_NUM_EVA:-1}"
export OFG_INTROSPECTOR_MODE="${OFG_INTROSPECTOR_MODE:-local}"
export OFG_REQUIRE_BENCHMARK_TRIM="${OFG_REQUIRE_BENCHMARK_TRIM:-1}"
export OFG_LLM_PREFLIGHT="${OFG_LLM_PREFLIGHT:-1}"
export OFG_LLM_REQUEST_TIMEOUT_SECONDS="${OFG_LLM_REQUEST_TIMEOUT_SECONDS:-600}"
export OFG_LLM_MAX_RETRIES="${OFG_LLM_MAX_RETRIES:-0}"
export LLM_NUM_EXP="${LLM_NUM_EXP:-$OFG_NUM_EXP}"
export LLM_NUM_EVA="${LLM_NUM_EVA:-$OFG_NUM_EVA}"
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
oss_fuzz_dir=""
if ! oss_fuzz_dir="$(materialize_oss_fuzz_checkout)"; then
  printf 'missing_oss_fuzz_checkout: no valid OSS-Fuzz checkout at OFG_OSS_FUZZ_DIR=%s and runtime clone is disabled or failed.
' "${OFG_OSS_FUZZ_DIR:-/opt/hgb/oss-fuzz}" >"$run_log"
  printf 'prepare oss-fuzz checkout
' >"$command_file"
  metadata missing_oss_fuzz_checkout 2 'missing_oss_fuzz_checkout: OSS-Fuzz checkout is unavailable or invalid; rebuild the image with OFG_INSTALL_OSS_FUZZ=1 or set OFG_OSS_FUZZ_DIR' "$command_file" "$run_log" "$benchmark_yaml"
  summary missing_oss_fuzz_checkout 2 'missing_oss_fuzz_checkout: OSS-Fuzz checkout is unavailable or invalid; rebuild the image with OFG_INSTALL_OSS_FUZZ=1 or set OFG_OSS_FUZZ_DIR'
  exit 2
fi
if ! prepare_oss_fuzz_venv "$oss_fuzz_dir" >"$workspace/logs/oss_fuzz_venv.log" 2>&1; then
  printf 'prepare oss-fuzz venv
' >"$command_file"
  metadata failed 65 'ofg_oss_fuzz_dependency_setup_failed: missing OSS-Fuzz helper venv' "$command_file" "$workspace/logs/oss_fuzz_venv.log" "$benchmark_yaml"
  summary failed 65 'ofg_oss_fuzz_dependency_setup_failed: missing OSS-Fuzz helper venv'
  exit 65
fi
if ! ofg_llm_preflight "$workspace/logs/llm_preflight.log"; then
  reason="$(classify_ofg_failure 1 "$workspace/logs/llm_preflight.log")"
  printf 'llm preflight
' >"$command_file"
  metadata failed 65 "$reason" "$command_file" "$workspace/logs/llm_preflight.log" "$benchmark_yaml"
  summary failed 65 "$reason"
  exit 65
fi
cmd=("$python" /opt/hgb/bin/ofg_run_wrapper.py --artifact "$artifact" -- -y "$benchmark_yaml" --model "$OPENAI_MODEL" --oss-fuzz-dir "$oss_fuzz_dir" --run-timeout "${OFG_RUN_TIMEOUT:-300}" --num-samples "${OFG_NUM_SAMPLES:-1}" --work-dir "$workspace/ofg-work")
printf '%q ' "${cmd[@]}" >"$command_file"; printf '\n' >>"$command_file"
code=0
(cd "$artifact" && timeout "${OFG_TOTAL_TIMEOUT_SECONDS:-600}" "${cmd[@]}") >"$run_log" 2>&1 || code=$?
status=completed; reason=none
if [[ "$code" -ne 0 ]]; then
  status=failed; reason="$(classify_ofg_failure "$code" "$run_log")"
elif grep -Eiq 'Bad model type|Exception while running experiment|Traceback' "$run_log"; then
  code=1
  status=failed; reason="$(classify_ofg_failure "$code" "$run_log")"
fi
metadata "$status" "$code" "$reason" "$command_file" "$run_log" "$benchmark_yaml"
summary "$status" "$code" "$reason"
exit "$code"
