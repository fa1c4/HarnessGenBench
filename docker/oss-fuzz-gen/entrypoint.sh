#!/usr/bin/env bash
set -euo pipefail

artifact=/opt/hgb/artifacts/oss-fuzz-gen
python=/opt/hgb/venv/bin/python
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

# ---------------------------------------------------------------------------
# Profile configuration: alpha/paper-faithful require real Introspector and
# real coverage; compat-smoke may use the local shim, 1/1/1 budgets, and skip
# coverage. Legacy env must never silently force alpha into compat behavior.
# ---------------------------------------------------------------------------

hgb_profile="${HGB_BASELINE_PROFILE:-${HGB_PROFILE:-alpha}}"
hgb_protocol="${HGB_BASELINE_PROTOCOL:-${HGB_PROTOCOL:-blind-project}}"

apply_profile_defaults() {
  case "$hgb_profile" in
    alpha)
      export OFG_INTROSPECTOR_MODE="${OFG_INTROSPECTOR_MODE:-remote}"
      export OFG_SKIP_COVERAGE_GAINS="${OFG_SKIP_COVERAGE_GAINS:-0}"
      export OFG_NUM_SAMPLES="${OFG_NUM_SAMPLES:-3}"
      export OFG_NUM_EXP="${OFG_NUM_EXP:-1}"
      export OFG_NUM_EVA="${OFG_NUM_EVA:-1}"
      export OFG_NUM_EVALUATIONS="${OFG_NUM_EVALUATIONS:-3}"
      export OFG_MAX_ROUND="${OFG_MAX_ROUND:-5}"
      export OFG_RUN_TIMEOUT="${OFG_RUN_TIMEOUT:-900}"
      export OFG_GENERATION_TIMEOUT_SECONDS="${OFG_GENERATION_TIMEOUT_SECONDS:-7200}"
      export OFG_MAX_BENCHMARK_FUNCTIONS="${OFG_MAX_BENCHMARK_FUNCTIONS:-3}"
      export HGB_EXCLUDE_FROM_AGGREGATE="${HGB_EXCLUDE_FROM_AGGREGATE:-0}"
      export HGB_ALLOW_REFERENCE_USAGE="${HGB_ALLOW_REFERENCE_USAGE:-0}"
      export OFG_ALLOW_GCS_TARGET_DOWNLOAD="${OFG_ALLOW_GCS_TARGET_DOWNLOAD:-0}"
      ;;
    paper-faithful)
      export OFG_INTROSPECTOR_MODE="${OFG_INTROSPECTOR_MODE:-remote}"
      export OFG_SKIP_COVERAGE_GAINS="${OFG_SKIP_COVERAGE_GAINS:-0}"
      export OFG_NUM_SAMPLES="${OFG_NUM_SAMPLES:-10}"
      export OFG_NUM_EXP="${OFG_NUM_EXP:-1}"
      export OFG_NUM_EVA="${OFG_NUM_EVA:-1}"
      export OFG_NUM_EVALUATIONS="${OFG_NUM_EVALUATIONS:-3}"
      export OFG_MAX_ROUND="${OFG_MAX_ROUND:-5}"
      export OFG_RUN_TIMEOUT="${OFG_RUN_TIMEOUT:-900}"
      export OFG_GENERATION_TIMEOUT_SECONDS="${OFG_GENERATION_TIMEOUT_SECONDS:-7200}"
      export OFG_MAX_BENCHMARK_FUNCTIONS="${OFG_MAX_BENCHMARK_FUNCTIONS:-3}"
      export HGB_EXCLUDE_FROM_AGGREGATE="${HGB_EXCLUDE_FROM_AGGREGATE:-0}"
      export HGB_ALLOW_REFERENCE_USAGE="${HGB_ALLOW_REFERENCE_USAGE:-0}"
      export OFG_ALLOW_GCS_TARGET_DOWNLOAD="${OFG_ALLOW_GCS_TARGET_DOWNLOAD:-0}"
      ;;
    reproduction-gamma)
      # reproduction-gamma is the paper-faithful default for this plan. It
      # pins the real Fuzz Introspector mode, forbids project-YAML fallback and
      # bad-benchmark synthesis by default, and uses a meaningful generation
      # budget (never 1/1/1). See plan sections 2.3 and 7.
      export OFG_INTROSPECTOR_MODE="${OFG_INTROSPECTOR_MODE:-real}"
      export OFG_SKIP_COVERAGE_GAINS="${OFG_SKIP_COVERAGE_GAINS:-0}"
      export OFG_ALLOW_PROJECT_YAML_FALLBACK="${OFG_ALLOW_PROJECT_YAML_FALLBACK:-0}"
      export OFG_SYNTHESIZE_ON_BAD_BENCHMARK="${OFG_SYNTHESIZE_ON_BAD_BENCHMARK:-0}"
      export OFG_NUM_SAMPLES="${OFG_NUM_SAMPLES:-10}"
      export OFG_NUM_EXP="${OFG_NUM_EXP:-1}"
      export OFG_NUM_EVA="${OFG_NUM_EVA:-1}"
      export OFG_NUM_EVALUATIONS="${OFG_NUM_EVALUATIONS:-3}"
      export OFG_MAX_ROUND="${OFG_MAX_ROUND:-5}"
      export OFG_RUN_TIMEOUT="${OFG_RUN_TIMEOUT:-900}"
      export OFG_GENERATION_TIMEOUT_SECONDS="${OFG_GENERATION_TIMEOUT_SECONDS:-7200}"
      export OFG_MAX_BENCHMARK_FUNCTIONS="${OFG_MAX_BENCHMARK_FUNCTIONS:-3}"
      export HGB_EXCLUDE_FROM_AGGREGATE="${HGB_EXCLUDE_FROM_AGGREGATE:-0}"
      export HGB_ALLOW_REFERENCE_USAGE="${HGB_ALLOW_REFERENCE_USAGE:-0}"
      export OFG_ALLOW_GCS_TARGET_DOWNLOAD="${OFG_ALLOW_GCS_TARGET_DOWNLOAD:-0}"
      ;;
    reproduction-delta)
      # reproduction-delta is the strict paper-faithful profile (plan
      # oss-fuzz-gen_reproduction_delta.md section 1). It is stricter than
      # reproduction-gamma: OFG_INTROSPECTOR_MODE defaults to real, coverage
      # gains are never skipped, GCS target download is forbidden, project-YAML
      # fallback and bad-benchmark synthesis are forbidden unless an explicit
      # compat variant is recorded and the row is excluded from the aggregate.
      # No selected-harness API rank/report and no exact reference harness as
      # example are produced (enforced by ofg_run_wrapper.py / ofg_api_rank.py).
      export OFG_INTROSPECTOR_MODE="${OFG_INTROSPECTOR_MODE:-real}"
      export OFG_SKIP_COVERAGE_GAINS="${OFG_SKIP_COVERAGE_GAINS:-0}"
      export OFG_ALLOW_PROJECT_YAML_FALLBACK="${OFG_ALLOW_PROJECT_YAML_FALLBACK:-0}"
      export OFG_SYNTHESIZE_ON_BAD_BENCHMARK="${OFG_SYNTHESIZE_ON_BAD_BENCHMARK:-0}"
      export OFG_ALLOW_GCS_TARGET_DOWNLOAD="${OFG_ALLOW_GCS_TARGET_DOWNLOAD:-0}"
      export OFG_NUM_SAMPLES="${OFG_NUM_SAMPLES:-10}"
      export OFG_NUM_EXP="${OFG_NUM_EXP:-1}"
      export OFG_NUM_EVA="${OFG_NUM_EVA:-1}"
      export OFG_NUM_EVALUATIONS="${OFG_NUM_EVALUATIONS:-3}"
      export OFG_MAX_ROUND="${OFG_MAX_ROUND:-5}"
      export OFG_RUN_TIMEOUT="${OFG_RUN_TIMEOUT:-900}"
      export OFG_GENERATION_TIMEOUT_SECONDS="${OFG_GENERATION_TIMEOUT_SECONDS:-7200}"
      export OFG_MAX_BENCHMARK_FUNCTIONS="${OFG_MAX_BENCHMARK_FUNCTIONS:-3}"
      export HGB_EXCLUDE_FROM_AGGREGATE="${HGB_EXCLUDE_FROM_AGGREGATE:-0}"
      export HGB_ALLOW_REFERENCE_USAGE="${HGB_ALLOW_REFERENCE_USAGE:-0}"
      ;;
    compat-smoke)
      export OFG_INTROSPECTOR_MODE="${OFG_INTROSPECTOR_MODE:-local}"
      export OFG_SKIP_COVERAGE_GAINS="${OFG_SKIP_COVERAGE_GAINS:-1}"
      export OFG_NUM_SAMPLES="${OFG_NUM_SAMPLES:-1}"
      export OFG_NUM_EXP="${OFG_NUM_EXP:-1}"
      export OFG_NUM_EVA="${OFG_NUM_EVA:-1}"
      export OFG_NUM_EVALUATIONS="${OFG_NUM_EVALUATIONS:-1}"
      export OFG_MAX_ROUND="${OFG_MAX_ROUND:-5}"
      export OFG_RUN_TIMEOUT="${OFG_RUN_TIMEOUT:-300}"
      export OFG_GENERATION_TIMEOUT_SECONDS="${OFG_GENERATION_TIMEOUT_SECONDS:-600}"
      export OFG_MAX_BENCHMARK_FUNCTIONS="${OFG_MAX_BENCHMARK_FUNCTIONS:-1}"
      export HGB_EXCLUDE_FROM_AGGREGATE="${HGB_EXCLUDE_FROM_AGGREGATE:-1}"
      export HGB_ALLOW_REFERENCE_USAGE="${HGB_ALLOW_REFERENCE_USAGE:-0}"
      export OFG_ALLOW_GCS_TARGET_DOWNLOAD="${OFG_ALLOW_GCS_TARGET_DOWNLOAD:-0}"
      ;;
    *) ;;
  esac
  export HGB_BASELINE_PROFILE="$hgb_profile"
  export HGB_BASELINE_PROTOCOL="$hgb_protocol"
  export HGB_TASK_FAMILY="harness_generator"
  export HGB_GENERATOR="${HGB_GENERATOR:-oss-fuzz-gen}"
  export HGB_GENERATOR_ARTIFACT_DIR="$artifact"
  export OFG_LLM_PREFLIGHT="${OFG_LLM_PREFLIGHT:-1}"
  export OFG_LLM_REQUEST_TIMEOUT_SECONDS="${OFG_LLM_REQUEST_TIMEOUT_SECONDS:-${HGB_LLM_REQUEST_TIMEOUT_SECONDS:-1200}}"
  export OFG_LLM_MAX_RETRIES="${OFG_LLM_MAX_RETRIES:-0}"
  export HGB_LLM_PARALLELISM="${HGB_LLM_PARALLELISM:-4}"
  export HGB_LLM_MIN_INTERVAL_SECONDS="${HGB_LLM_MIN_INTERVAL_SECONDS:-3}"
  export HGB_LLM_LOCK_DIR="${HGB_LLM_LOCK_DIR:-/tmp/hgb-llm-locks}"
  export LLM_NUM_EXP="${LLM_NUM_EXP:-$OFG_NUM_EXP}"
  export LLM_NUM_EVA="${LLM_NUM_EVA:-$OFG_NUM_EVA}"
}

validate_profile_invariants() {
  "$python" /opt/hgb/bin/ofg_profile.py validate --profile "$hgb_profile" --protocol "$hgb_protocol" >/dev/null 2>"$workspace/logs/profile_validation.log" || {
    local violations
    violations="$(cat "$workspace/logs/profile_validation.log")"
    printf 'ofg_profile_violation: %s\n' "$violations" >&2
    return 1
  }
}

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
  printf 'ofg_oss_fuzz_dependency_setup_failed: missing OSS-Fuzz helper venv at %s\n' "$venv_target" >&2
  return 1
}
ofg_llm_preflight() {
  local log_file="$1"
  [[ "${OFG_LLM_PREFLIGHT:-1}" == "1" ]] || return 0
  "$python" - >"$log_file" 2>&1 <<'PY_OFG_PREFLIGHT'
import fcntl
import hashlib
import os
import random
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import openai

sys.path.insert(0, "/opt/hgb/bin")
try:
    import hgb_llm_trace
except Exception as exc:  # noqa: BLE001 - tracing is best-effort.
    hgb_llm_trace = None
    print(f"HGB_LLM_TRACE: preflight tracing unavailable: {exc}")

api_key = os.getenv('OPENAI_API_KEY') or os.getenv('API_KEY') or os.getenv('DEEPSEEK_API_KEY') or ''
model = os.getenv('OPENAI_MODEL') or os.getenv('MODEL') or 'gpt-4o-mini'
base_url = os.getenv('OPENAI_BASE_URL') or os.getenv('BASE_URL') or ''
lock_root = Path(os.getenv('HGB_LLM_LOCK_DIR') or '/tmp/hgb-llm-locks')
cache_seconds = float(os.getenv('OFG_LLM_PREFLIGHT_CACHE_SECONDS', '3600'))
max_attempts = max(1, int(os.getenv('OFG_LLM_PREFLIGHT_MAX_ATTEMPTS', '3')))
max_sleep = max(1.0, float(os.getenv('HGB_LLM_RATE_LIMIT_MAX_SLEEP_SECONDS', '180')))


def redact(text: object) -> str:
    value = str(text)
    for secret in (api_key, os.getenv('API_KEY', ''), os.getenv('DEEPSEEK_API_KEY', '')):
        if secret:
            value = value.replace(secret, '[REDACTED]')
    value = re.sub(r'api_key:\s*[^\s,}\']+', 'api_key: [REDACTED]', value, flags=re.I)
    value = re.sub(r'(authorization:\s*bearer\s+)[^\s,}\']+', r'\1[REDACTED]', value, flags=re.I)
    return value


def rate_limit_sleep_seconds(exc: Exception) -> float:
    text = str(exc)
    match = re.search(r'Limit resets at:\s*([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8}) UTC', text)
    if match:
        try:
            reset = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc).timestamp()
            return max(0.0, min(reset - time.time() + random.uniform(0.5, 2.0), max_sleep))
        except ValueError:
            pass
    return min(10.0 + random.uniform(0.5, 2.0), max_sleep)


def is_rate_limited(exc: Exception) -> bool:
    status = getattr(exc, 'status_code', None)
    text = str(exc).lower()
    return status == 429 or 'rate limit' in text or 'too many requests' in text or 'error code: 429' in text


kwargs = {'api_key': api_key, 'timeout': float(os.getenv('OFG_LLM_REQUEST_TIMEOUT_SECONDS', '1200'))}
if base_url:
    kwargs['base_url'] = base_url
try:
    kwargs['max_retries'] = int(os.getenv('OFG_LLM_MAX_RETRIES', '0'))
except ValueError:
    print(f"Invalid OFG_LLM_MAX_RETRIES: {os.getenv('OFG_LLM_MAX_RETRIES')}")
    sys.exit(1)

cache_key = hashlib.sha256('\0'.join([base_url, model, hashlib.sha256(api_key.encode()).hexdigest()]).encode()).hexdigest()[:24]
try:
    lock_root.mkdir(parents=True, exist_ok=True)
    lock_path = lock_root / f'ofg_preflight_{cache_key}.lock'
    ok_path = lock_root / f'ofg_preflight_{cache_key}.ok'
    with lock_path.open('w') as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        if ok_path.exists() and time.time() - ok_path.stat().st_mtime < cache_seconds:
            print('llm_preflight_cached_ok')
            sys.exit(0)
        for attempt in range(1, max_attempts + 1):
            try:
                client = openai.OpenAI(**kwargs)
                request = {
                    'model': model,
                    'messages': [{'role': 'user', 'content': 'Return OK.'}],
                    'max_tokens': 1,
                    'temperature': 0,
                }
                if hgb_llm_trace is not None:
                    hgb_llm_trace.trace_call(
                        lambda: client.chat.completions.create(**request),
                        stage='oss-fuzz-gen-preflight',
                        provider='openai-compatible',
                        operation='chat.completions.create',
                        model=model,
                        request=request,
                    )
                else:
                    client.chat.completions.create(**request)
                ok_path.write_text(f'{time.time()}\n', encoding='utf-8')
                print('llm_preflight_ok')
                sys.exit(0)
            except Exception as exc:  # noqa: BLE001 - preflight must preserve provider exception text.
                if is_rate_limited(exc) and attempt < max_attempts:
                    delay = rate_limit_sleep_seconds(exc)
                    print(f'ofg_llm_rate_limited: preflight attempt {attempt} hit rate limit; retrying in {delay:.1f}s')
                    time.sleep(delay)
                    continue
                print(f'{type(exc).__name__}: {redact(exc)}')
                sys.exit(1)
except Exception as exc:  # noqa: BLE001
    print(f'{type(exc).__name__}: {redact(exc)}')
    sys.exit(1)
PY_OFG_PREFLIGHT
}

redact_log_file() {
  [[ "$#" -gt 0 ]] || return 0
  "$python" - "$@" <<'PY_OFG_REDACT' || true
import os
import re
import sys
from pathlib import Path
secrets = [os.getenv(name, '') for name in ('OPENAI_API_KEY', 'API_KEY', 'DEEPSEEK_API_KEY')]
for raw in sys.argv[1:]:
    path = Path(raw)
    if not path.exists() or not path.is_file():
        continue
    text = path.read_text(encoding='utf-8', errors='replace')
    for secret in secrets:
        if secret:
            text = text.replace(secret, '[REDACTED]')
    text = re.sub(r'api_key:\s*[^\s,}\']+', 'api_key: [REDACTED]', text, flags=re.I)
    text = re.sub(r'(authorization:\s*bearer\s+)[^\s,}\']+', r'\1[REDACTED]', text, flags=re.I)
    path.write_text(text, encoding='utf-8')
PY_OFG_REDACT
}
classify_ofg_failure() {
  local code="$1" log_file="$2"
  if [[ -f "$log_file" ]]; then
    if grep -Eiq 'ofg_profile_violation' "$log_file"; then
      printf 'ofg_profile_violation: alpha/paper profile invariants were violated'
      return 0
    fi
    if grep -Eiq 'ModuleNotFoundError: No module named .pkg_resources.|No module named .pkg_resources.|pkg_resources' "$log_file"; then
      printf 'ofg_oss_fuzz_dependency_setup_failed: OSS-Fuzz-Gen Python environment is missing pkg_resources'
      return 0
    fi
    if grep -Eiq 'introspector_validation_failed|ofg_introspector_build_failed' "$log_file"; then
      printf 'ofg_introspector_build_failed: real Fuzz Introspector build did not produce valid reports'
      return 0
    fi
    if grep -Eiq 'AuthenticationError|Authentication Fails|401 Authorization Required|HTTP/1\.1 401|Error code: 401|PermissionDeniedError|Error code: 403|invalid api key' "$log_file"; then
      printf 'ofg_invalid_api_key: OpenAI-compatible API key was rejected'
      return 0
    fi
    if grep -Eiq 'RateLimitError|Error code: 429|HTTP/1\.1 429|Too Many Requests|rate limit exceeded|ofg_llm_rate_limited' "$log_file"; then
      printf 'ofg_llm_rate_limited: OpenAI-compatible API rate limit was reached; reduce HGB_LLM_PARALLELISM or increase HGB_LLM_MIN_INTERVAL_SECONDS'
      return 0
    fi
    if grep -Eiq 'ofg_empty_llm_response|LLM returned empty response|NoneType.*split|expected non-empty LLM response' "$log_file"; then
      printf 'ofg_empty_llm_response: OpenAI-compatible endpoint returned empty response content'
      return 0
    fi
    if [[ "$code" == "124" ]] && grep -Eiq 'OnePromptPrototyper succeded|Final fuzz target function referenced: True' "$log_file"; then
      printf 'ofg_post_success_validation_timeout: generated harness compiled and referenced the selected function before later validation timed out'
      return 0
    fi
    if grep -Eiq 'ofg_function_not_referenced|Final fuzz target function referenced: False' "$log_file" && grep -Eiq 'Fuzz target compiles: True' "$log_file"; then
      printf 'ofg_function_not_referenced: generated harness compiled but did not reference the selected function'
      return 0
    fi
    if grep -Eiq 'ofg_empty_fix_prompt' "$log_file"; then
      printf 'ofg_empty_fix_prompt: OSS-Fuzz-Gen stopped because the repair prompt had no actionable build errors'
      return 0
    fi
    if [[ "$code" == "124" ]] && grep -Eiq '===== ROUND .* Recompile|Recompile|fixing build' "$log_file"; then
      printf 'ofg_recompile_timeout: OSS-Fuzz-Gen timed out while recompiling or repairing the generated harness'
      return 0
    fi
    if grep -Eiq 'APITimeoutError|ReadTimeout|The read operation timed out|Request timed out|timed out while requesting|LLM request timeout' "$log_file"; then
      printf 'ofg_llm_request_timeout: OpenAI-compatible LLM request timed out after the configured request timeout'
      return 0
    fi
    if grep -Eiq 'missing_oss_fuzz_checkout|OSS-Fuzz checkout is unavailable|no valid OSS-Fuzz checkout|No such file or directory.*infra/helper\.py|FileNotFoundError.*infra/helper\.py' "$log_file"; then
      printf 'missing_oss_fuzz_checkout: OSS-Fuzz checkout is unavailable or invalid; rebuild the image with OFG_INSTALL_OSS_FUZZ=1 or set OFG_OSS_FUZZ_DIR'
      return 0
    fi
    if [[ "$code" == "124" ]]; then
      printf 'OSS-Fuzz-Gen timed out'
      return 0
    fi
  fi
  if [[ "$code" == "124" ]]; then
    printf 'OSS-Fuzz-Gen timed out'
    return 0
  fi
  printf 'run_all_experiments exited %s' "$code"
}

# ---------------------------------------------------------------------------
# Stage helpers (schema v2 result.json via target_contract.sh)
# ---------------------------------------------------------------------------
hgb_ofg_set_stage() {
  hgb_result_set_stage "$workspace/stages.json" "$1" "${2:-completed}"
}
hgb_ofg_result_status() {
  hgb_result_status_from_stages "$workspace/stages.json"
}

# ---------------------------------------------------------------------------
# Real Fuzz Introspector build: produces all_functions.json, calltree.json,
# type_info.json, report_manifest.json under $workspace/introspector/.
# In alpha/paper this MUST be real; compat-smoke may use the local shim.
# ---------------------------------------------------------------------------
run_introspector() {
  local introspector_dir="$workspace/introspector"
  mkdir -p "$introspector_dir"
  if [[ "$hgb_profile" == "compat-smoke" ]]; then
    # compat-smoke: emit a minimal stub from the benchmark/project source so
    # the local introspector shim has something to read. This is NOT a
    # substitute for real Introspector in alpha/paper.
    "$python" - "$introspector_dir" "${HGB_TARGET_SOURCE_DIR:-/target/source_input}" "${HGB_TARGET_PROJECT:-}" <<'PY_OFG_STUB'
import json
import os
import re
import sys
from pathlib import Path
out_dir, source_dir, project = sys.argv[1:4]
out = Path(out_dir)
out.mkdir(parents=True, exist_ok=True)
functions = []
src = Path(source_dir)
if src.is_dir():
    for p in sorted(src.rglob('*')):
        if not p.is_file() or p.suffix.lower() not in {'.c', '.h', '.cc', '.cpp', '.cxx', '.hpp', '.hh'}:
            continue
        try:
            text = p.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for m in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*\)\s*\{', text):
            name = m.group(1)
            if name in {'if', 'for', 'while', 'switch', 'return', 'main'}:
                continue
            functions.append({"name": name, "function_signature": f"int {name}()",
                              "source_file": str(p), "return-type": "int",
                              "function_arguments": []})
(out / "all_functions.json").write_text(json.dumps(functions[:200], indent=2), encoding='utf-8')
(out / "calltree.json").write_text(json.dumps({}, indent=2), encoding='utf-8')
(out / "type_info.json").write_text(json.dumps({}, indent=2), encoding='utf-8')
(out / "report_manifest.json").write_text(json.dumps({"project": project, "compat_shim": True}, indent=2), encoding='utf-8')
PY_OFG_STUB
    return 0
  fi
  # alpha/paper: run the pinned Fuzz Introspector sanitizer/build path. This
  # is delegated to the OSS-Fuzz infra introspector helper against an isolated
  # project overlay with a neutral temporary fuzz-entrypoint stub. The real
  # implementation requires Docker; if it is unavailable we fail truthfully.
  local oss_fuzz_dir="$1"
  local project="${HGB_TARGET_PROJECT:-$(hgb_target_manifest_value project)}"
  local fuzz_target="${HGB_TARGET_FUZZ_TARGET:-$(hgb_target_manifest_value fuzz_target)}"
  local source_dir="${HGB_TARGET_SOURCE_DIR:-/target/source_input}"
  local overlay_dir="$workspace/introspector_overlay"
  mkdir -p "$overlay_dir"
  # Stage source into the overlay so Introspector sees complete project source.
  rsync -a --delete "$source_dir/" "$overlay_dir/src/" 2>/dev/null || true
  # Neutral stub fuzz target (linking only; never used as generation context).
  cat >"$overlay_dir/hgb_introspector_stub.c" <<'EOF'
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    return 0;
}
EOF
  local introspector_log="$workspace/logs/introspector_build.log"
  if [[ -x "$oss_fuzz_dir/infra/helper.py" ]]; then
    (cd "$oss_fuzz_dir" && python3 infra/helper.py build_fuzzers --sanitizer address \
        --engine introspector --architecture x86_64 \
        "$project" "$overlay_dir" >"$introspector_log" 2>&1) || {
      printf 'ofg_introspector_build_failed: introspector helper exited non-zero\n' >>"$introspector_log"
      return 1
    }
  else
    printf 'ofg_introspector_build_failed: no infra/helper.py in %s\n' "$oss_fuzz_dir" >>"$introspector_log"
    return 1
  fi
  # Locate the target-scoped Introspector report (beta plan section 5): match
  # by project and fuzz target, NOT the first matching `inspector` directory.
  local report_root
  report_root="$("$python" - "$oss_fuzz_dir/build/out" "$project" "$fuzz_target" <<'PY_OFG_REPORT_SELECT'
import sys
from pathlib import Path
sys.path.insert(0, "/opt/hgb/bin")
try:
    from ofg_introspector_adapter import select_inspector_report, parse_report_manifest, parse_all_functions, parse_calltree
except Exception:
    print("", end="")
    sys.exit(0)
root, project, fuzz_target = sys.argv[1:4]
selected = select_inspector_report(root, project, fuzz_target)
if selected is not None:
    print(str(selected), end="")
PY_OFG_REPORT_SELECT
  )"
  if [[ -z "$report_root" || ! -d "$report_root" ]]; then
    printf 'ofg_introspector_build_failed: no target-scoped inspector report for project=%s fuzz_target=%s\n' "$project" "$fuzz_target" >>"$introspector_log"
    return 1
  fi
  for f in all_functions.json calltree.json type_info.json report_manifest.json; do
    [[ -f "$report_root/$f" ]] && cp "$report_root/$f" "$introspector_dir/$f"
  done
  # Generate function_source_map.json if upstream did not emit it directly.
  if [[ ! -f "$report_root/function_source_map.json" ]]; then
    "$python" - "$report_root" "$introspector_dir/function_source_map.json" "${HGB_TARGET_SOURCE_DIR:-/target/source_input}" <<'PY_OFG_FSM'
import json
import sys
from pathlib import Path
sys.path.insert(0, "/opt/hgb/bin")
from ofg_introspector_adapter import generate_function_source_map
report_dir, out_path, source_root = sys.argv[1:4]
mapping = generate_function_source_map(report_dir, source_root)
Path(out_path).write_text(json.dumps(mapping, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY_OFG_FSM
  else
    cp "$report_root/function_source_map.json" "$introspector_dir/function_source_map.json"
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Synthesize target-aware benchmark YAML from real Introspector data.
# Missing benchmark YAML must synthesize or fail, never soft-skip.
# ---------------------------------------------------------------------------
synthesize_benchmark_from_introspector() {
  local out_yaml="$1" selection_json="$2"
  local introspector_dir="$workspace/introspector"
  "$python" /opt/hgb/bin/ofg_benchmark_synthesis.py \
    --report-dir "$introspector_dir" \
    --source-dir "${HGB_TARGET_SOURCE_DIR:-/target/source_input}" \
    --project "${HGB_TARGET_PROJECT:-$(hgb_target_manifest_value project)}" \
    --target-name "${HGB_TARGET:-$(hgb_target_manifest_value target)}" \
    --fuzz-target "${HGB_TARGET_FUZZ_TARGET:-$(hgb_target_manifest_value fuzz_target)}" \
    --max-functions "${OFG_MAX_BENCHMARK_FUNCTIONS:-3}" \
    --benchmark-out "$out_yaml" \
    --selection-out "$selection_json" >"$workspace/logs/benchmark_synthesis.log" 2>&1
}

# ---------------------------------------------------------------------------
# Independent evaluator: overlay candidate, replay FuzzBench build, smoke,
# reachability, campaign, coverage.
# ---------------------------------------------------------------------------
run_evaluator() {
  local eval_dir="$workspace/evaluation"
  mkdir -p "$eval_dir"
  local selected_functions
  selected_functions="$(json_file_value "$workspace/benchmark/selection.json" selected)"
  selected_functions="$(printf '%s' "$selected_functions" | "$python" -c 'import json,sys; d=json.load(sys.stdin); print(",".join(r.get("name","") for r in d))' 2>/dev/null || true)"
  local evaluator_root="${HGB_EVALUATOR_ROOT:-}"
  [[ -z "$evaluator_root" && -d "/evaluator" ]] && evaluator_root="/evaluator"
  [[ -z "$evaluator_root" && -d "${HGB_TARGET_PACKAGE:-/target}/evaluator_only" ]] && evaluator_root="${HGB_TARGET_PACKAGE:-/target}/evaluator_only"
  # Beta plan section 8/9: delegate to the shared harness evaluator. It
  # overlays the candidate at the exact native path, uses one deterministic
  # image tag for build/smoke/campaign/coverage, requires nonzero executions,
  # reads coverage from a real report, and computes the line coverage diff.
  # Evaluator CLI failure must propagate (no `|| true`): section 9 forbids
  # swallowing evaluator failure.
  if [[ -n "$evaluator_root" ]]; then
    "$python" /opt/hgb/bin/hgb_harness_evaluator.py \
      --generator oss-fuzz-gen \
      --target-root "${HGB_TARGET_PACKAGE:-/target}" \
      --evaluator-root "$evaluator_root" \
      --candidates "$workspace/generated_harnesses" \
      --work-dir "$eval_dir" \
      --project "${HGB_TARGET_PROJECT:-$(hgb_target_manifest_value project)}" \
      --fuzz-target "${HGB_TARGET_FUZZ_TARGET:-$(hgb_target_manifest_value fuzz_target)}" \
      --profile "$hgb_profile" \
      --protocol "$hgb_protocol" \
      --campaign-seconds "${OFG_CAMPAIGN_SECONDS:-60}" \
      --build-timeout-seconds "${OFG_EVAL_BUILD_TIMEOUT:-1800}" \
      --intended-apis "$selected_functions" \
      --strict \
      --run-native-control \
      >"$workspace/logs/evaluator.log" 2>&1
    return $?
  fi
  # Monolithic layout fallback (legacy/compat): ofg_evaluator without the split.
  "$python" /opt/hgb/bin/ofg_evaluator.py \
    --target-root "${HGB_TARGET_PACKAGE:-/target}" \
    --candidates-dir "$workspace/generated_harnesses" \
    --work-dir "$eval_dir" \
    --fuzz-target "${HGB_TARGET_FUZZ_TARGET:-$(hgb_target_manifest_value fuzz_target)}" \
    --selected-functions $selected_functions \
    --build-timeout "${OFG_EVAL_BUILD_TIMEOUT:-1800}" \
    --campaign-seconds "${OFG_CAMPAIGN_SECONDS:-60}" \
    --strict \
    >"$workspace/logs/evaluator.log" 2>&1
  return $?
}

write_final_result() {
  local status="$1" reason="$2" exit_code="$3"
  local leakage_audit="$workspace/leakage_audit.json"
  "$python" /opt/hgb/bin/ofg_profile.py audit \
    --generator-input "$workspace" \
    --canary "${HGB_REF_CANARY:-HGB_REF_CANARY_none}" \
    --extra-dir "$workspace/generated_harnesses" \
    --extra-dir "$workspace/benchmark" >"$leakage_audit" 2>/dev/null || true
  local method_variant excluded
  if [[ "$hgb_profile" == "compat-smoke" ]]; then
    method_variant="compat-smoke"; excluded=true
  elif [[ "$hgb_profile" == "reproduction-gamma" || "$hgb_profile" == "reproduction-delta" ]]; then
    method_variant="paper-faithful"; excluded=false
  else
    method_variant="$hgb_profile"; excluded=false
  fi
  "$python" - "$workspace/result.json" "$status" "$reason" "$exit_code" \
    "$(commit)" "${OFG_OSS_FUZZ_COMMIT:-unknown}" \
    "$(hgb_target_manifest_value fuzzbench_commit)" "$OFG_INTROSPECTOR_MODE" \
    "${OFG_NUM_SAMPLES:-3}" "${OFG_MAX_ROUND:-5}" "${OFG_RUN_TIMEOUT:-900}" \
    "$method_variant" "$excluded" "$leakage_audit" "$hgb_profile" "$hgb_protocol" \
    "${HGB_TARGET:-$(hgb_target_manifest_value target)}" \
    "${HGB_DOCKER_IMAGE_DIGEST:-}" "${OFG_NUM_EVALUATIONS:-3}" \
    "${OFG_GENERATION_TIMEOUT_SECONDS:-7200}" <<'PY_HGB_RESULT'
import json
import os
import sys
from pathlib import Path
(out, status, reason, exit_code, ofg_commit, oss_commit, fb_commit, intro_mode,
 num_samples, max_round, run_timeout, method_variant, excluded, leakage_path,
 profile, protocol, target, image_digest, num_evals, gen_timeout) = sys.argv[1:]
try:
    stages = json.loads(Path(os.environ.get("workspace", "/workspace") + "/stages.json").read_text(encoding="utf-8"))
except Exception:
    stages = {}
leakage = {}
try:
    leakage = json.loads(Path(leakage_path).read_text(encoding="utf-8"))
except Exception:
    leakage = {}
# Fold the evaluator's per-candidate metrics into the run result when present
# so the run-level result.json carries real coverage/campaign/diff evidence.
metrics = {}
try:
    ev = json.loads(Path(os.environ.get("workspace", "/workspace") + "/evaluation/result.json").read_text(encoding="utf-8"))
    metrics = ev.get("metrics") or {}
except Exception:
    metrics = {}
# Fold the prompt audit (plan section 3), introspector provenance (plan
# section 4), and coverage diff (plan section 6) into the run result so the
# matrix gate can prove the row is paper-equivalent.
prompt_audit = {}
try:
    prompt_audit = json.loads(Path(os.environ.get("workspace", "/workspace") + "/generation/audit/prompt_audit.json").read_text(encoding="utf-8"))
except Exception:
    prompt_audit = {}
introspector = {}
try:
    introspector = json.loads(Path(os.environ.get("workspace", "/workspace") + "/introspector/provenance.json").read_text(encoding="utf-8"))
except Exception:
    introspector = {"mode": intro_mode, "used_local_shim": intro_mode == "local", "function_count": 0}
coverage_diff = metrics.get("coverage_diff") or {}
result = {
    "schema_version": 2,
    "generator": "oss-fuzz-gen",
    "task_family": "harness_generator",
    "profile": profile,
    "protocol": protocol,
    "target": target,
    "applicability": "applicable",
    "status": status,
    "reason": reason,
    "stages": stages,
    "artifacts": {},
    "metrics": metrics,
    "prompt_audit": prompt_audit,
    "introspector": introspector,
    "coverage_diff": coverage_diff,
    "provenance": {
        "oss_fuzz_gen_commit": ofg_commit,
        "oss_fuzz_commit": oss_commit,
        "fuzzbench_commit": fb_commit,
        "docker_image_digest": image_digest,
        "introspector_mode": intro_mode,
        "ofg_num_samples": int(num_samples),
        "ofg_num_evaluations": int(num_evals),
        "ofg_max_round": int(max_round),
        "ofg_run_timeout": int(run_timeout),
        "ofg_generation_timeout_seconds": int(gen_timeout),
    },
    "reference_leakage_audit": leakage,
    "method_variant": method_variant,
    "excluded_from_aggregate": excluded == "true",
}
Path(out).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY_HGB_RESULT
}

# ===========================================================================
# generate-target mode
# ===========================================================================
if [[ "$mode" == "generate-target" ]]; then
  # shellcheck source=/opt/hgb/bin/target_contract.sh
  source /opt/hgb/bin/target_contract.sh
  apply_profile_defaults
  export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
  export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
  export OPENAI_MODEL="${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
  mkdir -p "$workspace/logs" "$workspace/generated_harnesses" "$workspace/benchmark" \
           "$workspace/generation" "$workspace/introspector"
  hgb_result_init_stages "$workspace/stages.json"
  hgb_require_target_package
  hgb_ofg_set_stage target_prepared completed

  if [[ "${HGB_DRY_RUN:-0}" == "1" ]]; then
    printf 'oss-fuzz-gen generate-target dry-run for %s\n' "${HGB_TARGET:-unknown}" >"$workspace/command.txt"
    hgb_write_common_metadata dry_run_ok 'dry run validated target package' 0 harness_generator
    hgb_write_common_summary dry_run_ok 'dry run validated target package' harness_generator
    exit 0
  fi

  if ! validate_profile_invariants; then
    hgb_ofg_set_stage target_prepared failed
    reason="ofg_profile_violation: profile invariants failed for $hgb_profile/$hgb_protocol"
    write_final_result failed "$reason" 65
    hgb_write_common_metadata failed "$reason" 65 harness_generator
    hgb_write_common_summary failed "$reason" harness_generator
    exit 65
  fi

  if ! hgb_api_key_present; then
    printf 'OPENAI_API_KEY is not set; OSS-Fuzz-Gen target generation skipped.\n' >"$workspace/logs/run.log"
    hgb_ofg_set_stage generation failed
    reason="missing_api_key: OPENAI_API_KEY is not set"
    write_final_result failed "$reason" 2
    hgb_write_common_metadata missing_api_key 'OPENAI_API_KEY is not set' 2 harness_generator
    hgb_write_common_summary missing_api_key 'OPENAI_API_KEY is not set' harness_generator
    exit 2
  fi

  project="${HGB_TARGET_PROJECT:-$(hgb_target_manifest_value project)}"
  fuzz_target="${HGB_TARGET_FUZZ_TARGET:-$(hgb_target_manifest_value fuzz_target)}"
  target_name="${HGB_TARGET:-$(hgb_target_manifest_value target)}"

  # --- OSS-Fuzz checkout (pinned, never floating master) ---
  oss_fuzz_dir=""
  if ! oss_fuzz_dir="$(materialize_oss_fuzz_checkout)"; then
    printf 'missing_oss_fuzz_checkout: no valid pinned OSS-Fuzz checkout\n' >"$workspace/logs/oss_fuzz_checkout.log"
    reason="missing_oss_fuzz_checkout: rebuild the image with OFG_INSTALL_OSS_FUZZ=1 or set OFG_OSS_FUZZ_DIR"
    hgb_ofg_set_stage introspector_build failed
    write_final_result failed "$reason" 2
    hgb_write_common_metadata missing_oss_fuzz_checkout "$reason" 2 harness_generator
    hgb_write_common_summary missing_oss_fuzz_checkout "$reason" harness_generator
    exit 2
  fi
  if ! prepare_oss_fuzz_venv "$oss_fuzz_dir" >"$workspace/logs/oss_fuzz_venv.log" 2>&1; then
    reason="ofg_oss_fuzz_dependency_setup_failed: missing OSS-Fuzz helper venv"
    hgb_ofg_set_stage introspector_build failed
    write_final_result failed "$reason" 65
    hgb_write_common_metadata failed "$reason" 65 harness_generator
    hgb_write_common_summary failed "$reason" harness_generator
    exit 65
  fi

  # --- LLM preflight (before any paid request) ---
  if ! ofg_llm_preflight "$workspace/logs/llm_preflight.log"; then
    redact_log_file "$workspace/logs/llm_preflight.log"
    reason="$(classify_ofg_failure 1 "$workspace/logs/llm_preflight.log")"
    hgb_ofg_set_stage generation failed
    write_final_result failed "$reason" 65
    hgb_write_common_metadata failed "$reason" 65 harness_generator
    hgb_write_common_summary failed "$reason" harness_generator
    exit 65
  fi

  # --- Real Fuzz Introspector build ---
  if ! run_introspector "$oss_fuzz_dir"; then
    reason="$(classify_ofg_failure 1 "$workspace/logs/introspector_build.log")"
    [[ -z "$reason" ]] && reason="ofg_introspector_build_failed: real Fuzz Introspector build did not produce valid reports"
    hgb_ofg_set_stage introspector_build failed
    write_final_result failed "$reason" 65
    hgb_write_common_metadata failed "$reason" 65 harness_generator
    hgb_write_common_summary failed "$reason" harness_generator
    exit 65
  fi
  # Validate reports are non-empty and project-sourced.
  if ! "$python" /opt/hgb/bin/ofg_introspector_adapter.py --report-dir "$workspace/introspector" \
        --source-root "${HGB_TARGET_SOURCE_DIR:-/target/source_input}" \
        --project "$project" --target-name "$target_name" --fuzz-target "$fuzz_target" \
        --max-functions 1 >/dev/null 2>>"$workspace/logs/introspector_build.log"; then
    reason="ofg_introspector_build_failed: introspector reports are empty or stub-only"
    hgb_ofg_set_stage introspector_build failed
    write_final_result failed "$reason" 65
    hgb_write_common_metadata failed "$reason" 65 harness_generator
    hgb_write_common_summary failed "$reason" harness_generator
    exit 65
  fi
  hgb_ofg_set_stage introspector_build completed

  # --- Synthesize target-aware benchmark YAML (no answer leakage) ---
  generated_yaml="$workspace/benchmark/generated.yaml"
  selection_json="$workspace/benchmark/selection.json"
  if ! synthesize_benchmark_from_introspector "$generated_yaml" "$selection_json"; then
    reason="ofg_benchmark_synthesis_failed: could not synthesize benchmark YAML from introspector data"
    hgb_ofg_set_stage benchmark_synthesized failed
    write_final_result failed "$reason" 65
    hgb_write_common_metadata failed "$reason" 65 harness_generator
    hgb_write_common_summary failed "$reason" harness_generator
    exit 65
  fi
  benchmark_yaml="$generated_yaml"
  benchmark_match_kind="synthesized"
  hgb_ofg_set_stage benchmark_synthesized completed

  # --- Generation + automatic build repair via upstream wrapper ---
  # Beta plan section 7: allow multiple samples/trials using configurable
  # defaults (OFG_NUM_SAMPLES, OFG_NUM_EVALUATIONS, OFG_GENERATION_TIMEOUT_SECONDS).
  export HGB_GENERATION_WORK_DIR="$workspace/generation/work"
  mkdir -p "$HGB_GENERATION_WORK_DIR"
  cmd=("$python" /opt/hgb/bin/ofg_run_wrapper.py --artifact "$artifact" -- \
        --model "$OPENAI_MODEL" -y "$benchmark_yaml" --oss-fuzz-dir "$oss_fuzz_dir" \
        --run-timeout "${OFG_RUN_TIMEOUT:-900}" --num-samples "${OFG_NUM_SAMPLES:-3}" \
        --max-round "${OFG_MAX_ROUND:-5}" --work-dir "$HGB_GENERATION_WORK_DIR")
  printf '%q ' "${cmd[@]}" >"$workspace/command.txt"; printf '\n' >>"$workspace/command.txt"
  code=0
  (cd "$artifact" && PIP_CACHE_DIR="$workspace/generation/pip-cache" \
      timeout "${OFG_GENERATION_TIMEOUT_SECONDS:-${HGB_GENERATION_TIMEOUT_SECONDS:-10800}}" "${cmd[@]}") >"$workspace/logs/run.log" 2>&1 || code=$?
  redact_log_file "$workspace/logs/run.log"

  # --- Preserve compiling candidates ---
  if [[ -d "$HGB_GENERATION_WORK_DIR" ]]; then
    n=0
    while IFS= read -r generated; do
      n=$((n + 1))
      cp "$generated" "$workspace/generated_harnesses/${n}_$(basename "$generated")" 2>/dev/null || true
    done < <(find "$HGB_GENERATION_WORK_DIR" -type f \( -path '*/fixed_targets/*' -o -path '*/raw_targets/*' -o -path '*/fuzz_targets/*' \) 2>/dev/null | sort)
  fi
  if [[ "$(hgb_count_files "$workspace/generated_harnesses" -type f)" == "0" && -f "$workspace/logs/run.log" ]]; then
    "$python" - "$workspace/logs/run.log" "$workspace/generated_harnesses" <<'PY_OFG_LOG_HARNESS' || true
import re
import sys
from pathlib import Path
log_path = Path(sys.argv[1])
out_dir = Path(sys.argv[2])
text = log_path.read_text(encoding='utf-8', errors='replace')
blocks = re.findall(r"```(?:c\+\+|cpp|cc|c)?\s*\n(.*?)```", text, flags=re.S | re.I)
count = 0
out_dir.mkdir(parents=True, exist_ok=True)
for block in blocks:
    if 'LLVMFuzzerTestOneInput' not in block:
        continue
    block = block.strip() + '\n'
    count += 1
    (out_dir / f'log_candidate_{count}.cc').write_text(block, encoding='utf-8')
print(count)
PY_OFG_LOG_HARNESS
  fi

  if [[ "$code" -ne 0 ]]; then
    reason="$(classify_ofg_failure "$code" "$workspace/logs/run.log")"
    hgb_ofg_set_stage generation failed
    write_final_result failed "$reason" "$code"
    hgb_write_common_metadata failed "$reason" "$code" harness_generator
    hgb_write_common_summary failed "$reason" harness_generator
    exit "$code"
  fi
  hgb_ofg_set_stage generation completed
  hgb_ofg_set_stage compilation_repair completed

  generated_harness_count="$(hgb_count_generated_harness_files "$workspace/generated_harnesses")"
  if [[ "${generated_harness_count:-0}" -eq 0 ]]; then
    reason="ofg_no_compiling_candidate: OSS-Fuzz-Gen produced no harness candidate"
    hgb_ofg_set_stage candidate_build failed
    write_final_result failed "$reason" 65
    hgb_write_common_metadata failed "$reason" 65 harness_generator
    hgb_write_common_summary failed "$reason" harness_generator
    exit 65
  fi
  hgb_ofg_set_stage candidate_build completed

  # --- Independent evaluator: build, smoke, reachability, campaign, coverage ---
  # Beta plan section 9: evaluator CLI failure must propagate to infra_failure.
  # No `|| true` around run_evaluator: a nonzero exit is a real failure.
  eval_code=0
  run_evaluator || eval_code=$?
  eval_result_json="$workspace/evaluation/result.json"
  eval_results="$workspace/evaluation/results.json"
  eval_status=""
  if [[ -f "$eval_result_json" ]]; then
    eval_status="$(json_file_value "$eval_result_json" status 2>/dev/null || printf '')"
  fi
  # If the evaluator crashed (nonzero exit, no result.json), it is infra.
  if [[ "$eval_code" -ne 0 && -z "$eval_status" ]]; then
    reason="infra_failure/failed_stage=evaluator: independent evaluator exited $eval_code (see logs/evaluator.log)"
    hgb_ofg_set_stage candidate_build failed
    for s in sanitizer_smoke api_reachability campaign coverage; do hgb_ofg_set_stage "$s" failed; done
    write_final_result failed "$reason" 65
    hgb_write_common_metadata failed "$reason" 65 harness_generator
    hgb_write_common_summary failed "$reason" harness_generator
    exit 65
  fi
  # Propagate the evaluator's per-stage states and metrics into the run result.
  if [[ -f "$eval_result_json" ]]; then
    "$python" - "$eval_result_json" "$workspace/stages.json" <<'PY_OFG_PROPAGATE'
import json
import sys
from pathlib import Path
result = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
stages_path = Path(sys.argv[2])
stages = json.loads(stages_path.read_text(encoding="utf-8")) if stages_path.is_file() else {}
ev_stages = result.get("stages") or {}
for stage in ("candidate_build", "sanitizer_smoke", "api_reachability", "campaign", "coverage"):
    if ev_stages.get(stage):
        stages[stage] = ev_stages[stage]
stages_path.write_text(json.dumps(stages, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY_OFG_PROPAGATE
  fi
  if [[ "$eval_status" != "evaluated" ]]; then
    if [[ "$eval_status" == "infra_failure" ]]; then
      reason="infra_failure: independent evaluator reported infrastructure failure (see evaluation/result.json)"
    else
      reason="quality_failure: independent evaluator did not reach evaluated (see evaluation/result.json)"
    fi
    for s in sanitizer_smoke api_reachability campaign coverage; do
      [[ "$(json_file_value "$workspace/stages.json" "$s" 2>/dev/null)" == "completed" ]] || hgb_ofg_set_stage "$s" failed
    done
    final_status="$(hgb_ofg_result_status)"
    [[ "$eval_status" == "infra_failure" ]] && final_status="infra_failure"
    [[ "$final_status" == "failed" && "$eval_status" == "quality_failure" ]] && final_status="quality_failure"
    write_final_result "$final_status" "$reason" 65
    hgb_write_common_metadata "$final_status" "$reason" 65 harness_generator
    hgb_write_common_summary "$final_status" "$reason" harness_generator
    exit 65
  fi
  for s in sanitizer_smoke api_reachability campaign coverage; do hgb_ofg_set_stage "$s" completed; done

  # --- Final status: only all-complete yields evaluated ---
  final_status="$(hgb_ofg_result_status)"
  final_code=0
  [[ "$final_status" == "evaluated" ]] || final_code=65
  reason="none"
  [[ "$final_status" != "evaluated" ]] && reason="ofg_incomplete: one or more stages did not complete"
  write_final_result "$final_status" "$reason" "$final_code"
  hgb_write_common_metadata "$final_status" "$reason" "$final_code" harness_generator
  hgb_write_common_summary "$final_status" "$reason" harness_generator
  if [[ "${HGB_SAVE_MODE:-compact}" == "compact" ]]; then
    rm -rf "$HGB_GENERATION_WORK_DIR" "$workspace/generation/pip-cache" "$workspace/oss-fuzz" "$workspace/introspector_overlay"
  fi
  exit "$final_code"
fi

# ===========================================================================
# smoke mode (legacy compatibility)
# ===========================================================================
[[ "$mode" == "smoke" ]] || { echo "unknown mode: $mode" >&2; exit 64; }
apply_profile_defaults
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
  exit 2
fi
if [[ -z "$OPENAI_API_KEY" ]]; then
  printf 'OPENAI_API_KEY is not set; OSS-Fuzz-Gen smoke not launched.\n' >"$run_log"
  exit 2
fi
oss_fuzz_dir=""
if ! oss_fuzz_dir="$(materialize_oss_fuzz_checkout)"; then
  printf 'missing_oss_fuzz_checkout\n' >"$run_log"
  exit 2
fi
if ! prepare_oss_fuzz_venv "$oss_fuzz_dir" >"$workspace/logs/oss_fuzz_venv.log" 2>&1; then
  exit 65
fi
if ! ofg_llm_preflight "$workspace/logs/llm_preflight.log"; then
  redact_log_file "$workspace/logs/llm_preflight.log"
  exit 65
fi
cmd=("$python" /opt/hgb/bin/ofg_run_wrapper.py --artifact "$artifact" -- -y "$benchmark_yaml" --model "$OPENAI_MODEL" --oss-fuzz-dir "$oss_fuzz_dir" --run-timeout "${OFG_RUN_TIMEOUT:-300}" --num-samples "${OFG_NUM_SAMPLES:-3}" --max-round "${OFG_MAX_ROUND:-5}" --work-dir "$workspace/ofg-work")
printf '%q ' "${cmd[@]}" >"$command_file"; printf '\n' >>"$command_file"
code=0
(cd "$artifact" && timeout "${OFG_TOTAL_TIMEOUT_SECONDS:-600}" "${cmd[@]}") >"$run_log" 2>&1 || code=$?
redact_log_file "$run_log"
status=completed; reason=none
if [[ "$code" -ne 0 ]]; then
  status=failed; reason="$(classify_ofg_failure "$code" "$run_log")"
fi
{
  printf '{\n'
  printf '  "fuzzer": "oss-fuzz-gen",\n'
  printf '  "status": "%s",\n' "$(json_escape "$status")"
  printf '  "upstream_commit": "%s",\n' "$(json_escape "$(commit)")"
  printf '  "benchmark": "%s",\n' "$(json_escape "$benchmark")"
  printf '  "exit_code": %s,\n' "$code"
  printf '  "reason": "%s"\n' "$(json_escape "$reason")"
  printf '}\n'
} >"$workspace/metadata.json"
exit "$code"
