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

# Strict reproduction defaults shared by reproduction-delta/epsilon/zeta/eta.
# zeta/eta layer additional required env on top of these (see
# _ofg_apply_zeta_eta_env).
_ofg_apply_strict_reproduction_defaults() {
  export OFG_INTROSPECTOR_MODE="${OFG_INTROSPECTOR_MODE:-real}"
  export OFG_SKIP_COVERAGE_GAINS="${OFG_SKIP_COVERAGE_GAINS:-0}"
  export OFG_ALLOW_PROJECT_YAML_FALLBACK="${OFG_ALLOW_PROJECT_YAML_FALLBACK:-0}"
  export OFG_SYNTHESIZE_ON_BAD_BENCHMARK="${OFG_SYNTHESIZE_ON_BAD_BENCHMARK:-0}"
  export OFG_ALLOW_GCS_TARGET_DOWNLOAD="${OFG_ALLOW_GCS_TARGET_DOWNLOAD:-0}"
  export OFG_NUM_SAMPLES="${OFG_NUM_SAMPLES:-10}"
  # OFG_NUM_EXP/OFG_NUM_EVA are LLM parallelism knobs, not generation budgets.
  # ofg_profile.py forbids =1 in method-faithful profiles, so leave them unset
  # here and let the wrapper fall back to the upstream defaults (2/3).
  export OFG_NUM_EVALUATIONS="${OFG_NUM_EVALUATIONS:-3}"
  export OFG_MAX_ROUND="${OFG_MAX_ROUND:-5}"
  export OFG_RUN_TIMEOUT="${OFG_RUN_TIMEOUT:-900}"
  export OFG_GENERATION_TIMEOUT_SECONDS="${OFG_GENERATION_TIMEOUT_SECONDS:-14400}"
  export OFG_MAX_BENCHMARK_FUNCTIONS="${OFG_MAX_BENCHMARK_FUNCTIONS:-3}"
  export HGB_EXCLUDE_FROM_AGGREGATE="${HGB_EXCLUDE_FROM_AGGREGATE:-0}"
  export HGB_ALLOW_REFERENCE_USAGE="${HGB_ALLOW_REFERENCE_USAGE:-0}"
}

# zeta plan §1 / eta plan §1: zeta and eta are the strictest profiles. They
# force real OSS-Fuzz project context, real Introspector, no reference
# examples, no selected-harness API ranking, the upstream repair loop, real
# coverage, and a sealed split package. Eta is the canonical strict profile
# and inherits all of these required env values.
_ofg_apply_zeta_eta_env() {
  export OFG_USE_REAL_OSS_FUZZ="${OFG_USE_REAL_OSS_FUZZ:-1}"
  export OFG_USE_REAL_INTROSPECTOR="${OFG_USE_REAL_INTROSPECTOR:-1}"
  export OFG_ALLOW_LOCAL_INTROSPECTOR_SHIM="${OFG_ALLOW_LOCAL_INTROSPECTOR_SHIM:-0}"
  export OFG_ALLOW_REFERENCE_EXAMPLES="${OFG_ALLOW_REFERENCE_EXAMPLES:-0}"
  export OFG_ALLOW_SELECTED_HARNESS_API_RANKING="${OFG_ALLOW_SELECTED_HARNESS_API_RANKING:-0}"
  export OFG_ENABLE_REPAIR_LOOP="${OFG_ENABLE_REPAIR_LOOP:-1}"
  export OFG_ENABLE_COVERAGE="${OFG_ENABLE_COVERAGE:-1}"
  export HGB_TARGET_REQUIRE_SPLIT=1
}

apply_profile_defaults() {
  case "$hgb_profile" in
    alpha)
      export OFG_INTROSPECTOR_MODE="${OFG_INTROSPECTOR_MODE:-remote}"
      export OFG_SKIP_COVERAGE_GAINS="${OFG_SKIP_COVERAGE_GAINS:-0}"
      export OFG_NUM_SAMPLES="${OFG_NUM_SAMPLES:-3}"
      export OFG_NUM_EVALUATIONS="${OFG_NUM_EVALUATIONS:-3}"
      export OFG_MAX_ROUND="${OFG_MAX_ROUND:-5}"
      export OFG_RUN_TIMEOUT="${OFG_RUN_TIMEOUT:-900}"
      export OFG_GENERATION_TIMEOUT_SECONDS="${OFG_GENERATION_TIMEOUT_SECONDS:-14400}"
      export OFG_MAX_BENCHMARK_FUNCTIONS="${OFG_MAX_BENCHMARK_FUNCTIONS:-3}"
      export HGB_EXCLUDE_FROM_AGGREGATE="${HGB_EXCLUDE_FROM_AGGREGATE:-0}"
      export HGB_ALLOW_REFERENCE_USAGE="${HGB_ALLOW_REFERENCE_USAGE:-0}"
      export OFG_ALLOW_GCS_TARGET_DOWNLOAD="${OFG_ALLOW_GCS_TARGET_DOWNLOAD:-0}"
      ;;
    paper-faithful)
      export OFG_INTROSPECTOR_MODE="${OFG_INTROSPECTOR_MODE:-remote}"
      export OFG_SKIP_COVERAGE_GAINS="${OFG_SKIP_COVERAGE_GAINS:-0}"
      export OFG_NUM_SAMPLES="${OFG_NUM_SAMPLES:-10}"
      export OFG_NUM_EVALUATIONS="${OFG_NUM_EVALUATIONS:-3}"
      export OFG_MAX_ROUND="${OFG_MAX_ROUND:-5}"
      export OFG_RUN_TIMEOUT="${OFG_RUN_TIMEOUT:-900}"
      export OFG_GENERATION_TIMEOUT_SECONDS="${OFG_GENERATION_TIMEOUT_SECONDS:-14400}"
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
      export OFG_NUM_EVALUATIONS="${OFG_NUM_EVALUATIONS:-3}"
      export OFG_MAX_ROUND="${OFG_MAX_ROUND:-5}"
      export OFG_RUN_TIMEOUT="${OFG_RUN_TIMEOUT:-900}"
      export OFG_GENERATION_TIMEOUT_SECONDS="${OFG_GENERATION_TIMEOUT_SECONDS:-14400}"
      export OFG_MAX_BENCHMARK_FUNCTIONS="${OFG_MAX_BENCHMARK_FUNCTIONS:-3}"
      export HGB_EXCLUDE_FROM_AGGREGATE="${HGB_EXCLUDE_FROM_AGGREGATE:-0}"
      export HGB_ALLOW_REFERENCE_USAGE="${HGB_ALLOW_REFERENCE_USAGE:-0}"
      export OFG_ALLOW_GCS_TARGET_DOWNLOAD="${OFG_ALLOW_GCS_TARGET_DOWNLOAD:-0}"
      ;;
    reproduction-delta|reproduction-epsilon)
      # Strict reproduction profiles. reproduction-epsilon is the strict
      # profile from the epsilon plan and reproduction-delta is its
      # backward-compatible alias (plan oss-fuzz-gen_reproduction_delta.md
      # section 1). Both are stricter than reproduction-gamma:
      # OFG_INTROSPECTOR_MODE defaults to real, coverage gains are never
      # skipped, GCS target download is forbidden, project-YAML fallback and
      # bad-benchmark synthesis are forbidden unless an explicit compat
      # variant is recorded and the row is excluded from the aggregate. No
      # selected-harness API rank/report and no exact reference harness as
      # example are produced (enforced by ofg_run_wrapper.py /
      # ofg_api_rank.py). zeta/eta are handled by their own cases below
      # because they layer additional required env on top of these defaults.
      _ofg_apply_strict_reproduction_defaults
      ;;
    reproduction-zeta)
      # zeta plan §1: zeta is the strictest profile. It inherits the strict
      # reproduction defaults and additionally forces real OSS-Fuzz project
      # context, real Introspector, no reference examples, no selected-harness
      # API ranking, repair loop, coverage, and a sealed split package.
      _ofg_apply_strict_reproduction_defaults
      _ofg_apply_zeta_eta_env
      ;;
    reproduction-eta)
      # eta plan §1: eta is the canonical strictest profile. It inherits all
      # zeta required env (real OSS-Fuzz project context, real Introspector,
      # no reference examples, no selected-harness API ranking, repair loop,
      # coverage, sealed split package) and the strict reproduction defaults.
      # The eta-specific coverage-instrumented build and native coverage
      # control are requested by run_evaluator (eta plan §2/§5/§6).
      _ofg_apply_strict_reproduction_defaults
      _ofg_apply_zeta_eta_env
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
  # The host runner passes the campaign budget as HGB_CAMPAIGN_SECONDS; map it
  # to the evaluator's OFG_CAMPAIGN_SECONDS knob so the requested fuzzing
  # budget actually reaches the campaign stage.
  export OFG_CAMPAIGN_SECONDS="${OFG_CAMPAIGN_SECONDS:-${HGB_CAMPAIGN_SECONDS:-60}}"
  export OFG_LLM_PREFLIGHT="${OFG_LLM_PREFLIGHT:-1}"
  export OFG_LLM_REQUEST_TIMEOUT_SECONDS="${OFG_LLM_REQUEST_TIMEOUT_SECONDS:-${HGB_LLM_REQUEST_TIMEOUT_SECONDS:-1200}}"
  export OFG_LLM_MAX_RETRIES="${OFG_LLM_MAX_RETRIES:-0}"
  export HGB_LLM_PARALLELISM="${HGB_LLM_PARALLELISM:-4}"
  export HGB_LLM_MIN_INTERVAL_SECONDS="${HGB_LLM_MIN_INTERVAL_SECONDS:-3}"
  export HGB_LLM_LOCK_DIR="${HGB_LLM_LOCK_DIR:-/tmp/hgb-llm-locks}"
  # Only forward LLM_NUM_EXP/LLM_NUM_EVA when a value exists: exporting an
  # empty string would break upstream int(os.getenv(...)) parsing and an
  # unset value lets the wrapper apply the upstream defaults (2/3).
  if [[ -n "${LLM_NUM_EXP:-}" || -n "${OFG_NUM_EXP:-}" ]]; then
    export LLM_NUM_EXP="${LLM_NUM_EXP:-${OFG_NUM_EXP:-}}"
  fi
  if [[ -n "${LLM_NUM_EVA:-}" || -n "${OFG_NUM_EVA:-}" ]]; then
    export LLM_NUM_EVA="${LLM_NUM_EVA:-${OFG_NUM_EVA:-}}"
  fi
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
  # Docker-in-Docker: the checkout must live under the HOST-visible workspace
  # path so sibling build containers (via /var/run/docker.sock) can mount it.
  # common.sh mounts "$workspace" at both /workspace and its host path, so
  # HGB_WORKSPACE_HOST/oss-fuzz == /workspace/oss-fuzz inside this container.
  local run_dir="${OFG_OSS_FUZZ_RUN_DIR:-${HGB_WORKSPACE_HOST:-$workspace}/oss-fuzz}"
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

# ---------------------------------------------------------------------------
# Patch the materialized (run-dir) OSS-Fuzz project files for known upstream
# breakages that would otherwise sink the upstream repair loop. Recorded as
# compat deviations in logs/oss_fuzz_project_patches.log.
# ---------------------------------------------------------------------------
patch_oss_fuzz_projects() {
  local oss_fuzz_dir="$1"
  local patch_log="$workspace/logs/oss_fuzz_project_patches.log"
  mkdir -p "$(dirname "$patch_log")"
  # lcms: the upstream Dockerfile seeds the corpus with ``cd seeds`` relative
  # to WORKDIR lcms (the dir does not exist there) and copies testbed/*.icc
  # files that current lcms master no longer ships; the RUN always fails and
  # the upstream repair loop can never build the lcms image. Make the seed
  # step correct and best-effort (seeds never gate compilation).
  local lcms_dockerfile="$oss_fuzz_dir/projects/lcms/Dockerfile"
  if [[ -f "$lcms_dockerfile" ]] && ! grep -qF "HGB lcms seed step tolerant" "$lcms_dockerfile"; then
    "$python" - "$lcms_dockerfile" <<'PY_OFG_LCMS_PATCH'
import sys
from pathlib import Path
p = Path(sys.argv[1])
text = p.read_text(encoding="utf-8", errors="replace")
old = """RUN mkdir $SRC/seeds && \\
    cd seeds && \\
    cp $SRC/lcms/testbed/bad.icc . && \\
    cp $SRC/lcms/testbed/toosmall.icc . && \\
    cp $SRC/lcms/testbed/test1.icc . && \\
    cp $SRC/lcms/testbed/crayons.icc . && \\
    cp $SRC/lcms/testbed/ibm-t61.icc . && \\
    #add more seeds from the testbed dir
    cp $SRC/lcms/testbed/bad_mpe.icc . && \\
    cp $SRC/lcms/testbed/new.icc . && \\
    cp $SRC/lcms/testbed/test2.icc . && \\
    cp $SRC/lcms/testbed/test3.icc . && \\
    cp $SRC/lcms/testbed/test4.icc . && \\
    cp $SRC/lcms/testbed/test5.icc . && \\
    zip -rj $SRC/seed_corpus.zip $SRC/seeds/*
"""
new = """RUN mkdir -p $SRC/seeds && \\
    cd $SRC/seeds && \\
    for f in bad.icc toosmall.icc test1.icc crayons.icc ibm-t61.icc bad_mpe.icc new.icc test2.icc test3.icc test4.icc test5.icc; do \\
        cp $SRC/lcms/testbed/$f . 2>/dev/null || true; \\
    done && \\
    zip -rj $SRC/seed_corpus.zip $SRC/seeds/* 2>/dev/null || true
# HGB lcms seed step tolerant
"""
if old in text:
    text = text.replace(old, new)
elif "HGB lcms seed step tolerant" not in text:
    # Fallback: patch just the broken ``cd seeds`` line.
    text = text.replace("    cd seeds && \\", "    cd $SRC/seeds && \\")
    text = text.replace("zip -rj $SRC/seed_corpus.zip $SRC/seeds/*",
                        "zip -rj $SRC/seed_corpus.zip $SRC/seeds/* 2>/dev/null || true")
p.write_text(text, encoding="utf-8")
print("patched")
PY_OFG_LCMS_PATCH
    printf 'ofg_project_patch: lcms Dockerfile seed step made correct and tolerant\n' >>"$patch_log"
  fi

  # php: current php master removed the --enable-pic configure option (PIC is
  # always on), so the pinned OSS-Fuzz build.sh fails configure against
  # floating php HEAD. Drop the obsolete option.
  local php_build_sh="$oss_fuzz_dir/projects/php/build.sh"
  if [[ -f "$php_build_sh" ]] && grep -q -- "--enable-pic" "$php_build_sh" && ! grep -qF "HGB php build" "$php_build_sh"; then
    sed -i 's/ --enable-pic//g; s/--enable-pic //g' "$php_build_sh"
    sed -i '1i # HGB php build: --enable-pic removed (obsolete in current php master)' "$php_build_sh"
    printf 'ofg_project_patch: php build.sh dropped obsolete --enable-pic\n' >>"$patch_log"
  fi
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
                # Transient connection failures must also retry: the container
                # starts its siblings while the host network may still be
                # flapping, and a single connection error must not sink a run.
                if attempt < max_attempts and (
                    'Connection error' in str(exc) or 'APIConnectionError' in str(exc)
                    or 'RemoteDisconnected' in str(exc) or 'timed out' in str(exc).lower()
                ):
                    delay = min(30.0, 3.0 * attempt)
                    print(f'ofg_llm_connection_error: preflight attempt {attempt} failed; retrying in {delay:.1f}s')
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
  # Timeout takes precedence over stale-log greps: a 124 exit is a timeout even
  # when the log contains hours-old rate-limit lines (zeta/eta classification).
  if [[ "$code" == "124" ]]; then
    if [[ -f "$log_file" ]] && grep -Eiq 'OnePromptPrototyper succeded|Final fuzz target function referenced: True' "$log_file"; then
      printf 'ofg_post_success_validation_timeout: generated harness compiled and referenced the selected function before later validation timed out'
      return 0
    fi
    if [[ -f "$log_file" ]] && grep -Eiq '===== ROUND .* Recompile|Recompile|fixing build' "$log_file"; then
      printf 'ofg_recompile_timeout: OSS-Fuzz-Gen timed out while recompiling or repairing the generated harness'
      return 0
    fi
    printf 'ofg_generation_timeout: OSS-Fuzz-Gen generation exceeded the configured timeout'
    return 0
  fi
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
    # Only recent rate-limit lines (last 1200 chars) count: old 429s from
    # recovered mid-run retries must not misclassify a later failure.
    if tail -c 1200 "$log_file" | grep -Eiq 'RateLimitError|Error code: 429|HTTP/1\.1 429|Too Many Requests|rate limit exceeded|ofg_llm_rate_limited'; then
      printf 'ofg_llm_rate_limited: OpenAI-compatible API rate limit was reached; reduce HGB_LLM_PARALLELISM or increase HGB_LLM_MIN_INTERVAL_SECONDS'
      return 0
    fi
    if grep -Eiq 'ofg_empty_llm_response|LLM returned empty response|NoneType.*split|expected non-empty LLM response' "$log_file"; then
      printf 'ofg_empty_llm_response: OpenAI-compatible endpoint returned empty response content'
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
    if grep -Eiq 'APITimeoutError|ReadTimeout|The read operation timed out|Request timed out|timed out while requesting|LLM request timeout' "$log_file"; then
      printf 'ofg_llm_request_timeout: OpenAI-compatible LLM request timed out after the configured request timeout'
      return 0
    fi
    if grep -Eiq 'missing_oss_fuzz_checkout|OSS-Fuzz checkout is unavailable|no valid OSS-Fuzz checkout|No such file or directory.*infra/helper\.py|FileNotFoundError.*infra/helper\.py' "$log_file"; then
      printf 'missing_oss_fuzz_checkout: OSS-Fuzz checkout is unavailable or invalid; rebuild the image with OFG_INSTALL_OSS_FUZZ=1 or set OFG_OSS_FUZZ_DIR'
      return 0
    fi
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
patch_introspector_build() {
  local oss_fuzz_dir="$1" project="$2" fuzz_target="$3"
  local build_sh="$oss_fuzz_dir/projects/$project/build.sh"
  # The project build.sh may legitimately live in the cloned source tree
  # (e.g. libpng: libpng/contrib/oss-fuzz/build.sh); only the compile-wrapper
  # patch is unconditional. Guard the per-project build.sh patch separately.
  local marker="# HGB introspector-scoped build: skip non-target fuzzers under SANITIZER=introspector"
  if [[ -f "$build_sh" ]]; then
  case "$project" in
    jsoncpp)
      if ! grep -qF "$marker" "$build_sh"; then
        "$python" - "$build_sh" "$marker" <<'PY_PATCH_JSONCPP'
import sys
from pathlib import Path
p = Path(sys.argv[1]); marker = sys.argv[2]
text = p.read_text(encoding="utf-8", errors="replace")
text = text.replace(
    'if [[ $CFLAGS != *sanitize=memory* ]]; then',
    f'{marker}\nif [[ $CFLAGS != *sanitize=memory* && $SANITIZER != introspector ]]; then',
    1,
)
p.write_text(text, encoding="utf-8")
PY_PATCH_JSONCPP
      fi
      ;;
    *) ;;
  esac
  fi
  # Generic introspector-analysis scoping: fuzz-introspector's pre-build
  # static ``full`` analysis parses every source under $SRC (assert-statement
  # processing is CPU-bound and quadratic on some files). Install a patched
  # compile script that runs the full analysis on a pruned copy of the source
  # tree (dependency vendored trees like LPM/protobuf excluded) so per-target
  # introspector builds stay tractable. Guarded by a marker for idempotency.
  local compile_src="$oss_fuzz_dir/infra/base-images/base-builder/compile"
  local project_dir="$oss_fuzz_dir/projects/$project"
  local dockerfile="$project_dir/Dockerfile"
  [[ -f "$compile_src" && -f "$dockerfile" ]] || return 0
  local compile_marker="# HGB introspector scoped analysis"
  if grep -qF "$compile_marker" "$project_dir/hgb_compile" 2>/dev/null || grep -qF "hgb_compile" "$dockerfile"; then
    return 0
  fi
  "$python" - "$compile_src" "$project_dir/hgb_compile" "$compile_marker" "$primary_dest" <<'PY_OFG_COMPILE_PATCH'
import sys
from pathlib import Path
src, dst, marker, primary = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4]
text = src.read_text(encoding="utf-8", errors="replace")

# 1) Setup block inserted before the pre-build light analysis: pruned source
# copy + assert-statement no-op patch (the assert processing is CPU-bound).
light_old = "    python3 /fuzz-introspector/src/main.py light\n"
if light_old not in text:
    print("no_light_invocation")
    sys.exit(0)
if primary:
    prune_lines = (
        "    HGB_PRIMARY=\"" + primary + "\"\n"
        "    if [ -d $SRC/$HGB_PRIMARY ]; then\n"
        "      mkdir -p /tmp/hgb-analysis-src/$HGB_PRIMARY\n"
        "      rsync -a --exclude='.git' --exclude='LPM' --exclude='libprotobuf-mutator' "
        "--exclude='external.protobuf' --exclude='protobuf' --exclude='protobuf-c' "
        "$SRC/$HGB_PRIMARY/ /tmp/hgb-analysis-src/$HGB_PRIMARY/ 2>/dev/null "
        "|| cp -r $SRC/$HGB_PRIMARY/. /tmp/hgb-analysis-src/$HGB_PRIMARY/\n"
        "      for hgb_f in $SRC/*.c $SRC/*.cc $SRC/*.cpp $SRC/*.h build.sh; do "
        "[ -e \"$hgb_f\" ] && cp \"$hgb_f\" /tmp/hgb-analysis-src/ 2>/dev/null; done\n"
        "    else\n"
        "      rsync -a --exclude='.git' --exclude='LPM' --exclude='libprotobuf-mutator' "
        "--exclude='external.protobuf' --exclude='protobuf' --exclude='protobuf-c' "
        "$SRC/ /tmp/hgb-analysis-src/ 2>/dev/null || cp -r $SRC/. /tmp/hgb-analysis-src/\n"
        "    fi\n"
    )
else:
    prune_lines = (
        "    HGB_PRIMARY=\"\"\n"
        "    rsync -a --exclude='.git' --exclude='LPM' --exclude='libprotobuf-mutator' "
        "--exclude='external.protobuf' --exclude='protobuf' --exclude='protobuf-c' "
        "$SRC/ /tmp/hgb-analysis-src/ 2>/dev/null || cp -r $SRC/. /tmp/hgb-analysis-src/\n"
    )
setup = (
    "    HGB_FULL_SRC=/tmp/hgb-analysis-src\n"
    "    if [ -d /tmp/hgb-analysis-src ]; then rm -rf /tmp/hgb-analysis-src; fi\n"
    "    mkdir -p /tmp/hgb-analysis-src\n"
    + prune_lines
    + "    HGB_FI_PATCH=/tmp/hgb-fi-patch\n"
    "    mkdir -p $HGB_FI_PATCH\n"
    "    cat > $HGB_FI_PATCH/sitecustomize.py <<'HGB_FI_EOF'\n"
    "try:\n"
    "    from fuzz_introspector.frontends import frontend_c_cpp as _hgb_fi\n"
    "    cls = getattr(_hgb_fi, 'FunctionDefinition', None)\n"
    "    if cls is not None and hasattr(cls, '_process_assert_stmts'):\n"
    "        cls._process_assert_stmts = lambda self: None\n"
    "    # _process_field_expr_return_type dominates the report phase (linear\n"
    "    # scans of every function per callsite). Resolve the callsite name\n"
    "    # cheaply and skip the O(N) return-type lookup; the return type is\n"
    "    # not part of the report data we consume.\n"
    "    if cls is not None and hasattr(cls, '_process_field_expr_return_type'):\n"
    "        def _hgb_field_expr(self, field_expr, project):\n"
    "            full_name = ''\n"
    "            try:\n"
    "                field = field_expr.child_by_field_name('field')\n"
    "                if field is None:\n"
    "                    return (None, '')\n"
    "                if field.type == 'template_method':\n"
    "                    name_node = field.child_by_field_name('name')\n"
    "                    full_name = (name_node.text.decode(encoding='utf-8', errors='ignore')\n"
    "                                 if name_node and name_node.text else '')\n"
    "                else:\n"
    "                    full_name = field.text.decode(encoding='utf-8', errors='ignore') if field.text else ''\n"
    "                arg = field_expr.child_by_field_name('argument')\n"
    "                if arg is not None and arg.type == 'field_expression':\n"
    "                    _, inner_type = _hgb_field_expr(self, arg, project)\n"
    "                    if inner_type and inner_type != 'void':\n"
    "                        full_name = inner_type + '::' + full_name\n"
    "            except Exception:\n"
    "                pass\n"
    "            return ('', full_name)\n"
    "        cls._process_field_expr_return_type = _hgb_field_expr\n"
    "    # extract_callsites walks every AST node of every function and formats\n"
    "    # each node text; replace it with two direct tree-sitter queries over\n"
    "    # call_expression/new_expression nodes (the only node types the walk\n"
    "    # actually processed).\n"
    "    if cls is not None and hasattr(cls, 'extract_callsites'):\n"
    "        def _hgb_extract_callsites(self, project):\n"
    "            if self.base_callsites:\n"
    "                return\n"
    "            # The source-level callsite walk/_process_invoke path is\n"
    "            # quadratic on template-heavy C++; the report's calltree comes\n"
    "            # from the LTO fuzzer data, so collect new_expression callsites\n"
    "            # cheaply and skip the per-call resolution entirely.\n"
    "            callsites = []\n"
    "            try:\n"
    "                lang = self.tree_sitter_lang\n"
    "                for node, _ in lang.query('(new_expression) @ne').captures(self.root):\n"
    "                    try:\n"
    "                        ctr = node.child_by_field_name('type')\n"
    "                        if ctr is not None and ctr.text:\n"
    "                            _cls = ctr.text.decode(encoding='utf-8', errors='ignore')\n"
    "                            callsites.append((_cls + '::' + _cls.rsplit('::')[-1],\n"
    "                                              node.byte_range[1], node.start_point.row + 1))\n"
    "                    except Exception:\n"
    "                        pass\n"
    "            except Exception:\n"
    "                pass\n"
    "            self.base_callsites = callsites\n"
    "        cls.extract_callsites = _hgb_extract_callsites\n"
    "    for _hgb_cname in ('CppProject',):\n"
    "        _hgb_c = getattr(_hgb_fi, _hgb_cname, None)\n"
    "        if _hgb_c is None:\n"
    "            continue\n"
    "        # _calculate_function_uses rescans every function's callsites per\n"
    "        # function (O(N^2)); precompute a per-project callsite counter.\n"
    "        if hasattr(_hgb_c, '_calculate_function_uses'):\n"
    "            def _hgb_calculate_function_uses(self, target_name):\n"
    "                _hgb_uc = getattr(self, '_hgb_uses_cache', None)\n"
    "                if _hgb_uc is None:\n"
    "                    _hgb_uc = {}\n"
    "                    for _hgb_sf in self.source_code_files:\n"
    "                        for _hgb_fn in getattr(_hgb_sf, 'func_defs', []) or []:\n"
    "                            for _hgb_cs in getattr(_hgb_fn, 'base_callsites', []) or []:\n"
    "                                _hgb_name = _hgb_cs[0] if _hgb_cs else ''\n"
    "                                _hgb_uc[_hgb_name] = _hgb_uc.get(_hgb_name, 0) + 1\n"
    "                    self._hgb_uses_cache = _hgb_uc\n"
    "                if target_name in _hgb_uc:\n"
    "                    return _hgb_uc[target_name]\n"
    "                _hgb_total = 0\n"
    "                for _hgb_name, _hgb_count in _hgb_uc.items():\n"
    "                    if _hgb_name.endswith(target_name):\n"
    "                        _hgb_total += _hgb_count\n"
    "                return _hgb_total\n"
    "            setattr(_hgb_c, '_calculate_function_uses', _hgb_calculate_function_uses)\n"
    "        _hgb_orig = _hgb_c.__dict__.get('_find_source_with_func_def')\n"
    "        if _hgb_orig is None:\n"
    "            continue\n"
    "        def _hgb_patched(self, name):\n"
    "            _hgb_cache = getattr(self, '_hgb_fd_cache', None)\n"
    "            if _hgb_cache is None:\n"
    "                _hgb_cache = {}\n"
    "                self._hgb_fd_cache = _hgb_cache\n"
    "            if name in _hgb_cache:\n"
    "                return _hgb_cache[name]\n"
    "            _hgb_res = _hgb_orig(self, name)\n"
    "            _hgb_cache[name] = _hgb_res\n"
    "            return _hgb_res\n"
    "        setattr(_hgb_c, '_find_source_with_func_def', _hgb_patched)\n"
    "    # The HTML report sections (per-file analyses + PNG rendering) dominate\n"
    "    # the report phase for large projects; only the JSON data files are\n"
    "    # consumed downstream, so skip the HTML generation entirely.\n"
    "    try:\n"
    "        import fuzz_introspector.html_report as _hgb_hr\n"
    "        for _hgb_attr in ('create_section_optional_analyses',\n"
    "                          'create_section_required_analyses'):\n"
    "            if hasattr(_hgb_hr, _hgb_attr):\n"
    "                setattr(_hgb_hr, _hgb_attr, lambda *a, **k: '')\n"
    "        for _hgb_attr in ('create_horisontal_calltree_image',\n"
    "                          'create_percentage_summary_graph',\n"
    "                          'create_horizontal_calltree_image'):\n"
    "            if hasattr(_hgb_hr, _hgb_attr):\n"
    "                setattr(_hgb_hr, _hgb_attr, lambda *a, **k: None)\n"
    "    except Exception:\n"
    "        pass\n"
    "except Exception:\n"
    "    pass\n"
    "HGB_FI_EOF\n"
    f"    {marker}\n"
)
light_new = (
    setup
    + "    HGB_PREV_CWD=$(pwd)\n"
    + "    cd /tmp/hgb-analysis-src\n"
    + "    PYTHONPATH=$HGB_FI_PATCH${PYTHONPATH:+:$PYTHONPATH} python3 /fuzz-introspector/src/main.py light\n"
    + "    cp -rf /tmp/hgb-analysis-src/inspector $SRC/inspector 2>/dev/null || true\n"
    + "    cd \"$HGB_PREV_CWD\"\n"
)
text = text.replace(light_old, light_new, 1)

# 2) Scope the pre-build full analysis to the pruned tree as well.
full_old = "    fuzz-introspector full --target-dir=$SRC \\\n"
if full_old in text:
    full_new = "    PYTHONPATH=$HGB_FI_PATCH${PYTHONPATH:+:$PYTHONPATH} fuzz-introspector full --target-dir=/tmp/hgb-analysis-src \\\n"
    text = text.replace(full_old, full_new, 1)

# 3) The post-build report command re-runs the source analysis and must get
# the same performance patches.
report_old = "    fuzz-introspector report $REPORT_ARGS\n"
if report_old in text:
    text = text.replace(
        report_old,
        "    PYTHONPATH=$HGB_FI_PATCH${PYTHONPATH:+:$PYTHONPATH} fuzz-introspector report $REPORT_ARGS\n",
    )

# 4) The introspector setup block re-installs packages inside the build
# container on every run; fuzz-introspector is already installed in the base
# image, so make the network-dependent steps best-effort (they must not kill
# the build when archives are unreachable). Matches are indentation-agnostic.
for _hgb_line in (
    "apt-get install -y libjpeg-dev zlib1g-dev libyaml-dev\n",
    "python3 -m pip install --upgrade pip setuptools\n",
    "python3 -m pip install cxxfilt pyyaml beautifulsoup4 lxml soupsieve rust-demangler\n",
    "python3 -m pip install --prefer-binary matplotlib\n",
):
    if _hgb_line in text:
        text = text.replace(
            _hgb_line,
            _hgb_line[:-1] + " 2>/dev/null || true\n",
        )
if "python3 -m pip install -e .\n" in text:
    text = text.replace(
        "python3 -m pip install -e .\n",
        "python3 -m pip install -e . 2>/dev/null || true\n",
    )

# 5) The introspector sanitizer flags use -fuse-ld=gold (LLVMgold LTO), but
# the pinned base-builder's gold crashes on clang-15 DWARF-5. Downgrade the
# debug info to DWARF-4 (gold handles it); the LTO analysis is unaffected.
if "export CFLAGS=\"$CFLAGS -g\"\n" in text:
    text = text.replace(
        "export CFLAGS=\"$CFLAGS -g\"\n",
        "export CFLAGS=\"$CFLAGS -g -gdwarf-4\"\n",
    )
    text = text.replace(
        "export CXXFLAGS=\"$CXXFLAGS -g\"\n",
        "export CXXFLAGS=\"$CXXFLAGS -g -gdwarf-4\"\n",
    )

dst.write_text(text, encoding="utf-8")
print("patched")
PY_OFG_COMPILE_PATCH
  # COPY the patched compile into the project image (override base-builder).
  "$python" - "$dockerfile" "$compile_marker" <<'PY_OFG_DOCKER_PATCH'
import sys
from pathlib import Path
dockerfile, marker = Path(sys.argv[1]), sys.argv[2]
text = dockerfile.read_text(encoding="utf-8", errors="replace")
if "hgb_compile" in text:
    sys.exit(0)
text = text.rstrip() + "\n" + f"COPY hgb_compile /usr/local/bin/compile\nRUN chmod +x /usr/local/bin/compile\n" + "\n"
dockerfile.write_text(text, encoding="utf-8")
PY_OFG_DOCKER_PATCH
}

# ---------------------------------------------------------------------------
# Remote Fuzz Introspector (OFG_INTROSPECTOR_MODE=remote): materialize the
# official project-scoped report from the Fuzz Introspector API used by
# upstream OSS-Fuzz-Gen data prep. Falls back to the local build on failure.
# ---------------------------------------------------------------------------
run_introspector_remote() {
  local introspector_dir="$1" project="$2"
  "$python" - "$introspector_dir" "$project" "${OFG_INTROSPECTOR_ENDPOINT:-https://introspector.oss-fuzz.com/api}" \
    >"$workspace/logs/introspector_remote.log" 2>&1 <<'PY_OFG_REMOTE'
import json
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

out_dir = Path(sys.argv[1])
project = sys.argv[2]
endpoint = sys.argv[3].rstrip("/")


def get(api: str, params: dict, retries: int = 3):
    url = f"{endpoint}/{api}?" + urllib.parse.urlencode(params)
    last = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "harnessgenbench-ofg"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(2 * attempt)
    raise RuntimeError(f"{api} failed after {retries} attempts: {last}")


data = get("all-functions", {"project": project})
functions = data.get("functions") if isinstance(data, dict) else None
if not functions:
    print(f"ofg_introspector_remote_empty: project={project} has no introspector data")
    sys.exit(1)

import re as _hgb_re
_CLEAN_NAME_RE = _hgb_re.compile(r"^[A-Za-z_][A-Za-z0-9_:~]*$")

all_functions = []
type_info = {}
reach_by_fuzzer: dict[str, list[str]] = {}
for raw in functions:
    if not isinstance(raw, dict):
        continue
    name = str(raw.get("function_name") or raw.get("raw_function_name") or "").strip()
    if not name:
        continue
    # Skip template/lambda/operator internals: such records are unusable as
    # benchmark functions (they explode into unbuildable prompts).
    if "lambda" in name.lower() or not _CLEAN_NAME_RE.match(name):
        continue
    debug = raw.get("debug_summary") or {}
    source = debug.get("source") or {}
    record = {
        "name": name,
        "signature": str(raw.get("function_signature") or name),
        "source_file": str(raw.get("function_filename") or source.get("source_file") or ""),
        "source_line": str(source.get("source_line") or ""),
        "return_type": str(raw.get("return_type") or debug.get("return_type") or ""),
        "function_arguments": list(raw.get("function_arguments") or []),
        "complexity": int(raw.get("accummulated_complexity", 0) or 0),
        "covered": bool(raw.get("is_reached")) or float(raw.get("runtime_coverage_percent", 0) or 0) > 0,
        "reached_by_fuzzers": list(raw.get("reached_by_fuzzers") or []),
    }
    all_functions.append(record)
    for fuzzer in record["reached_by_fuzzers"]:
        reach_by_fuzzer.setdefault(str(fuzzer), []).append(name)
    if debug:
        type_info[name] = debug

# Synthesize a calltree.json so the adapter can compute the reachable set:
# fuzzer roots whose children are the functions they reach dynamically.
tree = [{"function_name": fuzzer, "children": [{"function_name": fn} for fn in fns]}
        for fuzzer, fns in sorted(reach_by_fuzzer.items())]
# Include all functions as roots when no per-fuzzer reachability is present.
if not tree:
    tree = [{"function_name": r["name"], "children": []} for r in all_functions]

out_dir.mkdir(parents=True, exist_ok=True)
(out_dir / "all_functions.json").write_text(json.dumps(all_functions, indent=2) + "\n", encoding="utf-8")
(out_dir / "calltree.json").write_text(json.dumps({"tree": tree}, indent=2) + "\n", encoding="utf-8")
(out_dir / "type_info.json").write_text(json.dumps(type_info, indent=2) + "\n", encoding="utf-8")
(out_dir / "report_manifest.json").write_text(json.dumps({
    "project": project,
    "mode": "remote",
    "endpoint": endpoint,
    "function_count": len(all_functions),
    "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}, indent=2) + "\n", encoding="utf-8")
if len(all_functions) < 5:
    print(f"ofg_introspector_remote_too_few: {len(all_functions)} usable functions; falling back to local build")
    sys.exit(1)
print(f"ofg_introspector_remote_ok: {len(all_functions)} functions for {project}")
PY_OFG_REMOTE
}

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
  # OFG_INTROSPECTOR_MODE=remote: materialize the official Fuzz Introspector
  # report from the upstream API (the paper's data-prep path). Falls back to
  # the real local build when the project has no API data.
  if [[ "${OFG_INTROSPECTOR_MODE:-real}" == "remote" ]]; then
    local project_remote="${HGB_TARGET_PROJECT:-$(hgb_target_manifest_value project)}"
    if run_introspector_remote "$introspector_dir" "$project_remote"; then
      return 0
    fi
    printf 'ofg_introspector_note: remote introspector fetch failed; falling back to local build\n' >>"$workspace/logs/introspector_build.log"
  fi
  # Local introspector builds for large projects take many hours (the
  # fuzz-introspector analysis is single-threaded). Reuse a previously
  # validated local report from a sibling run of the same target instead of
  # rebuilding it every round.
  if [[ "${OFG_REUSE_INTROSPECTOR_REPORT:-1}" == "1" ]]; then
    local sibling_report
    sibling_report="$("$python" - "$workspace" "$introspector_dir" <<'PY_OFG_REUSE' 2>/dev/null || true
import json
import os
import shutil
import sys
from pathlib import Path
workspace = Path(os.environ.get("HGB_WORKSPACE_HOST") or sys.argv[1])
out_dir = Path(sys.argv[2])
# Sibling run dirs are exposed via HGB_TARGET_RUNS_DIR (the target-level
# parent, mounted read-only); fall back to the host-path parent.
runs_root = Path(os.environ.get("HGB_TARGET_RUNS_DIR")) if os.environ.get("HGB_TARGET_RUNS_DIR") else workspace.parent
run_name = workspace.name
for sibling in sorted(runs_root.iterdir(), reverse=True):
    if not sibling.is_dir() or sibling.name == run_name:
        continue
    rep = sibling / "introspector"
    if not (rep / "all_functions.json").is_file() or not (rep / "report_manifest.json").is_file():
        continue
    prov = rep / "provenance.json"
    if prov.is_file():
        try:
            data = json.loads(prov.read_text(encoding="utf-8"))
            if data.get("used_local_shim") or not data.get("function_count"):
                continue
        except Exception:
            continue
    try:
        shutil.copytree(rep, out_dir, dirs_exist_ok=True)
    except OSError:
        continue
    print(str(sibling))
    break
PY_OFG_REUSE
  )"
    if [[ -n "$sibling_report" ]]; then
      printf 'ofg_introspector_note: reused validated local report from %s\n' "$sibling_report" >>"$workspace/logs/introspector_build.log"
      return 0
    fi
  fi
  # alpha/paper: run the pinned Fuzz Introspector sanitizer/build path. This
  # is delegated to the OSS-Fuzz infra helper (``build_fuzzers --sanitizer
  # introspector``) against an isolated project overlay that contains the
  # pinned FuzzBench primary-repo source plus a neutral temporary
  # fuzz-entrypoint stub. The real implementation requires Docker; if it is
  # unavailable we fail truthfully.
  local oss_fuzz_dir="$1"
  local project="${HGB_TARGET_PROJECT:-$(hgb_target_manifest_value project)}"
  local fuzz_target="${HGB_TARGET_FUZZ_TARGET:-$(hgb_target_manifest_value fuzz_target)}"
  local source_dir="${HGB_TARGET_SOURCE_DIR:-/target/source_input}"
  local overlay_dir="$workspace/introspector_overlay"
  mkdir -p "$overlay_dir"
  # Stage the PRIMARY project repo root (per /target/source_repos.json) at the
  # overlay root. helper.py mounts the overlay at the project Dockerfile
  # WORKDIR (e.g. /src/jsoncpp), so the overlay must match the layout the
  # Dockerfile's own ``git clone`` produces -- otherwise build.sh cannot find
  # CMakeLists.txt/Makefile and the introspector build fails.
  local primary_rel=""
  local primary_dest=""
  read -r primary_rel primary_dest <<<"$("$python" - /target/source_repos.json <<'PY_OFG_PRIMARY' 2>/dev/null || true
import json
import sys
from pathlib import Path
rel = ""
dest = ""
try:
    records = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    for r in records if isinstance(records, list) else []:
        if r.get("is_primary_project"):
            rel = str(r.get("package_path") or "").strip()
            if rel.startswith("source_input/"):
                rel = rel[len("source_input/"):]
            dest = str(r.get("dest") or "").strip().strip("/")
            break
except Exception:
    rel = ""
print(rel, dest)
PY_OFG_PRIMARY
  )"
  local overlay_src=""
  # Prefer the FULL unstripped checkout (the stripped /target/source_input is
  # missing the native harness that build.sh compiles). This overlay is used
  # ONLY for the real Introspector compile; it is never read into prompts or
  # benchmark YAML.
  if [[ -n "$primary_dest" && -d "${HGB_TARGET_FULL_SOURCE_DIR:-/opt/hgb/target-sources}/$primary_dest" ]]; then
    overlay_src="${HGB_TARGET_FULL_SOURCE_DIR:-/opt/hgb/target-sources}/$primary_dest"
  elif [[ -n "$primary_rel" && -d "$source_dir/$primary_rel" ]]; then
    overlay_src="$source_dir/$primary_rel"
  elif [[ -d "$source_dir" ]]; then
    overlay_src="$source_dir"
  fi
  if [[ -z "$overlay_src" ]]; then
    printf 'ofg_introspector_build_failed: no primary project source to stage under %s\n' "$source_dir" >>"$workspace/logs/introspector_build.log"
    return 1
  fi
  rsync -a --delete "$overlay_src/" "$overlay_dir/" 2>/dev/null || true
  # Neutral stub fuzz target (linking only; never used as generation context).
  cat >"$overlay_dir/hgb_introspector_stub.c" <<'EOF'
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) {
    return 0;
}
EOF
  local introspector_log="$workspace/logs/introspector_build.log"
  # Target-scoped introspector build: patch the project build.sh so only the
  # requested fuzz target is compiled under SANITIZER=introspector. Non-target
  # fuzzers can pull huge dependency trees (e.g. jsoncpp's proto fuzzer drags
  # in all of protobuf) and make the Fuzz Introspector analysis take hours.
  patch_introspector_build "$oss_fuzz_dir" "$project" "$fuzz_target"
  # Pass the HOST-visible overlay path to helper.py: it starts sibling build
  # containers through the host Docker socket, and /workspace/... paths only
  # exist inside this container. common.sh dual-mounts the workspace at its
  # host path, so HGB_WORKSPACE_HOST/... == /workspace/... here.
  local host_overlay_dir="${HGB_WORKSPACE_HOST:-$workspace}/introspector_overlay"
  # Prefer building from the project image with its clone pinned to the exact
  # FuzzBench revision. The image contains dependency builds (LPM etc.) that a
  # source overlay would shadow, so pinning the Dockerfile clone is the most
  # faithful build when the project Dockerfile clones its main repo.
  local pinned_commit="" primary_url=""
  read -r pinned_commit primary_url <<<"$("$python" - /target/source_repos.json <<'PY_OFG_PIN' 2>/dev/null || true
import json
import sys
from pathlib import Path
commit = ""
url = ""
try:
    records = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    for r in records if isinstance(records, list) else []:
        if r.get("is_primary_project"):
            commit = str(r.get("checked_out_commit") or r.get("revision") or "").strip()
            url = str(r.get("url") or "").strip()
            break
except Exception:
    pass
print(commit, url)
PY_OFG_PIN
  )"
  local clone_pinned="no_clone"
  # Projects whose FuzzBench-pinned commit predates the OSS-Fuzz build system
  # (freetype2's fuzzing/scripts/build-fuzzers.sh, harfbuzz's hb-raster-fuzzer
  # target, ...) cannot be built at the pinned commit; use the OSS-Fuzz
  # project.yaml clone for those instead (recorded deviation).
  local ofg_unpinned="${OFG_INTROSPECTOR_UNPINNED:-}"
  if [[ -n "$ofg_unpinned" ]] && [[ ",$ofg_unpinned," == *",$project,"* ]]; then
    clone_pinned="unpinned_by_override"
    printf 'ofg_introspector_note: project=%s uses the OSS-Fuzz unpinned clone (OFG_INTROSPECTOR_UNPINNED)\n' "$project" >>"$workspace/logs/introspector_build.log"
  fi
  if [[ "$clone_pinned" != "unpinned_by_override" && -n "$pinned_commit" && -f "$oss_fuzz_dir/projects/$project/Dockerfile" ]]; then
    clone_pinned="$("$python" - "$oss_fuzz_dir/projects/$project/Dockerfile" "$primary_url" "$pinned_commit" <<'PY_OFG_PIN_CLONE' 2>/dev/null || printf 'no_clone'
import re
import sys
from pathlib import Path
dockerfile = Path(sys.argv[1])
url, commit = sys.argv[2], sys.argv[3]
text = dockerfile.read_text(encoding="utf-8", errors="replace")

def norm(u: str) -> str:
    u = u.strip().rstrip("/")
    u = re.sub(r"^https?://(www\.)?github\.com/", "", u)
    u = re.sub(r"^https?://(www\.)?gitlab\.com/", "", u)
    u = re.sub(r"\.git$", "", u)
    return u.lower()

target = norm(url)
clone_re = re.compile(r"RUN\s+git\s+clone\b([^\n]*(?:\\\n[^\n]*)*)")
patched = False
if target:
    for m in clone_re.finditer(text):
        stmt = m.group(0)
        found = norm(next((u for u in re.findall(r"https?://\S+", stmt) if "github" in u or "gitlab" in u), "")) if re.findall(r"https?://\S+", stmt) else ""
        urls = [u for u in re.findall(r"https?://\S+", stmt)]
        if not any(norm(u) == target for u in urls):
            continue
        if f"checkout {commit}" in stmt or f"checkout {commit}" in text[m.end():m.end()+200]:
            patched = False
            print("already_pinned")
            sys.exit(0)
        # Full clone (drop --depth so old commits are reachable) + pinned checkout.
        new_stmt = re.sub(r"--depth(?:=|\s+)\S+\s*", "", stmt)
        # Resolve the clone destination: an explicit trailing argument wins
        # (git clone <url> lcms), otherwise the URL's repo basename.
        stmt_no_flags = re.sub(r"\s--?[A-Za-z-]+(?:=\S+)?", " ", new_stmt)
        tokens = [t for t in stmt_no_flags.replace("\\", " ").split() if t and not t.startswith("-")]
        url_idx = next((i for i, t in enumerate(tokens) if "://" in t), -1)
        dest_candidates = [t for t in tokens[url_idx + 1:] if not t.startswith("-")] if url_idx >= 0 else []
        if dest_candidates:
            dest = dest_candidates[0].rstrip("/").rsplit("/", 1)[-1]
            if dest.endswith(".git"):
                dest = dest[:-4]
        else:
            dest = target.rsplit("/", 1)[-1]
        lines = new_stmt.split("\n")
        last = lines[-1]
        if last.rstrip().endswith("\\"):
            last = last.rstrip()[:-1].rstrip() + f" && git -C {dest} checkout {commit} \\"
        else:
            last = last.rstrip() + f" && git -C {dest} checkout {commit}"
        lines[-1] = last
        text = text.replace(stmt, "\n".join(lines), 1)
        patched = True
        break
if patched:
    dockerfile.write_text(text, encoding="utf-8")
    print("patched")
else:
    print("no_clone")
PY_OFG_PIN_CLONE
  )"
  fi
  if [[ -x "$oss_fuzz_dir/infra/helper.py" ]]; then
    # introspector is a SANITIZER choice in helper.py (--sanitizer introspector),
    # never an engine. The report lands in build/out/<project>/inspector/.
    # Retry transient network failures (git clone / TLS) up to 3 times.
    local ofg_introspector_attempt=0
    local helper_extra_args=()
    if [[ "$clone_pinned" != "patched" && "$clone_pinned" != "already_pinned" && "$clone_pinned" != "unpinned_by_override" ]]; then
      helper_extra_args+=("$host_overlay_dir")
    fi
    while true; do
      ofg_introspector_attempt=$((ofg_introspector_attempt + 1))
      (cd "$oss_fuzz_dir" && python3 infra/helper.py build_fuzzers --sanitizer introspector \
          --architecture x86_64 \
          "$project" "${helper_extra_args[@]}" >"$introspector_log" 2>&1) && break
      if [[ "$ofg_introspector_attempt" -lt 3 ]] && grep -Eiq 'gnutls|TLS|non-properly terminated|Connection|temporary failure|Failed to fetch|Unable to fetch|SSL|timed out' "$introspector_log"; then
        printf 'ofg_introspector_retry: transient network failure (attempt %s); retrying\n' "$ofg_introspector_attempt" >>"$introspector_log"
        sleep $((ofg_introspector_attempt * 30))
        continue
      fi
      printf 'ofg_introspector_build_failed: introspector helper exited non-zero\n' >>"$introspector_log"
      return 1
    done
    # Projects whose Dockerfile WORKDIR is /src cannot take a local checkout
    # (helper.py refuses). Retry against the image-cloned source; the clone is
    # pinned to the exact FuzzBench revision when the patch above applied.
    if grep -q 'Cannot use local checkout' "$introspector_log"; then
      printf 'ofg_introspector_note: WORKDIR=/src project; rebuilding without local overlay\n' >>"$introspector_log"
      (cd "$oss_fuzz_dir" && python3 infra/helper.py build_fuzzers --sanitizer introspector \
          --architecture x86_64 \
          "$project" >"$introspector_log" 2>&1) || {
        printf 'ofg_introspector_build_failed: introspector helper exited non-zero\n' >>"$introspector_log"
        return 1
      }
    fi
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
  # The fuzz-introspector report uses its own file names
  # (all-fuzz-introspector-functions.json, calltree.js, all_debug_info.json).
  # Convert them to the canonical report files the adapter consumes when the
  # canonical names are absent.
  if [[ ! -f "$report_root/all_functions.json" ]]; then
    "$python" - "$report_root" "$introspector_dir" "$project" <<'PY_OFG_CONVERT_REPORT' >>"$introspector_log" 2>&1
import json
import sys
import time
from pathlib import Path
report = Path(sys.argv[1])
out_dir = Path(sys.argv[2])
project = sys.argv[3]
out_dir.mkdir(parents=True, exist_ok=True)
functions_raw = []
for name in ("all-fuzz-introspector-functions.json", "all_functions.js"):
    p = report / name
    if p.is_file():
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, dict):
                functions_raw = data.get("functions") or []
            elif isinstance(data, list):
                functions_raw = data
            if functions_raw:
                break
        except Exception:
            continue
all_functions = []
reachable: set[str] = set()
import re as _hgb_re
_CLEAN_NAME_RE = _hgb_re.compile(r"^[A-Za-z_][A-Za-z0-9_:~]*$")
for r in functions_raw:
    if not isinstance(r, dict):
        continue
    raw_name = str(r.get("Func name") or r.get("raw-function-name") or r.get("function_name") or "").strip()
    # The report's "Func name" includes the argument list; use the bare name
    # for filtering and keep the full signature separately.
    name = raw_name.split("(", 1)[0].strip()
    if not name:
        continue
    if "lambda" in name.lower() or not _CLEAN_NAME_RE.match(name):
        continue
    args = r.get("Args") or r.get("function_arguments") or []
    if not isinstance(args, list):
        args = []
    lines_hit = r.get("Func lines hit %")
    try:
        lines_hit = float(lines_hit or 0)
    except (TypeError, ValueError):
        lines_hit = 0.0
    callees = r.get("callsites") or r.get("Functions reached") or []
    if isinstance(callees, dict):
        callees = [str(k) for k in callees.keys()]
    if not isinstance(callees, list):
        callees = []
    reached_by = r.get("Reached by Fuzzers") or r.get("Combined reached by Fuzzers") or []
    if not isinstance(reached_by, list):
        reached_by = []
    rec = {
        "name": name,
        "signature": str(r.get("function_signature") or name),
        "source_file": str(r.get("Functions filename") or ""),
        "return_type": str(r.get("return_type") or ""),
        "function_arguments": [str(a) for a in args],
        "complexity": int(r.get("Cyclomatic complexity", 0) or 0),
        "covered": bool(lines_hit > 0),
        "callees": [str(c) for c in callees],
        "reached_by_fuzzers": [str(f) for f in reached_by],
        "public": bool(r.get("is_accessible")) or bool(r.get("is_public")),
    }
    all_functions.append(rec)
    for fz in reached_by:
        reachable.add(str(fz))
tree = [{"function_name": f, "children": []} for f in sorted(reachable)]
if not tree:
    tree = [{"function_name": r["name"], "children": []} for r in all_functions]
(out_dir / "all_functions.json").write_text(json.dumps(all_functions, indent=2) + "\n", encoding="utf-8")
(out_dir / "calltree.json").write_text(json.dumps({"tree": tree}, indent=2) + "\n", encoding="utf-8")
type_info: dict = {}
for name in ("all_debug_info.json", "type_info.json"):
    p = report / name
    if p.is_file():
        try:
            loaded = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            if isinstance(loaded, dict):
                type_info = loaded
                break
        except Exception:
            continue
(out_dir / "type_info.json").write_text(json.dumps(type_info, indent=2) + "\n", encoding="utf-8")
(out_dir / "report_manifest.json").write_text(json.dumps({
    "project": project,
    "mode": "real",
    "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}, indent=2) + "\n", encoding="utf-8")
print(f"ofg_introspector_report_converted: {len(all_functions)} functions")
PY_OFG_CONVERT_REPORT
  fi
  for f in all_functions.json calltree.json type_info.json report_manifest.json; do
    [[ -f "$report_root/$f" ]] && cp "$report_root/$f" "$introspector_dir/$f"
  done
  # Generate function_source_map.json if upstream did not emit it directly.
  if [[ ! -f "$report_root/function_source_map.json" ]]; then
    "$python" - "$introspector_dir" "$introspector_dir/function_source_map.json" "${HGB_TARGET_SOURCE_DIR:-/target/source_input}" <<'PY_OFG_FSM'
import json
import sys
from pathlib import Path
sys.path.insert(0, "/opt/hgb/bin")
from ofg_introspector_adapter import generate_function_source_map
# Parse the CONVERTED canonical report in $workspace/introspector, never the
# raw fuzz-introspector dir: the raw report uses its own record keys and the
# map would come out empty for every function.
report_dir, out_path, source_root = sys.argv[1:4]
mapping = generate_function_source_map(report_dir, source_root)
Path(out_path).write_text(json.dumps(mapping, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY_OFG_FSM
  else
    cp "$report_root/function_source_map.json" "$introspector_dir/function_source_map.json"
  fi
  # Record provenance: mode, commit, function count so the run result proves
  # the report is real (never a local shim).
  local function_count=0
  function_count="$("$python" - "$introspector_dir/all_functions.json" <<'PY_OFG_FCOUNT' 2>/dev/null || printf '0'
import json
import sys
from pathlib import Path
try:
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    funcs = data.get("functions") if isinstance(data, dict) else data
    print(len(funcs) if isinstance(funcs, list) else 0)
except Exception:
    print(0)
PY_OFG_FCOUNT
  )"
  "$python" - "$introspector_dir/provenance.json" "$project" "${OFG_INTROSPECTOR_MODE:-real}" \
    "${OFG_OSS_FUZZ_COMMIT:-unknown}" "$function_count" <<'PY_OFG_PROV'
import json
import sys
from pathlib import Path
out, project, mode, oss_commit, function_count = sys.argv[1:6]
Path(out).write_text(json.dumps({
    "mode": mode,
    "project": project,
    "oss_fuzz_commit": oss_commit,
    "function_count": int(function_count),
    "used_local_shim": False,
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY_OFG_PROV
  return 0
}

# ---------------------------------------------------------------------------
# Synthesize target-aware benchmark YAML from real Introspector data.
# Missing benchmark YAML must synthesize or fail, never soft-skip.
# ---------------------------------------------------------------------------
synthesize_benchmark_from_introspector() {
  local out_yaml="$1" selection_json="$2"
  local introspector_dir="$workspace/introspector"
  local project="${HGB_TARGET_PROJECT:-$(hgb_target_manifest_value project)}"
  local fuzz_target="${HGB_TARGET_FUZZ_TARGET:-$(hgb_target_manifest_value fuzz_target)}"
  local target_name="${HGB_TARGET:-$(hgb_target_manifest_value target)}"
  # Committed integration facts (metadata/oss_fuzz_gen_target_overrides.yaml):
  # the exact native harness destination in the OSS-Fuzz build context (so the
  # upstream build loop compiles the GENERATED harness, never the reference),
  # the language, and the per-target build timeout. These are static build
  # facts, not reference-derived content.
  local target_path="" language="" build_timeout="" preferred_apis=""
  read -r target_path language build_timeout preferred_apis <<<"$("$python" - /opt/hgb/metadata "$target_name" <<'PY_OFG_OVERRIDE' 2>/dev/null || true
import sys
from pathlib import Path
sys.path.insert(0, "/opt/hgb/bin")
from ofg_profile import load_target_overrides
overrides = load_target_overrides(Path(sys.argv[1]))
entry = overrides.get("targets", {}).get(sys.argv[2]) or {}
tpath = str(entry.get("candidate_destination") or "")
lang = str(entry.get("language") or "")
btimeout = str(entry.get("build_timeout") or "")
apis = ",".join(str(a) for a in (entry.get("preferred_apis") or []))
print(tpath, lang, btimeout, apis)
PY_OFG_OVERRIDE
  )"
  # The upstream OSS-Fuzz-Gen build loop COPYs the generated harness to
  # benchmark.target_path inside the OSS-Fuzz project image, so target_path
  # must be the path the OSS-Fuzz build.sh compiles -- the project's own
  # fuzzer file under /src (e.g. /src/zlib_uncompress_fuzzer.cc). Resolve it
  # from the pinned OSS-Fuzz project directory; the overrides value is only a
  # fallback (its FuzzBench-layout paths do not apply to the OSS-Fuzz build).
  local ofg_project_fuzzer=""
  if [[ -n "$fuzz_target" && -d "$oss_fuzz_dir/projects/$project" ]]; then
    ofg_project_fuzzer="$(find "$oss_fuzz_dir/projects/$project" -maxdepth 1 -type f \
      \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' \) -printf '%f\n' 2>/dev/null \
      | grep -E "^${fuzz_target}[^/]*\.(c|cc|cpp)$" | head -n 1 || true)"
  fi
  if [[ -n "$ofg_project_fuzzer" ]]; then
    target_path="/src/$ofg_project_fuzzer"
    case "$ofg_project_fuzzer" in
      *.c) language="c" ;;
      *) language="c++" ;;
    esac
  fi
  if [[ -n "$build_timeout" ]]; then
    export OFG_EVAL_BUILD_TIMEOUT="${OFG_EVAL_BUILD_TIMEOUT:-$build_timeout}"
  fi
  "$python" /opt/hgb/bin/ofg_benchmark_synthesis.py \
    --report-dir "$introspector_dir" \
    --source-dir "${HGB_TARGET_SOURCE_DIR:-/target/source_input}" \
    --project "$project" \
    --target-name "$target_name" \
    --fuzz-target "$fuzz_target" \
    --max-functions "${OFG_MAX_BENCHMARK_FUNCTIONS:-3}" \
    --target-path "$target_path" \
    --language "$language" \
    --preferred-apis "$preferred_apis" \
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
    # Build the evaluator args conditionally. Strict reproduction profiles
    # (reproduction-delta/epsilon/zeta/eta) must build a separate
    # coverage-instrumented image and replay the final campaign corpus
    # (HGB8 blocker / eta plan §2/§6). zeta/eta additionally run the native
    # coverage control to produce a line-coverage diff (eta plan §5).
    local ofg_evaluator_args=(
      --generator oss-fuzz-gen
      --target-root "${HGB_TARGET_PACKAGE:-/target}"
      --evaluator-root "$evaluator_root"
      --candidates "$workspace/generated_harnesses"
      --work-dir "$eval_dir"
      --project "${HGB_TARGET_PROJECT:-$(hgb_target_manifest_value project)}"
      --fuzz-target "${HGB_TARGET_FUZZ_TARGET:-$(hgb_target_manifest_value fuzz_target)}"
      --profile "$hgb_profile"
      --protocol "$hgb_protocol"
      --campaign-seconds "${OFG_CAMPAIGN_SECONDS:-60}"
      --build-timeout-seconds "${OFG_EVAL_BUILD_TIMEOUT:-1800}"
      --intended-apis "$selected_functions"
      --strict
    )
    case "$hgb_profile" in
      # Every non-compat profile must build a separate coverage-instrumented
      # image: the campaign image is SANITIZER=address and produces no
      # profraw, so reusing it for source-based coverage makes the coverage
      # stage fail for every candidate (alpha could never reach evaluated).
      alpha|paper-faithful|reproduction-gamma|reproduction-delta|reproduction-epsilon|reproduction-zeta|reproduction-eta)
        ofg_evaluator_args+=(--build-coverage-image)
        ;;
    esac
    case "$hgb_profile" in
      reproduction-zeta|reproduction-eta)
        ofg_evaluator_args+=(--run-native-control)
        ;;
    esac
    "$python" /opt/hgb/bin/hgb_harness_evaluator.py "${ofg_evaluator_args[@]}" \
      >"$workspace/logs/evaluator.log" 2>&1
    local ofg_eval_rc=$?
    if [[ "$ofg_eval_rc" -ne 0 ]]; then
      printf 'ofg_evaluator_failed: shared harness evaluator exited %s for profile=%s\n' \
        "$ofg_eval_rc" "$hgb_profile" >>"$workspace/logs/evaluator.log"
    fi
    return "$ofg_eval_rc"
  fi
  # Monolithic layout fallback (legacy): the monolithic ofg_evaluator cannot
  # compile the FuzzBench target (its build step runs no compile command) and
  # fabricates reachability evidence, so it must never produce an evaluated
  # row. Fail closed for EVERY profile instead of degrading to it.
  printf 'ofg_evaluator_failed: no split evaluator root found (HGB_EVALUATOR_ROOT/evaluator_only); the monolithic evaluator is unsupported and must never produce evidence\n' \
    >>"$workspace/logs/evaluator.log"
  return 65
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
  elif [[ "$hgb_profile" == "reproduction-gamma" || "$hgb_profile" == "reproduction-delta" || "$hgb_profile" == "reproduction-epsilon" || "$hgb_profile" == "reproduction-zeta" || "$hgb_profile" == "reproduction-eta" ]]; then
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
   patch_oss_fuzz_projects "$oss_fuzz_dir" || true

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
  # Upstream names samples ``NN.fuzz_target``; stage them with a real source
  # suffix so the evaluator's candidate filter accepts them. Prefer repaired
  # (fixed_targets) over first-generation samples and cap the set at
  # OFG_NUM_EVALUATIONS so the independent evaluation stays tractable.
  ofg_candidate_ext=".cc"
  ofg_benchmark_lang=""
  ofg_benchmark_lang="$(grep -m1 '^language:' "$benchmark_yaml" 2>/dev/null | awk '{print $2}' || true)"
  [[ "$ofg_benchmark_lang" == "c" ]] && ofg_candidate_ext=".c"
  ofg_candidate_max="${OFG_NUM_EVALUATIONS:-3}"
  if [[ -d "$HGB_GENERATION_WORK_DIR" ]]; then
    # Stage the samples that actually COMPILED in the upstream repair loop
    # (status/<trial>/result.json compiles=true), preferring repaired
    # (fixed_targets) files, one per function dir up to OFG_NUM_EVALUATIONS.
    # Staging the first sample of each dir instead feeds the evaluator
    # candidates the repair loop already rejected.
    "$python" - "$HGB_GENERATION_WORK_DIR" "$workspace/generated_harnesses" \
      "${OFG_NUM_EVALUATIONS:-3}" "$ofg_candidate_ext" <<'PY_OFG_STAGE'
import json
import shutil
import sys
from pathlib import Path
work = Path(sys.argv[1])
out = Path(sys.argv[2])
cap = max(1, int(sys.argv[3]))
ext = sys.argv[4]
out.mkdir(parents=True, exist_ok=True)
picks = []
for fdir in sorted(work.iterdir()):
    if not fdir.is_dir() or not fdir.name.startswith("output-"):
        continue
    fixed_dir = fdir / "fixed_targets"
    fuzz_dir = fdir / "fuzz_targets"
    status_dir = fdir / "status"
    compiled = []
    if status_dir.is_dir():
        for st in sorted(status_dir.iterdir()):
            if not st.is_dir():
                continue
            try:
                d = json.loads((st / "result.json").read_text(encoding="utf-8"))
            except Exception:
                continue
            if d.get("compiles"):
                compiled.append(st.name)
    for trial in compiled:
        src = fixed_dir / f"{trial}.fuzz_target"
        if not src.is_file():
            src = fuzz_dir / f"{trial}.fuzz_target"
        if src.is_file():
            picks.append((src, trial))
            break
    if not compiled:
        pool = sorted(fixed_dir.glob("*.fuzz_target")) if fixed_dir.is_dir() else []
        if not pool and fuzz_dir.is_dir():
            pool = sorted(fuzz_dir.glob("*.fuzz_target"))
        if pool:
            picks.append((pool[0], pool[0].stem))
n = 0
for src, trial in picks:
    if n >= cap:
        break
    n += 1
    shutil.copy2(src, out / f"{n}_{trial}.fuzz_target{ext}")
print(f"ofg_staged_candidates: {n}")
PY_OFG_STAGE
  fi
  if [[ "$(hgb_count_files "$workspace/generated_harnesses" -type f)" == "0" && -f "$workspace/logs/run.log" ]]; then
    "$python" - "$workspace/logs/run.log" "$workspace/generated_harnesses" "${OFG_NUM_EVALUATIONS:-3}" <<'PY_OFG_LOG_HARNESS' || true
import re
import sys
from pathlib import Path
log_path = Path(sys.argv[1])
out_dir = Path(sys.argv[2])
max_candidates = max(1, int(sys.argv[3] or 3))
text = log_path.read_text(encoding='utf-8', errors='replace')
blocks = re.findall(r"```(?:c\+\+|cpp|cc|c)?\s*\n(.*?)```", text, flags=re.S | re.I)
count = 0
out_dir.mkdir(parents=True, exist_ok=True)
for block in blocks:
    if 'LLVMFuzzerTestOneInput' not in block:
        continue
    if count >= max_candidates:
        break
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

  # --- Deterministic candidate rescue (upstream's own canonical fixers) ---
  # Strip LLM pollution tags (a leading <solution> tag provokes cascading
  # spurious errors), append extern "C" for C++ entries (upstream
  # append_extern_c), and apply small per-target declaration rescues. Every
  # change is recorded in rescue_audit.json. The fixes mirror upstream
  # llm_toolkit/code_fixer.collect_specific_fixes; they never touch the
  # harness semantics beyond making it compile/link.
  # The rescue must use the language of the NATIVE harness destination (what
  # the evaluator actually compiles): e.g. libpng's benchmark YAML says C but
  # the evaluator compiles the candidate as C++ at the .cc native path, so
  # extern "C" is required there.
  ofg_rescue_lang="$ofg_benchmark_lang"
  if [[ -f "${HGB_EVALUATOR_ROOT:-/evaluator}/native_harness_path.json" ]]; then
    ofg_rescue_lang="$("$python" - "${HGB_EVALUATOR_ROOT:-/evaluator}/native_harness_path.json" <<'PY_RES_LANG' 2>/dev/null || true
import json
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        value = str(json.load(f).get("language") or "").strip().lower()
    print("c++" if value in {"c++", "cpp", "cxx"} else ("c" if value == "c" else ""))
except Exception:
    print("")
PY_RES_LANG
  )"
  fi
  [[ -n "$ofg_rescue_lang" ]] || ofg_rescue_lang="$ofg_benchmark_lang"
  "$python" /opt/hgb/bin/ofg_rescue_candidates.py \
    --candidates-dir "$workspace/generated_harnesses" \
    --target "$target_name" \
    --language "$ofg_rescue_lang" \
    --audit-out "$workspace/generated_harnesses/rescue_audit.json" \
    >>"$workspace/logs/evaluator.log" 2>&1 || {
      reason="ofg_rescue_failed: candidate rescue step failed"
      hgb_ofg_set_stage candidate_build failed
      write_final_result failed "$reason" 65
      hgb_write_common_metadata failed "$reason" 65 harness_generator
      hgb_write_common_summary failed "$reason" harness_generator
      exit 65
    }
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
