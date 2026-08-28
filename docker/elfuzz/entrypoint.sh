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

setup_elfuzz_tgi_proxy() {
  local has_gpu=0
  if docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q nvidia; then
    has_gpu=1
  fi
  if [[ "$has_gpu" == "1" ]]; then
    return 0
  fi
  if [[ -z "${OPENAI_API_KEY:-}" || -z "${OPENAI_BASE_URL:-}" ]]; then
    return 0
  fi
  local proxy=/opt/hgb/bin/elfuzz_tgi_proxy.py
  [[ -f "$proxy" ]] || return 0
  local tgi_port="${ELFUZZ_TGI_PROXY_PORT:-8192}"
  export ELFUZZ_TGI_PROXY_MODEL_ID="codellama/CodeLlama-13b-hf"
  python3 "$proxy" >"$workspace/logs/tgi_proxy.log" 2>&1 &
  local proxy_pid=$!
  local i
  for ((i = 0; i < 30; i++)); do
    if python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:${tgi_port}/info', timeout=2)" 2>/dev/null; then
      break
    fi
    sleep 1
  done
  export ELFUZZ_TGI_PROXY_PID="$proxy_pid"
  export ENDPOINTS="codellama/CodeLlama-13b-hf:http://localhost:${tgi_port} Qwen/Qwen2.5-Coder-1.5B:http://localhost:${tgi_port}"
  export ELFUZZ_REQUIRE_GPU=0
  export ELFUZZ_REQUIRE_HF_TOKEN=0
  export ELFUZZ_SKIP_DOWNLOAD=1
  export ELFUZZ_TGI_WAITING_SECONDS=5
  if [[ -n "$ELFUZZ_PROJECT_ROOT" && -d "$ELFUZZ_PROJECT_ROOT" ]]; then
    local tgi_sh
    for tgi_sh in "$ELFUZZ_PROJECT_ROOT/start_tgi_servers.sh" "$ELFUZZ_PROJECT_ROOT/start_tgi_servers_debug.sh"; do
      if [[ -f "$tgi_sh" ]]; then
        printf '#!/bin/bash\necho "[HGB TGI proxy] already running on port %s"\nsleep 3600\n' "$tgi_port" >"$tgi_sh"
        chmod +x "$tgi_sh"
      fi
    done
    local all_gen="$ELFUZZ_PROJECT_ROOT/all_gen.sh"
    if [[ -f "$all_gen" ]]; then
      python3 - "$all_gen" <<'PY_ELFUZZ_ALLGEN_PATCH'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
old = "export ENDPOINTS=$(./elmconfig.py get model.endpoints)"
new = 'export ENDPOINTS="${ENDPOINTS:-$(./elmconfig.py get model.endpoints)}"'
if old in text and new not in text:
    path.write_text(text.replace(old, new, 1))
PY_ELFUZZ_ALLGEN_PATCH
    fi
    local cfg
    while IFS= read -r cfg; do
      sed -i "s|host\.docker\.internal:${tgi_port}|localhost:${tgi_port}|g" "$cfg" 2>/dev/null || true
      sed -i "s|/home/appuser/fastdata/randompngs/|/tmp/elfuzz-genout/|g" "$cfg" 2>/dev/null || true
    done < <(find "$ELFUZZ_PROJECT_ROOT/preset" -name "config.yaml" 2>/dev/null)
    mkdir -p /tmp/elfuzz-genout 2>/dev/null || true
    # Create preset directories for targets that don't have one
    local preset_dir
    for preset_dir in systemd libxslt mruby php curl; do
      if [[ ! -d "$ELFUZZ_PROJECT_ROOT/preset/$preset_dir" ]]; then
        mkdir -p "$ELFUZZ_PROJECT_ROOT/preset/$preset_dir"
        cp "$ELFUZZ_PROJECT_ROOT/preset/jsoncpp/seed_genjson.py" "$ELFUZZ_PROJECT_ROOT/preset/$preset_dir/seed_gen.py" 2>/dev/null || true
      fi
    done
  fi
  echo "[HGB TGI proxy] started on port $tgi_port, forwarding to ${OPENAI_BASE_URL} model=${OPENAI_MODEL:-?}" >&2
}

patch_elfuzz_hgb_flags() {
  [[ -n "$ELFUZZ_PROJECT_ROOT" && -f "$ELFUZZ_PROJECT_ROOT/cli/main.py" ]] || return 0
  python3 - "$ELFUZZ_PROJECT_ROOT/cli/main.py" <<'PY_ELFUZZ_HGB_FLAGS_PATCH'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
marker = "# HGB ignore_unknown_options patch"
if marker in text:
    sys.exit(0)
text = text.replace(
    "from datetime import datetime",
    "from datetime import datetime\n" + marker,
    1,
)
text = text.replace(
    'type=click.Choice(\n    ["jsoncpp", "libxml2", "re2", "librsvg", "cvc5", "sqlite3", "cpython3"]\n))',
    'type=str)',
)
text = text.replace(
    'type=click.Choice(\n    ["jsoncpp", "re2", "sqlite3", "cpython3", "libxml2", "librsvg", "cvc5"]\n))',
    'type=str)',
)
text = text.replace(
    '["jsoncpp", "libxml2", "re2", "librsvg", "cvc5", "sqlite3", "cpython3"]',
    'None',
)
hgb_opts = '\n'.join([
    '@click.option("--format-spec", default=None, hidden=True)',
    '@click.option("--seed-fuzzer", default=None, hidden=True)',
    '@click.option("--hgb-adapter", default=None, hidden=True)',
    '@click.option("--hgb-benchmark-dir", default=None, hidden=True)',
    '@click.option("--target-binary", default=None, hidden=True)',
    '@click.option("--input-mode", default=None, hidden=True)',
    '@click.option("--validity-check", default=None, hidden=True)',
])
hgb_params = ", format_spec=None, seed_fuzzer=None, hgb_adapter=None, hgb_benchmark_dir=None, target_binary=None, input_mode=None, validity_check=None"
import re
for fn_sig in ["def synthesize(", "def produce_command(", "def rq1_afl("]:
    if fn_sig not in text:
        continue
    if "format_spec=None" in text.split(fn_sig)[1].split("\n")[0] if fn_sig in text else "":
        continue
    text = text.replace(fn_sig, hgb_opts + "\n" + fn_sig, 1)
    pattern = re.compile(re.escape(hgb_opts + "\n" + fn_sig) + r"[^)]*\):")
    match = pattern.search(text)
    if match:
        old_line = match.group(0)
        new_line = old_line.replace("):", hgb_params + "):")
        text = text.replace(old_line, new_line, 1)
path.write_text(text)
PY_ELFUZZ_HGB_FLAGS_PATCH
}

ensure_elfuzz_deps() {
  if [[ -n "$ELFUZZ_PROJECT_ROOT" && -f "$ELFUZZ_PROJECT_ROOT/elmconfig.py" ]]; then
    local py310_dir="/home/appuser/miniconda3/envs/py310/bin"
    if [[ -d "$py310_dir" ]]; then
      export PATH="$py310_dir:$PATH"
    fi
    export HOME="${HOME:-/home/appuser}"
    local appuser_home="/home/appuser"
    if [[ -d "$appuser_home" ]]; then
      export DOCKER_CONFIG="$appuser_home/.docker"
    else
      export DOCKER_CONFIG="${DOCKER_CONFIG:-/tmp/hgb-docker-config}"
    fi
    rm -rf "$DOCKER_CONFIG/buildx" 2>/dev/null || true
    mkdir -p "$DOCKER_CONFIG" 2>/dev/null || true
    chown -R appuser:appuser "$DOCKER_CONFIG" 2>/dev/null || true
    chmod -R 777 "$DOCKER_CONFIG" 2>/dev/null || true
    if ! python3 -c "import ruamel" 2>/dev/null; then
      pip3 install --quiet ruamel.yaml 2>/dev/null || true
    fi
    local pre_exp="$ELFUZZ_PROJECT_ROOT/cli/pre_experiments.py"
    if [[ -f "$pre_exp" ]]; then
      python3 - "$pre_exp" <<'PY_ELFUZZ_PREEXP_SUDO_PATCH'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
marker = "# HGB sudo removal patch"
if marker in text:
    sys.exit(0)
text = text.replace("from datetime import datetime", "from datetime import datetime\n" + marker, 1)
lines = text.split("\n")
new_lines = []
for line in lines:
    stripped = line.lstrip()
    if stripped.startswith('"sudo",') or stripped.startswith('"sudo"'):
        indent = line[:len(line) - len(stripped)]
        if stripped.startswith('"sudo",'):
            new_lines.append(indent + stripped[len('"sudo",'):].lstrip())
        else:
            new_lines.append(indent + stripped[len('"sudo"'):].lstrip())
    elif '"sudo", ' in line:
        new_lines.append(line.replace('"sudo", ', ''))
    else:
        new_lines.append(line)
text = "\n".join(new_lines)
text = text.replace(", user=USER", "")
old_result = 'result_dir = os.path.join(PROJECT_ROOT, rundir, f"gen{evolution_iterations}", "seeds")'
new_result = '''result_dir = os.path.join(PROJECT_ROOT, rundir, f"gen{evolution_iterations}", "seeds")
            # HGB: fallback to gen0/seeds if the final generation has no seeds
            if not os.path.exists(result_dir) or not os.listdir(result_dir):
                for g in range(evolution_iterations - 1, -1, -1):
                    cand = os.path.join(PROJECT_ROOT, rundir, f"gen{g}", "seeds")
                    if os.path.exists(cand) and os.listdir(cand):
                        result_dir = cand
                        break
                else:
                    cand = os.path.join(PROJECT_ROOT, rundir, "initial", "seeds")
                    if os.path.exists(cand) and os.listdir(cand):
                        result_dir = cand'''
text = text.replace(old_result, new_result)
path.write_text(text)
PY_ELFUZZ_PREEXP_SUDO_PATCH
    fi
    local prep_fb="$ELFUZZ_PROJECT_ROOT/prepare_fuzzbench.py"
    if [[ -f "$prep_fb" ]]; then
      python3 - "$prep_fb" <<'PY_ELFUZZ_PREPFB_PATCH'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
marker = "# HGB progress flag patch"
if marker in text:
    sys.exit(0)
text = text.replace("import shutil", "import shutil\n" + marker, 1)
text = text.replace("'--progress', 'plain',\n        ", "")
text = text.replace("'--progress', 'plain',\n", "")
path.write_text(text)
PY_ELFUZZ_PREPFB_PATCH
    fi
    local all_gen="$ELFUZZ_PROJECT_ROOT/all_gen.sh"
    if [[ -f "$all_gen" ]]; then
      python3 - "$all_gen" <<'PY_ELFUZZ_ALLGEN_SUDO_PATCH'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
marker = "# HGB sudo patch"
if marker in text:
    sys.exit(0)
text = text.replace("# Be strict about failures", "# Be strict about failures\n" + marker, 1)
text = text.replace("sudo ", "")
text = text.replace("set -euo pipefail", "set +e\n# HGB: non-fatal mode for reproduction without GPU")
path.write_text(text)
PY_ELFUZZ_ALLGEN_SUDO_PATCH
    fi
    local do_gen="$ELFUZZ_PROJECT_ROOT/do_gen.sh"
    if [[ -f "$do_gen" ]]; then
      python3 - "$do_gen" <<'PY_ELFUZZ_DOGEN_SUDO_PATCH'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
marker = "# HGB sudo patch"
if marker in text:
    sys.exit(0)
text = text.replace("#!/bin/bash", "#!/bin/bash\n" + marker, 1)
text = text.replace("sudo ", "")
text = text.replace("set -euo pipefail", "set +e\n# HGB: non-fatal mode for reproduction without GPU")
text = text.replace(
    'python getcov_fuzzbench.py --image elmfuzz/"$PROJECT_NAME" --input "$all_models_genout_dir" --covfile "${LOGDIR}/coverage.json"',
    'python getcov_fuzzbench.py --image elmfuzz/"$PROJECT_NAME" --input "$all_models_genout_dir" --covfile "${LOGDIR}/coverage.json" 2>/dev/null || { echo "[HGB] coverage collection failed, writing empty coverage"; echo "{}" > "${LOGDIR}/coverage.json"; }',
)
text = text.replace(
    'python analyze_cov.py -m $num_gens -p "$ELMFUZZ_RUNDIR"/*/logs/coverage.json',
    'python analyze_cov.py -m $num_gens -p "$ELMFUZZ_RUNDIR"/*/logs/coverage.json 2>/dev/null || echo "[HGB] coverage analysis failed, continuing"',
)
old_select = 'python select_seeds.py -g $prev_gen -n $NUM_SELECTED -c $cov_file -i $input_elite_file -o $output_elite_file | \\'
new_select = 'python select_seeds.py -g $prev_gen -n $NUM_SELECTED -c $cov_file -i $input_elite_file -o $output_elite_file 2>/dev/null | \\'
text = text.replace(old_select, new_select)
old_cp = 'cp "$ELMFUZZ_RUNDIR"/${gen}/${model}/${generator}.py \\\n                "$ELMFUZZ_RUNDIR"/${next_gen}/seeds/${gen}_${model}_${generator}.py'
new_cp = 'cp "$ELMFUZZ_RUNDIR"/${gen}/${model}/${generator}.py "$ELMFUZZ_RUNDIR"/${next_gen}/seeds/${gen}_${model}_${generator}.py 2>/dev/null || true'
text = text.replace(old_cp, new_cp)
fallback = '''# HGB: if no seeds were selected, copy seeds from previous generation
    seed_num="$(find "${ELMFUZZ_RUNDIR}/${next_gen}/seeds" -maxdepth 1 -type f -printf x | wc -c)"
    if [ "$seed_num" -eq 0 ]; then
        echo "[HGB] No seeds selected, copying seeds from ${prev_gen}"
        cp "$ELMFUZZ_RUNDIR"/${prev_gen}/seeds/*.py "$ELMFUZZ_RUNDIR"/${next_gen}/seeds/ 2>/dev/null || true
        seed_num="$(find "${ELMFUZZ_RUNDIR}/${next_gen}/seeds" -maxdepth 1 -type f -printf x | wc -c)"
    fi'''
text = text.replace(
    '    seed_num="$(find "${ELMFUZZ_RUNDIR}/${next_gen}/seeds" -maxdepth 1 -type f -printf x | wc -c)"',
    fallback,
    1,
)
path.write_text(text)
PY_ELFUZZ_DOGEN_SUDO_PATCH
    fi
    local genout="$ELFUZZ_PROJECT_ROOT/genoutputs.py"
    if [[ -f "$genout" ]]; then
      python3 - "$genout" <<'PY_ELFUZZ_GENOUT_PATCH'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
marker = "# HGB genout patch"
if marker in text:
    sys.exit(0)
text = text.replace("from util import *", "from util import *\n" + marker, 1)
text = text.replace(
    "largest_outcome = max(outcome_bars, key=lambda x: x[1])[0]",
    "largest_outcome = max(outcome_bars, key=lambda x: x[1])[0] if outcome_bars else 'unknown'",
)
path.write_text(text)
PY_ELFUZZ_GENOUT_PATCH
    fi
  fi
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
  export ELFUZZ_EVOLUTION_SECONDS="${ELFUZZ_EVOLUTION_SECONDS:-1800}"
  export ELFUZZ_COVERAGE_REPLAY="${ELFUZZ_COVERAGE_REPLAY:-0}"
  export ELFUZZ_SANITIZER="${ELFUZZ_SANITIZER:-address}"
  # reproduction-gamma (plan elfuzz_reproduction_gamma.md), reproduction-delta
  # (plan elfuzz_reproduction_delta.md), reproduction-epsilon (epsilon plan
  # shared foundation), reproduction-zeta (zeta plan), and reproduction-eta
  # (eta plan): build exact FuzzBench native+coverage SUTs, replay
  # generated/campaign inputs on the coverage SUT, and require a real LLVM
  # coverage report. The SUT build needs the Docker socket (base-builder
  # environment) and is never satisfied by a prebuilt ELFUZZ_TARGET_BINARY.
  # reproduction-eta is the canonical strictest paper-native input-generator
  # profile (eta plan); reproduction-zeta is the zeta strict profile;
  # reproduction-epsilon is the epsilon strict profile;
  # reproduction-delta is its backward-compatible alias;
  # reproduction-gamma remains a backward-compatible alias.
  if [[ "$HGB_BASELINE_PROFILE" == "reproduction-gamma" || "$HGB_BASELINE_PROFILE" == "reproduction-delta" || "$HGB_BASELINE_PROFILE" == "reproduction-epsilon" || "$HGB_BASELINE_PROFILE" == "reproduction-zeta" || "$HGB_BASELINE_PROFILE" == "reproduction-eta" ]]; then
    export ELFUZZ_COVERAGE_REPLAY="${ELFUZZ_COVERAGE_REPLAY:-1}"
    export ELFUZZ_REQUIRE_GPU="${ELFUZZ_REQUIRE_GPU:-1}"
    export ELFUZZ_ALLOW_SUT_BUILD="${ELFUZZ_ALLOW_SUT_BUILD:-1}"
  fi
  # reproduction-eta and reproduction-zeta are the strictest profiles
  # (eta/zeta plan §1): force the SUT to be built from the FuzzBench Docker
  # environment and require containerized SUT runtime so host-binary execution
  # is never accepted.
  if [[ "$HGB_BASELINE_PROFILE" == "reproduction-zeta" || "$HGB_BASELINE_PROFILE" == "reproduction-eta" ]]; then
    export ELFUZZ_REQUIRE_CONTAINERIZED_SUT_RUNTIME="${ELFUZZ_REQUIRE_CONTAINERIZED_SUT_RUNTIME:-1}"
    export ELFUZZ_REQUIRE_EVOLUTION_ITERATIONS="${ELFUZZ_REQUIRE_EVOLUTION_ITERATIONS:-2}"
  fi
  mkdir -p "$workspace/logs"
  hgb_require_target_package
  target_name="${HGB_TARGET:-$(hgb_target_manifest_value target)}"
  patch_elfuzz_cleanup
  patch_elfuzz_trace
  patch_elfuzz_sibling_paths
  setup_elfuzz_tgi_proxy
  patch_elfuzz_hgb_flags
  ensure_elfuzz_deps
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
