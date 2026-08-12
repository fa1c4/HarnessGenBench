#!/usr/bin/env bash
set -euo pipefail

artifact=/opt/hgb/artifacts/promefuzz
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
mode="${1:-smoke-pugixml}"
mkdir -p "$workspace/logs" "$workspace/artifacts" /run/hgb
json_escape() { local v="${1:-}"; v="${v//\\/\\\\}"; v="${v//\"/\\\"}"; v="${v//$'\n'/\\n}"; printf '%s' "$v"; }
count_files() { local d="$1"; shift || true; [[ -d "$d" ]] || { printf '0'; return 0; }; find "$d" "$@" 2>/dev/null | wc -l | tr -d ' '; }
commit() { git -C "$artifact" rev-parse HEAD 2>/dev/null || printf unknown; }
promefuzz_processors_ready() {
  [[ -x "$1/build/bin/preprocessor" && -x "$1/build/bin/cgprocessor" ]]
}
compile_db_has_entries() {
  local db="$1"
  [[ -f "$db" ]] || return 1
  python3 - "$db" <<'PY_COMPILE_DB_CHECK' >/dev/null 2>&1
import json
import sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(1)
sys.exit(0 if isinstance(data, list) and len(data) > 0 else 1)
PY_COMPILE_DB_CHECK
}
filter_compile_db() {
  local db="$1" phase="$2" result
  [[ -f "$db" ]] || return 0
  if ! result="$("$python" /opt/hgb/bin/hgb_compile_db.py --input "$db" --output "$db" --source-root /target/source_input --source-root "$workspace/build_context/src" --source-root "$workspace/promefuzz_build/src" 2>&1)"; then
    printf 'Could not filter %s compile_commands.json: %s\n' "$phase" "$result" >>"$workspace/logs/compile_commands.log"
    return 1
  fi
  printf 'Filtered %s compile_commands.json: %s\n' "$phase" "$result" >>"$workspace/logs/compile_commands.log"
}

write_synthetic_compile_db() {
  local db="$1" language="$2" project="$3"
  mkdir -p "$(dirname "$db")"
  python3 - "$db" "$language" "$project" <<'PY_SYNTHETIC_COMPILE_DB'
import json
import shlex
import sys
from pathlib import Path

db, language, project = sys.argv[1:4]
root = Path("/target/source_input")
source_exts = {".c", ".cc", ".cpp", ".cxx"}
header_exts = {".h", ".hh", ".hpp", ".hxx"}
ignored_parts = {
    ".git", ".hg", ".svn", "build", "cmake-build-debug",
    "cmake-build-release", "out", "workspace",
}
include_dirs: list[Path] = []

def add_include(path: Path) -> None:
    if path.exists() and path.is_dir() and path not in include_dirs:
        include_dirs.append(path)

add_include(root)
if project:
    add_include(root / project)
    add_include(root / project / "include")
    add_include(root / project / "src")
for child in (root.rglob("*") if root.exists() else []):
    if not child.is_dir():
        continue
    if any(part in ignored_parts for part in child.parts):
        continue
    if child.name in {"include", "inc", "src"}:
        add_include(child)
for header in (root.rglob("*") if root.exists() else []):
    if len(include_dirs) >= 120:
        break
    if header.is_file() and header.suffix.lower() in header_exts:
        if not any(part in ignored_parts for part in header.parts):
            add_include(header.parent)

include_args = [f"-I{path}" for path in include_dirs]
entries = []
for source in sorted(root.rglob("*") if root.exists() else []):
    if not source.is_file() or source.suffix.lower() not in source_exts:
        continue
    if any(part in ignored_parts for part in source.parts):
        continue
    suffix = source.suffix.lower()
    is_c = suffix == ".c" and language == "c"
    compiler = "clang" if is_c else "clang++"
    std = "-std=c11" if is_c else "-std=c++17"
    args = [compiler, std, "-D_FORTIFY_SOURCE=0", *include_args, "-c", str(source), "-o", "/tmp/hgb-promefuzz-null.o"]
    entries.append({
        "directory": str(source.parent),
        "file": str(source),
        "arguments": args,
        "command": shlex.join(args),
    })
Path(db).write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
print(len(entries))
PY_SYNTHETIC_COMPILE_DB
}
stage_fuzzbench_source() {
  local destination="$1" benchmark=/target/fuzzbench_benchmark child name
  rm -rf "$destination"
  mkdir -p "$destination"
  cp -a /target/source_input/. "$destination/"
  while IFS= read -r -d '' child; do
    name="$(basename "$child")"
    case "$name" in Dockerfile|benchmark.yaml|.dockerignore) continue ;; esac
    rm -rf "$destination/$name"
    cp -a "$child" "$destination/$name"
  done < <(find "$benchmark" -mindepth 1 -maxdepth 1 -print0)
}

fuzzbench_build_workdir() {
  local dockerfile="${1:-/target/fuzzbench_benchmark/Dockerfile}" raw workdir=""
  [[ -f "$dockerfile" ]] || return 0
  while IFS= read -r raw; do
    [[ -n "$raw" ]] || continue
    case "$raw" in
      /src) workdir="" ;;
      /src/*) workdir="${raw#/src/}" ;;
      '$SRC'|'${SRC}') workdir="" ;;
      '${SRC}/'*) workdir="${raw#'${SRC}/'}" ;;
      /*) return 0 ;;
      ..|../*|*/../*|*/..) return 0 ;;
      '$SRC/'*) workdir="${raw#'$SRC/'}" ;;
      *) workdir="${workdir:+$workdir/}$raw" ;;
    esac
  done < <(awk '
    toupper($1) == "WORKDIR" {
      $1 = ""
      sub(/^[[:space:]]+/, "")
      sub(/[[:space:]]+#.*/, "")
      print
    }
  ' "$dockerfile")
  printf '%s\n' "$workdir"
}

fuzzbench_target_build_available() {
  local build_script="${1:-/target/fuzzbench_benchmark/build.sh}"
  [[ -f "$build_script" ]] || return 1
  ! grep -Fq 'FuzzBench benchmark did not include a top-level build.sh; target build is unavailable for this package.' "$build_script"
}

is_positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

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

# ---------------------------------------------------------------------------
# PromeFuzz profile/stage/result helpers (alpha/paper-faithful/compat-smoke)
# ---------------------------------------------------------------------------

promefuzz_stages_file() { printf '%s/promefuzz_stages.json' "$workspace"; }

promefuzz_init_stages() {
  "$python" - "$(promefuzz_stages_file)" <<'PY_PROMEFUZZ_INIT_STAGES'
import json
import sys
from pathlib import Path
sys.path.insert(0, "/opt/hgb/bin")
import promefuzz_profile
Path(sys.argv[1]).write_text(json.dumps(promefuzz_profile.default_stages(), indent=2) + "\n", encoding="utf-8")
PY_PROMEFUZZ_INIT_STAGES
}

promefuzz_set_stage() {
  local name="$1" state="${2:-completed}"
  "$python" - "$(promefuzz_stages_file)" "$name" "$state" <<'PY_PROMEFUZZ_SET_STAGE'
import json
import sys
from pathlib import Path
sys.path.insert(0, "/opt/hgb/bin")
import promefuzz_profile
p = Path(sys.argv[1])
try:
    stages = json.loads(p.read_text(encoding="utf-8"))
except Exception:
    stages = promefuzz_profile.default_stages()
promefuzz_profile.mark_stage(stages, sys.argv[2], sys.argv[3])
p.write_text(json.dumps(stages, indent=2) + "\n", encoding="utf-8")
PY_PROMEFUZZ_SET_STAGE
}

promefuzz_result_status() {
  "$python" - "$(promefuzz_stages_file)" <<'PY_PROMEFUZZ_RESULT_STATUS'
import json
import sys
from pathlib import Path
sys.path.insert(0, "/opt/hgb/bin")
import promefuzz_profile
try:
    stages = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except Exception:
    stages = promefuzz_profile.default_stages()
print(promefuzz_profile.result_status_from_stages(stages))
PY_PROMEFUZZ_RESULT_STATUS
}

promefuzz_write_config() {
  local cfg="$1"
  cat >"$cfg" <<EOF_PROMEFUZZ_CONFIG
[comprehender]
embedding_llm = "hgb_embedding"
comprehension_llm = "hgb_cloud"

[generator]
generation_llm = "hgb_cloud"

[analyzer]
analysis_llm = "hgb_cloud"

[llm]
default_llm = "hgb_cloud"
validate_llm = false
enable_log = true

[llm.hgb_cloud]
llm_type = "openai"
base_url = "${OPENAI_BASE_URL:-https://api.openai.com/v1}"
api_key = "${OPENAI_API_KEY:-}"
model = "${OPENAI_MODEL:-}"
temperature = 0.0
max_tokens = -1
timeout = ${PROME_FUZZ_LLM_REQUEST_TIMEOUT_SECONDS:-${HGB_LLM_REQUEST_TIMEOUT_SECONDS:-1200}}
retry_times = ${PROME_FUZZ_LLM_RETRY_TIMES:-3}

[llm.hgb_embedding]
llm_type = "${PROME_FUZZ_EMBEDDING_LLM_TYPE:-mock}"
host = "${PROME_FUZZ_EMBEDDING_HOST:-localhost}"
port = ${PROME_FUZZ_EMBEDDING_PORT:-11434}
base_url = "${PROME_FUZZ_EMBEDDING_BASE_URL:-${OPENAI_BASE_URL:-https://api.openai.com/v1}}"
api_key = "${PROME_FUZZ_EMBEDDING_API_KEY:-${OPENAI_API_KEY:-}}"
model = "${PROME_FUZZ_EMBEDDING_MODEL:-hgb-hash-embedding}"
temperature = 0.0
max_tokens = ${PROME_FUZZ_EMBEDDING_MAX_TOKENS:--1}
timeout = ${PROME_FUZZ_EMBEDDING_TIMEOUT:-60}
retry_times = ${PROME_FUZZ_EMBEDDING_RETRY_TIMES:-3}
EOF_PROMEFUZZ_CONFIG
  printf '%s\n' "$cfg"
}

promefuzz_embedding_preflight() {
  local log_file="$1"
  [[ "${PROME_FUZZ_EMBEDDING_PREFLIGHT:-1}" == "1" ]] || return 0
  "$python" - >"$log_file" 2>&1 <<'PY_PROMEFUZZ_EMBEDDING_PREFLIGHT'
import json
import os
import sys
import urllib.error
import urllib.request

api_key = os.getenv("PROME_FUZZ_EMBEDDING_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("API_KEY") or ""
model = os.getenv("PROME_FUZZ_EMBEDDING_MODEL") or ""
base_url = os.getenv("PROME_FUZZ_EMBEDDING_BASE_URL") or os.getenv("OPENAI_BASE_URL") or os.getenv("BASE_URL") or ""
llm_type = (os.getenv("PROME_FUZZ_EMBEDDING_LLM_TYPE") or "").strip().lower()
timeout = float(os.getenv("PROME_FUZZ_EMBEDDING_TIMEOUT") or "60")

if llm_type in {"mock", "local", "hash"}:
    print("embedding_preflight_skipped: mock/local/hash embedding is compat-smoke only")
    sys.exit(0)

if llm_type == "ollama":
    host = os.getenv("PROME_FUZZ_EMBEDDING_HOST", "localhost")
    port = os.getenv("PROME_FUZZ_EMBEDDING_PORT", "11434")
    url = f"http://{host}:{port}/api/embeddings"
    payload = json.dumps({"model": model or "nomic-embed-text", "prompt": "hgb"}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
else:
    if not base_url:
        print("embedding_preflight_failed: missing base_url")
        sys.exit(1)
    url = base_url.rstrip("/") + "/embeddings"
    payload = json.dumps({"model": model, "input": "hgb"}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(url, data=payload, headers=headers)

try:
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", "replace")
    if resp.status == 200:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = {}
        dims = 0
        if isinstance(data, dict):
            emb = data.get("data") or data.get("embedding") or data.get("embeddings")
            if isinstance(emb, list) and emb and isinstance(emb[0], list):
                dims = len(emb[0])
            elif isinstance(emb, list):
                dims = len(emb)
        print(json.dumps({"ok": True, "model": model, "dimensions": dims, "endpoint_class": "ollama" if llm_type == "ollama" else "openai-compatible"}))
        sys.exit(0)
    print(f"embedding_preflight_failed: HTTP {resp.status}")
    sys.exit(1)
except urllib.error.HTTPError as exc:
    print(f"embedding_preflight_failed: HTTP {exc.code} {exc.reason}")
    sys.exit(1)
except (urllib.error.URLError, OSError, TimeoutError) as exc:
    print(f"embedding_preflight_failed: {type(exc).__name__}: {exc}")
    sys.exit(1)
PY_PROMEFUZZ_EMBEDDING_PREFLIGHT
}

promefuzz_write_final_result() {
  local status="$1" reason="$2" exit_code="$3" leakage_json="${4:-{\}}"
  local profile="${HGB_BASELINE_PROFILE:-${HGB_PROFILE:-alpha}}"
  local protocol="${HGB_BASELINE_PROTOCOL:-${HGB_PROTOCOL:-blind-project}}"
  local target="${HGB_TARGET:-$(hgb_target_manifest_value target)}"
  local method_variant="$profile" excluded=false
  [[ "$profile" == "compat-smoke" ]] && { method_variant="compat-smoke"; excluded=true; }
  [[ "$profile" == "reproduction-gamma" ]] && method_variant="paper-faithful"
  [[ "$profile" == "reproduction-delta" ]] && method_variant="paper-faithful"
  [[ "$profile" == "reproduction-epsilon" ]] && method_variant="paper-faithful"
  [[ "$profile" == "reproduction-zeta" ]] && method_variant="paper-faithful"
  [[ "$profile" == "reproduction-eta" ]] && method_variant="paper-faithful"
  PROME_FUZZ_PROFILE="$profile" PROME_FUZZ_PROTOCOL="$protocol" PROME_FUZZ_TARGET="$target" \
  PROME_FUZZ_STATUS="$status" PROME_FUZZ_REASON="$reason" PROME_FUZZ_CODE="$exit_code" \
  PROME_FUZZ_METHOD="$method_variant" PROME_FUZZ_EXCLUDED="$excluded" \
  PROME_FUZZ_LEAKAGE="$leakage_json" \
  PROME_FUZZ_METRICS="${PROME_FUZZ_EVALUATOR_METRICS:-}" \
  PROME_FUZZ_SELECTED="${PROME_FUZZ_EVALUATOR_SELECTED:-}" \
  PROME_FUZZ_CANDIDATE_COUNT="${PROME_FUZZ_CANDIDATE_COUNT:-0}" \
    "$python" - "$workspace/result.json" "$(promefuzz_stages_file)" "$(commit)" <<'PY_PROMEFUZZ_WRITE_FINAL'
import json
import os
import sys
from pathlib import Path
sys.path.insert(0, "/opt/hgb/bin")
import promefuzz_profile
out = Path(sys.argv[1])
stages_path = Path(sys.argv[2])
ofg_commit = sys.argv[3]
try:
    stages = json.loads(stages_path.read_text(encoding="utf-8"))
except Exception:
    stages = promefuzz_profile.default_stages()
try:
    leakage = json.loads(os.environ.get("PROME_FUZZ_LEAKAGE", "{}") or "{}")
except Exception:
    leakage = {}
try:
    metrics = json.loads(os.environ.get("PROME_FUZZ_METRICS", "") or "{}")
except Exception:
    metrics = {}
try:
    selected = json.loads(os.environ.get("PROME_FUZZ_SELECTED", "") or "{}")
except Exception:
    selected = {}
try:
    candidate_count = int(os.environ.get("PROME_FUZZ_CANDIDATE_COUNT", "0") or "0")
except ValueError:
    candidate_count = 0
result = promefuzz_profile.build_result(
    profile=os.environ["PROME_FUZZ_PROFILE"],
    protocol=os.environ["PROME_FUZZ_PROTOCOL"],
    target=os.environ["PROME_FUZZ_TARGET"],
    status=os.environ["PROME_FUZZ_STATUS"],
    reason=os.environ["PROME_FUZZ_REASON"],
    stages=stages,
    method_variant=os.environ["PROME_FUZZ_METHOD"],
    excluded_from_aggregate=os.environ["PROME_FUZZ_EXCLUDED"] == "true",
    reference_leakage_audit=leakage,
    metrics=metrics,
    selected_candidate=selected,
    candidate_count=candidate_count,
    provenance={
        "promefuzz_commit": ofg_commit,
        "fuzzbench_commit": os.environ.get("HGB_FUZZBENCH_COMMIT", ""),
        "embedding_model": os.environ.get("PROME_FUZZ_EMBEDDING_MODEL", ""),
        "embedding_llm_type": os.environ.get("PROME_FUZZ_EMBEDDING_LLM_TYPE", ""),
        "build_context_method": os.environ.get("PROME_FUZZ_BUILD_CONTEXT_METHOD", "auto"),
        "all_cover_candidates": os.environ.get("PROME_FUZZ_ALL_COVER_CANDIDATES", ""),
        "all_cover_max_wall_seconds": os.environ.get("PROME_FUZZ_ALL_COVER_MAX_WALL_SECONDS", ""),
        "generation_budget_seconds": os.environ.get("PROME_GENERATION_BUDGET_SECONDS", ""),
        "max_candidates": os.environ.get("PROME_MAX_CANDIDATES", ""),
        "campaign_seconds": os.environ.get("HGB_CAMPAIGN_SECONDS", ""),
        "consumer_cases_status": os.environ.get("PROME_FUZZ_CONSUMER_CASES_STATUS", ""),
    },
    method={
        "compile_db": {
            "strategy": os.environ.get("PROME_FUZZ_COMPILE_DB_STRATEGY", ""),
            "count": int(os.environ.get("PROME_FUZZ_COMPILE_DB_COUNT", "0") or "0"),
        },
        "link_context": {
            "driver_build_args_count": int(os.environ.get("PROME_FUZZ_DRIVER_BUILD_ARGS_COUNT", "0") or "0"),
        },
        "consumer_knowledge": {
            "enabled": os.environ.get("PROME_FUZZ_CONSUMER_CASES_STATUS", "") == "available",
            "artifacts_nonempty": os.environ.get("PROME_FUZZ_CONSUMER_ARTIFACTS_NONEMPTY", "") == "true",
        },
        "embedding": {
            "provider": os.environ.get("PROME_FUZZ_EMBEDDING_LLM_TYPE", ""),
            "model": os.environ.get("PROME_FUZZ_EMBEDDING_MODEL", ""),
        },
        "generation_mode": os.environ.get("PROME_FUZZ_GENERATION_MODE", "ALL-COVER"),
    },
)
out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY_PROMEFUZZ_WRITE_FINAL
}

summary() {
  local status="$1" code="$2" reason="$3"
  {
    printf '# HarnessGenBench PromeFuzz Summary\n\n'
    printf -- '- Run directory: `%s`\n' "$workspace"
    printf -- '- Upstream commit: `%s`\n' "$(commit)"
    printf -- '- Target: `%s`\n' "${HGB_TARGET:-unknown}"
    printf -- '- Profile: `%s`\n' "${HGB_BASELINE_PROFILE:-${HGB_PROFILE:-alpha}}"
    printf -- '- Protocol: `%s`\n' "${HGB_BASELINE_PROTOCOL:-${HGB_PROTOCOL:-blind-project}}"
    printf -- '- Status: `%s`\n' "$status"
    printf -- '- Exit code: `%s`\n' "$code"
    printf -- '- API key present: `%s`\n' "$(hgb_api_key_present 2>/dev/null && printf true || printf false)"
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
    printf '  "target": "%s",\n' "$(json_escape "${HGB_TARGET:-pugixml}")"
    printf '  "api_key_present": %s,\n' "$([[ -n "${OPENAI_API_KEY:-${API_KEY:-}}" ]] && printf true || printf false)"
    printf '  "runtime_config": "%s",\n' "$(json_escape "$cfg")"
    printf '  "exit_code": %s,\n' "$code"
    printf '  "reason": "%s",\n' "$(json_escape "$reason")"
    printf '  "command_file": "%s",\n' "$(json_escape "$workspace/command.txt")"
    printf '  "log_file": "%s"\n' "$(json_escape "$workspace/logs/run.log")"
    printf '}\n'
  } >"$workspace/metadata.json"
}

if [[ "$mode" == "generate-target" ]]; then
  # shellcheck source=/opt/hgb/bin/target_contract.sh
  source /opt/hgb/bin/target_contract.sh
  export HGB_GENERATOR="${HGB_GENERATOR:-promefuzz}"
  export HGB_GENERATOR_ARTIFACT_DIR="$artifact"
  export HGB_TASK_FAMILY="harness_generator"
  export HGB_CAPABILITY="harness_generator"
  export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
  export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
  export OPENAI_MODEL="${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
  export HGB_LLM_REQUEST_TIMEOUT_SECONDS="${HGB_LLM_REQUEST_TIMEOUT_SECONDS:-1200}"
  export PROME_FUZZ_LLM_REQUEST_TIMEOUT_SECONDS="${PROME_FUZZ_LLM_REQUEST_TIMEOUT_SECONDS:-$HGB_LLM_REQUEST_TIMEOUT_SECONDS}"
  export PROME_FUZZ_FAIL_FAST_ON_PROVIDER_ERROR="${PROME_FUZZ_FAIL_FAST_ON_PROVIDER_ERROR:-1}"
  export PROME_FUZZ_PROVIDER_ERROR_FILE="$workspace/logs/provider_error.log"
  export PROME_FUZZ_SKIP_BAD_DOCS="${PROME_FUZZ_SKIP_BAD_DOCS:-1}"
  export NLTK_DATA="${NLTK_DATA:-/opt/hgb/nltk_data}"
  # --- Profile and protocol resolution ---
  export HGB_PROFILE="${HGB_BASELINE_PROFILE:-${HGB_PROFILE:-alpha}}"
  export HGB_PROTOCOL="${HGB_BASELINE_PROTOCOL:-${HGB_PROTOCOL:-blind-project}}"
  export HGB_BASELINE_PROFILE="$HGB_PROFILE"
  export HGB_BASELINE_PROTOCOL="$HGB_PROTOCOL"
  promefuzz_profile="$HGB_PROFILE"
  promefuzz_protocol="$HGB_PROTOCOL"
  mkdir -p "$workspace/logs" "$workspace/generated_harnesses" "$workspace/promefuzz_out" /run/hgb/promefuzz
  promefuzz_init_stages
  # Validate profile/protocol invariants before any expensive work.
  if ! "$python" /opt/hgb/bin/promefuzz_profile.py validate --profile "$promefuzz_profile" --protocol "$promefuzz_protocol" >/dev/null 2>"$workspace/logs/profile_validation.log"; then
    violations="$(cat "$workspace/logs/profile_validation.log" 2>/dev/null || printf 'unknown')"
    reason="promefuzz_profile_violation: $violations"
    hgb_write_common_metadata infra_failure "$reason" 65 harness_generator
    promefuzz_set_stage target_prepared failed
    promefuzz_write_final_result infra_failure "$reason" 65
    hgb_write_common_summary failed "$reason" harness_generator
    exit 65
  fi
  case "$promefuzz_profile" in
    alpha|paper-faithful|reproduction-gamma|reproduction-delta|reproduction-epsilon|reproduction-zeta|reproduction-eta)
      promefuzz_method_faithful=1
      export PROME_FUZZ_EMBEDDING_LLM_TYPE="${PROME_FUZZ_EMBEDDING_LLM_TYPE:-openai}"
      export PROME_FUZZ_EMBEDDING_MODEL="${PROME_FUZZ_EMBEDDING_MODEL:-text-embedding-3-small}"
      export HGB_PROMEFUZZ_SYNTHETIC_COMPILE_DB=0
      export HGB_EXCLUDE_FROM_AGGREGATE=0
      promefuzz_allow_synthetic=0
      # Gamma plan section 2.3 / delta plan section 3: reproduction-gamma,
      # reproduction-delta, and reproduction-epsilon default to the exact
      # FuzzBench build.sh replay so the compile DB provably originates from the
      # FuzzBench build command, not a generic top-level CMake export.
      if [[ "$promefuzz_profile" == "reproduction-gamma" ]]; then
        export PROME_FUZZ_BUILD_CONTEXT_METHOD="${PROME_FUZZ_BUILD_CONTEXT_METHOD:-exact_fuzzbench}"
      fi
      # Delta/epsilon/zeta/eta plan section 3: reproduction-delta,
      # reproduction-epsilon, reproduction-zeta, and reproduction-eta use the
      # fuzzbench_replay strategy name so provenance.json records the exact
      # FuzzBench build.
      if [[ "$promefuzz_profile" == "reproduction-delta" || "$promefuzz_profile" == "reproduction-epsilon" || "$promefuzz_profile" == "reproduction-zeta" || "$promefuzz_profile" == "reproduction-eta" ]]; then
        export PROME_FUZZ_BUILD_CONTEXT_METHOD="${PROME_FUZZ_BUILD_CONTEXT_METHOD:-fuzzbench_replay}"
      fi
      # Zeta plan §1 / eta plan §1: zeta and eta are the strictest profiles.
      # Force exact FuzzBench compile context, verified link args, consumer
      # cases, real embedding, and a sealed split package. Eta is the canonical
      # strict profile and inherits all zeta required env values.
      if [[ "$promefuzz_profile" == "reproduction-zeta" || "$promefuzz_profile" == "reproduction-eta" ]]; then
        export PROMEFUZZ_EMBEDDING_PROVIDER="${PROMEFUZZ_EMBEDDING_PROVIDER:-real}"
        export PROMEFUZZ_ALLOW_HASH_EMBEDDING=0
        export PROMEFUZZ_ALLOW_SYNTHETIC_COMPILE_DB=0
        export PROMEFUZZ_ALLOW_EMPTY_LINK_ARGS=0
        export PROMEFUZZ_REQUIRE_CONSUMER_CASES=1
        export PROME_FUZZ_BUILD_CONTEXT_METHOD="${PROME_FUZZ_BUILD_CONTEXT_METHOD:-fuzzbench_replay}"
        export HGB_TARGET_REQUIRE_SPLIT=1
      fi
      ;;
    compat-smoke)
      promefuzz_method_faithful=0
      export PROME_FUZZ_EMBEDDING_LLM_TYPE="${PROME_FUZZ_EMBEDDING_LLM_TYPE:-mock}"
      export PROME_FUZZ_EMBEDDING_MODEL="${PROME_FUZZ_EMBEDDING_MODEL:-hgb-hash-embedding}"
      export HGB_PROMEFUZZ_SYNTHETIC_COMPILE_DB="${HGB_PROMEFUZZ_SYNTHETIC_COMPILE_DB:-1}"
      export HGB_EXCLUDE_FROM_AGGREGATE=1
      promefuzz_allow_synthetic=1
      ;;
  esac
  # Official ALL-COVER budgets: practical multi-candidate budget for alpha,
  # upstream/paper-aligned values may override via env.
  export PROME_FUZZ_ALL_COVER_CANDIDATES="${PROME_FUZZ_ALL_COVER_CANDIDATES:-4}"
  export PROME_FUZZ_ALL_COVER_MAX_WALL_SECONDS="${PROME_FUZZ_ALL_COVER_MAX_WALL_SECONDS:-5400}"
  export PROME_FUZZ_ALL_COVER_MAX_LLM_CALLS="${PROME_FUZZ_ALL_COVER_MAX_LLM_CALLS:-64}"
  export PROME_FUZZ_ALL_COVER_REPAIR_ATTEMPTS="${PROME_FUZZ_ALL_COVER_REPAIR_ATTEMPTS:-3}"
  # Beta plan section 8: define ALL-COVER/generation/campaign budgets in one
  # place. A smaller user-supplied budget is recorded but is not a paper
  # reproduction unless the paper budget matches.
  export PROME_GENERATION_BUDGET_SECONDS="${PROME_GENERATION_BUDGET_SECONDS:-3600}"
  export PROME_MAX_CANDIDATES="${PROME_MAX_CANDIDATES:-10}"
  export HGB_CAMPAIGN_SECONDS="${HGB_CAMPAIGN_SECONDS:-300}"
  export PROME_FUZZ_CAMPAIGN_SECONDS="${PROME_FUZZ_CAMPAIGN_SECONDS:-$HGB_CAMPAIGN_SECONDS}"
  promefuzz_set_stage target_prepared completed
  hgb_require_target_package
  target_name="${HGB_TARGET:-$(hgb_target_manifest_value target)}"
  project="${HGB_TARGET_PROJECT:-$(hgb_target_manifest_value project)}"
  fuzz_target="${HGB_TARGET_FUZZ_TARGET:-$(hgb_target_manifest_value fuzz_target)}"
  safe_target="$(printf '%s' "$target_name" | sed 's/[^A-Za-z0-9_]/_/g')"
  # --- Delta/Epsilon plan section 2: fail-closed split package assertions ---
  # In blind-project + a strict reproduction profile (reproduction-delta or its
  # canonical alias reproduction-epsilon), the generator mount must be the
  # sanitized generator_input half and must never expose reference_harnesses,
  # selected_reference_harnesses, or fuzzbench_selected_harness_apis.json.
  # The evaluator half must provide evaluator_manifest.json.
  if [[ "$promefuzz_profile" == "reproduction-delta" || "$promefuzz_profile" == "reproduction-epsilon" || "$promefuzz_profile" == "reproduction-zeta" || "$promefuzz_profile" == "reproduction-eta" ]] && [[ "$promefuzz_protocol" == "blind-project" ]]; then
    if ! test -f /target/target_manifest.json; then
      reason="promefuzz_delta_manifest_missing: /target/target_manifest.json is missing; the generator_input half was not mounted"
      hgb_write_common_metadata infra_failure "$reason" 65 harness_generator
      promefuzz_write_final_result infra_failure "$reason" 65
      hgb_write_common_summary infra_failure "$reason" harness_generator
      exit 65
    fi
    if test -e /target/reference_harnesses || test -e /target/selected_reference_harnesses || test -e /target/fuzzbench_selected_harness_apis.json; then
      reason="promefuzz_delta_reference_leak: reference_harnesses/selected_reference_harnesses/fuzzbench_selected_harness_apis.json leaked into the generator mount"
      hgb_write_common_metadata infra_failure "$reason" 65 harness_generator
      promefuzz_write_final_result infra_failure "$reason" 65
      hgb_write_common_summary infra_failure "$reason" harness_generator
      exit 65
    fi
    if ! test -f /evaluator/evaluator_manifest.json; then
      reason="promefuzz_delta_evaluator_manifest_missing: /evaluator/evaluator_manifest.json is missing; the evaluator_only half was not mounted"
      hgb_write_common_metadata infra_failure "$reason" 65 harness_generator
      promefuzz_write_final_result infra_failure "$reason" 65
      hgb_write_common_summary infra_failure "$reason" harness_generator
      exit 65
    fi
    # Delta plan section 2.4: leakage audit before any LLM/embedding call.
    # Scan /target for reference_harnesses tokens, selected harness paths,
    # native harness source, or the canary. A hit is infra_failure.
    promefuzz_leakage_preaudit='{"leaked":false}'
    if [[ -n "${HGB_REF_CANARY:-}" ]]; then
      if grep -RqF -- "${HGB_REF_CANARY}" /target 2>/dev/null; then
        promefuzz_leakage_preaudit='{"leaked":true,"reason":"canary_in_target"}'
      fi
    fi
    if grep -RqE -- 'reference_harnesses|selected_reference_harnesses|fuzzbench_selected_harness_apis' /target 2>/dev/null; then
      promefuzz_leakage_preaudit='{"leaked":true,"reason":"reference_token_in_target"}'
    fi
    if printf '%s' "$promefuzz_leakage_preaudit" | grep -q '"leaked": *true'; then
      printf 'PromeFuzz delta pre-audit FAILED: reference leakage detected in /target\n' >"$workspace/logs/leakage_preaudit.log"
      printf '%s\n' "$promefuzz_leakage_preaudit" >>"$workspace/logs/leakage_preaudit.log"
      reason="promefuzz_delta_reference_leak_preaudit: reference harness content leaked into the generator mount before any LLM/embedding call"
      hgb_write_common_metadata infra_failure "$reason" 65 harness_generator
      promefuzz_write_final_result infra_failure "$reason" 65
      hgb_write_common_summary infra_failure "$reason" harness_generator
      exit 65
    fi
    printf 'PromeFuzz delta pre-audit passed: no reference leakage in /target\n' >"$workspace/logs/leakage_preaudit.log"
  fi
  # --- Blind-project / api-oracle isolation ---
  # The PromeFuzz generator must never see the exact target reference harness,
  # the selected-harness-APIs report, or reference-derived API filtering.
  if [[ "$promefuzz_protocol" == "blind-project" || "$promefuzz_protocol" == "api-oracle" ]]; then
    export HGB_API_SELECTION_MODE="${HGB_API_SELECTION_MODE:-ranked}"
    export HGB_API_REPORT_MODE="${HGB_API_REPORT_MODE:-dynamic_only}"
    export HGB_SELECTED_API_REPORT=""
    if [[ -d /target/reference_harnesses ]]; then
      printf 'blind-project: /target/reference_harnesses is evaluator-only; PromeFuzz ignores it\n' >"$workspace/logs/reference_isolation.log"
    fi
  fi
  export HGB_SELECTED_API_MAX="${HGB_SELECTED_API_MAX:-8}"
  export HGB_SELECTED_API_FALLBACK_MAX="${HGB_SELECTED_API_FALLBACK_MAX:-4}"
  # Resolve the native harness destination from manifest metadata (path only,
  # never the reference harness body).
  if ! native_harness_destination="$("$python" /opt/hgb/bin/hgb_target_harness.py --target-root /target --fuzz-target "$fuzz_target" --field destination 2>"$workspace/logs/native_harness.log")"; then
    promefuzz_set_stage target_prepared failed
    reason="promefuzz_native_harness_unresolved: target package does not identify a native C/C++ harness path"
    hgb_write_common_metadata infra_failure "$reason" 65 harness_generator
    promefuzz_write_final_result infra_failure "$reason" 65
    hgb_write_common_summary failed "$reason" harness_generator
    exit 65
  fi
  language="$("$python" /opt/hgb/bin/hgb_target_harness.py --target-root /target --fuzz-target "$fuzz_target" --field language)"
  fuzzbench_build_workdir="$(fuzzbench_build_workdir)"
  promefuzz_pool_size="${PROME_FUZZ_POOL_SIZE:-1}"
  if ! is_positive_integer "$promefuzz_pool_size"; then
    reason="invalid PROME_FUZZ_POOL_SIZE: $promefuzz_pool_size"
    hgb_write_common_metadata infra_failure "$reason" 64 harness_generator
    promefuzz_write_final_result infra_failure "$reason" 64
    hgb_write_common_summary failed "$reason" harness_generator
    exit 64
  fi
  native_build_enabled="${HGB_PROMEFUZZ_NATIVE_BUILD:-1}"
  native_build_root="$workspace/promefuzz_native_build"
  native_template="$native_build_root/template"
  native_harness_json=""
  native_build_json=false
  if [[ "$native_build_enabled" == "1" ]]; then
    if ! fuzzbench_target_build_available; then
      printf 'FuzzBench provides no reproducible top-level build.sh for this target; using PromeFuzz compiler validation instead.\n' >"$workspace/logs/native_build.log"
      native_build_enabled=0
    fi
  fi
  if [[ "$native_build_enabled" == "1" ]]; then
    stage_fuzzbench_source "$native_template"
    baseline_source="$native_template/${native_harness_destination#/src/}"
    # Blind-project: overlay a NEUTRAL fuzz-entrypoint stub at the native
    # destination, never the exact target reference harness body.
    "$python" - "$baseline_source" "$language" <<'PY_PROMEFUZZ_NEUTRAL_STUB'
import sys
from pathlib import Path
sys.path.insert(0, "/opt/hgb/bin")
import promefuzz_build_context as pbc
pbc.write_neutral_stub(Path(sys.argv[1]), sys.argv[2])
PY_PROMEFUZZ_NEUTRAL_STUB
    native_harness_json="$("$python" /opt/hgb/bin/hgb_target_harness.py --target-root /target --fuzz-target "$fuzz_target")"
    printf '%s\n' "$native_harness_json" >"$workspace/promefuzz_native_harness.json"
    export PROME_FUZZ_DRIVER_BUILD_WRAPPER=/opt/hgb/bin/promefuzz_target_build.sh
    export PROME_FUZZ_NATIVE_SOURCE_TEMPLATE="$native_template"
    export PROME_FUZZ_NATIVE_BUILD_ROOT="$native_build_root"
    export PROME_FUZZ_NATIVE_HARNESS_DESTINATION="$native_harness_destination"
    export PROME_FUZZ_NATIVE_FUZZ_TARGET="$fuzz_target"
    export PROME_FUZZ_NATIVE_BUILD_WORKDIR_RELATIVE="$fuzzbench_build_workdir"
    export PROME_FUZZ_NATIVE_BUILD_LOG_DIR="$workspace/logs/native-build"
    export PROME_FUZZ_NATIVE_RUN_LOG_DIR="$workspace/logs/native-run"
    export FUZZER="${FUZZER:-libfuzzer}"
    native_build_json=true
    if [[ "${HGB_PROMEFUZZ_VALIDATE_TARGET_BASELINE:-1}" == "1" ]]; then
      baseline_binary="$native_build_root/baseline/$fuzz_target"
      if ! bash /opt/hgb/bin/promefuzz_target_build.sh "$baseline_source" "$baseline_binary" >"$workspace/logs/baseline-build.log" 2>&1; then
        promefuzz_set_stage build_context failed
        reason="promefuzz_baseline_build_failed: native baseline build or smoke test failed; inspect baseline-build.log before spending LLM budget"
        hgb_write_common_metadata infra_failure "$reason" 65 harness_generator
        promefuzz_write_final_result infra_failure "$reason" 65
        hgb_write_common_summary failed "$reason" harness_generator
        exit 65
      fi
    fi
  fi
  # --- Real compile database capture from the pinned FuzzBench build ---
  compile_db="$workspace/build_context/compile_commands.json"
  promefuzz_build_context_args=(
    /opt/hgb/bin/promefuzz_build_context.py
    --target-root /target --work-dir "$workspace" --fuzz-target "$fuzz_target"
    --language "$language" --profile "$promefuzz_profile"
    --capture-method "${PROME_FUZZ_BUILD_CONTEXT_METHOD:-auto}"
    --build-workdir-relative "$fuzzbench_build_workdir"
    --build-timeout "${PROME_FUZZ_NATIVE_BUILD_TIMEOUT_SECONDS:-900}"
  )
  [[ "$promefuzz_allow_synthetic" == "1" ]] && promefuzz_build_context_args+=(--allow-synthetic)
  if ! "$python" "${promefuzz_build_context_args[@]}" >"$workspace/logs/build_context.log" 2>&1; then
    promefuzz_set_stage build_context failed
    if [[ "$promefuzz_method_faithful" == "1" ]]; then
      reason="promefuzz_build_context_failed: real compile database could not be captured from the pinned FuzzBench build; inspect build_context.log"
      hgb_write_common_metadata infra_failure "$reason" 65 harness_generator
      promefuzz_write_final_result infra_failure "$reason" 65
      hgb_write_common_summary infra_failure "$reason" harness_generator
      exit 65
    else
      hgb_soft_skip needs_compile_commands 'PromeFuzz could not capture a compile_commands.json; inspect build_context.log' harness_generator
    fi
  fi
  # Re-filter the captured database so compiler probes/duplicates/stale
  # commands never reach PromeFuzz while real target commands survive.
  filter_compile_db "$compile_db" cmake || true
  if ! compile_db_has_entries "$compile_db"; then
    promefuzz_set_stage build_context failed
    if [[ "$promefuzz_method_faithful" == "1" ]]; then
      reason="promefuzz_build_context_empty: real compile database is empty after filtering; inspect build_context.log"
      hgb_write_common_metadata infra_failure "$reason" 65 harness_generator
      promefuzz_write_final_result infra_failure "$reason" 65
      hgb_write_common_summary infra_failure "$reason" harness_generator
      exit 65
    else
      hgb_soft_skip needs_compile_commands 'PromeFuzz requires a non-empty compile_commands.json' harness_generator
    fi
  fi
  promefuzz_set_stage build_context completed
  preserved_compile_db="$workspace/compile_commands.json"
  cp "$compile_db" "$preserved_compile_db" 2>/dev/null || true
  compile_db_for_metadata="$preserved_compile_db"
  # Recovered libraries and link arguments from the real build.
  libraries_json="$workspace/build_context/libraries.json"
  link_context_json="$workspace/build_context/link_context.json"
  driver_build_args_json="[]"
  if [[ -f "$libraries_json" ]]; then
    driver_build_args_json="$("$python" - "$libraries_json" <<'PY_PROMEFUZZ_DRIVER_ARGS'
import json
import sys
from pathlib import Path
try:
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    print(json.dumps(data.get("driver_build_args", [])))
except Exception:
    print("[]")
PY_PROMEFUZZ_DRIVER_ARGS
)"
  fi
  # Beta plan section 5: enforce nonempty, verified link/build context. In
  # alpha/paper-faithful empty driver_build_args is an infra_failure with
  # failed_stage=link_context, never a soft skip.
  driver_build_args_count="$(printf '%s' "$driver_build_args_json" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || printf '0')"
  link_verified=false
  if [[ "$driver_build_args_count" -gt 0 ]]; then
    link_verified=true
    "$python" - "$link_context_json" "$libraries_json" "$workspace/link_probe" "$language" "$workspace/build_context/src" >"$workspace/logs/verify_link_set.log" 2>&1 <<'PY_PROMEFUZZ_VERIFY_LINK' || link_verified=false
import json
import sys
from pathlib import Path
sys.path.insert(0, "/opt/hgb/bin")
import promefuzz_build_context as pbc
link_context_path = Path(sys.argv[1])
libraries_path = Path(sys.argv[2])
work_dir = Path(sys.argv[3])
language = sys.argv[4]
source_root = Path(sys.argv[5])
try:
    libraries = json.loads(libraries_path.read_text(encoding="utf-8"))
except Exception:
    libraries = {}
driver_build_args = libraries.get("driver_build_args", [])
ok, msg = pbc.verify_and_record_link_set(
    link_context_path=link_context_path,
    driver_build_args=driver_build_args,
    work_dir=work_dir,
    language=language,
    source_root=source_root,
)
print(msg)
sys.exit(0 if ok else 1)
PY_PROMEFUZZ_VERIFY_LINK
  else
    printf 'driver_build_args is empty; link context not verified\n' >"$workspace/logs/verify_link_set.log"
    [[ -f "$link_context_json" ]] && python3 - "$link_context_json" <<'PY_PROMEFUZZ_LINK_EMPTY'
import json, sys
from pathlib import Path
p = Path(sys.argv[1])
try:
    data = json.loads(p.read_text(encoding="utf-8"))
except Exception:
    data = {}
data["verified"] = False
data["verify_message"] = "driver_build_args is empty"
p.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY_PROMEFUZZ_LINK_EMPTY
  fi
  if [[ "$promefuzz_method_faithful" == "1" ]]; then
    if [[ "$driver_build_args_count" -le 0 ]]; then
      promefuzz_set_stage build_context failed
      reason="promefuzz_link_context_empty: driver_build_args is empty; alpha/paper-faithful require verified nonempty link/build arguments (failed_stage=link_context)"
      hgb_write_common_metadata infra_failure "$reason" 65 harness_generator
      promefuzz_write_final_result infra_failure "$reason" 65
      hgb_write_common_summary infra_failure "$reason" harness_generator
      exit 65
    fi
    if [[ "$link_verified" != "true" ]]; then
      promefuzz_set_stage build_context failed
      reason="promefuzz_link_context_unverified: verify_link_set failed to build a minimal consumer with the recovered driver_build_args (failed_stage=link_context)"
      hgb_write_common_metadata infra_failure "$reason" 65 harness_generator
      promefuzz_write_final_result infra_failure "$reason" 65
      hgb_write_common_summary infra_failure "$reason" harness_generator
      exit 65
    fi
  fi
  # --- Embedding preflight (real provider required in alpha/paper-faithful) ---
  if [[ "$promefuzz_method_faithful" == "1" ]] && [[ "${PROME_FUZZ_EMBEDDING_PREFLIGHT:-1}" == "1" ]]; then
    if ! promefuzz_embedding_preflight "$workspace/logs/embedding_preflight.log"; then
      promefuzz_set_stage knowledge failed
      reason="promefuzz_embedding_unavailable: real embedding service is unavailable; configure PROME_FUZZ_EMBEDDING_LLM_TYPE/MODEL/BASE_URL/API_KEY"
      hgb_write_common_metadata infra_failure "$reason" 2 harness_generator
      promefuzz_write_final_result infra_failure "$reason" 2
      hgb_write_common_summary infra_failure "$reason" harness_generator
      exit 2
    fi
  fi
  # --- PromeFuzz config and libraries.toml with real driver_build_args ---
  config=/run/hgb/promefuzz/config.toml
  libraries=/run/hgb/promefuzz/libraries.toml
  promefuzz_write_config "$config"
  driver_build_args_toml="$driver_build_args_json"
  # Beta plan section 6: wire consumer knowledge into the upstream PromeFuzz
  # config. consumer_cases.json was produced by build_context capture from
  # legitimate examples/tests/docs only (never the reference harness).
  consumer_cases_json="$workspace/knowledge/consumer_cases.json"
  consumer_cases_status="unavailable"
  consumer_case_paths_toml="[]"
  if [[ -f "$consumer_cases_json" ]]; then
    consumer_cases_count="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("consumer_count",0))' "$consumer_cases_json" 2>/dev/null || printf '0')"
    if [[ "${consumer_cases_count:-0}" -gt 0 ]]; then
      consumer_cases_status="available"
      consumer_case_paths_toml='["/workspace/knowledge/consumer_cases"]'
    fi
  fi
  cat >"$libraries" <<EOF_PROMEFUZZ_LIBS
[$safe_target]
language = "$language"
header_paths = ["/target/source_input"]
compile_commands_path = "$compile_db"
document_paths = ["/target/docs"]
document_has_api_usage = true
output_path = "$workspace/promefuzz_out/$safe_target"
source_paths = ["/target/source_input"]
exclude_paths = ["/target/source_input/test", "/target/source_input/tests", "/target/source_input/example", "/target/source_input/examples", "/target/source_input/third_party", "/target/source_input/benchmark", "/target/source_input/benchmarks"]
driver_headers = []
driver_build_args = $driver_build_args_toml
consumer_build_args = $driver_build_args_toml
consumer_case_paths = $consumer_case_paths_toml
EOF_PROMEFUZZ_LIBS
  printf 'PromeFuzz config: %s\nPromeFuzz libraries: %s\n' "$config" "$libraries" >"$workspace/command.txt"
  if [[ "${HGB_DRY_RUN:-0}" == "1" ]]; then
    cp "$libraries" "$workspace/promefuzz_libraries.toml" 2>/dev/null || true
    hgb_write_common_metadata dry_run_ok 'dry run prepared PromeFuzz config, real compile_commands.json, and link context' 0 harness_generator
    hgb_write_common_summary dry_run_ok 'dry run prepared PromeFuzz config, real compile_commands.json, and link context' harness_generator
    exit 0
  fi
  if ! hgb_api_key_present; then
    printf 'OPENAI_API_KEY is not set; PromeFuzz target generation skipped.\n' >"$workspace/logs/run.log"
    reason="missing_api_key: OPENAI_API_KEY is not set"
    hgb_write_common_metadata missing_api_key 'OPENAI_API_KEY is not set' 2 harness_generator
    promefuzz_write_final_result failed "$reason" 2
    hgb_write_common_summary missing_api_key 'OPENAI_API_KEY is not set' harness_generator
    exit 2
  fi
  # --- Public API preprocessing (no reference-harness filtering) ---
  api_selection_metadata="$workspace/promefuzz_api_selection.json"
  selected_api_names_file="$workspace/promefuzz_selected_apis.json"
  api_extract_args=(
    /opt/hgb/bin/extract_api_list.py
    --source /target/source_input --out "$selected_api_names_file"
    --max "${PROME_FUZZ_MAX_APIS:-${HGB_SELECTED_API_MAX:-8}}"
    --fallback-max "${HGB_SELECTED_API_FALLBACK_MAX:-4}"
    --selection-mode "${HGB_API_SELECTION_MODE:-ranked}"
    --report-mode "${HGB_API_REPORT_MODE:-dynamic_only}"
    --project "$project" --target-name "$target_name" --fuzz-target "$fuzz_target"
    --selection-metadata "$api_selection_metadata"
  )
  selected_api_count="$(python3 "${api_extract_args[@]}" 2>"$workspace/logs/promefuzz_api_extract.log" || printf '0')"
  selected_api_count="${selected_api_count##*$'\n'}"
  export PROME_FUZZ_SELECTED_API_NAMES_FILE="$selected_api_names_file"
  export PROME_FUZZ_API_SELECTION_METADATA_FILE="$api_selection_metadata"
  runtime_artifact=/run/hgb/promefuzz/artifact
  rm -rf "$runtime_artifact"
  mkdir -p "$runtime_artifact"
  cp -a "$artifact/." "$runtime_artifact/"
  python3 - "$runtime_artifact" <<'PY_PROMEFUZZ_LLM_TRACE_PATCH'
from pathlib import Path
import sys
root = Path(sys.argv[1])
llm_py = root / "src/llm/llm.py"
if llm_py.exists():
    llm_text = llm_py.read_text()
    if "import hgb_llm_trace" not in llm_text:
        llm_text = llm_text.replace("import sys\n", "import sys\nsys.path.insert(0, \"/opt/hgb/bin\")\ntry:\n    import hgb_llm_trace\nexcept Exception:\n    hgb_llm_trace = None\n", 1)
    old = """            completion = self.client.chat.completions.create(**api_params)"""
    new = """            if hgb_llm_trace is not None:
                completion = hgb_llm_trace.trace_call(
                    lambda: self.client.chat.completions.create(**api_params),
                    stage=\"promefuzz\",
                    provider=\"openai-compatible\",
                    operation=\"chat.completions.create\",
                    model=self.model,
                    request=api_params,
                )
            else:
                completion = self.client.chat.completions.create(**api_params)"""
    if old in llm_text and "hgb_llm_trace.trace_call" not in llm_text:
        llm_text = llm_text.replace(old, new)
    fail_fast_old = '        except Exception as e:\n            logger.error(f"OpenAI API exception: {e}")\n            return None'
    fail_fast_new = '        except Exception as e:\n            error_text = str(e)\n            for _secret in (os.environ.get("OPENAI_API_KEY", ""), os.environ.get("API_KEY", "")):\n                if _secret:\n                    error_text = error_text.replace(_secret, "[REDACTED]")\n            logger.error(f"OpenAI API exception: {error_text}")\n            _nonretryable = (\n                "Error code: 400", "Error code: 401", "Error code: 402",\n                "Error code: 403", "Error code: 404", "Error code: 422",\n                "Insufficient Balance", "ExceededBudget", "budget_exceeded",\n                "invalid api key", "invalid_request_error", "model_not_found",\n            )\n            if (os.environ.get("PROME_FUZZ_FAIL_FAST_ON_PROVIDER_ERROR", "1") != "0"\n                    and any(_marker.lower() in error_text.lower() for _marker in _nonretryable)):\n                _message = "hgb_llm_nonretryable: " + error_text\n                _error_file = os.environ.get("PROME_FUZZ_PROVIDER_ERROR_FILE", "")\n                if _error_file:\n                    try:\n                        with open(_error_file, "w", encoding="utf-8") as _handle:\n                            _handle.write(_message + "\\n")\n                    except OSError:\n                        pass\n                logger.critical(_message)\n                os._exit(78)\n            return None'
    if "PROME_FUZZ_FAIL_FAST_ON_PROVIDER_ERROR" not in llm_text:
        if "import os\n" not in llm_text:
            llm_text = llm_text.replace("import sys\n", "import os\nimport sys\n", 1)
        if fail_fast_old in llm_text:
            llm_text = llm_text.replace(fail_fast_old, fail_fast_new)
    llm_py.write_text(llm_text)
rag_py = root / "src/llm/rag.py"
utils_py = root / "src/utils.py"
if rag_py.exists():
    text = rag_py.read_text()
    start = text.find("    def add_document(self, document: Path):")
    end = text.find("    def add_webpage(self, url: str):", start)
    if start != -1 and end != -1 and "PROME_FUZZ_SKIP_BAD_DOCS" not in text[start:end]:
        robust_add_document = '    def add_document(self, document: Path):\n        """\n        Add a local document to the retriever, skipping unusable documents in HGB mode.\n        """\n        skip_bad = os.environ.get("PROME_FUZZ_SKIP_BAD_DOCS", "1") != "0"\n        document = Path(document)\n        if self.is_in_database(document):\n            logger.warning(f"Document {document} already exists in the retriever")\n            return\n        if skip_bad:\n            try:\n                if not document.is_file() or document.stat().st_size == 0:\n                    logger.warning(f"Skipping empty or missing document {document}")\n                    return\n                max_bytes = int(os.environ.get("PROME_FUZZ_MAX_DOC_BYTES", "5242880") or "0")\n                if max_bytes > 0 and document.stat().st_size > max_bytes:\n                    logger.warning(f"Skipping large document {document} ({document.stat().st_size} bytes)")\n                    return\n            except OSError as exc:\n                logger.warning(f"Skipping unreadable document {document}: {exc}")\n                return\n\n        from src.utils import ProgressTitle\n\n        with ProgressTitle(f"Loading document {document}..."):\n            try:\n                suffix = document.suffix.lower()\n                if suffix == ".pdf":\n                    loader = UnstructuredPDFLoader(str(document), mode="elements", strategy="fast")\n                    docs = loader.load()\n                elif suffix in [".html", ".htm"]:\n                    loader = UnstructuredHTMLLoader(str(document), mode="elements", strategy="fast")\n                    docs = loader.load()\n                else:\n                    loader = TextLoader(document, autodetect_encoding=True)\n                    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200, add_start_index=True)\n                    docs = loader.load_and_split(splitter)\n            except Exception as exc:\n                if skip_bad:\n                    logger.warning(f"Skipping document {document}: {exc}")\n                    return\n                raise\n\n            docs = filter_complex_metadata(docs)\n            docs = [doc for doc in docs if getattr(doc, "page_content", "").strip()]\n            if not docs:\n                logger.warning(f"Skipping document {document}: no non-empty chunks")\n                return\n            self.vector_store.add_documents(docs)\n\n        self._add_to_document_list(document)\n\n'
        text = text[:start] + robust_add_document + text[end:]
    if "class LocalHashEmbeddings" not in text:
        marker = "\n\nclass OllamaRetriever(RAGRetriever):\n"
        local_code = '''

class LocalHashEmbeddings:
    def __init__(self, dimensions: int = 384):
        self.dimensions = int(dimensions or 384)

    def _embed(self, text: str) -> list[float]:
        import hashlib
        vec = [0.0] * self.dimensions
        tokens = str(text or "").split() or [str(text or "")]
        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8", "ignore")).digest()
            idx = int.from_bytes(digest[:4], "little") % self.dimensions
            sign = 1.0 if digest[4] & 1 else -1.0
            vec[idx] += sign
        norm = sum(v * v for v in vec) ** 0.5 or 1.0
        return [v / norm for v in vec]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed(text) for text in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)


class LocalRetriever(RAGRetriever):
    def __init__(self, dimensions: int = 384, database_path: Path = None):
        embedding_client = LocalHashEmbeddings(dimensions)
        self.vector_store = Chroma(
            embedding_function=embedding_client,
            persist_directory=str(database_path.resolve()) if database_path else None,
            client_settings=chromadb_config.Settings(anonymized_telemetry=False),
        )
        self.database_path = database_path
        self._load_document_list()
'''
        if marker in text:
            text = text.replace(marker, local_code + marker, 1)
        rag_py.write_text(text)
if utils_py.exists():
    text = utils_py.read_text()
    old = '''    else:\n        raise ValueError(f"Unsupported LLM type: {llm_type}")\n\n    # create database path\n'''
    new = '''    elif llm_type in ("mock", "local", "hash"):\n        selected_llm.setdefault("dimensions", 384)\n    else:\n        raise ValueError(f"Unsupported LLM type: {llm_type}")\n\n    # create database path\n'''
    if old in text and 'llm_type in ("mock", "local", "hash")' not in text:
        text = text.replace(old, new, 1)
    old = '''    elif llm_type == LLM.LLM_TYPES.OPENAI.value:\n        rag_retriever = RAG.OpenAIRetriever(\n            selected_llm["base_url"],\n            selected_llm["api_key"],\n            selected_llm["model"],\n            selected_llm["max_tokens"],\n            database_path=database_path,\n        )\n\n    logger.success(f"The RAG retriever {llm_name} has been setup.")\n'''
    new = '''    elif llm_type == LLM.LLM_TYPES.OPENAI.value:\n        rag_retriever = RAG.OpenAIRetriever(\n            selected_llm["base_url"],\n            selected_llm["api_key"],\n            selected_llm["model"],\n            selected_llm["max_tokens"],\n            database_path=database_path,\n        )\n    elif llm_type in ("mock", "local", "hash"):\n        rag_retriever = RAG.LocalRetriever(\n            int(selected_llm.get("dimensions", 384)),\n            database_path=database_path,\n        )\n\n    logger.success(f"The RAG retriever {llm_name} has been setup.")\n'''
    if old in text and 'RAG.LocalRetriever' not in text:
        text = text.replace(old, new, 1)
    utils_py.write_text(text)
knowledge_py = root / "src/comprehender/knowledge.py"
if knowledge_py.exists():
    ktext = knowledge_py.read_text()
    if "import os\n" not in ktext:
        ktext = ktext.replace("from pathlib import Path\n", "from pathlib import Path\nimport os\n", 1)
    old = '                except Exception as e:\n                    logger.critical(f"Failed to load document {doc}: {e}")\n                    exit(1)\n'
    new = '                except Exception as e:\n                    if os.environ.get("PROME_FUZZ_SKIP_BAD_DOCS", "1") != "0":\n                        logger.warning(f"Skipping document {doc}: {e}")\n                        continue\n                    logger.critical(f"Failed to load document {doc}: {e}")\n                    exit(1)\n'
    if old in ktext and "PROME_FUZZ_SKIP_BAD_DOCS" not in ktext:
        ktext = ktext.replace(old, new, 1)
    knowledge_py.write_text(ktext)
driver_py = root / "src/generator/driver.py"
if driver_py.exists():
    text = driver_py.read_text()
    if "PROME_FUZZ_DRIVER_BUILD_WRAPPER" not in text:
        if "import os\n" not in text:
            text = text.replace("import threading\n", "import os\nimport threading\n", 1)
        old = '''        logger.debug(f"Building fuzz driver {self.id} with command: {build_cmd}")

        # build fuzz driver
        try:
            output = subprocess.check_output(
                build_cmd, stderr=subprocess.STDOUT, shell=True, text=True
            )'''
        new = '''        build_wrapper = os.environ.get("PROME_FUZZ_DRIVER_BUILD_WRAPPER", "").strip()
        wrapper_cmd = ["bash", build_wrapper, str(src_path), str(bin_path)] if build_wrapper else []
        logger.debug(
            f"Building fuzz driver {self.id} with "
            f"{'target build wrapper: ' + ' '.join(wrapper_cmd) if wrapper_cmd else 'command: ' + build_cmd}"
        )

        # build fuzz driver
        try:
            output = subprocess.check_output(
                wrapper_cmd if wrapper_cmd else build_cmd,
                stderr=subprocess.STDOUT,
                shell=not bool(wrapper_cmd),
                text=True,
            )'''
        if old in text:
            text = text.replace(old, new, 1)
    text = text.replace('''f"{func.name.split("::")[-1]}("''', '''f"{func.name.split('::')[-1]}("''')
    text = text.replace(
        '''f"Function in fuzz driver does not exist in API collection: {calling["calleeName"]} at {calling["calleeDeclLoc"]}"''',
        '''f"Function in fuzz driver does not exist in API collection: {calling['calleeName']} at {calling['calleeDeclLoc']}"''',
    )
    driver_py.write_text(text)
preprocess_py = root / "cli/preprocess.py"
if preprocess_py.exists():
    text = preprocess_py.read_text()
    if "import os\n" not in text:
        text = text.replace("import json\n", "import json\nimport os\n", 1)
    if "from pathlib import Path\n" not in text:
        if "import os\n" in text:
            text = text.replace("import os\n", "import os\nfrom pathlib import Path\n", 1)
        else:
            text = "from pathlib import Path\n" + text
    old = """    api = api_extractor.extract(pool_size=pool_size)
    api.dump(out_path / "api.pkl")"""
    new = """    api = api_extractor.extract(pool_size=pool_size)
    max_apis = int(os.environ.get("PROME_FUZZ_MAX_APIS", os.environ.get("HGB_SELECTED_API_MAX", "8")) or "0")

    def _hgb_api_rank(func):
        text = " ".join(str(getattr(func, attr, "")) for attr in ("header", "name", "loc", "decl_loc")).lower()
        penalty = 0
        for token in ("/test", "/tests", "/example", "/examples", "test::", "testing"):
            if token in text:
                penalty += 10
        return (penalty, len(str(getattr(func, "name", ""))), str(getattr(func, "name", "")), str(getattr(func, "loc", "")))

    selected_names_file = os.environ.get("PROME_FUZZ_SELECTED_API_NAMES_FILE", "")
    selected_names = []
    if selected_names_file:
        try:
            selected_data = json.loads(Path(selected_names_file).read_text(encoding="utf-8"))
            for item in selected_data:
                if isinstance(item, str):
                    selected_names.append(item.split("::")[-1])
                elif isinstance(item, dict) and item.get("name"):
                    selected_names.append(str(item.get("name")).split("::")[-1])
        except Exception as exc:
            logger.warning(f"Could not load HGB selected API names from {selected_names_file}: {exc}")
    selected_rank = {name: index for index, name in enumerate(selected_names)}

    def _hgb_mark_api_fallback(reason):
        metadata_file = os.environ.get("PROME_FUZZ_API_SELECTION_METADATA_FILE", "")
        if not metadata_file:
            return
        try:
            metadata_path = Path(metadata_file)
            metadata = json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.exists() else {}
            metadata["fallback_used"] = True
            metadata["api_selection_source"] = "dynamic"
            metadata["promefuzz_api_object_filter_fallback_reason"] = reason
            metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\\n", encoding="utf-8")
        except Exception as exc:
            logger.warning(f"Could not mark HGB API fallback metadata: {exc}")

    if selected_rank and getattr(api, "funcs", None):
        before = api.count
        matched = [func for func in api.funcs if str(getattr(func, "name", "")).split("::")[-1] in selected_rank]
        if matched:
            api.funcs = sorted(matched, key=lambda func: (selected_rank.get(str(getattr(func, "name", "")).split("::")[-1], 9999), _hgb_api_rank(func)))
            if max_apis > 0:
                api.funcs = api.funcs[:max_apis]
            logger.info(f"Filtered API functions from {before} to {api.count} using HGB selected FuzzBench harness APIs.")
        else:
            logger.warning("No PromeFuzz API functions matched HGB selected harness APIs; falling back to ranked trimming.")
            _hgb_mark_api_fallback("promefuzz_api_object_name_mismatch")
    if max_apis > 0 and api.count > max_apis:
        before = api.count
        api.funcs = sorted(api.funcs, key=_hgb_api_rank)[:max_apis]
        logger.info(f"Limiting API functions from {before} to {api.count} for HGB integration. Set PROME_FUZZ_MAX_APIS=0 to disable.")
    api.dump(out_path / "api.pkl")"""
    if old in text and "PROME_FUZZ_MAX_APIS" not in text:
        text = text.replace(old, new, 1)
    preprocess_py.write_text(text)
PY_PROMEFUZZ_LLM_TRACE_PATCH
  if ! promefuzz_processors_ready "$runtime_artifact"; then
    printf 'PromeFuzz processor binaries are missing under %s/build/bin. Rebuild the image so docker/promefuzz/Dockerfile runs setup.sh.\n' "$runtime_artifact" >"$workspace/logs/processor.log"
    if [[ "$promefuzz_method_faithful" == "1" ]]; then
      reason="missing_processor_binaries: PromeFuzz processor binaries are missing; rebuild the PromeFuzz image so setup.sh runs during docker build"
      hgb_write_common_metadata infra_failure "$reason" 65 harness_generator
      promefuzz_set_stage api_preprocess failed
      promefuzz_write_final_result infra_failure "$reason" 65
      hgb_write_common_summary infra_failure "$reason" harness_generator
      exit 65
    else
      hgb_soft_skip missing_processor_binaries 'PromeFuzz processor binaries are missing; rebuild the PromeFuzz image so setup.sh runs during docker build' harness_generator
    fi
  fi
  cfg_flag=-c
  if ! (cd "$runtime_artifact" && "$python" PromeFuzz.py --help 2>/dev/null | grep -q -- ' -c'); then
    cfg_flag=--config
  fi
  stages=(preprocess comprehend generate stats)
  : >"$workspace/command.txt"
  code=0
  failed_stage=none
  for stage in "${stages[@]}"; do
    stage_args=("$python" PromeFuzz.py "$cfg_flag" "$config" -F "$libraries" "$stage")
    stage_args+=(--pool-size "$promefuzz_pool_size")
    if [[ "$stage" == "comprehend" ]]; then
      stage_args+=(--task "${PROME_FUZZ_COMPREHEND_TASK:-funcpurp}")
    fi
    printf '%q ' "${stage_args[@]}" >>"$workspace/command.txt"; printf '\n' >>"$workspace/command.txt"
    stage_code=0
    (cd "$runtime_artifact" && timeout "${HGB_GENERATION_TIMEOUT_SECONDS:-10800}" "${stage_args[@]}") >"$workspace/logs/${stage}.log" 2>&1 || stage_code=$?
    if [[ "$stage" == "stats" ]]; then
      continue
    fi
    if [[ "$stage_code" -ne 0 ]]; then
      code="$stage_code"
      failed_stage="$stage"
      break
    fi
    # Stage validation after each upstream stage.
    if [[ "$stage" == "preprocess" ]]; then
      api_json="$workspace/promefuzz_out/$safe_target/preprocessor/api.json"
      api_count_after_preprocess="$($python - "$api_json" <<'PY_PROME_API_COUNT'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    print(0)
    raise SystemExit
if isinstance(data, list):
    print(len(data))
elif isinstance(data, dict):
    funcs = data.get("funcs") or data.get("functions") or data
    print(len(funcs) if hasattr(funcs, "__len__") else 0)
else:
    print(0)
PY_PROME_API_COUNT
)"
      if [[ "${api_count_after_preprocess:-0}" == "0" ]]; then
        promefuzz_set_stage api_preprocess failed
        reason="promefuzz_no_api_candidates: PromeFuzz preprocess completed but extracted zero API functions"
        hgb_write_common_metadata quality_failure "$reason" 1 harness_generator
        promefuzz_write_final_result quality_failure "$reason" 1
        hgb_write_common_summary quality_failure "$reason" harness_generator
        exit 1
      fi
      promefuzz_set_stage api_preprocess completed
    elif [[ "$stage" == "comprehend" ]]; then
      # Validate knowledge artifacts: metadata/type dependency relations and
      # real embeddings must exist where the target API requires structured
      # objects. Consumer call graph/call order are generated when consumer
      # cases exist (recorded by build_context/consumer_cases.json).
      # Beta plan section 6: assert PromeFuzz produced nonempty
      # retrieval/correlation knowledge when consumer cases exist.
      knowledge_dir="$workspace/promefuzz_out/$safe_target"
      comprehend_ok=1
      "$python" - "$knowledge_dir" "$consumer_cases_status" >"$workspace/logs/comprehend_knowledge_audit.log" 2>&1 <<'PY_PROMEFUZZ_COMPREHEND_AUDIT' || comprehend_ok=0
import json
import sys
from pathlib import Path
knowledge_dir = Path(sys.argv[1])
consumer_status = sys.argv[2]
# Look for the upstream comprehend/retrieval artifacts. PromeFuzz writes
# metadata/type/correlation JSON under the output knowledge directory.
candidate_globs = ("*knowledge*", "*comprehend*", "*correlation*", "*retriev*", "*embed*")
knowledge_files = []
if knowledge_dir.is_dir():
    for path in sorted(knowledge_dir.rglob("*")):
        if path.is_file() and any(g.replace("*", "") in path.name.lower() for g in candidate_globs):
            knowledge_files.append(str(path))
if consumer_status == "available" and not knowledge_files:
    print("comprehend produced no retrieval/correlation knowledge despite available consumer cases")
    sys.exit(1)
print(f"knowledge_artifacts={len(knowledge_files)}")
PY_PROMEFUZZ_COMPREHEND_AUDIT
      if [[ "$comprehend_ok" != "1" && "$promefuzz_method_faithful" == "1" ]]; then
        promefuzz_set_stage knowledge failed
        reason="promefuzz_comprehend_empty: PromeFuzz comprehend produced no retrieval/correlation knowledge despite available consumer cases"
        hgb_write_common_metadata quality_failure "$reason" 1 harness_generator
        promefuzz_write_final_result quality_failure "$reason" 1
        hgb_write_common_summary quality_failure "$reason" harness_generator
        exit 1
      fi
      promefuzz_set_stage knowledge completed
      # Eta plan §4: record knowledge_usage.json proving counts of documents,
      # API usage patterns, call correlations, retrieved examples, and APIs
      # used in final prompts. This is required for eta and recorded for all
      # method-faithful profiles.
      "$python" - "$workspace/promefuzz_out/$safe_target" "$consumer_cases_status" "${selected_api_count:-0}" <<'PY_PROMEFUZZ_KNOWLEDGE_USAGE' 2>"$workspace/logs/knowledge_usage.log" || true
import json
import sys
from pathlib import Path
sys.path.insert(0, "/opt/hgb/bin")
try:
    import promefuzz_build_context as pbc
    knowledge_dir = Path(sys.argv[1])
    consumer_status = sys.argv[2]
    selected_api_count = int(sys.argv[3] or 0)
    consumer_count = 0
    consumer_cases_path = Path("/workspace/knowledge/consumer_cases.json")
    if consumer_cases_path.is_file():
        try:
            consumer_count = json.loads(consumer_cases_path.read_text(encoding="utf-8")).get("consumer_count", 0)
        except Exception:
            consumer_count = 0
    pbc.write_knowledge_usage(
        knowledge_dir,
        consumer_cases_status=consumer_status,
        consumer_count=consumer_count,
        selected_api_count=selected_api_count,
    )
except Exception as exc:
    print(f"knowledge_usage_write_failed: {exc}", file=sys.stderr)
PY_PROMEFUZZ_KNOWLEDGE_USAGE
    elif [[ "$stage" == "generate" ]]; then
      promefuzz_set_stage generation completed
    fi
  done
  if [[ -f "$runtime_artifact/logs/llm.log" ]]; then
    cp "$runtime_artifact/logs/llm.log" "$workspace/logs/promefuzz_llm.log" 2>/dev/null || true
  fi
  final_driver_dir="$workspace/promefuzz_out/$safe_target/fuzz_driver"
  temporary_driver_dir="$workspace/promefuzz_out/$safe_target/tmp"
  n=0
  while IFS= read -r generated; do
    n=$((n + 1))
    cp "$generated" "$workspace/generated_harnesses/${n}_$(basename "$generated")" 2>/dev/null || true
  done < <(find "$final_driver_dir" -maxdepth 1 -type f \( -name 'fuzz_driver_*.c' -o -name 'fuzz_driver_*.cc' -o -name 'fuzz_driver_*.cpp' -o -name 'fuzz_driver_*.cxx' \) 2>/dev/null | sort)
  temporary_harness_attempt_count="$(find "$temporary_driver_dir" -type f \( -name 'fuzz_driver_*.c' -o -name 'fuzz_driver_*.cc' -o -name 'fuzz_driver_*.cpp' -o -name 'fuzz_driver_*.cxx' \) 2>/dev/null | wc -l | tr -d ' ')"
  generated_harness_count="$(count_files "$workspace/generated_harnesses" -type f)"
  if [[ "$code" -eq 0 && "${generated_harness_count:-0}" -eq 0 ]]; then
    code=1
    failed_stage=generate
    promefuzz_set_stage generation failed
    reason='PromeFuzz generation completed without producing a sanitized target harness; temporary retry sources were not retained as results'
  fi
  status=evaluated
  reason=none
  if [[ "$code" -ne 0 ]]; then
    status=failed
    reason="PromeFuzz $failed_stage stage exited $code"
    stage_log="$workspace/logs/${failed_stage}.log"
    if [[ -f "$stage_log" ]]; then
      if grep -qi 'hgb_llm_nonretryable\|Insufficient Balance\|ExceededBudget\|budget_exceeded\|Error code: 402' "$stage_log" "$workspace/logs/provider_error.log" 2>/dev/null; then
        reason='PromeFuzz provider rejected a non-retryable request (such as exhausted credit, invalid credentials, or unavailable model); generation stopped without retrying indefinitely'
      elif grep -qi 'localhost.*11434\|port=11434\|/api/embeddings.*Connection refused' "$stage_log"; then
        reason='PromeFuzz embedding service is unavailable at localhost:11434; start Ollama or set PROME_FUZZ_EMBEDDING_LLM_TYPE/base/model/API key'
      elif grep -q 'openai.NotFoundError: Error code: 404\|Error code: 404' "$stage_log"; then
        reason='PromeFuzz embedding API returned 404; set PROME_FUZZ_EMBEDDING_MODEL and embedding base/API key to a compatible embeddings endpoint'
      elif grep -qi 'AuthenticationError\|PermissionDeniedError\|Error code: 401\|Error code: 403\|invalid api key' "$stage_log"; then
        reason='PromeFuzz LLM or embedding API credentials were rejected; verify base URL, model, and API key before rerunning'
      elif grep -qi 'ofg_empty_llm_response\|empty response\|NoneType.*split' "$stage_log"; then
        reason='PromeFuzz LLM API returned empty response content before harness generation'
      elif grep -qi 'APITimeoutError\|ReadTimeout\|The read operation timed out\|Request timed out' "$stage_log"; then
        reason='PromeFuzz LLM or embedding request timed out before harness generation; reduce API/doc caps or increase PROME_FUZZ_LLM_REQUEST_TIMEOUT_SECONDS/HGB_LLM_REQUEST_TIMEOUT_SECONDS'
      elif grep -qi 'Expected Embeddings to be non-empty\|no non-empty chunks\|Skipping document' "$stage_log"; then
        reason='promefuzz_no_usable_docs: PromeFuzz comprehension had no usable non-empty documentation chunks after filtering bad docs'
      elif grep -qi 'pdfminer\|partition_pdf\|Failed to load document.*pdf' "$stage_log"; then
        reason='PromeFuzz PDF document parsing failed; rebuild the image with pdfminer.six or skip bad docs with PROME_FUZZ_SKIP_BAD_DOCS=1'
      elif grep -qi 'nltk\|punkt_tab\|averaged_perceptron' "$stage_log"; then
        reason='PromeFuzz NLTK data is unavailable; rebuild the image so NLTK data is downloaded at docker build time'
      elif grep -qi 'Comprehension not done yet' "$stage_log"; then
        reason='promefuzz_no_api_candidates: PromeFuzz comprehension produced no completed API comprehension records'
      fi
    fi
  fi
  deprecated_api_event_count="$(grep -R -hE 'has failed to generate more than [0-9]+ times, deprecated' "$workspace/logs" 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "$code" -eq 0 && "${deprecated_api_event_count:-0}" -gt 0 ]]; then
    status=partial_completed
    reason="PromeFuzz finalized $generated_harness_count sanitized target harnesses but reported $deprecated_api_event_count deprecated API generation events"
  fi
  # --- Independent common harness evaluator (build + smoke + reachability +
  # campaign + coverage). Beta plan section 9: PromeFuzz reuses the shared
  # full evaluator (hgb_harness_evaluator.py) so there is no parallel,
  # incompatible evaluation abstraction. Only a candidate that passes the
  # exact FuzzBench build and evaluation reaches `evaluated`; a compile-only
  # candidate can never mark campaign/coverage completed. ---
  verification_code=not_run
  verified_harness_count=0
  evaluator_status=""
  evaluator_execs_done=0
  evaluator_cov_lines=""
  evaluator_reached_count=0
  evaluator_metrics_json="{}"
  evaluator_selected_json="{}"
  if [[ "${generated_harness_count:-0}" -gt 0 && "$code" -eq 0 ]]; then
    eval_dir="$workspace/evaluation"
    mkdir -p "$eval_dir"
    evaluator_root="${HGB_EVALUATOR_ROOT:-/target}"
    verification_code=0
    intended_apis_arg=""
    if [[ -f "$selected_api_names_file" ]]; then
      python3 - "$selected_api_names_file" >"$workspace/promefuzz_intended_apis.txt" 2>/dev/null <<'PY_PROMEFUZZ_INTENDED_APIS' || true
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception:
    data = []
names = []
for item in data if isinstance(data, list) else []:
    if isinstance(item, str):
        names.append(item.split('::')[-1])
    elif isinstance(item, dict) and item.get('name'):
        names.append(str(item.get('name')).split('::')[-1])
print(','.join(names))
PY_PROMEFUZZ_INTENDED_APIS
      intended_apis_arg="$(tr -d '\n' <"$workspace/promefuzz_intended_apis.txt" 2>/dev/null || true)"
    fi
    evaluator_args=(
      /opt/hgb/bin/hgb_harness_evaluator.py
      --generator promefuzz
      --target-root /target
      --evaluator-root "$evaluator_root"
      --candidates "$workspace/generated_harnesses"
      --work-dir "$eval_dir"
      --project "$project"
      --fuzz-target "$fuzz_target"
      --profile "$promefuzz_profile"
      --campaign-seconds "${PROME_FUZZ_CAMPAIGN_SECONDS:-$HGB_CAMPAIGN_SECONDS}"
      --build-timeout-seconds "${HGB_PROMEFUZZ_EVAL_BUILD_TIMEOUT:-1800}"
      --strict
    )
    [[ -n "$intended_apis_arg" ]] && evaluator_args+=(--intended-apis "$intended_apis_arg")
    # HGB8 blocker fix / eta plan §2: strict reproduction profiles must build
    # a separate coverage-instrumented image so coverage comes from a real
    # coverage build, not a stdout fallback. zeta/eta additionally run the
    # native coverage control to produce a line-coverage diff (eta plan §5).
    case "$promefuzz_profile" in
      reproduction-delta|reproduction-epsilon|reproduction-zeta|reproduction-eta)
        evaluator_args+=(--build-coverage-image)
        ;;
    esac
    case "$promefuzz_profile" in
      reproduction-zeta|reproduction-eta)
        evaluator_args+=(--run-native-control)
        ;;
    esac
    "$python" "${evaluator_args[@]}" >"$workspace/logs/evaluator.log" 2>&1 || verification_code=$?
    eval_result="$eval_dir/result.json"
    if [[ -f "$eval_result" ]]; then
      evaluator_status="$(python3 -c 'import json; d=json.load(open(sys.argv[1])); print(d.get("status",""))' "$eval_result" 2>/dev/null || printf '')"
      evaluator_execs_done="$(python3 -c 'import json; d=json.load(open(sys.argv[1])); print((d.get("metrics",{}) or {}).get("campaign",{}).get("execs_done",0))' "$eval_result" 2>/dev/null || printf 0)"
      evaluator_cov_lines="$(python3 -c 'import json; d=json.load(open(sys.argv[1])); v=(d.get("metrics",{}) or {}).get("coverage",{}).get("line_coverage",{}).get("covered"); print("" if v is None else v)' "$eval_result" 2>/dev/null || true)"
      evaluator_reached_count="$(python3 -c 'import json; d=json.load(open(sys.argv[1])); sel=d.get("selected_candidate",{}) or {}; print(len(sel.get("api_reachability",{}).get("reached_apis",[]) or []))' "$eval_result" 2>/dev/null || printf 0)"
      evaluator_metrics_json="$(python3 -c 'import json; d=json.load(open(sys.argv[1])); print(json.dumps(d.get("metrics",{}) or {}))' "$eval_result" 2>/dev/null || printf '{}')"
      evaluator_selected_json="$(python3 -c 'import json; d=json.load(open(sys.argv[1])); print(json.dumps(d.get("selected_candidate",{}) or {}))' "$eval_result" 2>/dev/null || printf '{}')"
      verified_harness_count="$(python3 -c 'import json; d=json.load(open(sys.argv[1])); sel=d.get("selected_candidate",{}) or {}; print(1 if sel.get("overlaid") and all((d.get("stages",{}) or {}).get(s)=="completed" for s in ("candidate_overlay","copy_audit","candidate_build","sanitizer_smoke","api_reachability","campaign","coverage")) else 0)' "$eval_result" 2>/dev/null || printf '0')"
      # Beta plan section 9: set campaign/coverage/reachability stages ONLY
      # from the shared evaluator output, never from a build-only success.
      for stage in candidate_overlay copy_audit candidate_build sanitizer_smoke api_reachability campaign coverage; do
        stage_state="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print((d.get("stages",{}) or {}).get(sys.argv[2],"pending"))' "$eval_result" "$stage" 2>/dev/null || printf pending)"
        promefuzz_set_stage "$stage" "$stage_state"
      done
      promefuzz_set_stage generation completed
    else
      for stage in candidate_overlay copy_audit candidate_build sanitizer_smoke api_reachability campaign coverage; do
        promefuzz_set_stage "$stage" failed
      done
      evaluator_status=""
    fi
    # Beta plan section 10: derive the canonical status from the evaluator.
    final_eval_status="$("$python" - "$evaluator_status" "$promefuzz_profile" "$workspace/promefuzz_stages.json" "${verified_harness_count:-0}" "${evaluator_execs_done:-0}" "${evaluator_cov_lines:-}" "${evaluator_reached_count:-0}" <<'PY_PROMEFUZZ_FINAL_STATUS'
import json
import os
import sys
sys.path.insert(0, "/opt/hgb/bin")
import promefuzz_profile
evaluator_status = sys.argv[1]
profile = sys.argv[2]
try:
    stages = json.loads(open(sys.argv[3]).read())
except Exception:
    stages = promefuzz_profile.default_stages()
candidate_count = int(sys.argv[4] or 0)
execs_done = int(sys.argv[5] or 0)
cov_lines = sys.argv[6]
try:
    cov_lines_int = int(cov_lines) if cov_lines not in ("", "None") else None
except ValueError:
    cov_lines_int = None
reached_count = int(sys.argv[7] or 0)
print(promefuzz_profile.finalize_status_from_evaluator(
    evaluator_status,
    stages=stages,
    profile=profile,
    coverage_covered_lines=cov_lines_int,
    campaign_execs_done=execs_done,
    reached_count=reached_count,
    candidate_count=candidate_count,
))
PY_PROMEFUZZ_FINAL_STATUS
)"
    if [[ "$final_eval_status" == "evaluated" ]]; then
      status=evaluated
      reason=none
      code=0
    elif [[ "$final_eval_status" == "infra_failure" ]]; then
      status=infra_failure
      reason="promefuzz_infra_failure: shared harness evaluator tooling failed"
      [[ "$verification_code" -ne 0 ]] && reason="$reason (exit $verification_code)"
      code=2
    elif [[ "$final_eval_status" == "compat_smoke_completed" ]]; then
      status=compat_smoke_completed
      reason="compat-smoke completed (excluded from aggregate)"
      code=0
    else
      status=quality_failure
      reason="promefuzz_no_verified_harness: no generated harness passed the exact FuzzBench build + smoke + reachability + campaign + coverage evaluation"
      code=5
    fi
  elif [[ "$code" -eq 0 ]]; then
    promefuzz_set_stage candidate_build failed
    status=quality_failure
    reason="promefuzz_no_generated_harness: generation produced no candidate harness to evaluate"
    code=4
  fi
  # Derive the canonical status from the PromeFuzz stage states as a backstop.
  stage_status="$(promefuzz_result_status)"
  if [[ "$status" == "evaluated" && "$stage_status" != "evaluated" ]]; then
    status=quality_failure
    reason="promefuzz_evaluator_incomplete: evaluator stages not all completed"
    code=5
  fi
  # --- Reference leakage audit ---
  # If the host placed a canary token in the evaluator-only reference source
  # (HGB_REF_CANARY), scan all PromeFuzz generator inputs and outputs to prove
  # it never reached prompts, logs, configs, API collections, embeddings, or
  # candidate context.
  promefuzz_leakage_audit='{}'
  if [[ -n "${HGB_REF_CANARY:-}" ]]; then
    promefuzz_leakage_audit="$("$python" /opt/hgb/bin/promefuzz_profile.py audit \
      --generator-input /target/source_input \
      --canary "$HGB_REF_CANARY" \
      --extra-dir "$workspace" \
      --extra-dir "$workspace/promefuzz_out" 2>/dev/null || printf '{"leaked":true,"error":"audit_failed"}')"
    if printf '%s' "$promefuzz_leakage_audit" | grep -q '"leaked": *true'; then
      printf 'Reference leakage audit FAILED: canary token found in PromeFuzz generator data\n' >"$workspace/logs/leakage_audit.log"
      printf '%s\n' "$promefuzz_leakage_audit" >>"$workspace/logs/leakage_audit.log"
      if [[ "$code" -eq 0 ]]; then
        code=8
        status=failed
        reason='promefuzz_reference_leakage: canary token from evaluator-only reference source reached PromeFuzz generator data'
      fi
    else
      printf 'Reference leakage audit passed: no canary leakage detected\n' >"$workspace/logs/leakage_audit.log"
    fi
  fi
  if [[ "${HGB_SAVE_MODE:-compact}" == "compact" ]]; then
    rm -rf "$workspace/promefuzz_build" "$workspace/promefuzz_native_build" "$workspace/promefuzz_out"
  fi
  api_selection_extra="$(hgb_api_selection_metadata_json "$api_selection_metadata")"
  extra=$(printf '%s  "libraries_file": "%s",\n  "compile_commands_path": "%s",\n  "api_candidate_count": %s,\n  "api_selection_metadata": "%s",\n  "command_file": "%s",\n  "failed_stage": "%s",\n  "native_build_enabled": %s,\n  "native_harness_destination": "%s",\n  "final_harness_count": %s,\n  "temporary_harness_attempt_count": %s,\n  "deprecated_api_event_count": %s,\n  "driver_build_args": %s,\n  "verified_harness_count": %s,\n  "candidate_verification_exit_code": "%s"' "$api_selection_extra" "$(hgb_json_escape "$libraries")" "$(hgb_json_escape "$compile_db_for_metadata")" "${selected_api_count:-0}" "$(hgb_json_escape "$api_selection_metadata")" "$(hgb_json_escape "$workspace/command.txt")" "$(hgb_json_escape "$failed_stage")" "$native_build_json" "$(hgb_json_escape "$native_harness_destination")" "${generated_harness_count:-0}" "${temporary_harness_attempt_count:-0}" "${deprecated_api_event_count:-0}" "$driver_build_args_json" "${verified_harness_count:-0}" "$(hgb_json_escape "$verification_code")")
  hgb_write_common_metadata "$status" "$reason" "$code" harness_generator "$extra"
  export PROME_FUZZ_EVALUATOR_METRICS="$evaluator_metrics_json"
  export PROME_FUZZ_EVALUATOR_SELECTED="$evaluator_selected_json"
  export PROME_FUZZ_CANDIDATE_COUNT="${generated_harness_count:-0}"
  export PROME_FUZZ_CONSUMER_CASES_STATUS="$consumer_cases_status"
  # Delta plan section 6: method evidence for the result row.
  export PROME_FUZZ_DRIVER_BUILD_ARGS_COUNT="$driver_build_args_count"
  promefuzz_compile_db_strategy=""
  promefuzz_compile_db_count=0
  if [[ -f "$workspace/build_context/provenance.json" ]]; then
    promefuzz_compile_db_strategy="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("strategy",""))' "$workspace/build_context/provenance.json" 2>/dev/null || printf '')"
    promefuzz_compile_db_count="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("compile_commands_count",0))' "$workspace/build_context/provenance.json" 2>/dev/null || printf '0')"
  fi
  export PROME_FUZZ_COMPILE_DB_STRATEGY="$promefuzz_compile_db_strategy"
  export PROME_FUZZ_COMPILE_DB_COUNT="$promefuzz_compile_db_count"
  # Consumer knowledge artifacts nonempty: true when comprehend produced
  # knowledge files AND consumer cases were available.
  promefuzz_consumer_artifacts_nonempty=false
  if [[ "$consumer_cases_status" == "available" && -f "$workspace/logs/comprehend_knowledge_audit.log" ]]; then
    if grep -q 'knowledge_artifacts=[1-9]' "$workspace/logs/comprehend_knowledge_audit.log" 2>/dev/null; then
      promefuzz_consumer_artifacts_nonempty=true
    fi
  fi
  export PROME_FUZZ_CONSUMER_ARTIFACTS_NONEMPTY="$promefuzz_consumer_artifacts_nonempty"
  export PROME_FUZZ_GENERATION_MODE="ALL-COVER"
  promefuzz_write_final_result "$status" "$reason" "$code" "$promefuzz_leakage_audit"
  hgb_write_common_summary "$status" "$reason" harness_generator
  exit "$code"
fi
[[ "$mode" == "smoke-pugixml" || "$mode" == "smoke" ]] || { echo "unknown mode: $mode" >&2; exit 64; }
export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
export OPENAI_MODEL="${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
export HGB_LLM_REQUEST_TIMEOUT_SECONDS="${HGB_LLM_REQUEST_TIMEOUT_SECONDS:-1200}"
export PROME_FUZZ_LLM_REQUEST_TIMEOUT_SECONDS="${PROME_FUZZ_LLM_REQUEST_TIMEOUT_SECONDS:-$HGB_LLM_REQUEST_TIMEOUT_SECONDS}"
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
