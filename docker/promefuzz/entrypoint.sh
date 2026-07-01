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

if [[ "$mode" == "generate-target" ]]; then
  # shellcheck source=/opt/hgb/bin/target_contract.sh
  source /opt/hgb/bin/target_contract.sh
  export HGB_GENERATOR="${HGB_GENERATOR:-promefuzz}"
  export HGB_GENERATOR_ARTIFACT_DIR="$artifact"
  export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
  export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
  export OPENAI_MODEL="${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
  mkdir -p "$workspace/logs" "$workspace/generated_harnesses" "$workspace/promefuzz_out" /run/hgb/promefuzz
  hgb_require_target_package
  target_name="${HGB_TARGET:-$(hgb_target_manifest_value target)}"
  safe_target="$(printf '%s' "$target_name" | sed 's/[^A-Za-z0-9_]/_/g')"
  language="c++"
  if find /target/source_input -type f \( -name '*.c' -o -name '*.h' \) 2>/dev/null | grep -q . && ! find /target/source_input -type f \( -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' -o -name '*.hpp' \) 2>/dev/null | grep -q .; then
    language="c"
  fi
  config=/run/hgb/promefuzz/config.toml
  libraries=/run/hgb/promefuzz/libraries.toml
  cat >"$config" <<EOF_PROMEFUZZ_CONFIG
[llm.hgb_cloud]
llm_type = "openai"
base_url = "${OPENAI_BASE_URL:-https://api.openai.com/v1}"
api_key = "${OPENAI_API_KEY:-}"
model = "${OPENAI_MODEL:-}"
EOF_PROMEFUZZ_CONFIG
  compile_db="$workspace/promefuzz_build/compile_commands.json"
  preserved_compile_db="$workspace/compile_commands.json"
  compile_db_for_metadata="$compile_db"
  mkdir -p "$workspace/promefuzz_build"
  cmake_src="$(find /target/source_input -name CMakeLists.txt -type f -printf '%h\n' 2>/dev/null | head -n 1 || true)"
  if [[ -n "$cmake_src" ]]; then
    cmake -S "$cmake_src" -B "$workspace/promefuzz_build" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON >"$workspace/logs/cmake.log" 2>&1 || true
  fi
  if [[ ! -f "$compile_db" && "${HGB_PROMEFUZZ_TRY_FUZZBENCH_BUILD:-1}" == "1" ]] && command -v bear >/dev/null 2>&1; then
    mkdir -p "$workspace/promefuzz_build/src" "$workspace/promefuzz_build/out" "$workspace/promefuzz_build/work"
    cp -a /target/source_input/. "$workspace/promefuzz_build/src/" 2>/dev/null || true
    (cd "$workspace/promefuzz_build" && SRC="$workspace/promefuzz_build/src" OUT="$workspace/promefuzz_build/out" WORK="$workspace/promefuzz_build/work" bear -- bash /target/fuzzbench_benchmark/build.sh) >"$workspace/logs/bear.log" 2>&1 || true
    if [[ -f "$workspace/promefuzz_build/compile_commands.json" && ! -f "$compile_db" ]]; then
      cp "$workspace/promefuzz_build/compile_commands.json" "$compile_db" 2>/dev/null || true
    fi
  fi
  if [[ -f "$compile_db" ]]; then
    cp "$compile_db" "$preserved_compile_db" 2>/dev/null || true
    compile_db_for_metadata="$preserved_compile_db"
  fi
  cat >"$libraries" <<EOF_PROMEFUZZ_LIBS
[$safe_target]
language = "$language"
header_paths = ["/target/source_input"]
compile_commands_path = "$compile_db"
document_paths = ["/target/docs"]
document_has_api_usage = true
output_path = "$workspace/promefuzz_out/$safe_target"
compile_args = ""
EOF_PROMEFUZZ_LIBS
  printf 'PromeFuzz config: %s\nPromeFuzz libraries: %s\n' "$config" "$libraries" >"$workspace/command.txt"
  if [[ ! -f "$compile_db" ]]; then
    cp "$libraries" "$workspace/promefuzz_libraries.toml" 2>/dev/null || true
    if [[ "${HGB_SAVE_MODE:-compact}" == "compact" ]]; then
      rm -rf "$workspace/promefuzz_build" "$workspace/promefuzz_out"
    fi
    hgb_soft_skip needs_compile_commands 'PromeFuzz requires compile_commands.json; no CMake database was created and FuzzBench build replay is disabled by default' harness_generator
  fi
  if [[ "${HGB_DRY_RUN:-0}" == "1" ]]; then
    cp "$libraries" "$workspace/promefuzz_libraries.toml" 2>/dev/null || true
    if [[ "${HGB_SAVE_MODE:-compact}" == "compact" ]]; then
      rm -rf "$workspace/promefuzz_build" "$workspace/promefuzz_out"
    fi
    hgb_write_common_metadata dry_run_ok 'dry run prepared PromeFuzz config and compile_commands.json' 0 harness_generator
    hgb_write_common_summary dry_run_ok 'dry run prepared PromeFuzz config and compile_commands.json' harness_generator
    exit 0
  fi
  if ! hgb_api_key_present; then
    printf 'OPENAI_API_KEY is not set; PromeFuzz target generation skipped.\n' >"$workspace/logs/run.log"
    hgb_write_common_metadata missing_api_key 'OPENAI_API_KEY is not set' 2 harness_generator
    hgb_write_common_summary missing_api_key 'OPENAI_API_KEY is not set' harness_generator
    exit 2
  fi
  runtime_artifact=/run/hgb/promefuzz/artifact
  rm -rf "$runtime_artifact"
  mkdir -p "$runtime_artifact"
  cp -a "$artifact/." "$runtime_artifact/"
  cfg_flag=-c
  if ! (cd "$runtime_artifact" && "$python" PromeFuzz.py --help 2>/dev/null | grep -q -- ' -c'); then
    cfg_flag=--config
  fi
  stages=(preprocess comprehend generate stats)
  : >"$workspace/command.txt"
  code=0
  for stage in "${stages[@]}"; do
    printf '%q ' "$python" PromeFuzz.py "$cfg_flag" "$config" -F "$libraries" "$stage" >>"$workspace/command.txt"; printf '\n' >>"$workspace/command.txt"
    stage_code=0
    (cd "$runtime_artifact" && timeout "${HGB_GENERATION_TIMEOUT_SECONDS:-900}" "$python" PromeFuzz.py "$cfg_flag" "$config" -F "$libraries" "$stage") >"$workspace/logs/${stage}.log" 2>&1 || stage_code=$?
    if [[ "$stage" == "stats" ]]; then
      continue
    fi
    if [[ "$stage_code" -ne 0 ]]; then
      code="$stage_code"
      break
    fi
  done
  n=0
  while IFS= read -r generated; do
    n=$((n + 1))
    cp "$generated" "$workspace/generated_harnesses/${n}_$(basename "$generated")" 2>/dev/null || true
  done < <(find "$workspace/promefuzz_out" "$runtime_artifact" -type f \( -name '*fuzz*.c' -o -name '*fuzz*.cc' -o -name '*fuzz*.cpp' -o -name 'fuzz_driver_*' \) 2>/dev/null | sort)
  status=completed
  reason=none
  if [[ "$code" -ne 0 ]]; then
    status=failed
    reason="PromeFuzz stage exited $code"
  fi
  if [[ "${HGB_SAVE_MODE:-compact}" == "compact" ]]; then
    rm -rf "$workspace/promefuzz_build" "$workspace/promefuzz_out"
  fi
  extra=$(printf '  "libraries_file": "%s",\n  "compile_commands_path": "%s",\n  "command_file": "%s"' "$(hgb_json_escape "$libraries")" "$(hgb_json_escape "$compile_db_for_metadata")" "$(hgb_json_escape "$workspace/command.txt")")
  hgb_write_common_metadata "$status" "$reason" "$code" harness_generator "$extra"
  hgb_write_common_summary "$status" "$reason" harness_generator
  exit "$code"
fi
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
