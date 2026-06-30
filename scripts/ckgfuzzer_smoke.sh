#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

json_escape() {
  local value="${1:-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "$value"
}

read_env_file() {
  local file="$1"
  [[ -f "$file" ]] || return 1
  # shellcheck disable=SC1090
  source "$file"
}

run_stage() {
  local stage="$1"
  local cwd="$2"
  local log_file="$3"
  local timeout_seconds="$4"
  shift 4
  local -a cmd=("$@")
  local code=0

  printf '%q ' "${cmd[@]}" >"$(dirname "$log_file")/$stage.cmd"
  printf '\n' >>"$(dirname "$log_file")/$stage.cmd"
  (
    cd "$cwd"
    timeout "$timeout_seconds" "${cmd[@]}"
  ) >"$log_file" 2>&1 || code=$?
  printf '%s\n' "$code" >"$(dirname "$log_file")/$stage.exit"
  return 0
}

copy_if_exists() {
  local src="$1"
  local dst="$2"
  if [[ -e "$src" ]]; then
    mkdir -p "$(dirname "$dst")"
    cp -a "$src" "$dst"
  fi
}

write_metadata() {
  local metadata_file="$1"
  local upstream_dir="$2"
  local project="$3"
  local model="$4"
  local config_file="$5"
  local repo_code="$6"
  local preproc_code="$7"
  local fuzzing_code="$8"
  local start_time="$9"
  local end_time="${10}"
  local commit
  commit="$(git -C "$upstream_dir" rev-parse HEAD)"
  {
    printf '{\n'
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$commit")"
    printf '  "project": "%s",\n' "$(json_escape "$project")"
    printf '  "model": "%s",\n' "$(json_escape "$model")"
    printf '  "config": "%s",\n' "$(json_escape "$config_file")"
    printf '  "start_time": "%s",\n' "$(json_escape "$start_time")"
    printf '  "end_time": "%s",\n' "$(json_escape "$end_time")"
    printf '  "stages": {\n'
    printf '    "repo": %s,\n' "$repo_code"
    printf '    "preproc": %s,\n' "$preproc_code"
    printf '    "fuzzing": %s\n' "$fuzzing_code"
    printf '  }\n'
    printf '}\n'
  } >"$metadata_file"
}

main() {
  local root upstream_dir engine_dir selected_env project workspace database_dir project_dir shared_dir config_file venv_dir
  local timeout_seconds timestamp run_dir generated_dir start_time end_time model
  local repo_code preproc_code fuzzing_code

  root="$(repo_root)"
  load_env
  require_cmd timeout

  upstream_dir="$root/external/CKGFuzzer"
  engine_dir="$upstream_dir/fuzzing_llm_engine"
  venv_dir="$upstream_dir/.venv-hgb"
  [[ -d "$upstream_dir/.git" ]] || die "Missing $upstream_dir. Run: bash scripts/ckgfuzzer_setup.sh"
  [[ -d "$venv_dir" ]] || die "Missing $venv_dir. Run: bash scripts/ckgfuzzer_setup.sh"

  selected_env="$root/${HGB_RESULTS_DIR:-results}/ckgfuzzer/selected_project.env"
  if [[ ! -f "$selected_env" ]]; then
    log "No prepared CKGFuzzer project found; running scripts/ckgfuzzer_prepare_project.sh"
    bash "$SCRIPT_DIR/ckgfuzzer_prepare_project.sh"
  fi
  read_env_file "$selected_env" || die "Could not read $selected_env"

  project="${CKGFUZZER_PROJECT:-hgb-sample}"
  workspace="${CKGFUZZER_WORKSPACE:?missing CKGFUZZER_WORKSPACE in selected_project.env}"
  database_dir="${CKGFUZZER_DATABASE_DIR:?missing CKGFUZZER_DATABASE_DIR in selected_project.env}"
  project_dir="${CKGFUZZER_PROJECT_DIR:?missing CKGFUZZER_PROJECT_DIR in selected_project.env}"
  shared_dir="${CKGFUZZER_SHARED_DIR:?missing CKGFUZZER_SHARED_DIR in selected_project.env}"
  config_file="${CKGFUZZER_CONFIG:?missing CKGFUZZER_CONFIG in selected_project.env}"
  timeout_seconds="${CKGFUZZER_TIMEOUT_SECONDS:-600}"
  [[ "$timeout_seconds" =~ ^[0-9]+$ ]] || die "CKGFUZZER_TIMEOUT_SECONDS must be an integer number of seconds"
  model="${CKGFUZZER_MODEL:-${OPENAI_MODEL:-gpt-4o-mini}}"

  timestamp="$(make_timestamp)"
  run_dir="$root/${HGB_RESULTS_DIR:-results}/ckgfuzzer/smoke_$timestamp"
  generated_dir="$run_dir/generated"
  ensure_dir "$run_dir/logs"
  ensure_dir "$run_dir/commands"
  ensure_dir "$generated_dir"

  # shellcheck disable=SC1091
  source "$venv_dir/bin/activate"
  export PYTHONPATH="$engine_dir:${PYTHONPATH:-}"
  export PATH="$shared_dir/codeql:$PATH"

  start_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  run_stage repo "$engine_dir/repo" "$run_dir/logs/repo.log" "$timeout_seconds" \
    python repo.py \
      --project_name "$project" \
      --shared_llm_dir "$shared_dir" \
      --saved_dir "$database_dir/codebase" \
      --language c \
      --src_api \
      --call_graph
  repo_code="$(cat "$run_dir/logs/repo.exit")"

  run_stage preproc "$engine_dir/repo" "$run_dir/logs/preproc.log" "$timeout_seconds" \
    python preproc.py \
      --project_name "$project" \
      --src_api_file_path "$database_dir"
  preproc_code="$(cat "$run_dir/logs/preproc.exit")"

  run_stage fuzzing "$engine_dir" "$run_dir/logs/fuzzing.log" "$timeout_seconds" \
    python fuzzing.py \
      --yaml "$config_file" \
      --gen_driver \
      --summary_api \
      --check_compilation \
      --gen_input
  fuzzing_code="$(cat "$run_dir/logs/fuzzing.exit")"

  end_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  copy_if_exists "$database_dir/api_summary" "$generated_dir/api_summary"
  copy_if_exists "$database_dir/api_combine" "$generated_dir/api_combine"
  copy_if_exists "$database_dir/src" "$generated_dir/src"
  copy_if_exists "$database_dir/agents_results" "$generated_dir/agents_results"
  copy_if_exists "$database_dir/fuzz_driver" "$generated_dir/fuzz_driver"
  copy_if_exists "$shared_dir/fuzz_driver/$project" "$generated_dir/shared_fuzz_driver"
  copy_if_exists "$database_dir/codebase/api/src_api.json" "$generated_dir/src_api.json"
  copy_if_exists "$database_dir/api_list.json" "$generated_dir/api_list.json"
  cp -a "$run_dir/logs"/*.log "$generated_dir/" 2>/dev/null || true

  write_metadata "$run_dir/metadata.json" "$upstream_dir" "$project" "$model" "$config_file" "$repo_code" "$preproc_code" "$fuzzing_code" "$start_time" "$end_time"

  if [[ "$repo_code" -ne 0 || "$preproc_code" -ne 0 || "$fuzzing_code" -ne 0 ]]; then
    if grep -RqiE 'codeql|No such file|database create' "$run_dir/logs"; then
      printf 'CKGFuzzer smoke recorded a likely CodeQL/database-stage issue.\n' >&2
    elif grep -RqiE 'api_key|OPENAI|unauthorized|model|ollama|embedding' "$run_dir/logs"; then
      printf 'CKGFuzzer smoke recorded a likely LLM/model/embedding issue.\n' >&2
    else
      printf 'CKGFuzzer smoke recorded a stage failure; inspect logs.\n' >&2
    fi
    printf 'Run directory: %s\n' "$run_dir" >&2
    exit 1
  fi

  log "CKGFuzzer smoke completed: $run_dir"
}

main "$@"
