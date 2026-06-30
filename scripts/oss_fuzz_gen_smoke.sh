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

first_existing_file() {
  local candidate
  for candidate in "$@"; do
    if [[ -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

locate_benchmark_yaml() {
  local upstream_dir="$1"
  local benchmark="$2"
  local preferred

  preferred="$upstream_dir/benchmark-sets/all/$benchmark.yaml"
  if [[ -f "$preferred" ]]; then
    printf '%s\n' "$preferred"
    return 0
  fi

  first_existing_file \
    "$upstream_dir/benchmark-sets/$benchmark.yaml" \
    "$upstream_dir/benchmark-sets/test/$benchmark.yaml" \
    "$upstream_dir/benchmark-sets/samples/$benchmark.yaml" && return 0

  find "$upstream_dir/benchmark-sets" -type f \( -name '*.yaml' -o -name '*.yml' \) \
    \( -iname "*$benchmark*" -o -exec grep -Il "$benchmark" {} \; \) \
    | sort \
    | head -n 1
}

append_if_supported() {
  local help_file="$1"
  local flag="$2"
  local value="$3"
  shift 3

  if grep -Eq -- "(^|[[:space:]])$flag([,=[:space:]]|$)" "$help_file"; then
    printf '%s\0%s\0' "$flag" "$value"
  fi
}

write_metadata() {
  local metadata_file="$1"
  local command_file="$2"
  local benchmark_yaml="$3"
  local model="$4"
  local timeout_seconds="$5"
  local total_timeout_seconds="$6"
  local upstream_commit="$7"
  local start_time="$8"
  local end_time="$9"
  local exit_code="${10}"
  local log_file="${11}"

  {
    printf '{\n'
    printf '  "command_file": "%s",\n' "$(json_escape "$command_file")"
    printf '  "benchmark_yaml": "%s",\n' "$(json_escape "$benchmark_yaml")"
    printf '  "model": "%s",\n' "$(json_escape "$model")"
    printf '  "timeout_seconds": %s,\n' "$timeout_seconds"
    printf '  "outer_timeout_seconds": %s,\n' "$total_timeout_seconds"
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$upstream_commit")"
    printf '  "start_time": "%s",\n' "$(json_escape "$start_time")"
    printf '  "end_time": "%s",\n' "$(json_escape "$end_time")"
    printf '  "exit_code": %s,\n' "$exit_code"
    printf '  "log_file": "%s"\n' "$(json_escape "$log_file")"
    printf '}\n'
  } >"$metadata_file"
}

diagnose_failure() {
  local log_file="$1"
  if grep -Eiq 'OPENAI|API key|api_key|credential|401|403|permission|unauthorized|quota|model' "$log_file"; then
    printf 'OSS-Fuzz-Gen smoke failed; run.log suggests a model/backend credential or quota issue.\n' >&2
  elif grep -Eiq 'docker|daemon|permission denied|Cannot connect to the Docker daemon|image|build failed' "$log_file"; then
    printf 'OSS-Fuzz-Gen smoke failed; run.log suggests a Docker or OSS-Fuzz image build issue.\n' >&2
  else
    printf 'OSS-Fuzz-Gen smoke failed; inspect run.log for the upstream error.\n' >&2
  fi
}

main() {
  local root upstream_dir venv_dir benchmark model run_timeout max_rounds workers timestamp
  local out_dir abs_out_dir log_file metadata_file help_file command_file benchmark_yaml
  local start_time end_time exit_code upstream_commit total_timeout
  local -a command extra_args run_command

  root="$(repo_root)"
  load_env
  require_cmd timeout

  upstream_dir="$root/external/oss-fuzz-gen"
  venv_dir="$upstream_dir/.venv-hgb"
  [[ -d "$upstream_dir/.git" ]] || die "Missing $upstream_dir. Run: bash scripts/oss_fuzz_gen_setup.sh"
  [[ -f "$upstream_dir/run_all_experiments.py" ]] || die "Missing run_all_experiments.py in $upstream_dir"
  [[ -d "$venv_dir" ]] || die "Missing $venv_dir. Run: bash scripts/oss_fuzz_gen_setup.sh"

  benchmark="${OFG_BENCHMARK:-tinyxml2}"
  model="${OFG_MODEL:-${OPENAI_MODEL:-gpt-4o-mini}}"
  run_timeout="${OFG_RUN_TIMEOUT:-${HGB_TIMEOUT_SECONDS:-300}}"
  [[ "$run_timeout" =~ ^[0-9]+$ ]] || die "OFG_RUN_TIMEOUT must be an integer number of seconds"
  total_timeout="${OFG_TOTAL_TIMEOUT_SECONDS:-$((run_timeout + 300))}"
  [[ "$total_timeout" =~ ^[0-9]+$ ]] || die "OFG_TOTAL_TIMEOUT_SECONDS must be an integer number of seconds"
  max_rounds="${OFG_MAX_ROUNDS:-1}"
  workers="${OFG_WORKERS:-1}"

  benchmark_yaml="$(locate_benchmark_yaml "$upstream_dir" "$benchmark")"
  [[ -n "$benchmark_yaml" && -f "$benchmark_yaml" ]] || die "Could not locate benchmark YAML for $benchmark under $upstream_dir/benchmark-sets"

  timestamp="$(make_timestamp)"
  out_dir="$root/${HGB_RESULTS_DIR:-results}/oss-fuzz-gen/smoke_$timestamp"
  ensure_dir "$out_dir"
  abs_out_dir="$(cd "$out_dir" && pwd)"
  log_file="$abs_out_dir/run.log"
  metadata_file="$abs_out_dir/metadata.json"
  help_file="$abs_out_dir/run_all_experiments_help.txt"
  command_file="$abs_out_dir/command.txt"

  # shellcheck disable=SC1091
  source "$venv_dir/bin/activate"
  (
    cd "$upstream_dir"
    python run_all_experiments.py --help
  ) >"$help_file" 2>&1 || true

  command=(python run_all_experiments.py -y "$benchmark_yaml" --model "$model" --run-timeout "$run_timeout" --work-dir "$abs_out_dir")

  mapfile -d '' -t extra_args < <(
    append_if_supported "$help_file" "--max-round" "$max_rounds"
    append_if_supported "$help_file" "--num-samples" "$max_rounds"
    append_if_supported "$help_file" "--workers" "$workers"
    append_if_supported "$help_file" "--num-workers" "$workers"
  )
  if [[ "${#extra_args[@]}" -gt 0 ]]; then
    command+=("${extra_args[@]}")
  fi
  run_command=(timeout "$total_timeout" "${command[@]}")

  printf '%q ' "${run_command[@]}" >"$command_file"
  printf '\n' >>"$command_file"

  start_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  upstream_commit="$(git -C "$upstream_dir" rev-parse HEAD)"
  exit_code=0
  (
    cd "$upstream_dir"
    "${run_command[@]}"
  ) >"$log_file" 2>&1 || exit_code=$?
  end_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  write_metadata "$metadata_file" "$command_file" "$benchmark_yaml" "$model" "$run_timeout" "$total_timeout" "$upstream_commit" "$start_time" "$end_time" "$exit_code" "$log_file"

  if [[ "$exit_code" -ne 0 ]]; then
    if [[ "$exit_code" -eq 124 ]]; then
      printf 'OSS-Fuzz-Gen smoke reached outer timeout (%s seconds). Logs and metadata were preserved.\n' "$total_timeout" >&2
    fi
    diagnose_failure "$log_file"
    printf 'Run directory: %s\n' "$abs_out_dir" >&2
    exit "$exit_code"
  fi

  log "OSS-Fuzz-Gen smoke completed: $abs_out_dir"
}

main "$@"
