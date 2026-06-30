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

extract_json_string() {
  local key="$1"
  local file="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$file" | head -n 1
}

count_files() {
  local dir="$1"
  shift
  if [[ ! -d "$dir" ]]; then
    printf '0'
    return 0
  fi
  find "$dir" "$@" 2>/dev/null | wc -l | tr -d ' '
}

write_metadata() {
  local metadata_file="$1"
  local upstream_dir="$2"
  local data_dir="$3"
  local program="$4"
  local formats="$5"
  local model="$6"
  local run_dir="$7"
  local output_dir="$8"
  local data_path="$9"
  local exit_code="${10}"
  local seed_count="${11}"
  local generator_count="${12}"
  local start_time="${13}"
  local end_time="${14}"
  local log_file="${15}"
  local upstream_commit data_commit

  upstream_commit="$(git -C "$upstream_dir" rev-parse HEAD 2>/dev/null || printf 'unknown')"
  data_commit="$(git -C "$data_dir" rev-parse HEAD 2>/dev/null || printf 'unknown')"
  {
    printf '{\n'
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$upstream_commit")"
    printf '  "data_commit": "%s",\n' "$(json_escape "$data_commit")"
    printf '  "program": "%s",\n' "$(json_escape "$program")"
    printf '  "formats": "%s",\n' "$(json_escape "$formats")"
    printf '  "model": "%s",\n' "$(json_escape "$model")"
    printf '  "run_dir": "%s",\n' "$(json_escape "$run_dir")"
    printf '  "output_dir": "%s",\n' "$(json_escape "$output_dir")"
    printf '  "generated_seed_count": %s,\n' "$seed_count"
    printf '  "generator_count": %s,\n' "$generator_count"
    printf '  "program_gen_exit_code": %s,\n' "$exit_code"
    printf '  "data_repo_comparison_path": "%s",\n' "$(json_escape "$data_path")"
    printf '  "start_time": "%s",\n' "$(json_escape "$start_time")"
    printf '  "end_time": "%s",\n' "$(json_escape "$end_time")"
    printf '  "log_file": "%s"\n' "$(json_escape "$log_file")"
    printf '}\n'
  } >"$metadata_file"
}

main() {
  local root upstream_dir data_dir selected_json program formats model timestamp run_dir runtime_dir output_dir log_file
  local venv_dir start_time end_time exit_code seed_count generator_count data_path timeout_seconds

  root="$(repo_root)"
  load_env
  require_cmd git
  require_cmd python3
  require_cmd timeout

  upstream_dir="$root/external/G2FUZZ"
  data_dir="$root/external/G2FUZZ-DATA"
  venv_dir="$upstream_dir/.venv-hgb"
  [[ -d "$upstream_dir/.git" ]] || die "Missing $upstream_dir. Run: bash scripts/g2fuzz_setup.sh"
  [[ -x "$venv_dir/bin/python" ]] || die "Missing G2FUZZ venv. Run: bash scripts/g2fuzz_setup.sh"

  selected_json="$root/${HGB_RESULTS_DIR:-results}/g2fuzz/selected_target.json"
  if [[ ! -f "$selected_json" ]]; then
    bash "$SCRIPT_DIR/g2fuzz_select_target.sh"
  fi
  program="$(extract_json_string program "$selected_json")"
  formats="$(python3.12 - "$selected_json" <<'PY'
import json, sys
data=json.load(open(sys.argv[1]))
print(",".join(data["formats"]))
PY
)"
  data_path="$(extract_json_string data_repo_comparison_path "$selected_json")"
  model="${G2FUZZ_MODEL:-gpt-4o-mini}"
  timeout_seconds="${G2FUZZ_TIMEOUT_SECONDS:-300}"
  [[ "$timeout_seconds" =~ ^[0-9]+$ ]] || die "G2FUZZ_TIMEOUT_SECONDS must be an integer"

  timestamp="$(make_timestamp)"
  run_dir="$root/${HGB_RESULTS_DIR:-results}/g2fuzz/seeds_$timestamp"
  runtime_dir="$run_dir/runtime"
  output_dir="$run_dir/${program}_output"
  ensure_dir "$runtime_dir/config"
  log_file="$run_dir/program_gen.log"

  cp "$upstream_dir/program_to_format.json" "$runtime_dir/config/program_to_format.json"
  cp "$upstream_dir/model_setting.json" "$runtime_dir/config/model_setting.json"
  cp "$runtime_dir/config/program_to_format.json" "$runtime_dir/program_to_format.json"
  python3.12 - "$runtime_dir/model_setting.json" "$model" <<'PY'
import json, sys
path, model = sys.argv[1], sys.argv[2]
data = {"model": [model]}
with open(path, "w") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
  cp "$runtime_dir/model_setting.json" "$runtime_dir/config/model_setting.json"

  start_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  exit_code=0
  if [[ -z "${OPENAI_API_KEY:-}" ]]; then
    {
      printf 'OPENAI_API_KEY is not set.\n'
      printf 'Upstream G2FUZZ requires openai_key.txt in the runtime working directory.\n'
      printf 'No credential file was created.\n'
    } >"$log_file"
    exit_code=2
  else
    printf '%s\n' "$OPENAI_API_KEY" >"$runtime_dir/openai_key.txt"
    chmod 600 "$runtime_dir/openai_key.txt"
    (
      cd "$runtime_dir"
      export OPENAI_BASE_URL="${OPENAI_BASE_URL:-}"
      timeout "$timeout_seconds" "$venv_dir/bin/python" "$upstream_dir/program_gen.py" \
        --output "$output_dir" \
        --program "$program"
    ) >"$log_file" 2>&1 || exit_code=$?
  fi

  end_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  seed_count="$(count_files "$output_dir/default/gen_seeds" -type f)"
  generator_count="$(count_files "$output_dir/default/generators" -type f)"
  write_metadata "$run_dir/metadata.json" "$upstream_dir" "$data_dir" "$program" "$formats" "$model" "$run_dir" "$output_dir" "$data_path" "$exit_code" "$seed_count" "$generator_count" "$start_time" "$end_time" "$log_file"

  bash "$SCRIPT_DIR/g2fuzz_collect_report.sh" "$run_dir" >/dev/null || true

  if [[ "$exit_code" -ne 0 ]]; then
    die "G2FUZZ seed generation failed or was skipped. Inspect $log_file and $run_dir/metadata.json"
  fi

  log "G2FUZZ seed generation complete: $run_dir"
}

main "$@"
