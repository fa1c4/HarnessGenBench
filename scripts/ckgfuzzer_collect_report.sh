#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

extract_json_string() {
  local key="$1"
  local file="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$file" | head -n 1
}

extract_stage_code() {
  local key="$1"
  local file="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" "$file" | head -n 1
}

count_files() {
  local dir="$1"
  shift
  find "$dir" "$@" 2>/dev/null | wc -l | tr -d ' '
}

main() {
  local root run_dir metadata_file summary_file project model repo_code preproc_code fuzzing_code
  local api_count driver_count compile_pass_count compile_fail_count input_status failed_stages

  root="$(repo_root)"
  run_dir="${1:-}"
  [[ -n "$run_dir" ]] || die "Usage: bash scripts/ckgfuzzer_collect_report.sh results/ckgfuzzer/<run-dir>"
  [[ "$run_dir" = /* ]] || run_dir="$root/$run_dir"
  [[ -d "$run_dir" ]] || die "Run directory not found: $run_dir"

  metadata_file="$run_dir/metadata.json"
  summary_file="$run_dir/HGB_SUMMARY.md"
  project="unknown"
  model="unknown"
  repo_code="unknown"
  preproc_code="unknown"
  fuzzing_code="unknown"
  if [[ -f "$metadata_file" ]]; then
    project="$(extract_json_string project "$metadata_file")"
    model="$(extract_json_string model "$metadata_file")"
    repo_code="$(extract_stage_code repo "$metadata_file")"
    preproc_code="$(extract_stage_code preproc "$metadata_file")"
    fuzzing_code="$(extract_stage_code fuzzing "$metadata_file")"
    [[ -n "$project" ]] || project="unknown"
    [[ -n "$model" ]] || model="unknown"
    [[ -n "$repo_code" ]] || repo_code="unknown"
    [[ -n "$preproc_code" ]] || preproc_code="unknown"
    [[ -n "$fuzzing_code" ]] || fuzzing_code="unknown"
  fi

  api_count=0
  if [[ -f "$run_dir/generated/api_list.json" ]]; then
    api_count="$(grep -E '"[^"]+"' "$run_dir/generated/api_list.json" | wc -l | tr -d ' ')"
  fi
  driver_count="$(count_files "$run_dir" -type f \( -name 'driver_*.c' -o -name 'driver_*.cc' -o -name '*fuzz*.c' -o -name '*fuzz*.cc' \))"
  compile_pass_count="$(count_files "$run_dir/generated" -type d -name '*compilation_pass*')"
  compile_fail_count="$(grep -RciE 'compilation failed|compile error|error:' "$run_dir/logs" 2>/dev/null | awk -F: '{s += $2} END {print s + 0}')"
  input_status="unknown"
  if grep -Rqi 'Generate Input' "$run_dir/logs" 2>/dev/null; then
    input_status="attempted"
  fi
  if grep -RqiE 'skip generate input|Skip Generate Input' "$run_dir/logs" 2>/dev/null; then
    input_status="skipped"
  fi

  failed_stages=""
  [[ "$repo_code" =~ ^[0-9]+$ && "$repo_code" -ne 0 ]] && failed_stages="${failed_stages} repo"
  [[ "$preproc_code" =~ ^[0-9]+$ && "$preproc_code" -ne 0 ]] && failed_stages="${failed_stages} preproc"
  [[ "$fuzzing_code" =~ ^[0-9]+$ && "$fuzzing_code" -ne 0 ]] && failed_stages="${failed_stages} fuzzing"
  [[ -n "$failed_stages" ]] || failed_stages=" none"

  {
    printf '# HarnessGenBench CKGFuzzer Summary\n\n'
    printf -- '- Run directory: `%s`\n' "$run_dir"
    printf -- '- Project: `%s`\n' "$project"
    printf -- '- Model: `%s`\n' "$model"
    printf -- '- APIs analyzed: %s\n' "$api_count"
    printf -- '- Generated driver candidates: %s\n' "$driver_count"
    printf -- '- Compile pass directory count: %s\n' "$compile_pass_count"
    printf -- '- Compile failure mentions: %s\n' "$compile_fail_count"
    printf -- '- Input generation status: %s\n' "$input_status"
    printf -- '- Stage exit codes: repo=`%s`, preproc=`%s`, fuzzing=`%s`\n' "$repo_code" "$preproc_code" "$fuzzing_code"
    printf -- '- Failed stages:%s\n' "$failed_stages"
    printf '\n## Logs\n\n'
    find "$run_dir/logs" -type f -name '*.log' 2>/dev/null | sort | sed "s#^$run_dir/##" | sed 's/^/- `/' | sed 's/$/`/'
    printf '\n## Generated Artifacts\n\n'
    find "$run_dir/generated" -maxdepth 3 -type f 2>/dev/null | sort | sed "s#^$run_dir/##" | head -80 | sed 's/^/- `/' | sed 's/$/`/'
  } >"$summary_file"

  log "Wrote $summary_file"
}

main "$@"
