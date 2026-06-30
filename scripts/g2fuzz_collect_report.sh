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

extract_json_number() {
  local key="$1"
  local file="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" "$file" | head -n 1
}

main() {
  local root run_dir metadata_file summary_file upstream_commit program formats model seed_count
  local afl_status queue_count crash_count hang_count data_path seed_run top_failure log_file

  root="$(repo_root)"
  run_dir="${1:-}"
  [[ -n "$run_dir" ]] || die "Usage: bash scripts/g2fuzz_collect_report.sh results/g2fuzz/<run-dir>"
  [[ "$run_dir" = /* ]] || run_dir="$root/$run_dir"
  [[ -d "$run_dir" ]] || die "Run directory not found: $run_dir"

  metadata_file="$run_dir/metadata.json"
  summary_file="$run_dir/HGB_SUMMARY.md"
  [[ -f "$metadata_file" ]] || die "Metadata not found: $metadata_file"

  upstream_commit="$(extract_json_string upstream_commit "$metadata_file")"
  program="$(extract_json_string program "$metadata_file")"
  formats="$(extract_json_string formats "$metadata_file")"
  model="$(extract_json_string model "$metadata_file")"
  seed_count="$(extract_json_number generated_seed_count "$metadata_file")"
  data_path="$(extract_json_string data_repo_comparison_path "$metadata_file")"
  seed_run="$(extract_json_string seed_run "$metadata_file")"
  afl_status="$(extract_json_number afl_exit_code "$metadata_file")"
  queue_count="$(extract_json_number queue_count "$metadata_file")"
  crash_count="$(extract_json_number crash_count "$metadata_file")"
  hang_count="$(extract_json_number hang_count "$metadata_file")"
  log_file="$(extract_json_string log_file "$metadata_file")"

  if [[ -n "$seed_run" ]]; then
    [[ "$seed_run" = /* ]] || seed_run="$root/$seed_run"
    if [[ -f "$seed_run/metadata.json" ]]; then
      [[ -n "$formats" ]] || formats="$(extract_json_string formats "$seed_run/metadata.json")"
      [[ -n "$model" ]] || model="$(extract_json_string model "$seed_run/metadata.json")"
      [[ -n "$seed_count" ]] || seed_count="$(extract_json_number generated_seed_count "$seed_run/metadata.json")"
      [[ -n "$data_path" ]] || data_path="$(extract_json_string data_repo_comparison_path "$seed_run/metadata.json")"
    fi
  fi

  [[ -n "$formats" ]] || formats="unknown"
  [[ -n "$model" ]] || model="unknown"
  [[ -n "$seed_count" ]] || seed_count="0"
  [[ -n "$afl_status" ]] || afl_status="not_run"
  [[ -n "$queue_count" ]] || queue_count="0"
  [[ -n "$crash_count" ]] || crash_count="0"
  [[ -n "$hang_count" ]] || hang_count="0"
  [[ -n "$data_path" ]] || data_path="not_available"

  top_failure="none"
  if [[ -f "$run_dir/TARGET_BUILD_MISSING.md" ]]; then
    top_failure="target .afl/.cmp binaries missing"
  elif [[ -f "$log_file" ]] && grep -qiE 'OPENAI_API_KEY|openai_key|api key|authentication|unauthorized|timeout|error|traceback|failed' "$log_file"; then
    top_failure="$(grep -iE 'OPENAI_API_KEY|openai_key|api key|authentication|unauthorized|timeout|error|traceback|failed' "$log_file" | head -n 1)"
  fi

  {
    printf '# HarnessGenBench G2FUZZ Summary\n\n'
    printf -- '- Run directory: `%s`\n' "$run_dir"
    printf -- '- Upstream commit: `%s`\n' "${upstream_commit:-unknown}"
    printf -- '- Selected target: `%s`\n' "${program:-unknown}"
    printf -- '- Selected format(s): `%s`\n' "$formats"
    printf -- '- Model: `%s`\n' "$model"
    printf -- '- Generated seed count: %s\n' "$seed_count"
    printf -- '- AFL run status: `%s`\n' "$afl_status"
    printf -- '- AFL queue/crash/hang counts: queue=%s, crashes=%s, hangs=%s\n' "$queue_count" "$crash_count" "$hang_count"
    printf -- '- Data repo comparison path: `%s`\n' "$data_path"
    [[ -n "$seed_run" ]] && printf -- '- Seed run: `%s`\n' "$seed_run"
    printf -- '- Top failure reason: %s\n' "$top_failure"
    printf '\n## Logs\n\n'
    find "$run_dir" -maxdepth 2 -type f \( -name '*.log' -o -name 'program_gen.log' -o -name 'TARGET_BUILD_MISSING.md' \) 2>/dev/null | sort | sed "s#^$run_dir/##" | sed 's/^/- `/' | sed 's/$/`/'
  } >"$summary_file"

  log "Wrote $summary_file"
}

main "$@"
