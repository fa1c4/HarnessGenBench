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

extract_command_value() {
  local flag="$1"
  local file="$2"
  sed -n "s/.*$flag[[:space:]]\([^[:space:]]*\).*/\1/p" "$file" | head -n 1
}

count_matches() {
  local dir="$1"
  shift
  find "$dir" "$@" 2>/dev/null | wc -l | tr -d ' '
}

print_paths() {
  local dir="$1"
  shift
  find "$dir" "$@" 2>/dev/null | sort | sed "s#^$dir/##" | head -n 40
}

main() {
  local run_dir metadata_file summary_file root model benchmark_yaml upstream_commit exit_code
  local log_count harness_count report_count coverage_count introspector_count crash_count
  local build_status runtime_status

  root="$(repo_root)"
  run_dir="${1:-}"
  [[ -n "$run_dir" ]] || die "Usage: bash scripts/oss_fuzz_gen_collect_report.sh results/oss-fuzz-gen/<run-dir>"
  [[ "$run_dir" = /* ]] || run_dir="$root/$run_dir"
  [[ -d "$run_dir" ]] || die "Run directory not found: $run_dir"

  metadata_file="$run_dir/metadata.json"
  summary_file="$run_dir/HGB_SUMMARY.md"

  model="unknown"
  benchmark_yaml="unknown"
  upstream_commit="unknown"
  exit_code="unknown"
  if [[ -f "$metadata_file" ]]; then
    model="$(extract_json_string model "$metadata_file")"
    benchmark_yaml="$(extract_json_string benchmark_yaml "$metadata_file")"
    upstream_commit="$(extract_json_string upstream_commit "$metadata_file")"
    exit_code="$(extract_json_number exit_code "$metadata_file")"
    [[ -n "$model" ]] || model="unknown"
    [[ -n "$benchmark_yaml" ]] || benchmark_yaml="unknown"
    [[ -n "$upstream_commit" ]] || upstream_commit="unknown"
    [[ -n "$exit_code" ]] || exit_code="unknown"
  else
    if [[ -f "$run_dir/command.txt" ]]; then
      benchmark_yaml="$(extract_command_value '--benchmark-yaml' "$run_dir/command.txt")"
      [[ -n "$benchmark_yaml" ]] || benchmark_yaml="$(extract_command_value '-y' "$run_dir/command.txt")"
      model="$(extract_command_value '--model' "$run_dir/command.txt")"
      [[ -n "$model" ]] || model="$(extract_command_value '-l' "$run_dir/command.txt")"
    fi
    if [[ -d "$root/external/oss-fuzz-gen/.git" ]]; then
      upstream_commit="$(git -C "$root/external/oss-fuzz-gen" rev-parse HEAD 2>/dev/null || true)"
    fi
    [[ -n "$model" ]] || model="unknown"
    [[ -n "$benchmark_yaml" ]] || benchmark_yaml="unknown"
    [[ -n "$upstream_commit" ]] || upstream_commit="unknown"
  fi

  log_count="$(count_matches "$run_dir" -type f -name '*.log')"
  harness_count="$(count_matches "$run_dir" -type f \( -name '*fuzz*.cc' -o -name '*fuzz*.cpp' -o -name '*fuzz*.c' \))"
  report_count="$(count_matches "$run_dir" -type f \( -name '*.html' -o -name '*.md' -o -name '*.json' \))"
  coverage_count="$(count_matches "$run_dir" -type f \( -iname '*coverage*' -o -name '*.profdata' -o -name '*.profraw' -o -name '*.sancov' \))"
  introspector_count="$(count_matches "$run_dir" -type f \( -iname '*introspector*' -o -path '*/fuzz-introspector/*' \))"
  crash_count="$(count_matches "$run_dir" -type f \( -path '*/crashes/*' -o -iname '*crash*' \))"

  build_status="unknown"
  runtime_status="unknown"
  if grep -RqiE 'build succeeded|build success|successfully built' "$run_dir" 2>/dev/null; then
    build_status="success observed"
  elif grep -RqiE 'build failed|failed to build|compile error|compilation failed' "$run_dir" 2>/dev/null; then
    build_status="failure observed"
  fi

  if grep -RqiE 'crash|runtime error|timeout|oom' "$run_dir" 2>/dev/null; then
    runtime_status="runtime issue mentioned in logs"
  elif grep -RqiE 'run succeeded|finished fuzzing|execution finished' "$run_dir" 2>/dev/null; then
    runtime_status="success observed"
  fi

  {
    printf '# HarnessGenBench OSS-Fuzz-Gen Summary\n\n'
    printf -- '- Run directory: `%s`\n' "$run_dir"
    printf -- '- Upstream commit: `%s`\n' "$upstream_commit"
    printf -- '- Benchmark YAML: `%s`\n' "$benchmark_yaml"
    printf -- '- Model: `%s`\n' "$model"
    printf -- '- Exit code: `%s`\n' "$exit_code"
    printf -- '- Build status: %s\n' "$build_status"
    printf -- '- Runtime status: %s\n' "$runtime_status"
    printf -- '- Runtime crash artifact count: %s\n' "$crash_count"
    printf -- '- Log files: %s\n' "$log_count"
    printf -- '- Generated harness candidates: %s\n' "$harness_count"
    printf -- '- Report artifact candidates: %s\n' "$report_count"
    printf -- '- Coverage artifact candidates: %s\n' "$coverage_count"
    printf -- '- Fuzz Introspector artifact candidates: %s\n' "$introspector_count"
    printf '\n## Logs\n\n'
    print_paths "$run_dir" -type f -name '*.log' | sed 's/^/- `/' | sed 's/$/`/'
    printf '\n## Generated Harness Candidates\n\n'
    print_paths "$run_dir" -type f \( -name '*fuzz*.cc' -o -name '*fuzz*.cpp' -o -name '*fuzz*.c' \) | sed 's/^/- `/' | sed 's/$/`/'
    printf '\n## Coverage And Introspector Candidates\n\n'
    print_paths "$run_dir" -type f \( -iname '*coverage*' -o -iname '*introspector*' -o -path '*/fuzz-introspector/*' -o -name '*.profdata' -o -name '*.sancov' \) | sed 's/^/- `/' | sed 's/$/`/'
  } >"$summary_file"

  log "Wrote $summary_file"
}

main "$@"
