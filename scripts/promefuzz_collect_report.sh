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
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$file" | head -n 1
}

count_files() {
  local dir="$1"
  shift
  find "$dir" "$@" 2>/dev/null | wc -l | tr -d ' '
}

first_failure_reason() {
  local run_dir="$1"
  local stage="$2"
  local log_file="$run_dir/logs/$stage.log"
  [[ -f "$log_file" ]] || {
    printf 'missing log for stage %s' "$stage"
    return
  }
  if grep -qiE 'OPENAI_API_KEY|api key|unauthorized|authentication|model|base_url|ollama|embedding' "$log_file"; then
    grep -iE 'OPENAI_API_KEY|api key|unauthorized|authentication|model|base_url|ollama|embedding' "$log_file" | head -n 1 | sed -E $'s/\x1B\[[0-9;]*[A-Za-z]//g'
  elif grep -qiE 'Docker|docker|Cannot connect|permission denied' "$log_file"; then
    grep -iE 'Docker|docker|Cannot connect|permission denied' "$log_file" | head -n 1 | sed -E $'s/\x1B\[[0-9;]*[A-Za-z]//g'
  elif grep -qiE 'No such file|not found|Missing|failed|error|traceback|critical' "$log_file"; then
    grep -iE 'No such file|not found|Missing|failed|error|traceback|critical' "$log_file" | head -n 1 | sed -E $'s/\x1B\[[0-9;]*[A-Za-z]//g'
  else
    tail -n 1 "$log_file" | sed -E $'s/\x1B\[[0-9;]*[A-Za-z]//g'
  fi
}

main() {
  local root run_dir metadata_file summary_file upstream_dir out_dir
  local upstream_commit target_commit image_name config_file
  local driver_count synthesized_status run_status stats_path failed_stages top_failure
  local stages=(fetch build_normal build_asan preprocess comprehend generate synthesize build_driver run_driver stats)
  local stage code target_dir

  root="$(repo_root)"
  run_dir="${1:-}"
  [[ -n "$run_dir" ]] || die "Usage: bash scripts/promefuzz_collect_report.sh results/promefuzz/<run-dir>"
  [[ "$run_dir" = /* ]] || run_dir="$root/$run_dir"
  [[ -d "$run_dir" ]] || die "Run directory not found: $run_dir"

  metadata_file="$run_dir/metadata.json"
  summary_file="$run_dir/HGB_SUMMARY.md"
  upstream_dir="$root/external/PromeFuzz"
  out_dir="$upstream_dir/database/pugixml/latest/out"

  upstream_commit="unknown"
  target_commit="unknown"
  image_name="unknown"
  config_file="unknown"
  if [[ -f "$metadata_file" ]]; then
    upstream_commit="$(extract_json_string upstream_commit "$metadata_file")"
    target_commit="$(extract_json_string target_commit "$metadata_file")"
    image_name="$(extract_json_string image_name "$metadata_file")"
    config_file="$(extract_json_string config "$metadata_file")"
  fi
  [[ -n "$upstream_commit" ]] || upstream_commit="unknown"
  [[ -n "$target_commit" ]] || target_commit="unknown"
  [[ -n "$image_name" ]] || image_name="unknown"
  [[ -n "$config_file" ]] || config_file="unknown"

  if [[ "$target_commit" == "unknown" && -d "$upstream_dir/database/pugixml/latest/code/.git" ]]; then
    target_commit="$(git -c safe.directory="$upstream_dir/database/pugixml/latest/code" -C "$upstream_dir/database/pugixml/latest/code" rev-parse HEAD 2>/dev/null || printf 'unknown')"
  fi

  driver_count=0
  target_dir="$run_dir/artifacts/fuzz_driver"
  if [[ ! -d "$target_dir" ]]; then
    target_dir="$out_dir/fuzz_driver"
  fi
  if [[ -d "$target_dir" ]]; then
    driver_count="$(count_files "$target_dir" -maxdepth 1 -type f \( -name 'fuzz_driver_*.c' -o -name 'fuzz_driver_*.cc' -o -name 'fuzz_driver_*.cpp' \))"
  fi

  synthesized_status="not_built"
  if [[ -x "$run_dir/artifacts/fuzz_driver/synthesized/synthesized_driver" || -x "$out_dir/fuzz_driver/synthesized/synthesized_driver" ]]; then
    synthesized_status="built"
  elif [[ -f "$run_dir/logs/build_driver.exit" ]]; then
    code="$(cat "$run_dir/logs/build_driver.exit")"
    synthesized_status="build_exit_$code"
  fi

  run_status="not_run"
  if [[ -f "$run_dir/logs/run_driver.exit" ]]; then
    code="$(cat "$run_dir/logs/run_driver.exit")"
    run_status="exit_$code"
  fi

  stats_path=""
  if [[ -f "$run_dir/statistics/statistics_for_pugixml.xlsx" ]]; then
    stats_path="$run_dir/statistics/statistics_for_pugixml.xlsx"
  elif [[ -f "$out_dir/statistics_for_pugixml.xlsx" ]]; then
    stats_path="$out_dir/statistics_for_pugixml.xlsx"
  else
    stats_path="not_generated"
  fi

  failed_stages=""
  top_failure=""
  for stage in "${stages[@]}"; do
    code=""
    if [[ -f "$metadata_file" ]]; then
      code="$(extract_stage_code "$stage" "$metadata_file")"
    fi
    if [[ -z "$code" && -f "$run_dir/logs/$stage.exit" ]]; then
      code="$(cat "$run_dir/logs/$stage.exit")"
    fi
    [[ -n "$code" ]] || code="not_run"
    if [[ "$code" != "0" ]]; then
      failed_stages="${failed_stages} $stage=$code"
      if [[ -z "$top_failure" ]]; then
        top_failure="$stage: $(first_failure_reason "$run_dir" "$stage")"
      fi
    fi
  done
  [[ -n "$failed_stages" ]] || failed_stages=" none"
  [[ -n "$top_failure" ]] || top_failure="none"

  {
    printf '# HarnessGenBench PromeFuzz Summary\n\n'
    printf -- '- Run directory: `%s`\n' "$run_dir"
    printf -- '- Upstream commit: `%s`\n' "$upstream_commit"
    printf -- '- Docker image: `%s`\n' "$image_name"
    printf -- '- Config: `%s`\n' "$config_file"
    printf -- '- Target: `pugixml`\n'
    printf -- '- Target commit: `%s`\n' "$target_commit"
    printf -- '- Generated fuzz-driver count: %s\n' "$driver_count"
    printf -- '- Synthesized driver build status: %s\n' "$synthesized_status"
    printf -- '- Smoke run status: %s\n' "$run_status"
    printf -- '- Statistics file: `%s`\n' "$stats_path"
    printf -- '- Failed stages:%s\n' "$failed_stages"
    printf -- '- Top failure reason: %s\n' "$top_failure"
    printf '\n## Stage Exit Codes\n\n'
    for stage in "${stages[@]}"; do
      code="not_run"
      if [[ -f "$metadata_file" ]]; then
        code="$(extract_stage_code "$stage" "$metadata_file")"
      fi
      if [[ -z "$code" && -f "$run_dir/logs/$stage.exit" ]]; then
        code="$(cat "$run_dir/logs/$stage.exit")"
      fi
      [[ -n "$code" ]] || code="not_run"
      printf -- '- %s: `%s`\n' "$stage" "$code"
    done
    printf '\n## Logs\n\n'
    find "$run_dir/logs" -type f -name '*.log' 2>/dev/null | sort | sed "s#^$run_dir/##" | sed 's/^/- `/' | sed 's/$/`/'
    printf '\n## Preserved Artifacts\n\n'
    find "$run_dir/artifacts" -maxdepth 4 -type f 2>/dev/null | sort | sed "s#^$run_dir/##" | head -80 | sed 's/^/- `/' | sed 's/$/`/'
  } >"$summary_file"

  log "Wrote $summary_file"
}

main "$@"
