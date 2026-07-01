#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

main() {
  local root run_dir metadata summary fuzzer title status reason commit code model target api_key_present
  local log_count generated_count crash_count hang_count queue_count
  root="$(repo_root)"
  fuzzer="oss-fuzz-gen"
  title="OSS-Fuzz-Gen"
  run_dir="${1:-}"
  if [[ -z "$run_dir" ]]; then
    run_dir="$(latest_workspace_run "$fuzzer" "$root")"
  fi
  [[ -n "$run_dir" ]] || die "No workspace run found for $fuzzer"
  [[ "$run_dir" = /* ]] || run_dir="$root/$run_dir"
  [[ -d "$run_dir" ]] || die "Run directory not found: $run_dir"
  metadata="$run_dir/metadata.json"
  summary="$run_dir/HGB_SUMMARY.md"

  status="unknown"; reason="none"; commit="unknown"; code="unknown"; model="unknown"; target="unknown"; api_key_present="unknown"
  if [[ -f "$metadata" ]]; then
    status="$(extract_json_string status "$metadata")"; [[ -n "$status" ]] || status="unknown"
    reason="$(extract_json_string reason "$metadata")"; [[ -n "$reason" ]] || reason="none"
    commit="$(extract_json_string upstream_commit "$metadata")"; [[ -n "$commit" ]] || commit="unknown"
    code="$(extract_json_number exit_code "$metadata")"; [[ -n "$code" ]] || code="$(extract_json_number afl_exit_code "$metadata")"; [[ -n "$code" ]] || code="unknown"
    model="$(extract_json_string model "$metadata")"; [[ -n "$model" ]] || model="unknown"
    target="$(extract_json_string target "$metadata")"; [[ -n "$target" ]] || target="$(extract_json_string program "$metadata")"; [[ -n "$target" ]] || target="unknown"
    api_key_present="$(sed -n 's/.*"api_key_present"[[:space:]]*:[[:space:]]*\(true\|false\).*/\1/p' "$metadata" | head -n 1)"; [[ -n "$api_key_present" ]] || api_key_present="unknown"
  fi

  log_count="$(count_files "$run_dir/logs" -type f)"
  generated_count="$(count_files "$run_dir" -type f \( -name '*fuzz*.c' -o -name '*fuzz*.cc' -o -name '*fuzz*.cpp' -o -name 'driver_*.c' \))"
  queue_count="$(count_files "$run_dir" -type f -path '*/queue/*')"
  crash_count="$(count_files "$run_dir" -type f -path '*/crashes/*' ! -name README.txt)"
  hang_count="$(count_files "$run_dir" -type f -path '*/hangs/*' ! -name README.txt)"

  if [[ "$reason" == "none" && -d "$run_dir/logs" ]] && grep -RqiE 'OPENAI_API_KEY|api key|unauthorized|authentication|quota|model|docker|permission|not found|error|failed|traceback|target binaries' "$run_dir/logs" 2>/dev/null; then
    reason="$(grep -RihE 'OPENAI_API_KEY|api key|unauthorized|authentication|quota|model|docker|permission|not found|error|failed|traceback|target binaries' "$run_dir/logs" 2>/dev/null | head -n 1)"
  fi

  {
    printf '# HarnessGenBench %s Summary\n\n' "$title"
    printf -- '- Run directory: `%s`\n' "$run_dir"
    printf -- '- Upstream commit: `%s`\n' "$commit"
    printf -- '- Status: `%s`\n' "$status"
    printf -- '- Exit code: `%s`\n' "$code"
    printf -- '- Target/program: `%s`\n' "$target"
    printf -- '- Model: `%s`\n' "$model"
    printf -- '- API key present: `%s`\n' "$api_key_present"
    printf -- '- Log files: %s\n' "$log_count"
    printf -- '- Generated harness candidates: %s\n' "$generated_count"
    printf -- '- Queue/crash/hang counts: queue=%s, crashes=%s, hangs=%s\n' "$queue_count" "$crash_count" "$hang_count"
    printf -- '- Top failure reason: %s\n' "$reason"
    printf '\n## Logs\n\n'
    list_files "$run_dir/logs" -type f | sort | sed "s#^$run_dir/##" | sed 's/^/- `/' | sed 's/$/`/'
    printf '\n## Generated Artifacts\n\n'
    list_files "$run_dir" -maxdepth 4 -type f \( -name '*fuzz*.c' -o -name '*fuzz*.cc' -o -name '*fuzz*.cpp' -o -name 'driver_*.c' -o -name 'TARGET_BUILD_MISSING.md' \) | sort | sed "s#^$run_dir/##" | head -100 | sed 's/^/- `/' | sed 's/$/`/'
  } >"$summary"
  log "Wrote $summary"
}
main "$@"
