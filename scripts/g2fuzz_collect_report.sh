#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

main() {
  local root run_dir metadata summary status reason code model target api_key_present
  local log_count generated_input_count generator_count crash_count hang_count queue_count method_profile task_family
  root="$(repo_root)"
  run_dir="${1:-}"
  if [[ -z "$run_dir" ]]; then
    run_dir="$(latest_workspace_run g2fuzz "$root")"
  fi
  [[ -n "$run_dir" ]] || die "No workspace run found for g2fuzz"
  [[ "$run_dir" = /* ]] || run_dir="$root/$run_dir"
  [[ -d "$run_dir" ]] || die "Run directory not found: $run_dir"
  metadata="$run_dir/metadata.json"
  summary="$run_dir/HGB_SUMMARY.md"

  status="unknown"; reason="none"; code="unknown"; model="unknown"; target="unknown"
  api_key_present="unknown"; method_profile="unknown"; task_family="input_generator"
  if [[ -f "$metadata" ]]; then
    status="$(extract_json_string status "$metadata")"; [[ -n "$status" ]] || status="unknown"
    reason="$(extract_json_string reason "$metadata")"; [[ -n "$reason" ]] || reason="none"
    code="$(extract_json_number exit_code "$metadata")"; [[ -n "$code" ]] || code="unknown"
    model="$(extract_json_string model "$metadata")"; [[ -n "$model" ]] || model="unknown"
    target="$(extract_json_string target "$metadata")"; [[ -n "$target" ]] || target="unknown"
    method_profile="$(extract_json_string method_profile "$metadata")"; [[ -n "$method_profile" ]] || method_profile="unknown"
    task_family="$(extract_json_string task_family "$metadata")"; [[ -n "$task_family" ]] || task_family="input_generator"
    api_key_present="$(python3 - "$metadata" <<"PY"
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
    print(str(bool(data.get("api_key_present", False))).lower())
except Exception:
    print("unknown")
PY
)"
  fi

  log_count="$(count_files "$run_dir/logs" -type f)"
  generated_input_count="$(extract_json_number generated_input_count "$metadata")"; [[ -n "$generated_input_count" ]] || generated_input_count="$(count_files "$run_dir/seeds/g2_generated" -type f)"
  generator_count="$(extract_json_number generator_count "$metadata")"; [[ -n "$generator_count" ]] || generator_count="$(count_files "$run_dir/generators/source" -type f -name "*.py")"
  queue_count="$(extract_json_number queue_count "$metadata")"; [[ -n "$queue_count" ]] || queue_count="$(count_files "$run_dir/seeds/afl_queue" -type f)"
  crash_count="$(extract_json_number crash_count "$metadata")"; [[ -n "$crash_count" ]] || crash_count="$(count_files "$run_dir/campaign/output" -type f -path "*/crashes/*" ! -name README.txt)"
  hang_count="$(extract_json_number hang_count "$metadata")"; [[ -n "$hang_count" ]] || hang_count="$(count_files "$run_dir/campaign/output" -type f -path "*/hangs/*" ! -name README.txt)"
  valid_g2="$(python3 - "$metadata" <<"PY"
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
    print(int(d.get("input_generation", {}).get("valid_g2_generated_count", d.get("valid_generated_input_count", 0)) or 0))
except Exception:
    print(0)
PY
)"
  execs_done="$(python3 - "$metadata" <<"PY"
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
    print(int(d.get("campaign", {}).get("execs_done", 0) or 0))
except Exception:
    print(0)
PY
)"
  pair_status="$(python3 - "$metadata" <<"PY"
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
    print(str(d.get("target_pair_build", {}).get("status", "pending")))
except Exception:
    print("pending")
PY
)"
  build_source="$(python3 - "$metadata" <<"PY"
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
    print(str(d.get("target_pair_build", {}).get("build_source", "none")))
except Exception:
    print("none")
PY
)"

  {
    printf "# HarnessGenBench G2Fuzz Summary\n\n"
    printf -- "- Run directory: `%s`\n" "$run_dir"
    printf -- "- Status: `%s`\n" "$status"
    printf -- "- Exit code: `%s`\n" "$code"
    printf -- "- Target/program: `%s`\n" "$target"
    printf -- "- Task family: `%s`\n" "$task_family"
    printf -- "- Method profile: `%s`\n" "$method_profile"
    printf -- "- Target pair build: `%s` (source: `%s`)\n" "$pair_status" "$build_source"
    printf -- "- Model: `%s`\n" "$model"
    printf -- "- API key present: `%s`\n" "$api_key_present"
    printf -- "- Log files: %s\n" "$log_count"
    printf -- "- Generated input count: %s (valid: %s)\n" "$generated_input_count" "$valid_g2"
    printf -- "- Generator source count: %s\n" "$generator_count"
    printf -- "- Campaign: execs_done=%s, queue=%s, crashes=%s, hangs=%s\n" "$execs_done" "$queue_count" "$crash_count" "$hang_count"
    printf -- "- Top failure reason: %s\n" "$reason"
    printf "\n## Logs\n\n"
    list_files "$run_dir/logs" -type f | sort | sed "s#^$run_dir/##" | sed "s/^/- /"
    printf "\n## Generated Inputs And Generators\n\n"
    list_files "$run_dir/generators/source" -maxdepth 2 -type f | sort | sed "s#^$run_dir/##" | head -100 | sed "s/^/- /"
    list_files "$run_dir/seeds/g2_generated" -maxdepth 2 -type f | sort | sed "s#^$run_dir/##" | head -100 | sed "s/^/- /"
    list_files "$run_dir/target" -maxdepth 1 -type f | sort | sed "s#^$run_dir/##" | sed "s/^/- /"
  } >"$summary"
  log "Wrote $summary"
}
main "$@"
