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

find_binary_pair() {
  local root="$1"
  local program="$2"
  local env_dir="${G2FUZZ_TARGET_DIR:-}"
  local dirs=()
  [[ -n "$env_dir" ]] && dirs+=("$env_dir")
  dirs+=("$root/${HGB_RESULTS_DIR:-results}/g2fuzz/targets/$program")
  dirs+=("$root/external/G2FUZZ")
  local dir
  for dir in "${dirs[@]}"; do
    if [[ -x "$dir/$program.afl" && -x "$dir/$program.cmp" ]]; then
      printf '%s\n%s\n' "$dir/$program.afl" "$dir/$program.cmp"
      return 0
    fi
  done
  return 1
}

write_metadata() {
  local metadata_file="$1"
  local upstream_dir="$2"
  local seed_run="$3"
  local program="$4"
  local seed_dir="$5"
  local afl_binary="$6"
  local cmp_binary="$7"
  local afl_out="$8"
  local exit_code="$9"
  local queue_count="${10}"
  local crash_count="${11}"
  local hang_count="${12}"
  local log_file="${13}"
  local upstream_commit
  upstream_commit="$(git -C "$upstream_dir" rev-parse HEAD 2>/dev/null || printf 'unknown')"
  {
    printf '{\n'
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$upstream_commit")"
    printf '  "program": "%s",\n' "$(json_escape "$program")"
    printf '  "seed_run": "%s",\n' "$(json_escape "$seed_run")"
    printf '  "seed_dir": "%s",\n' "$(json_escape "$seed_dir")"
    printf '  "afl_binary": "%s",\n' "$(json_escape "$afl_binary")"
    printf '  "cmp_binary": "%s",\n' "$(json_escape "$cmp_binary")"
    printf '  "afl_out": "%s",\n' "$(json_escape "$afl_out")"
    printf '  "afl_exit_code": %s,\n' "$exit_code"
    printf '  "queue_count": %s,\n' "$queue_count"
    printf '  "crash_count": %s,\n' "$crash_count"
    printf '  "hang_count": %s,\n' "$hang_count"
    printf '  "log_file": "%s"\n' "$(json_escape "$log_file")"
    printf '}\n'
  } >"$metadata_file"
}

main() {
  local root upstream_dir seed_run seed_meta program seed_dir timestamp run_dir afl_out initial_seeds log_file
  local afl_binary cmp_binary timeout_seconds memory_mb exit_code queue_count crash_count hang_count
  local -a pair

  root="$(repo_root)"
  load_env
  require_cmd git
  require_cmd timeout

  upstream_dir="$root/external/G2FUZZ"
  [[ -x "$upstream_dir/afl-fuzz" ]] || die "Missing $upstream_dir/afl-fuzz. Run: bash scripts/g2fuzz_setup.sh"

  seed_run="${1:-}"
  if [[ -z "$seed_run" ]]; then
    seed_run="$(find "$root/${HGB_RESULTS_DIR:-results}/g2fuzz" -maxdepth 1 -type d -name 'seeds_*' 2>/dev/null | sort | tail -n 1 || true)"
  fi
  [[ -n "$seed_run" ]] || die "Usage: bash scripts/g2fuzz_smoke_afl.sh results/g2fuzz/<seed-run>"
  [[ "$seed_run" = /* ]] || seed_run="$root/$seed_run"
  [[ -d "$seed_run" ]] || die "Seed run directory not found: $seed_run"
  seed_meta="$seed_run/metadata.json"
  [[ -f "$seed_meta" ]] || die "Seed metadata not found: $seed_meta"

  program="$(extract_json_string program "$seed_meta")"
  seed_dir="$seed_run/${program}_output/default/gen_seeds"
  timestamp="$(make_timestamp)"
  run_dir="$root/${HGB_RESULTS_DIR:-results}/g2fuzz/afl_$timestamp"
  afl_out="$run_dir/afl_out"
  initial_seeds="$run_dir/initial_seeds"
  log_file="$run_dir/afl.log"
  ensure_dir "$run_dir"
  ensure_dir "$initial_seeds"

  if [[ -d "$seed_dir" ]]; then
    cp -a "$seed_dir/." "$initial_seeds/" 2>/dev/null || true
  fi
  if [[ "$(count_files "$initial_seeds" -type f)" == "0" ]]; then
    printf 'empty\n' >"$initial_seeds/empty"
  fi

  afl_binary=""
  cmp_binary=""
  pair=()
  mapfile -t pair < <(find_binary_pair "$root" "$program" || true)
  if [[ ${#pair[@]} -lt 2 ]]; then
    {
      printf '# G2FUZZ Target Build Missing\n\n'
      printf 'AFL smoke was not run because target binaries were not found.\n\n'
      printf -- '- Program: `%s`\n' "$program"
      printf -- '- Missing AFL binary: `%s.afl`\n' "$program"
      printf -- '- Missing CMPLOG binary: `%s.cmp`\n' "$program"
      printf -- '- Searched: `G2FUZZ_TARGET_DIR`, `results/g2fuzz/targets/%s/`, and `external/G2FUZZ/`\n\n' "$program"
      printf 'Upstream requires compiling the target program twice, once in AFL default mode and once in cmplog mode, producing `program.afl` and `program.cmp`.\n'
      printf 'After building them, set `G2FUZZ_TARGET_DIR` to their directory and rerun this script.\n'
    } >"$run_dir/TARGET_BUILD_MISSING.md"
    printf 'Target binaries missing; see TARGET_BUILD_MISSING.md\n' >"$log_file"
    write_metadata "$run_dir/metadata.json" "$upstream_dir" "$seed_run" "$program" "$seed_dir" "" "" "$afl_out" 127 0 0 0 "$log_file"
    bash "$SCRIPT_DIR/g2fuzz_collect_report.sh" "$run_dir" >/dev/null || true
    die "G2FUZZ target binaries missing. See $run_dir/TARGET_BUILD_MISSING.md"
  fi
  afl_binary="${pair[0]}"
  cmp_binary="${pair[1]}"

  timeout_seconds="${G2FUZZ_AFL_TIMEOUT_SECONDS:-300}"
  memory_mb="${G2FUZZ_MEMORY_MB:-1024}"
  [[ "$timeout_seconds" =~ ^[0-9]+$ ]] || die "G2FUZZ_AFL_TIMEOUT_SECONDS must be an integer"
  [[ "$memory_mb" =~ ^[0-9]+$ ]] || die "G2FUZZ_MEMORY_MB must be an integer"

  exit_code=0
  AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    timeout "$timeout_seconds" "$upstream_dir/afl-fuzz" \
      -i "$initial_seeds" \
      -o "$afl_out" \
      -c "$cmp_binary" \
      -m "$memory_mb" \
      -k "$upstream_dir" \
      -- "$afl_binary" @@ >"$log_file" 2>&1 || exit_code=$?

  queue_count="$(count_files "$afl_out/default/queue" -type f)"
  crash_count="$(count_files "$afl_out/default/crashes" -type f ! -name 'README.txt')"
  hang_count="$(count_files "$afl_out/default/hangs" -type f ! -name 'README.txt')"
  write_metadata "$run_dir/metadata.json" "$upstream_dir" "$seed_run" "$program" "$seed_dir" "$afl_binary" "$cmp_binary" "$afl_out" "$exit_code" "$queue_count" "$crash_count" "$hang_count" "$log_file"
  bash "$SCRIPT_DIR/g2fuzz_collect_report.sh" "$run_dir" >/dev/null || true

  if [[ "$exit_code" -ne 0 && "$exit_code" -ne 124 ]]; then
    die "G2FUZZ AFL smoke failed. Inspect $log_file"
  fi
  log "G2FUZZ AFL smoke complete: $run_dir"
}

main "$@"
