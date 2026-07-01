#!/usr/bin/env bash
set -euo pipefail

artifact=/opt/hgb/artifacts/g2fuzz
data_artifact=/opt/hgb/artifacts/g2fuzz-data
python=/opt/hgb/venv/bin/python
workspace=/workspace

fix_workspace_permissions() {
  if [[ -n "${HGB_HOST_UID:-}" && -n "${HGB_HOST_GID:-}" ]] && command -v chown >/dev/null 2>&1; then
    chown -R "${HGB_HOST_UID}:${HGB_HOST_GID}" "$workspace" 2>/dev/null || true
  fi
}
trap fix_workspace_permissions EXIT
mode="${1:-generate-seeds}"
mkdir -p "$workspace/logs" "$workspace/config" "$workspace/artifacts"
json_escape() { local v="${1:-}"; v="${v//\\/\\\\}"; v="${v//\"/\\\"}"; v="${v//$'\n'/\\n}"; printf '%s' "$v"; }
count_files() { local d="$1"; shift || true; [[ -d "$d" ]] || { printf '0'; return 0; }; find "$d" "$@" 2>/dev/null | wc -l | tr -d ' '; }
extract_json_string() { local key="$1" file="$2"; [[ -f "$file" ]] || return 0; sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$file" | head -n 1; }
commit() { git -C "$artifact" rev-parse HEAD 2>/dev/null || printf unknown; }
data_commit() { git -C "$data_artifact" rev-parse HEAD 2>/dev/null || printf unknown; }
select_program() {
  "$python" - "$artifact/program_to_format.json" "${G2FUZZ_PROGRAM:-auto}" <<'PYSEL'
import json, sys
from pathlib import Path
programs=json.loads(Path(sys.argv[1]).read_text())
requested=sys.argv[2]
if requested != 'auto':
    if requested not in programs:
        raise SystemExit(f'unknown G2FUZZ program: {requested}')
    program=requested
else:
    program='jhead' if 'jhead' in programs else next(iter(programs))
print(program)
print(','.join(programs[program]))
PYSEL
}
write_seed_summary() {
  local status="$1" code="$2" reason="$3" program="$4" formats="$5" seeds="$6" generators="$7"
  {
    printf '# HarnessGenBench G2FUZZ Summary\n\n'
    printf -- '- Run directory: `%s`\n' "$workspace"
    printf -- '- Upstream commit: `%s`\n' "$(commit)"
    printf -- '- Data commit: `%s`\n' "$(data_commit)"
    printf -- '- Selected target: `%s`\n' "$program"
    printf -- '- Selected format(s): `%s`\n' "$formats"
    printf -- '- Model: `%s`\n' "${G2FUZZ_MODEL:-${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}}"
    printf -- '- Status: `%s`\n' "$status"
    printf -- '- Generated seed count: %s\n' "$seeds"
    printf -- '- Generator count: %s\n' "$generators"
    printf -- '- AFL run status: `not_run`\n'
    printf -- '- Top failure reason: %s\n' "$reason"
    printf '\n## Logs\n\n'
    find "$workspace/logs" -type f 2>/dev/null | sort | sed "s#^$workspace/##" | sed 's/^/- `/' | sed 's/$/`/'
  } >"$workspace/HGB_SUMMARY.md"
}
write_seed_metadata() {
  local status="$1" code="$2" reason="$3" program="$4" formats="$5" seeds="$6" generators="$7" output_dir="$8"
  {
    printf '{\n'
    printf '  "fuzzer": "g2fuzz",\n'
    printf '  "run_type": "seed_generation",\n'
    printf '  "status": "%s",\n' "$(json_escape "$status")"
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$(commit)")"
    printf '  "data_commit": "%s",\n' "$(json_escape "$(data_commit)")"
    printf '  "program": "%s",\n' "$(json_escape "$program")"
    printf '  "formats": "%s",\n' "$(json_escape "$formats")"
    printf '  "model": "%s",\n' "$(json_escape "${G2FUZZ_MODEL:-${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}}")"
    printf '  "api_key_present": %s,\n' "$([[ -n "${OPENAI_API_KEY:-${API_KEY:-}}" ]] && printf true || printf false)"
    printf '  "generated_seed_count": %s,\n' "$seeds"
    printf '  "generator_count": %s,\n' "$generators"
    printf '  "program_gen_exit_code": %s,\n' "$code"
    printf '  "reason": "%s",\n' "$(json_escape "$reason")"
    printf '  "output_dir": "%s",\n' "$(json_escape "$output_dir")"
    printf '  "data_repo_comparison_path": "%s",\n' "$(json_escape "$data_artifact/unifuzz/G2FUZZ_GPT35/$program")"
    printf '  "command_file": "%s",\n' "$(json_escape "$workspace/command.txt")"
    printf '  "log_file": "%s"\n' "$(json_escape "$workspace/logs/program_gen.log")"
    printf '}\n'
  } >"$workspace/metadata.json"
}
find_target_pair() {
  local program="$1" d
  for d in ${G2FUZZ_TARGET_DIR:-} "$workspace/targets/$program" "$artifact"; do
    [[ -n "$d" ]] || continue
    if [[ -x "$d/$program.afl" && -x "$d/$program.cmp" ]]; then
      printf '%s\n%s\n' "$d/$program.afl" "$d/$program.cmp"
      return 0
    fi
  done
  return 1
}
write_afl_summary() {
  local status="$1" code="$2" reason="$3" program="$4" queue="$5" crashes="$6" hangs="$7"
  {
    printf '# HarnessGenBench G2FUZZ Summary\n\n'
    printf -- '- Run directory: `%s`\n' "$workspace"
    printf -- '- Upstream commit: `%s`\n' "$(commit)"
    printf -- '- Selected target: `%s`\n' "$program"
    printf -- '- Status: `%s`\n' "$status"
    printf -- '- AFL run status: `%s`\n' "$code"
    printf -- '- AFL queue/crash/hang counts: queue=%s, crashes=%s, hangs=%s\n' "$queue" "$crashes" "$hangs"
    printf -- '- Top failure reason: %s\n' "$reason"
    printf '\n## Logs\n\n'
    find "$workspace" -maxdepth 3 -type f \( -name '*.log' -o -name 'TARGET_BUILD_MISSING.md' \) 2>/dev/null | sort | sed "s#^$workspace/##" | sed 's/^/- `/' | sed 's/$/`/'
  } >"$workspace/HGB_SUMMARY.md"
}
write_afl_metadata() {
  local status="$1" code="$2" reason="$3" program="$4" queue="$5" crashes="$6" hangs="$7" seed_run="$8"
  {
    printf '{\n'
    printf '  "fuzzer": "g2fuzz",\n'
    printf '  "run_type": "afl_smoke",\n'
    printf '  "status": "%s",\n' "$(json_escape "$status")"
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$(commit)")"
    printf '  "program": "%s",\n' "$(json_escape "$program")"
    printf '  "seed_run": "%s",\n' "$(json_escape "$seed_run")"
    printf '  "afl_exit_code": %s,\n' "$code"
    printf '  "queue_count": %s,\n' "$queue"
    printf '  "crash_count": %s,\n' "$crashes"
    printf '  "hang_count": %s,\n' "$hangs"
    printf '  "reason": "%s",\n' "$(json_escape "$reason")"
    printf '  "command_file": "%s",\n' "$(json_escape "$workspace/command.txt")"
    printf '  "log_file": "%s"\n' "$(json_escape "$workspace/logs/afl.log")"
    printf '}\n'
  } >"$workspace/metadata.json"
}

case "$mode" in
  generate-seeds|smoke)
    mapfile -t selected < <(select_program)
    program="${selected[0]}"
    formats="${selected[1]}"
    model="${G2FUZZ_MODEL:-${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}}"
    output_dir="$workspace/${program}_output"
    runtime=/run/hgb/g2fuzz-runtime
    mkdir -p "$runtime" "$workspace/config"
    cp "$artifact/program_to_format.json" "$runtime/program_to_format.json"
    cp "$artifact/program_to_format.json" "$workspace/config/program_to_format.json"
    "$python" - "$runtime/model_setting.json" "$model" <<'PYMODEL'
import json, sys
with open(sys.argv[1], 'w') as f:
    json.dump({'model': [sys.argv[2]]}, f, indent=2)
    f.write('\n')
PYMODEL
    cp "$runtime/model_setting.json" "$workspace/config/model_setting.json"
    printf '%q ' "$python" "$artifact/program_gen.py" --output "$output_dir" --program "$program" >"$workspace/command.txt"; printf '\n' >>"$workspace/command.txt"
    export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
    export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
    if [[ -z "$OPENAI_API_KEY" ]]; then
      printf 'OPENAI_API_KEY is not set. No credential file was created.\n' >"$workspace/logs/program_gen.log"
      write_seed_metadata missing_api_key 2 'OPENAI_API_KEY is not set' "$program" "$formats" 0 0 "$output_dir"
      write_seed_summary missing_api_key 2 'OPENAI_API_KEY is not set' "$program" "$formats" 0 0
      exit 2
    fi
    printf '%s\n' "$OPENAI_API_KEY" >"$runtime/openai_key.txt"
    chmod 600 "$runtime/openai_key.txt"
    code=0
    (cd "$runtime" && timeout "${G2FUZZ_TIMEOUT_SECONDS:-300}" "$python" "$artifact/program_gen.py" --output "$output_dir" --program "$program") >"$workspace/logs/program_gen.log" 2>&1 || code=$?
    rm -f "$runtime/openai_key.txt"
    seeds="$(count_files "$output_dir/default/gen_seeds" -type f)"
    generators="$(count_files "$output_dir/default/generators" -type f)"
    status=completed; reason=none
    [[ "$code" -eq 0 ]] || { status=failed; reason="program_gen exited $code"; }
    write_seed_metadata "$status" "$code" "$reason" "$program" "$formats" "$seeds" "$generators" "$output_dir"
    write_seed_summary "$status" "$code" "$reason" "$program" "$formats" "$seeds" "$generators"
    exit "$code"
    ;;
  smoke-afl)
    seed_run="${G2FUZZ_SEED_RUN:-/seed-run}"
    program="${G2FUZZ_PROGRAM:-}"
    if [[ -z "$program" && -f "$seed_run/metadata.json" ]]; then
      program="$(extract_json_string program "$seed_run/metadata.json")"
    fi
    if [[ -z "$program" || "$program" == auto ]]; then
      mapfile -t selected < <(select_program)
      program="${selected[0]}"
    fi
    seed_src="$seed_run/${program}_output/default/gen_seeds"
    mkdir -p "$workspace/initial_seeds" "$workspace/afl_out"
    if [[ -d "$seed_src" ]]; then cp -a "$seed_src/." "$workspace/initial_seeds/" 2>/dev/null || true; fi
    if [[ "$(count_files "$workspace/initial_seeds" -type f)" == "0" ]]; then printf 'empty\n' >"$workspace/initial_seeds/empty"; fi
    pair=()
    mapfile -t pair < <(find_target_pair "$program" || true)
    if [[ "${#pair[@]}" -lt 2 ]]; then
      cat >"$workspace/TARGET_BUILD_MISSING.md" <<EOF
# G2FUZZ Target Build Missing

AFL smoke was not run because target binaries were not found.

- Program: \`$program\`
- Missing AFL binary: \`$program.afl\`
- Missing CMPLOG binary: \`$program.cmp\`
- Searched: \`\$G2FUZZ_TARGET_DIR\`, \`/workspace/targets/$program/\`, and \`/opt/hgb/artifacts/g2fuzz/\`

Upstream requires compiling the target program twice, once in AFL default mode and once in cmplog mode, producing \`program.afl\` and \`program.cmp\`.
EOF
      printf 'Target binaries missing; soft-skip.\n' >"$workspace/logs/afl.log"
      printf 'soft-skip missing target binaries\n' >"$workspace/command.txt"
      write_afl_metadata soft_skip_target_binaries_missing 0 'target .afl/.cmp binaries missing' "$program" 0 0 0 "$seed_run"
      write_afl_summary soft_skip_target_binaries_missing 0 'target .afl/.cmp binaries missing' "$program" 0 0 0
      [[ "${G2FUZZ_REQUIRE_TARGET_BINARIES:-0}" == "1" ]] && exit 127 || exit 0
    fi
    afl="${pair[0]}"; cmp="${pair[1]}"
    printf '%q ' "$artifact/afl-fuzz" -i "$workspace/initial_seeds" -o "$workspace/afl_out" -c "$cmp" -m "${G2FUZZ_MEMORY_MB:-1024}" -k "$artifact" -- "$afl" @@ >"$workspace/command.txt"; printf '\n' >>"$workspace/command.txt"
    code=0
    AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 timeout "${G2FUZZ_AFL_TIMEOUT_SECONDS:-300}" "$artifact/afl-fuzz" -i "$workspace/initial_seeds" -o "$workspace/afl_out" -c "$cmp" -m "${G2FUZZ_MEMORY_MB:-1024}" -k "$artifact" -- "$afl" @@ >"$workspace/logs/afl.log" 2>&1 || code=$?
    queue="$(count_files "$workspace/afl_out/default/queue" -type f)"
    crashes="$(count_files "$workspace/afl_out/default/crashes" -type f ! -name README.txt)"
    hangs="$(count_files "$workspace/afl_out/default/hangs" -type f ! -name README.txt)"
    status=completed; reason=none
    [[ "$code" -eq 0 || "$code" -eq 124 ]] || { status=failed; reason="afl-fuzz exited $code"; }
    write_afl_metadata "$status" "$code" "$reason" "$program" "$queue" "$crashes" "$hangs" "$seed_run"
    write_afl_summary "$status" "$code" "$reason" "$program" "$queue" "$crashes" "$hangs"
    exit "$code"
    ;;
  *) echo "unknown mode: $mode" >&2; exit 64 ;;
esac
