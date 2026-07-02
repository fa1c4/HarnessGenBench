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
write_g2fuzz_preseeds() {
  local target="$1" formats="$2" seed_dir="$3"
  mkdir -p "$seed_dir"
  if [[ "$target" == *harfbuzz* || ",$formats," == *TTF* || ",$formats," == *OTF* || ",$formats," == *TTC* ]]; then
    python3 - "$seed_dir" <<'PY_G2_PRESEED'
from pathlib import Path
import sys
seed_dir = Path(sys.argv[1])
seed_dir.mkdir(parents=True, exist_ok=True)
seeds = {
    "hgb_minimal.ttf": bytes.fromhex("000100000000000000000000"),
    "hgb_minimal.otf": b"OTTO" + b"\x00" * 8,
    "hgb_minimal.ttc": b"ttcf\x00\x01\x00\x00\x00\x00\x00\x00",
}
for name, data in seeds.items():
    path = seed_dir / name
    if not path.exists():
        path.write_bytes(data)
PY_G2_PRESEED
  fi
  local copied=0
  while IFS= read -r corpus_file && [[ "$copied" -lt "${G2FUZZ_MAX_PRESEEDED_CORPUS_FILES:-32}" ]]; do
    cp "$corpus_file" "$seed_dir/hgb_corpus_${copied}_$(basename "$corpus_file")" 2>/dev/null || true
    copied=$((copied + 1))
  done < <(find /target -type f \( -path '*/corpus/*' -o -path '*/seeds/*' -o -path '*/seed_corpus/*' \) -size -1048576c 2>/dev/null | sort)
}
patch_g2fuzz_program_gen() {
  local py="$artifact/program_gen.py"
  [[ -f "$py" ]] || return 0
  python3 - "$py" <<'PY_G2_PROGRAM_PATCH'
from pathlib import Path
import sys
path = Path(sys.argv[1])
text = path.read_text()
text = text.replace(
    'feature_analysis(model, file_format, tmp_path, seeds_path, generators, output_path, 3)',
    'feature_analysis(model, file_format, tmp_path, seeds_path, generators, output_path, int(os.environ.get("G2FUZZ_TRY_NUM", "1") or "1"))',
)
text = text.replace(
    'feature_analysis(model, file_format, tmp_path, seeds_path, generators, output_path, 1)',
    'feature_analysis(model, file_format, tmp_path, seeds_path, generators, output_path, int(os.environ.get("G2FUZZ_TRY_NUM", "1") or "1"))',
)
path.write_text(text)
PY_G2_PROGRAM_PATCH
}
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


if [[ "$mode" == "generate-target" ]]; then
  # shellcheck source=/opt/hgb/bin/target_contract.sh
  source /opt/hgb/bin/target_contract.sh
  export HGB_GENERATOR="${HGB_GENERATOR:-g2fuzz}"
  export HGB_GENERATOR_ARTIFACT_DIR="$artifact"
  export HGB_CAPABILITY=input_generator
  export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
  export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
  export OPENAI_MODEL="${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
  mkdir -p "$workspace/logs" "$workspace/generated_inputs" "$workspace/config"
  hgb_require_target_package
  target_name="${HGB_TARGET:-$(hgb_target_manifest_value target)}"
  if [[ "${HGB_ALLOW_INPUT_GENERATOR_TO_RUN:-0}" != "1" ]]; then
    hgb_soft_skip not_harness_generator 'G2FUZZ generates inputs and AFL++ workflows, not source-level harnesses; set HGB_ALLOW_INPUT_GENERATOR_TO_RUN=1 to run it as an input generator baseline' input_generator
  fi
  safe_target="$(printf '%s' "$target_name" | sed 's/[^A-Za-z0-9_]/_/g')"
  runtime=/run/hgb/g2fuzz-target
  mkdir -p "$runtime"
  formats="$(python3 - "$target_name" "$safe_target" /opt/hgb/metadata/fuzzbench_target_formats.json "$runtime/program_to_format.json" <<'PY_G2_FORMATS'
import json, os, sys
name, safe, mapping_path, out_path = sys.argv[1:]
try:
    mapping = json.load(open(mapping_path, encoding='utf-8'))
except OSError:
    mapping = {}
formats = mapping.get(name) or ['custom']
if 'harfbuzz' in name:
    preferred = ['TTF', 'ttf', 'OTF', 'otf', 'TTC', 'ttc']
    formats = sorted(formats, key=lambda item: preferred.index(item) if item in preferred else len(preferred))
try:
    max_formats = int(os.environ.get('G2FUZZ_MAX_FORMATS', '1') or '0')
except ValueError:
    max_formats = 1
if max_formats > 0:
    formats = formats[:max_formats]
with open(out_path, 'w', encoding='utf-8') as f:
    json.dump({safe: formats}, f, indent=2)
    f.write('\n')
print(','.join(formats))
PY_G2_FORMATS
)"
  cp "$runtime/program_to_format.json" "$workspace/config/program_to_format.json"
  model="${G2FUZZ_MODEL:-${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}}"
  python3 - "$runtime/model_setting.json" "$model" <<'PY_G2_MODEL'
import json, sys
with open(sys.argv[1], 'w', encoding='utf-8') as f:
    json.dump({'model': [sys.argv[2]]}, f, indent=2)
    f.write('\n')
PY_G2_MODEL
  cp "$runtime/model_setting.json" "$workspace/config/model_setting.json"
  output_dir="$workspace/g2fuzz_output"
  write_g2fuzz_preseeds "$target_name" "$formats" "$output_dir/default/gen_seeds"
  patch_g2fuzz_program_gen
  printf '%q ' "$python" "$artifact/program_gen.py" --output "$output_dir" --program "$safe_target" >"$workspace/command.txt"; printf '\n' >>"$workspace/command.txt"
  if [[ "${HGB_DRY_RUN:-0}" == "1" ]]; then
    hgb_write_common_metadata dry_run_ok 'dry run prepared G2FUZZ target format mapping' 0 input_generator
    hgb_write_common_summary dry_run_ok 'dry run prepared G2FUZZ target format mapping' input_generator
    exit 0
  fi
  if ! hgb_api_key_present; then
    printf 'OPENAI_API_KEY is not set. No credential file was created.\n' >"$workspace/logs/program_gen.log"
    hgb_write_common_metadata missing_api_key 'OPENAI_API_KEY is not set' 2 input_generator
    hgb_write_common_summary missing_api_key 'OPENAI_API_KEY is not set' input_generator
    exit 2
  fi
  printf '%s\n' "$OPENAI_API_KEY" >"$runtime/openai_key.txt"
  chmod 600 "$runtime/openai_key.txt"
  code=0
  (cd "$runtime" && timeout "${G2FUZZ_PER_FORMAT_TIMEOUT_SECONDS:-${HGB_GENERATION_TIMEOUT_SECONDS:-900}}" "$python" "$artifact/program_gen.py" --output "$output_dir" --program "$safe_target") >"$workspace/logs/program_gen.log" 2>&1 || code=$?
  rm -f "$runtime/openai_key.txt"
  if [[ -d "$output_dir" ]]; then
    cp -a "$output_dir/." "$workspace/generated_inputs/" 2>/dev/null || true
  fi
  generated_inputs="$(hgb_count_files "$workspace/generated_inputs" -type f)"
  if [[ "${HGB_SAVE_MODE:-compact}" == "compact" ]]; then
    rm -rf "$output_dir"
  fi
  program_gen_code="$code"
  status=completed
  reason=none
  if [[ "$program_gen_code" -eq 124 && "$generated_inputs" -gt 0 ]]; then
    status=partial_completed
    reason="program_gen timed out after preserving $generated_inputs generated/preseeded inputs"
    code=0
  elif [[ "$program_gen_code" -ne 0 ]]; then
    status=failed
    reason="program_gen exited $program_gen_code"
  fi
  extra=$(printf '  "program": "%s",
  "formats": "%s",
  "output_dir": "%s",
  "program_gen_exit_code": %s,
  "command_file": "%s"' "$(hgb_json_escape "$safe_target")" "$(hgb_json_escape "$formats")" "$(hgb_json_escape "$output_dir")" "$program_gen_code" "$(hgb_json_escape "$workspace/command.txt")")
  hgb_write_common_metadata "$status" "$reason" "$code" input_generator "$extra"
  hgb_write_common_summary "$status" "$reason" input_generator
  exit "$code"
fi
case "$mode" in
  generate-seeds|smoke)
    mapfile -t selected < <(select_program)
    program="${selected[0]}"
    formats="${selected[1]}"
    model="${G2FUZZ_MODEL:-${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}}"
    output_dir="$workspace/${program}_output"
    write_g2fuzz_preseeds "$program" "$formats" "$output_dir/default/gen_seeds"
    patch_g2fuzz_program_gen
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
    (cd "$runtime" && timeout "${G2FUZZ_PER_FORMAT_TIMEOUT_SECONDS:-${G2FUZZ_TIMEOUT_SECONDS:-300}}" "$python" "$artifact/program_gen.py" --output "$output_dir" --program "$program") >"$workspace/logs/program_gen.log" 2>&1 || code=$?
    rm -f "$runtime/openai_key.txt"
    seeds="$(count_files "$output_dir/default/gen_seeds" -type f)"
    generators="$(count_files "$output_dir/default/generators" -type f)"
    status=completed; reason=none
    program_gen_code="$code"
    if [[ "$program_gen_code" -eq 124 && "$seeds" -gt 0 ]]; then
      status=partial_completed
      reason="program_gen timed out after generating $seeds seeds"
      code=0
    elif [[ "$program_gen_code" -ne 0 ]]; then
      status=failed
      reason="program_gen exited $program_gen_code"
    fi
    write_seed_metadata "$status" "$program_gen_code" "$reason" "$program" "$formats" "$seeds" "$generators" "$output_dir"
    write_seed_summary "$status" "$program_gen_code" "$reason" "$program" "$formats" "$seeds" "$generators"
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
