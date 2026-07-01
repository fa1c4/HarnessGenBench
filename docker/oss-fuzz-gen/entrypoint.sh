#!/usr/bin/env bash
set -euo pipefail

artifact=/opt/hgb/artifacts/oss-fuzz-gen
python=/opt/hgb/venv/bin/python
workspace=/workspace

fix_workspace_permissions() {
  if [[ -n "${HGB_HOST_UID:-}" && -n "${HGB_HOST_GID:-}" ]] && command -v chown >/dev/null 2>&1; then
    chown -R "${HGB_HOST_UID}:${HGB_HOST_GID}" "$workspace" 2>/dev/null || true
  fi
}
trap fix_workspace_permissions EXIT
mode="${1:-smoke}"
mkdir -p "$workspace/logs"

json_escape() { local v="${1:-}"; v="${v//\\/\\\\}"; v="${v//\"/\\\"}"; v="${v//$'\n'/\\n}"; printf '%s' "$v"; }
count_files() { local d="$1"; shift || true; [[ -d "$d" ]] || { printf '0'; return 0; }; find "$d" "$@" 2>/dev/null | wc -l | tr -d ' '; }
commit() { git -C "$artifact" rev-parse HEAD 2>/dev/null || printf unknown; }
summary() {
  local status="$1" exit_code="$2" reason="$3"
  {
    printf '# HarnessGenBench OSS-Fuzz-Gen Summary\n\n'
    printf -- '- Run directory: `%s`\n' "$workspace"
    printf -- '- Upstream commit: `%s`\n' "$(commit)"
    printf -- '- Status: `%s`\n' "$status"
    printf -- '- Exit code: `%s`\n' "$exit_code"
    printf -- '- Benchmark: `%s`\n' "${OFG_BENCHMARK:-tinyxml2}"
    printf -- '- Model: `%s`\n' "${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
    printf -- '- Generated harness candidates: %s\n' "$(count_files "$workspace" -type f \( -name '*fuzz*.cc' -o -name '*fuzz*.cpp' -o -name '*fuzz*.c' \))"
    printf -- '- Top failure reason: %s\n' "$reason"
    printf '\n## Logs\n\n'
    find "$workspace/logs" -type f 2>/dev/null | sort | sed "s#^$workspace/##" | sed 's/^/- `/' | sed 's/$/`/'
  } >"$workspace/HGB_SUMMARY.md"
}
metadata() {
  local status="$1" exit_code="$2" reason="$3" command_file="$4" log_file="$5" benchmark_yaml="$6"
  {
    printf '{\n'
    printf '  "fuzzer": "oss-fuzz-gen",\n'
    printf '  "status": "%s",\n' "$(json_escape "$status")"
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$(commit)")"
    printf '  "benchmark": "%s",\n' "$(json_escape "${OFG_BENCHMARK:-tinyxml2}")"
    printf '  "benchmark_yaml": "%s",\n' "$(json_escape "$benchmark_yaml")"
    printf '  "model": "%s",\n' "$(json_escape "${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}")"
    printf '  "api_key_present": %s,\n' "$([[ -n "${OPENAI_API_KEY:-${API_KEY:-}}" ]] && printf true || printf false)"
    printf '  "exit_code": %s,\n' "$exit_code"
    printf '  "reason": "%s",\n' "$(json_escape "$reason")"
    printf '  "command_file": "%s",\n' "$(json_escape "$command_file")"
    printf '  "log_file": "%s"\n' "$(json_escape "$log_file")"
    printf '}\n'
  } >"$workspace/metadata.json"
}


if [[ "$mode" == "generate-target" ]]; then
  # shellcheck source=/opt/hgb/bin/target_contract.sh
  source /opt/hgb/bin/target_contract.sh
  export HGB_GENERATOR="${HGB_GENERATOR:-oss-fuzz-gen}"
  export HGB_GENERATOR_ARTIFACT_DIR="$artifact"
  export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
  export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
  export OPENAI_MODEL="${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
  mkdir -p "$workspace/logs" "$workspace/generated_harnesses"
  hgb_require_target_package
  project="${HGB_TARGET_PROJECT:-$(hgb_target_manifest_value project)}"
  fuzz_target="${HGB_TARGET_FUZZ_TARGET:-$(hgb_target_manifest_value fuzz_target)}"
  target_name="${HGB_TARGET:-$(hgb_target_manifest_value target)}"

  synthesize_benchmark_yaml() {
    local out_yaml="$1"
    local api_json="$workspace/ofg_api_candidates.json"
    local api_count
    api_count="$(python3 /opt/hgb/bin/extract_api_list.py --source /target/source_input --out "$api_json" --max "${OFG_SYNTH_MAX_APIS:-3}" 2>"$workspace/logs/ofg_api_extract.log" || printf '0')"
    api_count="${api_count##*$'\n'}"
    if [[ "${api_count:-0}" == "0" ]]; then
      return 1
    fi
    python3 - "$api_json" "$out_yaml" "$project" "$fuzz_target" "$target_name" <<'PY_OFG_YAML'
import json
import sys
from pathlib import Path
api_json, out_yaml, project, fuzz_target, target_name = sys.argv[1:]
names = json.loads(Path(api_json).read_text(encoding='utf-8'))[:3]
source = Path('/target/source_input')
cpp_exts = {'.cc', '.cpp', '.cxx', '.hpp', '.hh', '.hxx'}
c_exts = {'.c', '.h'}
cpp_count = sum(1 for p in source.rglob('*') if p.suffix.lower() in cpp_exts)
c_count = sum(1 for p in source.rglob('*') if p.suffix.lower() in c_exts)
language = 'c++' if cpp_count >= c_count else 'c'
ref = None
ref_root = Path('/target/reference_harnesses')
if ref_root.exists():
    for candidate in ref_root.rglob('*'):
        if candidate.is_file() and candidate.suffix.lower() in {'.c', '.cc', '.cpp', '.cxx'}:
            ref = candidate
            break
target_path = str(ref) if ref else f'/src/{project}/{fuzz_target or target_name}.cc'
functions = []
for name in names:
    functions.append({
        'name': name,
        'params': [
            {'name': 'data', 'type': 'const uint8_t *'},
            {'name': 'size', 'type': 'size_t'},
        ],
        'return_type': 'int',
        'signature': f'int {name}(const uint8_t *, size_t)',
    })
with open(out_yaml, 'w', encoding='utf-8') as f:
    json.dump({
        'functions': functions,
        'language': language,
        'project': project,
        'target_name': fuzz_target or target_name,
        'target_path': target_path,
    }, f, indent=2)
    f.write('\n')
PY_OFG_YAML
  }

  if [[ "${HGB_DRY_RUN:-0}" == "1" ]]; then
    printf 'oss-fuzz-gen generate-target dry-run for %s\n' "$target_name" >"$workspace/command.txt"
    hgb_write_common_metadata dry_run_ok 'dry run validated target package' 0 harness_generator
    hgb_write_common_summary dry_run_ok 'dry run validated target package' harness_generator
    exit 0
  fi

  if ! hgb_api_key_present; then
    printf 'OPENAI_API_KEY is not set; OSS-Fuzz-Gen target generation skipped.\n' >"$workspace/logs/run.log"
    hgb_write_common_metadata missing_api_key 'OPENAI_API_KEY is not set' 2 harness_generator
    hgb_write_common_summary missing_api_key 'OPENAI_API_KEY is not set' harness_generator
    exit 2
  fi

  benchmark_yaml="${OFG_BENCHMARK_YAML:-}"
  if [[ -n "$benchmark_yaml" && ! -f "$benchmark_yaml" ]]; then
    printf 'Provided OFG_BENCHMARK_YAML does not exist: %s\n' "$benchmark_yaml" >"$workspace/logs/benchmark_yaml.log"
    benchmark_yaml=""
  fi
  if [[ -z "$benchmark_yaml" && -d "$artifact/benchmark-sets" ]]; then
    while IFS= read -r candidate; do
      if grep -Fq "$target_name" "$candidate" || grep -Fq "$fuzz_target" "$candidate" || grep -Eq "project:[[:space:]]*['\"]?$project['\"]?[[:space:]]*$" "$candidate"; then
        benchmark_yaml="$candidate"
        break
      fi
    done < <(find "$artifact/benchmark-sets" -type f \( -name '*.yaml' -o -name '*.yml' \) 2>/dev/null | sort)
  fi
  if [[ -z "$benchmark_yaml" ]]; then
    generated_yaml="$workspace/ofg_benchmark.yaml"
    if synthesize_benchmark_yaml "$generated_yaml"; then
      benchmark_yaml="$generated_yaml"
      printf 'Generated OSS-Fuzz-Gen benchmark YAML for project=%s target=%s: %s\n' "$project" "$target_name" "$benchmark_yaml" >"$workspace/logs/benchmark_yaml.log"
    else
      printf 'No compatible OSS-Fuzz-Gen benchmark YAML found for project=%s target=%s, and no API candidates could be extracted.\n' "$project" "$target_name" >"$workspace/logs/benchmark_yaml.log"
      hgb_soft_skip no_api_candidates 'OSS-Fuzz-Gen could not find or synthesize a benchmark YAML because no API candidates were extracted' harness_generator
    fi
  fi

  oss_fuzz_dir="${OFG_OSS_FUZZ_DIR:-$workspace/oss-fuzz}"
  mkdir -p "$workspace/pip-cache"
  cmd=("$python" run_all_experiments.py --model "$OPENAI_MODEL" -y "$benchmark_yaml" --oss-fuzz-dir "$oss_fuzz_dir" --run-timeout "${OFG_RUN_TIMEOUT:-300}" --work-dir "$workspace/ofg-work")
  printf '%q ' "${cmd[@]}" >"$workspace/command.txt"; printf '\n' >>"$workspace/command.txt"
  code=0
  (cd "$artifact" && PIP_CACHE_DIR="$workspace/pip-cache" timeout "${HGB_GENERATION_TIMEOUT_SECONDS:-900}" "${cmd[@]}") >"$workspace/logs/run.log" 2>&1 || code=$?
  if [[ -d "$workspace/ofg-work" ]]; then
    n=0
    while IFS= read -r generated; do
      n=$((n + 1))
      cp "$generated" "$workspace/generated_harnesses/${n}_$(basename "$generated")" 2>/dev/null || true
    done < <(find "$workspace/ofg-work" -type f \( -path '*/fixed_targets/*' -o -path '*/raw_targets/*' \) \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' \) 2>/dev/null | sort)
  fi
  if [[ "${HGB_SAVE_MODE:-compact}" == "compact" ]]; then
    rm -rf "$workspace/ofg-work" "$workspace/pip-cache" "$workspace/oss-fuzz"
  fi
  status=completed
  reason=none
  if [[ "$code" -ne 0 ]]; then
    status=failed
    reason="run_all_experiments exited $code"
  fi
  extra=$(printf '  "benchmark_yaml": "%s",\n  "command_file": "%s",\n  "log_file": "%s"' "$(hgb_json_escape "$benchmark_yaml")" "$(hgb_json_escape "$workspace/command.txt")" "$(hgb_json_escape "$workspace/logs/run.log")")
  hgb_write_common_metadata "$status" "$reason" "$code" harness_generator "$extra"
  hgb_write_common_summary "$status" "$reason" harness_generator
  exit "$code"
fi
[[ "$mode" == "smoke" ]] || { echo "unknown mode: $mode" >&2; exit 64; }
export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
export OPENAI_MODEL="${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
benchmark="${OFG_BENCHMARK:-tinyxml2}"
benchmark_yaml=""
if [[ -d "$artifact/benchmark-sets" ]]; then
  benchmark_yaml="$(find "$artifact/benchmark-sets" -type f \( -name '*.yaml' -o -name '*.yml' \) \( -iname "*$benchmark*" -o -exec grep -Il "$benchmark" {} \; \) 2>/dev/null | sort | head -n 1 || true)"
fi
help_file="$workspace/logs/help.txt"
run_log="$workspace/logs/run.log"
command_file="$workspace/command.txt"
(cd "$artifact" && "$python" run_all_experiments.py --help) >"$help_file" 2>&1 || true
if [[ -z "$benchmark_yaml" ]]; then
  printf 'Could not locate benchmark YAML for %s\n' "$benchmark" >"$run_log"
  printf 'locate benchmark yaml\n' >"$command_file"
  metadata missing_benchmark 2 'benchmark YAML not found' "$command_file" "$run_log" "$benchmark_yaml"
  summary missing_benchmark 2 'benchmark YAML not found'
  exit 2
fi
if [[ -z "$OPENAI_API_KEY" ]]; then
  printf 'OPENAI_API_KEY is not set; OSS-Fuzz-Gen smoke not launched.\n' >"$run_log"
  printf 'python run_all_experiments.py -y %q --model %q --run-timeout %q --work-dir %q\n' "$benchmark_yaml" "$OPENAI_MODEL" "${OFG_RUN_TIMEOUT:-300}" "$workspace/ofg-work" >"$command_file"
  metadata missing_api_key 2 'OPENAI_API_KEY is not set' "$command_file" "$run_log" "$benchmark_yaml"
  summary missing_api_key 2 'OPENAI_API_KEY is not set'
  exit 2
fi
cmd=("$python" run_all_experiments.py -y "$benchmark_yaml" --model "$OPENAI_MODEL" --run-timeout "${OFG_RUN_TIMEOUT:-300}" --work-dir "$workspace/ofg-work")
printf '%q ' "${cmd[@]}" >"$command_file"; printf '\n' >>"$command_file"
code=0
(cd "$artifact" && timeout "${OFG_TOTAL_TIMEOUT_SECONDS:-600}" "${cmd[@]}") >"$run_log" 2>&1 || code=$?
status=completed; reason=none
[[ "$code" -eq 0 ]] || { status=failed; reason="run_all_experiments exited $code"; }
metadata "$status" "$code" "$reason" "$command_file" "$run_log" "$benchmark_yaml"
summary "$status" "$code" "$reason"
exit "$code"
