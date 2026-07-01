#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat >&2 <<'EOF'
Usage:
  bash scripts/hgb_generate_matrix.sh --generators LIST|all --targets LIST|all [--dry-run]
EOF
}

generators=""
targets=""
jobs=1
dry_run=0
allow_input=0
continue_on_error=1
run_id=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --generators)
      generators="${2:-}"
      shift 2
      ;;
    --targets)
      targets="${2:-}"
      shift 2
      ;;
    --jobs)
      jobs="${2:-}"
      shift 2
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    --allow-input-generators|--allow-input-generator)
      allow_input=1
      shift
      ;;
    --continue-on-error)
      continue_on_error=1
      shift
      ;;
    --fail-fast)
      continue_on_error=0
      shift
      ;;
    --run-id)
      run_id="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ -n "$generators" && -n "$targets" ]] || { usage; exit 64; }
[[ "$jobs" =~ ^[0-9]+$ ]] || die "--jobs must be an integer"
if [[ "$jobs" != "1" ]]; then
  log "--jobs=$jobs requested; initial matrix implementation runs serially"
fi

root="$(repo_root)"
run_id="${run_id:-$(make_timestamp)}"
matrix_dir="$(hgb_workspace_dir "$root")/matrix/$run_id"
ensure_dir "$matrix_dir"
matrix_file="$matrix_dir/matrix.tsv"
printf 'generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n' >"$matrix_file"

if [[ "$generators" == "all" ]]; then
  generator_list=(oss-fuzz-gen ckgfuzzer promefuzz elfuzz g2fuzz)
else
  IFS=',' read -r -a generator_list <<<"$generators"
fi
if [[ "$targets" == "all" ]]; then
  mapfile -t target_list < <(bash "$SCRIPT_DIR/hgb_targets.sh" list)
else
  IFS=',' read -r -a target_list <<<"$targets"
fi

for generator in "${generator_list[@]}"; do
  valid_hgb_generator "$generator" || die "unknown generator: $generator"
  for target in "${target_list[@]}"; do
    safe_generator="${generator//[^A-Za-z0-9_]/_}"
    safe_target="${target//[^A-Za-z0-9_]/_}"
    pair_run_id="${run_id}_${safe_generator}_${safe_target}"
    workspace="$(workspace_generator_target_run_dir "$generator" "$target" "$pair_run_id" "$root")"
    args=(--generator "$generator" --target "$target" --run-id "$pair_run_id")
    if [[ "$dry_run" == "1" ]]; then args+=(--dry-run); fi
    if [[ "$allow_input" == "1" ]]; then args+=(--allow-input-generator); fi
    code=0
    bash "$SCRIPT_DIR/hgb_generate_harness.sh" "${args[@]}" >"$matrix_dir/${safe_generator}_${safe_target}.stdout" 2>"$matrix_dir/${safe_generator}_${safe_target}.stderr" || code=$?
    metadata="$workspace/metadata.json"
    summary="$workspace/HGB_SUMMARY.md"
    status="$(extract_json_string status "$metadata")"
    if [[ -z "$status" ]]; then
      status="failed_exit_$code"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$generator" "$target" "$status" "$workspace" "$metadata" "$summary" >>"$matrix_file"
    if [[ "$code" -ne 0 && "$continue_on_error" != "1" ]]; then
      python3 "$SCRIPT_DIR/hgb_collect_matrix.py" "$matrix_dir"
      exit "$code"
    fi
  done
done

python3 "$SCRIPT_DIR/hgb_collect_matrix.py" "$matrix_dir"
printf '%s\n' "$matrix_dir"
