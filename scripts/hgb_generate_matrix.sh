#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat >&2 <<'EOF'
Usage:
  bash scripts/hgb_generate_matrix.sh --generators LIST|all --targets LIST|all [--dry-run] [--parallel-worker N]

Options:
  --parallel-worker N        Run up to N targets concurrently for each generator (default: 5).
  --jobs N                   Backward-compatible alias for --parallel-worker.
  --allow-input-generators   Allow generators that require input corpus/source material.
  --target-package-mode MODE Prepare targets once per matrix run with shared, or once per pair with per-pair (default: shared).
  --layout compact|full      Target package layout for prepared packages (default: compact).
  --save-mode compact|debug  Compact removes duplicate transient outputs; debug preserves them (default: compact).
  --continue-on-error        Record every pair and continue after failures (default).
  --fail-fast                Stop launching new jobs after a failure; wait for active jobs.
  --run-id ID                Use ID for the matrix workspace.
EOF
}

generators=""
targets=""
parallel_worker=5
dry_run=0
allow_input=0
continue_on_error=1
target_package_mode="shared"
target_layout="compact"
save_mode="compact"
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
    --parallel-worker)
      parallel_worker="${2:-}"
      shift 2
      ;;
    --jobs)
      parallel_worker="${2:-}"
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
    --target-package-mode)
      target_package_mode="${2:-}"
      shift 2
      ;;
    --layout|--target-layout)
      target_layout="${2:-}"
      shift 2
      ;;
    --save-mode)
      save_mode="${2:-}"
      shift 2
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
[[ "$parallel_worker" =~ ^[1-9][0-9]*$ ]] || die "--parallel-worker must be a positive integer"
[[ "$target_package_mode" == "shared" || "$target_package_mode" == "per-pair" ]] || die "--target-package-mode must be shared or per-pair"
[[ "$target_layout" == "compact" || "$target_layout" == "full" ]] || die "--layout must be compact or full"
[[ "$save_mode" == "compact" || "$save_mode" == "debug" ]] || die "--save-mode must be compact or debug"

root="$(repo_root)"

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

[[ "${#generator_list[@]}" -gt 0 ]] || die "no generators selected"
[[ "${#target_list[@]}" -gt 0 ]] || die "no targets selected"

for generator in "${generator_list[@]}"; do
  valid_hgb_generator "$generator" || die "unknown generator: $generator"
done

run_id="${run_id:-$(make_timestamp)}"
matrix_dir="$(hgb_workspace_dir "$root")/matrix/$run_id"
row_dir="$matrix_dir/rows"
ensure_dir "$matrix_dir"
ensure_dir "$row_dir"
matrix_file="$matrix_dir/matrix.tsv"
printf 'generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n' >"$matrix_file"
{
  printf 'run_id=%s\n' "$run_id"
  printf 'target_package_mode=%s\n' "$target_package_mode"
  printf 'target_layout=%s\n' "$target_layout"
  printf 'save_mode=%s\n' "$save_mode"
  printf 'parallel_worker=%s\n' "$parallel_worker"
} >"$matrix_dir/run_config.txt"

safe_name() {
  local value="$1"
  value="${value//[^A-Za-z0-9_]/_}"
  printf '%s\n' "$value"
}

pair_row_file() {
  local generator="$1"
  local target="$2"
  local index="$3"
  local safe_generator safe_target index_label
  safe_generator="$(safe_name "$generator")"
  safe_target="$(safe_name "$target")"
  index_label="$(printf '%06d' "$index")"
  printf '%s/%s_%s_%s.tsv\n' "$row_dir" "$index_label" "$safe_generator" "$safe_target"
}

declare -A shared_target_packages=()

prepare_shared_target_packages() {
  local target output
  if [[ "$target_package_mode" != "shared" ]]; then
    return 0
  fi
  for target in "${target_list[@]}"; do
    if [[ -n "${shared_target_packages[$target]:-}" ]]; then
      continue
    fi
    output="$(hgb_workspace_dir "$root")/target-packages/$run_id/$target"
    log "preparing shared target package for $target: $output"
    bash "$SCRIPT_DIR/hgb_prepare_target.sh" --target "$target" --run-id "$run_id" --output "$output" --layout "$target_layout" >/dev/null
    shared_target_packages["$target"]="$output"
  done
}

preflight_generator() {
  local generator="$1"
  local artifact_name image
  local artifacts=()

  valid_hgb_generator "$generator" || die "unknown generator: $generator"
  artifact_name="$(generator_artifact_name "$generator")"
  artifacts=(fuzzbench "$artifact_name")
  if [[ "$generator" == "g2fuzz" ]]; then
    artifacts+=(g2fuzz-data)
  fi
  ensure_artifacts_present "$root" "${artifacts[@]}"

  if [[ "$dry_run" == "1" ]]; then
    return 0
  fi

  image="$(hgb_image_name "$generator" "$artifact_name" "$root")"
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    log "building generator image once for $generator: $image"
    hgb_build_image "$generator" "$artifact_name" "$root" >/dev/null
  fi
}

run_pair() {
  local generator="$1"
  local target="$2"
  local index="$3"
  local safe_generator safe_target index_label pair_run_id workspace metadata summary status
  local stdout_file stderr_file row_file code
  local args=()

  safe_generator="$(safe_name "$generator")"
  safe_target="$(safe_name "$target")"
  index_label="$(printf '%06d' "$index")"
  pair_run_id="${run_id}_${index_label}_${safe_generator}_${safe_target}"
  workspace="$(workspace_generator_target_run_dir "$generator" "$target" "$pair_run_id" "$root")"
  stdout_file="$matrix_dir/${index_label}_${safe_generator}_${safe_target}.stdout"
  stderr_file="$matrix_dir/${index_label}_${safe_generator}_${safe_target}.stderr"
  row_file="$(pair_row_file "$generator" "$target" "$index")"
  args=(--generator "$generator" --target "$target" --run-id "$pair_run_id" --layout "$target_layout" --save-mode "$save_mode")
  if [[ "$target_package_mode" == "shared" ]]; then
    args+=(--target-package "${shared_target_packages[$target]}")
  fi
  if [[ "$dry_run" == "1" ]]; then args+=(--dry-run); fi
  if [[ "$allow_input" == "1" ]]; then args+=(--allow-input-generator); fi

  code=0
  bash "$SCRIPT_DIR/hgb_generate_harness.sh" "${args[@]}" >"$stdout_file" 2>"$stderr_file" || code=$?

  metadata="$workspace/metadata.json"
  summary="$workspace/HGB_SUMMARY.md"
  status="$(extract_json_string status "$metadata")"
  if [[ -z "$status" ]]; then
    status="failed_exit_$code"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$generator" "$target" "$status" "$workspace" "$metadata" "$summary" >"$row_file"
  return "$code"
}

active_count=0
generator_failed=0
first_failure_code=0

wait_for_one() {
  local code=0

  if wait -n; then
    code=0
  else
    code=$?
  fi
  active_count=$((active_count - 1))
  if [[ "$code" -ne 0 ]]; then
    generator_failed=1
    if [[ "$first_failure_code" -eq 0 ]]; then
      first_failure_code="$code"
    fi
  fi
}

wait_for_slot() {
  while [[ "$active_count" -ge "$parallel_worker" ]]; do
    wait_for_one
  done
}

wait_for_generator() {
  while [[ "$active_count" -gt 0 ]]; do
    wait_for_one
  done
}

prepare_shared_target_packages

pair_index=0
for generator in "${generator_list[@]}"; do
  preflight_generator "$generator"
  active_count=0
  generator_failed=0
  first_failure_code=0
  generator_row_files=()

  for target in "${target_list[@]}"; do
    if [[ "$generator_failed" == "1" && "$continue_on_error" != "1" ]]; then
      break
    fi
    wait_for_slot
    if [[ "$generator_failed" == "1" && "$continue_on_error" != "1" ]]; then
      break
    fi
    pair_index=$((pair_index + 1))
    generator_row_files+=("$(pair_row_file "$generator" "$target" "$pair_index")")
    run_pair "$generator" "$target" "$pair_index" &
    active_count=$((active_count + 1))
  done

  wait_for_generator

  for row_file in "${generator_row_files[@]}"; do
    if [[ -f "$row_file" ]]; then
      cat "$row_file" >>"$matrix_file"
    fi
  done

  if [[ "$generator_failed" == "1" && "$continue_on_error" != "1" ]]; then
    python3 "$SCRIPT_DIR/hgb_collect_matrix.py" "$matrix_dir"
    exit "$first_failure_code"
  fi
done

python3 "$SCRIPT_DIR/hgb_collect_matrix.py" "$matrix_dir"
printf '%s\n' "$matrix_dir"
