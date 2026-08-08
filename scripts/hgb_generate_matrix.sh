#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat >&2 <<'EOF'
Usage:
  bash scripts/hgb_generate_matrix.sh --generators LIST|all --targets LIST|all|valuable|deduped [--dry-run] [--parallel-worker N]

Options:
  --parallel-worker N        Run up to N targets concurrently for each generator (default: 5).
  --targets VALUE            Comma list, all, or a named set from scripts/hgb_targets.sh list --sets.
  --jobs N                   Backward-compatible alias for --parallel-worker.
  --allow-input-generators   Legacy flag for input-generation baselines that still require opt-in.
  --target-package-mode MODE Prepare targets once per matrix run with shared, or once per pair with per-pair (default: shared).
  --layout compact|full      Target package layout for prepared packages (default: compact).
  --save-mode compact|debug  Compact removes duplicate transient outputs; debug preserves them (default: compact).
  --continue-on-error        Record every pair and continue after failures (default).
  --fail-fast                Stop launching new jobs after a failure; wait for active jobs.
  --profile NAME             Baseline profile passed to each pair (e.g. alpha, paper-native).
  --protocol NAME            Baseline protocol passed to each pair (e.g. paper-native).
  --strict                   Exit nonzero if any applicable pair fails to reach evaluated/Invalid.
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
profile=""
protocol=""
strict=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --generators|--generator)
      generators="${2:-}"
      shift 2
      ;;
    --targets|--target-set)
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
      printf 'WARNING: --allow-input-generators is a deprecated no-op; input-generator baselines run from metadata/baseline_contracts.yaml.\n' >&2
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
    --profile)
      profile="${2:-}"
      shift 2
      ;;
    --protocol)
      protocol="${2:-}"
      shift 2
      ;;
    --strict)
      strict=1
      shift
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
if [[ "$targets" != *,* ]]; then
  target_set_output=""
  if target_set_output="$(bash "$SCRIPT_DIR/hgb_targets.sh" list "$targets" 2>/dev/null)"; then
    mapfile -t target_list <<<"$target_set_output"
  else
    IFS=',' read -r -a target_list <<<"$targets"
  fi
else
  IFS=',' read -r -a target_list <<<"$targets"
fi

[[ "${#generator_list[@]}" -gt 0 ]] || die "no generators selected"
[[ "${#target_list[@]}" -gt 0 ]] || die "no targets selected"

for generator in "${generator_list[@]}"; do
  valid_hgb_generator "$generator" || die "unknown generator: $generator"
done

run_id="${run_id:-$(make_timestamp)}"
if [[ -n "$profile" ]]; then export HGB_BASELINE_PROFILE="$profile"; fi
if [[ -n "$protocol" ]]; then export HGB_BASELINE_PROTOCOL="$protocol"; fi
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
  local selected_targets=()
  if [[ "$target_package_mode" != "shared" ]]; then
    return 0
  fi
  if [[ "$#" -gt 0 ]]; then
    selected_targets=("$@")
  else
    selected_targets=("${target_list[@]}")
  fi
  for target in "${selected_targets[@]}"; do
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
  if [[ "$generator" == "elfuzz" ]]; then
    python3 "$root/docker/common/elfuzz_target_pipeline.py" validate-adapters --metadata-root "$root/metadata" \
      || die "ELFuzz adapter manifest does not cover the current valuable set; classify every new target in metadata/elfuzz_target_adapters.yaml"
  fi
  artifact_name="$(generator_artifact_name "$generator")"
  artifacts=(fuzzbench "$artifact_name")
  ensure_artifacts_present "$root" "${artifacts[@]}"

  if [[ "$dry_run" == "1" ]]; then
    return 0
  fi

  image="$(hgb_image_name "$generator" "$artifact_name" "$root")"
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    log "building generator image once for $generator: $image"
    hgb_build_image "$generator" "$artifact_name" "$root" >/dev/null
  elif [[ "$generator" == "oss-fuzz-gen" ]] && ! docker run --rm --entrypoint /bin/bash "$image" -lc 'test -f /opt/hgb/oss-fuzz/infra/helper.py && test -x /opt/hgb/bin/ofg_trim_benchmark.py && grep -Fq "_chat_completion_kwargs" /opt/hgb/artifacts/oss-fuzz-gen/llm_toolkit/models.py && grep -Fq "_copy_hgb_target_source" /opt/hgb/artifacts/oss-fuzz-gen/data_prep/project_src.py && grep -Fq "OFG_LOCAL_INTROSPECTOR_SHIM" /opt/hgb/bin/ofg_run_wrapper.py && grep -Fq "ofg_benchmark_trim_failed" /opt/hgb/entrypoint.sh && grep -Fq "OFG_OSS_FUZZ_VENV" /opt/hgb/entrypoint.sh' >/dev/null 2>&1; then
    log "rebuilding stale OSS-Fuzz-Gen image without /opt/hgb/oss-fuzz or current OSS-Fuzz-Gen fixes: $image"
    hgb_build_image "$generator" "$artifact_name" "$root" >/dev/null
  elif [[ "$generator" == "ckgfuzzer" ]] && ! docker run --rm --entrypoint /bin/bash "$image" -lc "grep -Fq 'timeout=float(llm_config.get' /opt/hgb/artifacts/ckgfuzzer/fuzzing_llm_engine/models/get_model.py && grep -Fq 'max_retries=int(llm_config.get' /opt/hgb/artifacts/ckgfuzzer/fuzzing_llm_engine/models/get_model.py && grep -Fq 'CKGFUZZER_LLM_MAX_RETRIES' /opt/hgb/entrypoint.sh" >/dev/null 2>&1; then
    log "rebuilding stale CKGFuzzer image without current LLM timeout/retry wiring: $image"
    hgb_build_image "$generator" "$artifact_name" "$root" >/dev/null
  elif [[ "$generator" == "promefuzz" ]] && ! docker run --rm --entrypoint /bin/bash "$image" -lc "test -f /opt/hgb/bin/promefuzz_target_build.sh && test -f /opt/hgb/bin/promefuzz_profile.py && test -f /opt/hgb/bin/promefuzz_build_context.py && test -f /opt/hgb/bin/hgb_harness_evaluator.py && command -v wget >/dev/null && command -v autoreconf >/dev/null && command -v nasm >/dev/null && command -v tclsh >/dev/null && test -x /usr/local/bin/python3.8 && test -f /usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.ubsan_standalone-x86_64.a && dpkg-query -W -f='\${db:Status-Status}' zlib1g-dev 2>/dev/null | grep -qx installed && grep -Fq 'fuzzbench_target_build_available' /opt/hgb/entrypoint.sh && grep -Fq 'promefuzz_build_context.py' /opt/hgb/entrypoint.sh && grep -Fq 'promefuzz_profile.py validate' /opt/hgb/entrypoint.sh && grep -Fq 'hgb_harness_evaluator.py' /opt/hgb/entrypoint.sh && grep -Fq 'consumer_case_paths' /opt/hgb/entrypoint.sh && grep -Fq 'verify_and_record_link_set' /opt/hgb/entrypoint.sh" >/dev/null 2>&1; then
    log "rebuilding stale PromeFuzz image without current target-build validation: $image"
    hgb_build_image "$generator" "$artifact_name" "$root" >/dev/null
  fi
}
generator_supports_target() {
  local generator="$1" target="$2"
  case "$generator" in
    elfuzz)
      local cls applicability
      cls="$(python3 "$root/docker/common/elfuzz_target_pipeline.py" classify --target "$target" --metadata-root "$root/metadata" 2>/dev/null || true)"
      applicability="$(printf '%s' "$cls" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("applicability",""))' 2>/dev/null || true)"
      [[ "$applicability" == "applicable" ]] && return 0
      return 1
      ;;
    *) return 0 ;;
  esac
}

record_not_applicable_target() {
  local generator="$1" target="$2" index="$3"
  local safe_generator safe_target index_label metadata_dir metadata status
  safe_generator="$(safe_name "$generator")"
  safe_target="$(safe_name "$target")"
  index_label="$(printf '%06d' "$index")"
  metadata_dir="$matrix_dir/not_applicable"
  metadata="$metadata_dir/${index_label}_${safe_generator}_${safe_target}.json"
  ensure_dir "$metadata_dir"
  if [[ "$generator" == "elfuzz" ]]; then
    python3 "$root/docker/common/elfuzz_target_pipeline.py" write-invalid --target "$target" --metadata-root "$root/metadata" --out "$metadata" >/dev/null
    status="not_applicable"
  else
    status="target_not_supported_by_elfuzz"
    {
      printf '{\n'
      printf '  "generator": "%s",\n' "$(json_escape "$generator")"
      printf '  "target": "%s",\n' "$(json_escape "$target")"
      printf '  "status": "target_not_supported_by_elfuzz",\n'
      printf '  "reason": "ELFuzz has no maintained native preset for this target; use ELFUZZ_TARGET_OVERRIDE, ELFUZZ_SUPPORTED_TARGETS, or ELFUZZ_TRUST_FUZZBENCH_TARGET=1 only when an upstream mapping is known",\n'
      printf '  "capability": "input_generator"\n'
      printf '}\n'
    } >"$metadata"
  fi
  printf '%s\t%s\t%s\t\t%s\t\n' "$generator" "$target" "$status" "$metadata" >>"$matrix_file"
}

record_preflight_failure() {
  local generator="$1" failure_code="$2" status="$3" target failure_log failure_metadata
  shift 3
  failure_log="$matrix_dir/$(safe_name "$generator")_preflight.log"
  failure_metadata="$matrix_dir/$(safe_name "$generator")_preflight_metadata.json"
  printf 'generator preflight failed: generator=%s exit_code=%s status=%s build_log=%s\n' "$generator" "$failure_code" "$status" "${HGB_LAST_IMAGE_BUILD_LOG:-}" >"$failure_log"
  {
    printf '{\n'
    printf '  "generator": "%s",\n' "$(json_escape "$generator")"
    printf '  "status": "%s",\n' "$(json_escape "$status")"
    printf '  "reason": "generator preflight failed before target preparation (exit %s)",\n' "$(json_escape "$failure_code")"
    printf '  "build_log": "%s",\n' "$(json_escape "${HGB_LAST_IMAGE_BUILD_LOG:-}")"
    printf '  "preflight_log": "%s"\n' "$(json_escape "$failure_log")"
    printf '}\n'
  } >"$failure_metadata"
  for target in "$@"; do
    pair_index=$((pair_index + 1))
    printf '%s\t%s\t%s\t\t%s\t\n' "$generator" "$target" "$status" "$failure_metadata" >>"$matrix_file"
  done
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
active_parallel_worker="$parallel_worker"

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
  while [[ "$active_count" -ge "$active_parallel_worker" ]]; do
    wait_for_one
  done
}

wait_for_generator() {
  while [[ "$active_count" -gt 0 ]]; do
    wait_for_one
  done
}

pair_index=0
for generator in "${generator_list[@]}"; do
  eligible_targets=()
  for target in "${target_list[@]}"; do
    if generator_supports_target "$generator" "$target"; then
      eligible_targets+=("$target")
    else
      pair_index=$((pair_index + 1))
      record_not_applicable_target "$generator" "$target" "$pair_index"
    fi
  done

  if [[ "${#eligible_targets[@]}" -eq 0 ]]; then
    log "no eligible targets for $generator after capability filtering"
    continue
  fi

  if preflight_generator "$generator"; then
    :
  else
    preflight_code=$?
    preflight_status="generator_preflight_failed"
    if [[ "${HGB_LAST_IMAGE_BUILD_FAILURE:-}" == "docker_layerdb_collision" ]]; then
      preflight_status="generator_preflight_docker_layerdb_collision"
    fi
    log "generator preflight failed for $generator (exit $preflight_code)"
    record_preflight_failure "$generator" "$preflight_code" "$preflight_status" "${eligible_targets[@]}"
    if [[ "$continue_on_error" != "1" ]]; then
      python3 "$SCRIPT_DIR/hgb_collect_matrix.py" "$matrix_dir"
      exit "$preflight_code"
    fi
    continue
  fi
  prepare_shared_target_packages "${eligible_targets[@]}"
  active_count=0
  generator_failed=0
  first_failure_code=0
  active_parallel_worker="$parallel_worker"
  if [[ "$generator" == "elfuzz" && "$active_parallel_worker" -gt 1 ]]; then
    active_parallel_worker=1
    log "serializing ELFuzz targets: its upstream TGI server uses the global container name tgi-server"
  fi
  generator_row_files=()

  for target in "${eligible_targets[@]}"; do
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
if [[ "$strict" == "1" ]]; then
  strict_violation=0
  while IFS=$'\t' read -r g t status ws metadata summary; do
    case "$status" in
      evaluated|not_applicable|dry_run_ok|completed|target_not_supported_by_elfuzz|generator_preflight_failed|generator_preflight_docker_layerdb_collision) ;;
      *) strict_violation=1; printf 'Matrix strict violation: generator=%s target=%s status=%s\n' "$g" "$t" "$status" >&2 ;;
    esac
  done < <(tail -n +2 "$matrix_file")
  if [[ "$strict_violation" == "1" ]]; then exit 1; fi
fi
printf '%s\n' "$matrix_dir"
