#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat >&2 <<'EOF'
Usage:
  bash scripts/hgb_generate_harness.sh --generator GENERATOR --target TARGET [options]

Options:
  -g, --generator NAME       oss-fuzz-gen, ckgfuzzer, promefuzz, elfuzz, or g2fuzz
  -t, --target NAME          enabled FuzzBench target name
      --target-package PATH  reuse an existing prepared target package
      --run-id ID            explicit run id
      --dry-run              validate and write metadata without expensive generation
      --layout compact|full  target package layout when preparing a package (default: compact)
      --save-mode compact|debug
                             compact removes duplicate transient outputs; debug preserves them
      --timeout SECONDS      generation timeout passed into the container
      --allow-input-generator
                             allow ELFuzz/G2FUZZ input-generation baselines to run
EOF
}

generator=""
target=""
target_package=""
run_id=""
timeout_seconds="${HGB_GENERATION_TIMEOUT_SECONDS:-900}"
dry_run=0
allow_input_generator=0
target_layout="compact"
save_mode="compact"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -g|--generator)
      generator="${2:-}"
      shift 2
      ;;
    -t|--target)
      target="${2:-}"
      shift 2
      ;;
    --target-package)
      target_package="${2:-}"
      shift 2
      ;;
    --run-id)
      run_id="${2:-}"
      shift 2
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    --layout|--target-layout)
      target_layout="${2:-}"
      shift 2
      ;;
    --save-mode)
      save_mode="${2:-}"
      shift 2
      ;;
    --timeout)
      timeout_seconds="${2:-}"
      shift 2
      ;;
    --allow-input-generator|--allow-input-generators)
      allow_input_generator=1
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

[[ -n "$generator" && -n "$target" ]] || { usage; exit 64; }
valid_hgb_generator "$generator" || die "unknown generator: $generator"
[[ "$timeout_seconds" =~ ^[0-9]+$ ]] || die "--timeout must be an integer"
[[ "$target_layout" == "compact" || "$target_layout" == "full" ]] || die "--layout must be compact or full"
[[ "$save_mode" == "compact" || "$save_mode" == "debug" ]] || die "--save-mode must be compact or debug"

root="$(repo_root)"
load_hgb_config

artifact_name="$(generator_artifact_name "$generator")"
artifacts=(fuzzbench "$artifact_name")
if [[ "$generator" == "g2fuzz" ]]; then
  artifacts+=(g2fuzz-data)
fi
ensure_artifacts_present "$root" "${artifacts[@]}"

run_id="${run_id:-$(make_timestamp)}"
if [[ -z "$target_package" ]]; then
  target_package="$(bash "$SCRIPT_DIR/hgb_prepare_target.sh" --target "$target" --run-id "$run_id" --layout "$target_layout")"
fi
target_package="$(cd "$target_package" && pwd)"
manifest="$target_package/target_manifest.json"
[[ -f "$manifest" ]] || die "missing target manifest: $manifest"
project="$(extract_json_string project "$manifest")"
fuzz_target="$(extract_json_string fuzz_target "$manifest")"
[[ -n "$project" ]] || die "target manifest has empty project: $manifest"
[[ -n "$fuzz_target" ]] || die "target manifest has empty fuzz_target: $manifest"

workspace="$(workspace_generator_target_run_dir "$generator" "$target" "$run_id" "$root")"
ensure_dir "$workspace/logs"

image="$(hgb_image_name "$generator" "$artifact_name" "$root")"
if ! docker image inspect "$image" >/dev/null 2>&1; then
  if [[ "$dry_run" == "1" ]]; then
    image="${HGB_DRY_RUN_SHIM_IMAGE:-ubuntu:24.04}"
    log "Docker image for $generator is missing; using $image dry-run shim with mounted HGB entrypoint"
  else
    image="$(hgb_build_image "$generator" "$artifact_name" "$root")"
  fi
fi

{
  printf 'generator=%s\n' "$generator"
  printf 'target=%s\n' "$target"
  printf 'target_package=%s\n' "$target_package"
  printf 'workspace=%s\n' "$workspace"
  printf 'image=%s\n' "$image"
  printf 'target_layout=%s\n' "$target_layout"
  printf 'save_mode=%s\n' "$save_mode"
} >"$workspace/host_command.txt"

export HGB_DRY_RUN="$dry_run"
export HGB_GENERATION_TIMEOUT_SECONDS="$timeout_seconds"
export HGB_ALLOW_INPUT_GENERATOR_TO_RUN="$allow_input_generator"
export HGB_SAVE_MODE="$save_mode"

code=0
run_hgb_target_container "$image" "$workspace" "$generator" "$target" "$target_package" "$project" "$fuzz_target" || code=$?
if [[ "$code" -eq 64 && ! -f "$workspace/metadata.json" ]]; then
  log "Docker image $image does not support generate-target yet; rebuilding and retrying once"
  image="$(hgb_build_image "$generator" "$artifact_name" "$root")"
  code=0
  run_hgb_target_container "$image" "$workspace" "$generator" "$target" "$target_package" "$project" "$fuzz_target" || code=$?
fi
status="$(extract_json_string status "$workspace/metadata.json")"
case "$status" in
  not_harness_generator|needs_ofg_benchmark_yaml|no_api_candidates|missing_codeql|upstream_cli_not_found|needs_compile_commands|target_not_supported_by_elfuzz|not_applicable|partial_completed|soft_skip|dry_run_ok)
    code=0
    ;;
esac

printf '%s\n' "$workspace"
exit "$code"
