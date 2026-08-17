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
      --profile NAME         baseline profile (e.g. alpha, paper-faithful, reproduction-gamma)
      --protocol NAME        baseline protocol (e.g. blind-project, target-aware)
      --allow-input-generator
                             legacy compatibility flag for input-generation baselines
EOF
}

generator=""
target=""
target_package=""
run_id=""
timeout_seconds="${HGB_GENERATION_TIMEOUT_SECONDS:-10800}"
dry_run=0
allow_input_generator=0
target_layout="compact"
save_mode="compact"
strict=0
force=0
profile=""
protocol=""

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
    --strict)
      strict=1
      shift
      ;;
    --force)
      force=1
      shift
      ;;
    --profile)
      profile="${2:-}"
      shift 2
      ;;
    --protocol)
      protocol="${2:-}"
      shift 2
      ;;
    --allow-input-generator|--allow-input-generators)
      printf 'WARNING: --allow-input-generator is a deprecated no-op; input-generator baselines run from metadata/baseline_contracts.yaml.\n' >&2
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
# Unknown profile is rejected with exit code 2 (epsilon plan E0.4). An empty
# profile is allowed here; the generator default is applied by the host runner
# or the container entrypoint.
if [[ -n "$profile" ]] && ! hgb_known_profile "$profile"; then
  die_profile "unknown profile: $profile (expected alpha, paper-faithful, reproduction-gamma, reproduction-delta, reproduction-epsilon, reproduction-zeta, reproduction-eta, reproduction-theta, or compat-smoke)"
fi
[[ "$timeout_seconds" =~ ^[0-9]+$ ]] || die "--timeout must be an integer"
[[ "$target_layout" == "compact" || "$target_layout" == "full" ]] || die "--layout must be compact or full"
[[ "$save_mode" == "compact" || "$save_mode" == "debug" ]] || die "--save-mode must be compact or debug"

root="$(repo_root)"
load_hgb_config

# Host-side ELFuzz classification gate: contractually Invalid (non-text) targets
# are resolved from the committed manifest before artifact checkout, Docker
# build, TGI, or model access. They write a not_applicable/Invalid result and
# exit 0 so matrix execution may continue.
if [[ "$generator" == "elfuzz" ]]; then
  elfuzz_cls="$(python3 "$root/docker/common/elfuzz_target_pipeline.py" classify --target "$target" --metadata-root "$root/metadata" 2>/dev/null || true)"
  elfuzz_applicability="$(printf '%s' "$elfuzz_cls" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("applicability",""))' 2>/dev/null || true)"
  if [[ "$elfuzz_applicability" == "Invalid" ]]; then
    run_id="${run_id:-$(make_timestamp)}"
    workspace="$(workspace_generator_target_run_dir "$generator" "$target" "$run_id" "$root")"
    ensure_dir "$workspace/logs"
    python3 "$root/docker/common/elfuzz_target_pipeline.py" write-invalid --target "$target" --metadata-root "$root/metadata" --out "$workspace/result.json" >/dev/null
    cp "$workspace/result.json" "$workspace/metadata.json"
    printf 'Invalid: ELFuzz supports text-input targets only\n' >&2
    printf '%s\n' "$workspace"
    exit 0
  fi
fi

artifact_name="$(generator_artifact_name "$generator")"
artifacts=(fuzzbench "$artifact_name")
ensure_artifacts_present "$root" "${artifacts[@]}"

run_id="${run_id:-$(make_timestamp)}"
# Export profile/protocol before target package preparation so
# hgb_targets.py package infers require_split for reproduction-delta blind
# harness generators (fail-closed split contract).
if [[ -n "$profile" ]]; then export HGB_BASELINE_PROFILE="$profile"; fi
if [[ -n "$protocol" ]]; then export HGB_BASELINE_PROTOCOL="$protocol"; fi
if [[ -z "$target_package" ]]; then
  prepare_args=(--target "$target" --run-id "$run_id" --layout "$target_layout")
  [[ "$force" == "1" ]] && prepare_args+=(--force)
  target_package="$(bash "$SCRIPT_DIR/hgb_prepare_target.sh" "${prepare_args[@]}")"
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
elif [[ "$dry_run" != "1" && "$generator" == "oss-fuzz-gen" ]] && ! docker run --rm --entrypoint /bin/bash "$image" -lc 'test -f /opt/hgb/oss-fuzz/infra/helper.py && test -x /opt/hgb/bin/ofg_trim_benchmark.py && test -x /opt/hgb/oss-fuzz-venv/bin/python && /opt/hgb/venv/bin/python -c "import pkg_resources; import google.cloud.logging" && /opt/hgb/oss-fuzz-venv/bin/python -c "import pkg_resources; import yaml" && grep -Fq "_chat_completion_kwargs" /opt/hgb/artifacts/oss-fuzz-gen/llm_toolkit/models.py && grep -Fq "_copy_hgb_target_source" /opt/hgb/artifacts/oss-fuzz-gen/data_prep/project_src.py && grep -Fq "OFG_LOCAL_INTROSPECTOR_SHIM" /opt/hgb/bin/ofg_run_wrapper.py && grep -Fq "ofg_benchmark_trim_failed" /opt/hgb/entrypoint.sh && grep -Fq "OFG_OSS_FUZZ_VENV" /opt/hgb/entrypoint.sh && grep -Fq "OFG_LLM_MAX_RETRIES" /opt/hgb/artifacts/oss-fuzz-gen/llm_toolkit/models.py && grep -Fq "ofg_empty_llm_response" /opt/hgb/artifacts/oss-fuzz-gen/llm_toolkit/output_parser.py && grep -Fq "ofg_docker_pull_timeout" /opt/hgb/entrypoint.sh && test -f /opt/hgb/bin/ofg_api_rank.py && grep -Fq "OFG_SKIP_LOCAL_COVERAGE" /opt/hgb/bin/ofg_run_wrapper.py && grep -Fq "OFG_ALLOW_TEST_BENCHMARKS" /opt/hgb/entrypoint.sh && grep -Fq "OFG_BUILD_IMAGE_PULL" /opt/hgb/artifacts/oss-fuzz-gen/experiment/oss_fuzz_checkout.py && grep -Fq "OFG_NONINTERACTIVE_BUILD_IMAGE" /opt/hgb/artifacts/oss-fuzz-gen/experiment/oss_fuzz_checkout.py && grep -Fq "OFG_LOCAL_PROJECT_EXAMPLES" /opt/hgb/bin/ofg_run_wrapper.py && grep -Fq "ofg_oss_fuzz_helper_prompt_eof" /opt/hgb/entrypoint.sh && grep -Fq "ofg_coverage_artifact_missing" /opt/hgb/entrypoint.sh && grep -Fq "ofg_llm_rate_limited" /opt/hgb/entrypoint.sh && grep -Fq "OFG_MAX_ROUND" /opt/hgb/entrypoint.sh && grep -Fq "ofg_low_confidence_api_candidate" /opt/hgb/bin/ofg_trim_benchmark.py && grep -Fq "generic_runtime_or_io_api" /opt/hgb/bin/ofg_api_rank.py && grep -Fq "_shared_llm_request_slot" /opt/hgb/artifacts/oss-fuzz-gen/llm_toolkit/models.py && grep -Fq "ofg_function_not_referenced" /opt/hgb/artifacts/oss-fuzz-gen/agent/one_prompt_prototyper.py' >/dev/null 2>&1; then
  log "rebuilding stale OSS-Fuzz-Gen image without current OSS-Fuzz-Gen runtime, ranking, coverage, or Docker-pressure fixes: $image"
  image="$(hgb_build_image "$generator" "$artifact_name" "$root")"
elif [[ "$dry_run" != "1" && "$generator" == "ckgfuzzer" ]] && ! docker run --rm --entrypoint /bin/bash "$image" -lc "grep -Fq 'timeout=float(llm_config.get' /opt/hgb/artifacts/ckgfuzzer/fuzzing_llm_engine/models/get_model.py && grep -Fq 'max_retries=int(llm_config.get' /opt/hgb/artifacts/ckgfuzzer/fuzzing_llm_engine/models/get_model.py && grep -Fq 'CKGFUZZER_LLM_MAX_RETRIES' /opt/hgb/entrypoint.sh && grep -Fq 'HGB_API_SELECTION_MODE="\${HGB_API_SELECTION_MODE:-ranked}"' /opt/hgb/entrypoint.sh && grep -Fq -- '--selection-mode "\${HGB_API_SELECTION_MODE:-ranked}"' /opt/hgb/entrypoint.sh && grep -Fq 'embed_batch_size: \${CKGFUZZER_EMBEDDING_BATCH_SIZE:-100}' /opt/hgb/entrypoint.sh && test -f /opt/hgb/build-markers/ckgfuzzer_api_selection_ranked_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_entrypoint_python_init_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_ustc_embedding_runtime_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_embedding_model_name_override_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_local_embedding_theta3_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_embedding_batch_size_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_evaluator_compile_coverage_seed_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_codeql_cache_graph_counts_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_bloaty_staged_project_rescue_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_coverage_compile_cache_key_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_coverage_late_sanitizer_env_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_coverage_inline_compile_env_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_reachability_cpp_symbols_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_split_benchmark_context_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_candidate_language_normalization_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_cwe_index_cache_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_external_verifier_check_defer_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_legacy_fuzzer_lib_alias_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_cpp_fuzzer_entrypoint_abi_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_target_rescue_candidates_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_curl_single_target_sealed_deps_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_campaign_internal_timeout_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_primary_api_plan_filter_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_expanded_target_rescues_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_all_valuable_rescues_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_zero_candidate_rescue_override_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_function_like_api_plan_filter_v1 && test -f /opt/hgb/build-markers/ckgfuzzer_rescue_first_fast_path_v1" >/dev/null 2>&1; then
  log "rebuilding stale CKGFuzzer image without current LLM timeout/retry, API selection, entrypoint Python, USTC embedding, embedding model-name, or local embedding, embedding batch-size, or evaluator compile/coverage seed, CodeQL cache graph-count, staged Bloaty rescue, coverage compile-cache-key, late sanitizer ENV, inline compile-env, C++ reachability-symbol, split benchmark-context, candidate language-normalization, or CWE index-cache, external verifier check-defer, legacy FUZZER_LIB alias, C++ fuzzer-entrypoint ABI, or target rescue-candidate, curl single-target sealed-dependency, campaign internal-timeout, primary API-plan filter, expanded target-rescue, all valuable rescue, zero-candidate rescue override, function-like API-plan filter, or rescue-first fast-path wiring: $image"
  image="$(hgb_build_image "$generator" "$artifact_name" "$root")"
elif [[ "$dry_run" != "1" && "$generator" == "promefuzz" ]] && ! docker run --rm --entrypoint /bin/bash "$image" -lc "test -f /opt/hgb/bin/promefuzz_target_build.sh && test -f /opt/hgb/bin/promefuzz_profile.py && test -f /opt/hgb/bin/promefuzz_build_context.py && test -f /opt/hgb/bin/promefuzz_evaluator.py && test -f /opt/hgb/bin/ofg_evaluator.py && command -v wget >/dev/null && command -v autoreconf >/dev/null && command -v nasm >/dev/null && command -v tclsh >/dev/null && test -x /usr/local/bin/python3.8 && test -f /usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.ubsan_standalone-x86_64.a && dpkg-query -W -f='\${db:Status-Status}' zlib1g-dev 2>/dev/null | grep -qx installed && grep -Fq 'fuzzbench_target_build_available' /opt/hgb/entrypoint.sh && grep -Fq 'promefuzz_build_context.py' /opt/hgb/entrypoint.sh && grep -Fq 'promefuzz_evaluator.py' /opt/hgb/entrypoint.sh && grep -Fq 'promefuzz_profile.py validate' /opt/hgb/entrypoint.sh" >/dev/null 2>&1; then
  log "rebuilding stale PromeFuzz image without current target-build validation: $image"
  image="$(hgb_build_image "$generator" "$artifact_name" "$root")"
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
if [[ -n "$profile" ]]; then export HGB_BASELINE_PROFILE="$profile"; fi
if [[ -n "$protocol" ]]; then export HGB_BASELINE_PROTOCOL="$protocol"; fi
export HGB_LLM_REQUEST_TIMEOUT_SECONDS="${HGB_LLM_REQUEST_TIMEOUT_SECONDS:-900}"
export CKGFUZZER_LLM_REQUEST_TIMEOUT_SECONDS="${CKGFUZZER_LLM_REQUEST_TIMEOUT_SECONDS:-$HGB_LLM_REQUEST_TIMEOUT_SECONDS}"
export CKGFUZZER_LLM_MAX_RETRIES="${CKGFUZZER_LLM_MAX_RETRIES:-3}"
export OFG_LLM_REQUEST_TIMEOUT_SECONDS="${OFG_LLM_REQUEST_TIMEOUT_SECONDS:-$HGB_LLM_REQUEST_TIMEOUT_SECONDS}"
export OFG_LLM_MAX_RETRIES="${OFG_LLM_MAX_RETRIES:-0}"
export OFG_MAX_ROUND="${OFG_MAX_ROUND:-5}"
export OFG_MIN_BENCHMARK_SCORE="${OFG_MIN_BENCHMARK_SCORE:-1}"
export OFG_SYNTHESIZE_ON_BAD_BENCHMARK="${OFG_SYNTHESIZE_ON_BAD_BENCHMARK:-1}"
export HGB_LLM_PARALLELISM="${HGB_LLM_PARALLELISM:-4}"
export HGB_LLM_MIN_INTERVAL_SECONDS="${HGB_LLM_MIN_INTERVAL_SECONDS:-3}"
export HGB_LLM_RATE_LIMIT_MAX_SLEEP_SECONDS="${HGB_LLM_RATE_LIMIT_MAX_SLEEP_SECONDS:-180}"
if [[ "$generator" == "g2fuzz" || "$generator" == "elfuzz" ]]; then
  export HGB_ALLOW_INPUT_GENERATOR_TO_RUN=1
else
  export HGB_ALLOW_INPUT_GENERATOR_TO_RUN="$allow_input_generator"
fi
export HGB_SAVE_MODE="$save_mode"
export HGB_STRICT="$strict"
export HGB_CAMPAIGN_SECONDS="${HGB_CAMPAIGN_SECONDS:-300}"

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
