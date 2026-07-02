#!/usr/bin/env bash
set -euo pipefail

repo_root() {
  git rev-parse --show-toplevel
}

hgb_root() {
  repo_root
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

require_cmd() {
  local cmd="${1:-}"
  [[ -n "$cmd" ]] || die "require_cmd needs a command name"
  command -v "$cmd" >/dev/null 2>&1 || die "Required command not found: $cmd"
}

require_docker() {
  require_cmd docker
  docker info >/dev/null 2>&1 || die "Docker is installed but not reachable by this user"
}

make_timestamp() {
  date -u +'%Y%m%dT%H%M%SZ'
}

ensure_dir() {
  local dir="${1:-}"
  [[ -n "$dir" ]] || die "ensure_dir needs a directory path"
  mkdir -p "$dir"
}

json_escape() {
  local value="${1:-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "$value"
}

hgb_artifacts_dir() {
  local root="${1:-$(hgb_root)}"
  printf '%s/%s\n' "$root" "${HGB_ARTIFACTS_DIR:-artifacts}"
}

hgb_workspace_dir() {
  local root="${1:-$(hgb_root)}"
  printf '%s/%s\n' "$root" "${HGB_WORKSPACE_DIR:-workspace}"
}

artifact_dir() {
  local name="$1"
  local root="${2:-$(repo_root)}"
  printf '%s/%s\n' "$(hgb_artifacts_dir "$root")" "$name"
}

workspace_run_dir() {
  local fuzzer="$1"
  local timestamp="${2:-$(make_timestamp)}"
  local root="${3:-$(repo_root)}"
  printf '%s/%s/%s\n' "$(hgb_workspace_dir "$root")" "$fuzzer" "$timestamp"
}


valid_hgb_generator() {
  case "${1:-}" in
    oss-fuzz-gen|ckgfuzzer|promefuzz|elfuzz|g2fuzz) return 0 ;;
    *) return 1 ;;
  esac
}

generator_artifact_name() {
  case "${1:-}" in
    oss-fuzz-gen) printf 'oss-fuzz-gen\n' ;;
    ckgfuzzer) printf 'ckgfuzzer\n' ;;
    promefuzz) printf 'promefuzz\n' ;;
    elfuzz) printf 'elfuzz\n' ;;
    g2fuzz) printf 'g2fuzz\n' ;;
    *) die "unknown generator: ${1:-}" ;;
  esac
}

workspace_generator_target_run_dir() {
  local generator="$1"
  local target="$2"
  local timestamp="${3:-$(make_timestamp)}"
  local root="${4:-$(repo_root)}"
  printf '%s/%s/%s/%s\n' "$(hgb_workspace_dir "$root")" "$generator" "$target" "$timestamp"
}

latest_workspace_run() {
  local fuzzer="$1"
  local root="${2:-$(repo_root)}"
  local base latest
  base="$(hgb_workspace_dir "$root")/$fuzzer"
  latest="$(find "$base" -mindepth 1 -maxdepth 1 -type d ! -name 'build_*' ! -name 'shell_*' 2>/dev/null | sort | tail -n 1 || true)"
  if [[ -z "$latest" ]]; then
    latest="$(find "$base" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1 || true)"
  fi
  printf '%s\n' "$latest"
}

load_hgb_config() {
  local root config legacy_env
  root="$(repo_root)"
  config="$root/configs/set_api_key.sh"
  legacy_env="$root/.env"

  if [[ -f "$config" ]]; then
    # shellcheck disable=SC1090
    source "$config"
  else
    printf 'WARNING: %s is missing. LLM-backed reproduction may fail. Copy configs/set_api_key.example.sh first.\n' "$config" >&2
    if [[ -f "$legacy_env" ]]; then
      printf 'WARNING: loading legacy .env for compatibility; prefer configs/set_api_key.sh.\n' >&2
      set -a
      # shellcheck disable=SC1090
      source "$legacy_env"
      set +a
    fi
  fi

  if [[ -n "${API_KEY:-}" ]]; then
    export OPENAI_API_KEY="${OPENAI_API_KEY:-$API_KEY}"
  fi
  if [[ -n "${BASE_URL:-}" ]]; then
    export OPENAI_BASE_URL="${OPENAI_BASE_URL:-$BASE_URL}"
  fi
  if [[ -n "${MODEL:-}" ]]; then
    export OPENAI_MODEL="${OPENAI_MODEL:-$MODEL}"
  fi
}

load_env() {
  load_hgb_config
}

count_files() {
  local dir="$1"
  shift || true
  if [[ ! -d "$dir" ]]; then
    printf '0\n'
    return 0
  fi
  find "$dir" "$@" 2>/dev/null | wc -l | tr -d ' '
}

list_files() {
  local dir="$1"
  shift || true
  if [[ ! -d "$dir" ]]; then
    return 0
  fi
  find "$dir" "$@" 2>/dev/null
}

safe_grep_count() {
  local pattern="$1"
  local dir="$2"
  shift 2 || true
  if [[ ! -d "$dir" ]]; then
    printf '0\n'
    return 0
  fi
  grep -RciE "$pattern" "$dir" "$@" 2>/dev/null | awk -F: '{s += $2} END {print s + 0}'
}

extract_json_string() {
  local key="$1"
  local file="$2"
  [[ -f "$file" ]] || return 0
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$file" | head -n 1
}

extract_json_number() {
  local key="$1"
  local file="$2"
  [[ -f "$file" ]] || return 0
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" "$file" | head -n 1
}

artifact_commit() {
  local path="$1"
  git -C "$path" rev-parse HEAD 2>/dev/null || printf 'unknown'
}

artifact_short_commit() {
  local path="$1"
  git -C "$path" rev-parse --short=12 HEAD 2>/dev/null || printf 'unknown'
}

ensure_artifacts_present() {
  local root="$1"
  shift
  local name path missing=0
  for name in "$@"; do
    path="$(artifact_dir "$name" "$root")"
    if [[ ! -d "$path/.git" ]]; then
      missing=1
      break
    fi
  done
  if [[ "$missing" -eq 1 ]]; then
    log "Artifact checkout missing; running scripts/clone_artifacts.sh"
    bash "$root/scripts/clone_artifacts.sh"
  fi
}

hgb_image_name() {
  local fuzzer="$1"
  local artifact_name="$2"
  local root="${3:-$(repo_root)}"
  local path short
  path="$(artifact_dir "$artifact_name" "$root")"
  short="$(artifact_short_commit "$path")"
  printf 'hgb-%s:%s\n' "$fuzzer" "$short"
}

hgb_build_image() {
  local fuzzer="$1"
  local artifact_name="$2"
  local root="${3:-$(repo_root)}"
  local image latest dockerfile log_file out_dir code image_id
  local build_args=()
  image="$(hgb_image_name "$fuzzer" "$artifact_name" "$root")"
  latest="hgb-$fuzzer:latest"
  dockerfile="$root/docker/$fuzzer/Dockerfile"
  out_dir="$(hgb_workspace_dir "$root")/$fuzzer/build_$(make_timestamp)"
  ensure_dir "$out_dir/logs"
  log_file="$out_dir/logs/docker_build.log"
  require_docker
  [[ -f "$dockerfile" ]] || die "Missing Dockerfile: $dockerfile"
  if [[ "$fuzzer" == "oss-fuzz-gen" ]]; then
    build_args+=(--build-arg "OFG_INSTALL_OSS_FUZZ=${OFG_INSTALL_OSS_FUZZ:-1}")
    if [[ -n "${OFG_OSS_FUZZ_REPO:-}" ]]; then
      build_args+=(--build-arg "OFG_OSS_FUZZ_REPO=${OFG_OSS_FUZZ_REPO}")
    fi
    if [[ -n "${OFG_OSS_FUZZ_REF:-}" ]]; then
      build_args+=(--build-arg "OFG_OSS_FUZZ_REF=${OFG_OSS_FUZZ_REF}")
    fi
  fi
  if [[ "$fuzzer" == "ckgfuzzer" ]]; then
    build_args+=(--build-arg "HGB_INSTALL_CODEQL=${HGB_INSTALL_CODEQL:-1}")
    if [[ -n "${CODEQL_BUNDLE_URL:-}" ]]; then
      build_args+=(--build-arg "CODEQL_BUNDLE_URL=${CODEQL_BUNDLE_URL}")
    fi
  fi
  code=0
  docker build "${build_args[@]}" -f "$dockerfile" -t "$image" -t "$latest" "$root" >"$log_file" 2>&1 || code=$?
  image_id="$(docker image inspect -f '{{.Id}}' "$image" 2>/dev/null || true)"
  {
    printf '{\n'
    printf '  "fuzzer": "%s",\n' "$(json_escape "$fuzzer")"
    printf '  "image": "%s",\n' "$(json_escape "$image")"
    printf '  "latest_tag": "%s",\n' "$(json_escape "$latest")"
    printf '  "image_id": "%s",\n' "$(json_escape "$image_id")"
    printf '  "artifact_commit": "%s",\n' "$(json_escape "$(artifact_commit "$(artifact_dir "$artifact_name" "$root")")")"
    printf '  "build_exit_code": %s,\n' "$code"
    printf '  "log_file": "%s"\n' "$(json_escape "$log_file")"
    printf '}\n'
  } >"$out_dir/metadata.json"
  if [[ "$code" -ne 0 ]]; then
    die "Docker build failed for $image. Inspect $log_file"
  fi
  printf '%s\n' "$image"
}

run_hgb_container() {
  local image="$1"
  local workspace="$2"
  local mode="$3"
  shift 3
  ensure_dir "$workspace"
  docker run --rm --init \
    -e API_KEY \
    -e BASE_URL \
    -e MODEL \
    -e OPENAI_API_KEY \
    -e OPENAI_BASE_URL \
    -e OPENAI_MODEL \
    -e OFG_OSS_FUZZ_DIR \
    -e OFG_ALLOW_RUNTIME_CLONE \
    -e OFG_OSS_FUZZ_REPO \
    -e HF_TOKEN \
    -e ELFUZZ_TARGET_OVERRIDE \
    -e ELFUZZ_TRUST_FUZZBENCH_TARGET \
    -e ELFUZZ_SUPPORTED_TARGETS \
    -e ELFUZZ_TGI_WAITING_SECONDS \
    -e ELFUZZ_EVOLUTION_ITERATIONS \
    -e ELFUZZ_PRODUCE_SECONDS \
    -e ELFUZZ_AFL_SECONDS \
    -e ELFUZZ_STAGE_TIMEOUT_SECONDS \
    -e ELFUZZ_HELP_ONLY \
    -e ELFUZZ_SKIP_DOWNLOAD \
    -e ELFUZZ_REQUIRE_HF_TOKEN \
    -e ELFUZZ_LOCAL_MODEL_CACHE_READY \
    -e CKGFUZZER_EMBEDDING_MODEL \
    -e CKGFUZZER_EMBEDDING_BASE_URL \
    -e CKGFUZZER_EMBEDDING_API_KEY \
    -e CKGFUZZER_LOCAL_API_COMBINATION \
    -e CKGFUZZER_MAX_COMBINATION_SIZE \
    -e CKGFUZZER_MAX_PLANNER_APIS \
    -e CKGFUZZER_MAX_SUMMARY_APIS \
    -e CKGFUZZER_MAX_CALL_GRAPH_APIS \
    -e CKGFUZZER_LOCAL_API_SUMMARY \
    -e CKGFUZZER_GEN_INPUT \
    -e PROME_FUZZ_EMBEDDING_LLM_TYPE \
    -e PROME_FUZZ_EMBEDDING_HOST \
    -e PROME_FUZZ_EMBEDDING_PORT \
    -e PROME_FUZZ_EMBEDDING_BASE_URL \
    -e PROME_FUZZ_EMBEDDING_API_KEY \
    -e PROME_FUZZ_EMBEDDING_MODEL \
    -e PROME_FUZZ_EMBEDDING_MAX_TOKENS \
    -e PROME_FUZZ_EMBEDDING_TIMEOUT \
    -e PROME_FUZZ_EMBEDDING_RETRY_TIMES \
    -e PROME_FUZZ_MAX_APIS \
    -e PROME_FUZZ_COMPREHEND_TASK \
    -e G2FUZZ_MAX_FORMATS \
    -e G2FUZZ_TRY_NUM \
    -e G2FUZZ_PER_FORMAT_TIMEOUT_SECONDS \
    -e G2FUZZ_MAX_PRESEEDED_CORPUS_FILES \
    -e PROME_FUZZ_SKIP_BAD_DOCS \
    -e PROME_FUZZ_MAX_DOC_BYTES \
    -e HGB_RUN_ID="$(basename "$workspace")" \
    -e HGB_HOST_UID="$(id -u)" \
    -e HGB_HOST_GID="$(id -g)" \
    -v "$workspace:/workspace" \
    "$@" \
    "$image" "$mode"
}

run_hgb_target_container() {
  local image="$1"
  local workspace="$2"
  local generator="$3"
  local target="$4"
  local target_package="$5"
  local project="$6"
  local fuzz_target="$7"
  local root artifact_name generator_commit
  local extra_docker_args=()
  shift 7
  root="$(repo_root)"
  artifact_name="$(generator_artifact_name "$generator")"
  generator_commit="$(artifact_commit "$(artifact_dir "$artifact_name" "$root")")"
  ensure_dir "$workspace"
  if [[ "$generator" != "promefuzz" && "$generator" != "ckgfuzzer" ]]; then
    extra_docker_args+=(-v "$root/artifacts:/opt/hgb/artifacts:ro")
  fi
  if [[ -n "${HGB_CODEQL_DIR:-}" ]]; then
    extra_docker_args+=(-v "${HGB_CODEQL_DIR}:/opt/hgb/codeql-host:ro" -e HGB_CODEQL_DIR=/opt/hgb/codeql-host)
  fi
  if [[ "$generator" == "ckgfuzzer" ]]; then
    ensure_dir "$workspace/docker_shared"
    extra_docker_args+=(-v "$workspace/docker_shared:$workspace/docker_shared" -e "HGB_CKG_DOCKER_SHARED=$workspace/docker_shared" -e "CKGFUZZER_MAX_CALL_GRAPH_APIS=${CKGFUZZER_MAX_CALL_GRAPH_APIS:-8}")
    if [[ -S /var/run/docker.sock ]]; then
      extra_docker_args+=(-v /var/run/docker.sock:/var/run/docker.sock)
    fi
  fi
  if [[ "$generator" == "elfuzz" && -S /var/run/docker.sock ]]; then
    extra_docker_args+=(-v /var/run/docker.sock:/var/run/docker.sock)
  fi
  docker run --rm --init \
    --entrypoint /opt/hgb/entrypoint.sh \
    -e API_KEY \
    -e BASE_URL \
    -e MODEL \
    -e OPENAI_API_KEY \
    -e OPENAI_BASE_URL \
    -e OPENAI_MODEL \
    -e OFG_OSS_FUZZ_DIR \
    -e OFG_ALLOW_RUNTIME_CLONE \
    -e OFG_OSS_FUZZ_REPO \
    -e HF_TOKEN \
    -e ELFUZZ_TARGET_OVERRIDE \
    -e ELFUZZ_TRUST_FUZZBENCH_TARGET \
    -e ELFUZZ_SUPPORTED_TARGETS \
    -e ELFUZZ_TGI_WAITING_SECONDS \
    -e ELFUZZ_EVOLUTION_ITERATIONS \
    -e ELFUZZ_PRODUCE_SECONDS \
    -e ELFUZZ_AFL_SECONDS \
    -e ELFUZZ_STAGE_TIMEOUT_SECONDS \
    -e ELFUZZ_HELP_ONLY \
    -e ELFUZZ_SKIP_DOWNLOAD \
    -e ELFUZZ_REQUIRE_HF_TOKEN \
    -e ELFUZZ_LOCAL_MODEL_CACHE_READY \
    -e CKGFUZZER_EMBEDDING_MODEL \
    -e CKGFUZZER_EMBEDDING_BASE_URL \
    -e CKGFUZZER_EMBEDDING_API_KEY \
    -e CKGFUZZER_LOCAL_API_COMBINATION \
    -e CKGFUZZER_MAX_COMBINATION_SIZE \
    -e CKGFUZZER_MAX_PLANNER_APIS \
    -e CKGFUZZER_MAX_SUMMARY_APIS \
    -e CKGFUZZER_MAX_CALL_GRAPH_APIS \
    -e CKGFUZZER_LOCAL_API_SUMMARY \
    -e CKGFUZZER_GEN_INPUT \
    -e PROME_FUZZ_EMBEDDING_LLM_TYPE \
    -e PROME_FUZZ_EMBEDDING_HOST \
    -e PROME_FUZZ_EMBEDDING_PORT \
    -e PROME_FUZZ_EMBEDDING_BASE_URL \
    -e PROME_FUZZ_EMBEDDING_API_KEY \
    -e PROME_FUZZ_EMBEDDING_MODEL \
    -e PROME_FUZZ_EMBEDDING_MAX_TOKENS \
    -e PROME_FUZZ_EMBEDDING_TIMEOUT \
    -e PROME_FUZZ_EMBEDDING_RETRY_TIMES \
    -e PROME_FUZZ_MAX_APIS \
    -e PROME_FUZZ_COMPREHEND_TASK \
    -e G2FUZZ_MAX_FORMATS \
    -e G2FUZZ_TRY_NUM \
    -e G2FUZZ_PER_FORMAT_TIMEOUT_SECONDS \
    -e G2FUZZ_MAX_PRESEEDED_CORPUS_FILES \
    -e PROME_FUZZ_SKIP_BAD_DOCS \
    -e PROME_FUZZ_MAX_DOC_BYTES \
    -e HGB_RUN_ID="$(basename "$workspace")" \
    -e HGB_GENERATOR="$generator" \
    -e HGB_GENERATOR_COMMIT="$generator_commit" \
    -e HGB_TARGET="$target" \
    -e HGB_TARGET_PACKAGE=/target \
    -e HGB_TARGET_PACKAGE_HOST="$target_package" \
    -e HGB_TARGET_MANIFEST=/target/target_manifest.json \
    -e HGB_TARGET_SOURCE_DIR=/target/source_input \
    -e HGB_TARGET_REFERENCE_DIR=/target/reference_harnesses \
    -e HGB_TARGET_PROJECT="$project" \
    -e HGB_TARGET_FUZZ_TARGET="$fuzz_target" \
    -e HGB_DRY_RUN="${HGB_DRY_RUN:-0}" \
    -e HGB_GENERATION_TIMEOUT_SECONDS="${HGB_GENERATION_TIMEOUT_SECONDS:-900}" \
    -e HGB_ALLOW_INPUT_GENERATOR_TO_RUN="${HGB_ALLOW_INPUT_GENERATOR_TO_RUN:-0}" \
    -e HGB_SAVE_MODE="${HGB_SAVE_MODE:-compact}" \
    -e HGB_HOST_UID="$(id -u)" \
    -e HGB_HOST_GID="$(id -g)" \
    -v "$workspace:/workspace" \
    -v "$target_package:/target:ro" \
    -v "$root/docker/$generator/entrypoint.sh:/opt/hgb/entrypoint.sh:ro" \
    -v "$root/docker/common:/opt/hgb/bin:ro" \
    -v "$root/metadata:/opt/hgb/metadata:ro" \
    "${extra_docker_args[@]}" \
    "$@" \
    "$image" generate-target
}
