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

read_env_file() {
  local file="$1"
  [[ -f "$file" ]] || return 1
  # shellcheck disable=SC1090
  source "$file"
}

copy_if_exists() {
  local src="$1"
  local dst="$2"
  if [[ -e "$src" ]]; then
    mkdir -p "$(dirname "$dst")"
    cp -a "$src" "$dst"
  fi
}

stage_code() {
  local run_dir="$1"
  local stage="$2"
  local exit_file="$run_dir/logs/$stage.exit"
  if [[ -f "$exit_file" ]]; then
    cat "$exit_file"
  else
    printf 'not_run'
  fi
}

write_metadata() {
  local metadata_file="$1"
  local upstream_dir="$2"
  local config_file="$3"
  local image_name="$4"
  local use_docker="$5"
  local start_time="$6"
  local end_time="$7"
  local commit="unknown"
  local target_commit="unknown"
  local stages=(fetch build_normal build_asan preprocess comprehend generate synthesize build_driver run_driver stats)
  local stage

  if [[ -d "$upstream_dir/.git" ]]; then
    commit="$(git -C "$upstream_dir" rev-parse HEAD 2>/dev/null || printf 'unknown')"
  fi
  if [[ -d "$upstream_dir/database/pugixml/latest/code/.git" ]]; then
    target_commit="$(git -c safe.directory="$upstream_dir/database/pugixml/latest/code" -C "$upstream_dir/database/pugixml/latest/code" rev-parse HEAD 2>/dev/null || printf 'unknown')"
  fi

  {
    printf '{\n'
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$commit")"
    printf '  "target": "pugixml",\n'
    printf '  "target_commit": "%s",\n' "$(json_escape "$target_commit")"
    printf '  "config": "%s",\n' "$(json_escape "$config_file")"
    printf '  "image_name": "%s",\n' "$(json_escape "$image_name")"
    printf '  "use_docker": "%s",\n' "$(json_escape "$use_docker")"
    printf '  "pool_size": "%s",\n' "$(json_escape "${PROMEFUZZ_POOL_SIZE:-1}")"
    printf '  "fuzz_seconds": "%s",\n' "$(json_escape "${PROMEFUZZ_FUZZ_SECONDS:-60}")"
    printf '  "start_time": "%s",\n' "$(json_escape "$start_time")"
    printf '  "end_time": "%s",\n' "$(json_escape "$end_time")"
    printf '  "stages": {\n'
    for stage in "${stages[@]}"; do
      printf '    "%s": "%s"' "$stage" "$(json_escape "$(stage_code "$(dirname "$metadata_file")" "$stage")")"
      if [[ "$stage" != "stats" ]]; then
        printf ','
      fi
      printf '\n'
    done
    printf '  }\n'
    printf '}\n'
  } >"$metadata_file"
}

make_stage_script() {
  local run_dir="$1"
  local stage="$2"
  local body="$3"
  local script_file="$run_dir/commands/$stage.sh"
  {
    printf '#!/usr/bin/env bash\n'
    printf 'set -euo pipefail\n'
    printf ': "${PROMEFUZZ_WORKDIR:=/promefuzz}"\n'
    printf ': "${HGB_PROMEFUZZ_RUN_DIR:=/hgb-run}"\n'
    printf 'cd "$PROMEFUZZ_WORKDIR"\n'
    printf '%s\n' "$body"
  } >"$script_file"
  chmod +x "$script_file"
}

run_stage() {
  local run_dir="$1"
  local upstream_dir="$2"
  local image_name="$3"
  local use_docker="$4"
  local stage="$5"
  local body="$6"
  local code=0
  local timeout_seconds="${PROMEFUZZ_STAGE_TIMEOUT_SECONDS:-1800}"
  local log_file="$run_dir/logs/$stage.log"

  make_stage_script "$run_dir" "$stage" "$body"

  if [[ "$use_docker" == "1" ]]; then
    timeout "$timeout_seconds" docker run --rm \
      --shm-size="${PROMEFUZZ_SHM_SIZE:-16g}" \
      -e OPENAI_API_KEY \
      -e OPENAI_BASE_URL \
      -e PROMEFUZZ_POOL_SIZE \
      -e PROMEFUZZ_FUZZ_SECONDS \
      -e PROMEFUZZ_PUGIXML_COMMIT \
      -e PROMEFUZZ_SKIP_COMPREHEND \
      -e PROMEFUZZ_WORKDIR=/promefuzz \
      -e HGB_PROMEFUZZ_RUN_DIR=/hgb-run \
      -v "$upstream_dir:/promefuzz" \
      -v "$run_dir:/hgb-run" \
      -w /promefuzz \
      "$image_name" \
      bash "/hgb-run/commands/$stage.sh" >"$log_file" 2>&1 || code=$?
  else
    (
      export PROMEFUZZ_WORKDIR="$upstream_dir"
      export HGB_PROMEFUZZ_RUN_DIR="$run_dir"
      export PROMEFUZZ_POOL_SIZE PROMEFUZZ_FUZZ_SECONDS PROMEFUZZ_PUGIXML_COMMIT PROMEFUZZ_SKIP_COMPREHEND
      export OPENAI_API_KEY="${OPENAI_API_KEY:-}"
      export OPENAI_BASE_URL="${OPENAI_BASE_URL:-}"
      cd "$upstream_dir"
      bash "$run_dir/commands/$stage.sh"
    ) >"$log_file" 2>&1 || code=$?
  fi

  printf '%s\n' "$code" >"$run_dir/logs/$stage.exit"
  if [[ "$code" -ne 0 ]]; then
    log "PromeFuzz stage '$stage' exited with $code; continuing to capture later-stage evidence"
  fi
}

main() {
  local root upstream_dir selected_env config_file timestamp run_dir image_name use_docker
  local start_time end_time stage_failed artifact_dir
  local stages=(fetch build_normal build_asan preprocess comprehend generate synthesize build_driver run_driver stats)
  local stage

  root="$(repo_root)"
  load_env

  require_cmd git
  require_cmd timeout

  upstream_dir="$root/external/PromeFuzz"
  [[ -d "$upstream_dir/.git" ]] || die "Missing $upstream_dir. Run: make clone"

  selected_env="$root/${HGB_RESULTS_DIR:-results}/promefuzz/selected_config.env"
  if [[ ! -f "$selected_env" ]]; then
    log "No PromeFuzz config selection found; running scripts/promefuzz_setup_config.sh"
    bash "$SCRIPT_DIR/promefuzz_setup_config.sh"
  fi
  read_env_file "$selected_env" || die "Could not read $selected_env"
  config_file="${PROMEFUZZ_CONFIG:?missing PROMEFUZZ_CONFIG in selected_config.env}"
  [[ -f "$config_file" ]] || die "Generated config not found: $config_file"

  image_name="${PROMEFUZZ_DOCKER_IMAGE:-hgb-promefuzz:latest}"
  use_docker="${PROMEFUZZ_USE_DOCKER:-1}"
  [[ "$use_docker" == "0" || "$use_docker" == "1" ]] || die "PROMEFUZZ_USE_DOCKER must be 0 or 1"
  [[ "${PROMEFUZZ_POOL_SIZE:-1}" =~ ^[0-9]+$ ]] || die "PROMEFUZZ_POOL_SIZE must be an integer"
  [[ "${PROMEFUZZ_FUZZ_SECONDS:-60}" =~ ^[0-9]+$ ]] || die "PROMEFUZZ_FUZZ_SECONDS must be an integer"
  [[ "${PROMEFUZZ_STAGE_TIMEOUT_SECONDS:-1800}" =~ ^[0-9]+$ ]] || die "PROMEFUZZ_STAGE_TIMEOUT_SECONDS must be an integer"

  timestamp="$(make_timestamp)"
  run_dir="$root/${HGB_RESULTS_DIR:-results}/promefuzz/smoke_$timestamp"
  ensure_dir "$run_dir/logs"
  ensure_dir "$run_dir/commands"
  ensure_dir "$run_dir/artifacts"
  cp "$config_file" "$run_dir/config.toml"

  if [[ "$use_docker" == "1" ]]; then
    require_cmd docker
    if ! docker image inspect "$image_name" >/dev/null 2>&1; then
      printf 'Docker image not found: %s\nRun: bash scripts/promefuzz_build_docker.sh\n' "$image_name" >"$run_dir/logs/docker_image.log"
      printf '125\n' >"$run_dir/logs/docker_image.exit"
      start_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
      end_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
      write_metadata "$run_dir/metadata.json" "$upstream_dir" "$run_dir/config.toml" "$image_name" "$use_docker" "$start_time" "$end_time"
      die "Docker image $image_name is missing. Run directory: $run_dir"
    fi
  fi

  start_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  run_stage "$run_dir" "$upstream_dir" "$image_name" "$use_docker" fetch '
if [ -d database/pugixml/latest/code/.git ]; then
  echo "database/pugixml/latest/code already exists; skipping fetch."
else
  rm -rf database/pugixml/code database/pugixml/latest
  cd database/pugixml
  ./fetch.sh "${PROMEFUZZ_PUGIXML_COMMIT:-}"
fi
'

  run_stage "$run_dir" "$upstream_dir" "$image_name" "$use_docker" build_normal '
test -d database/pugixml/latest/code
cd database/pugixml/latest
./build.sh normal
'

  run_stage "$run_dir" "$upstream_dir" "$image_name" "$use_docker" build_asan '
test -d database/pugixml/latest/code
cd database/pugixml/latest
./build.sh asan
'

  run_stage "$run_dir" "$upstream_dir" "$image_name" "$use_docker" preprocess '
if [ ! -x build/bin/preprocessor ] || [ ! -x build/bin/cgprocessor ]; then
  echo "PromeFuzz processor binaries missing in mounted workspace; running ./setup.sh."
  chmod +x ./setup.sh
  ./setup.sh
fi
./PromeFuzz.py --config "$HGB_PROMEFUZZ_RUN_DIR/config.toml" -F database/pugixml/latest/lib.toml preprocess --pool-size "${PROMEFUZZ_POOL_SIZE:-1}"
'

  run_stage "$run_dir" "$upstream_dir" "$image_name" "$use_docker" comprehend '
if [ "${PROMEFUZZ_SKIP_COMPREHEND:-0}" = "1" ]; then
  echo "PROMEFUZZ_SKIP_COMPREHEND=1; skipping comprehension."
  exit 0
fi
./PromeFuzz.py --config "$HGB_PROMEFUZZ_RUN_DIR/config.toml" -F database/pugixml/latest/lib.toml comprehend --pool-size "${PROMEFUZZ_POOL_SIZE:-1}"
'

  run_stage "$run_dir" "$upstream_dir" "$image_name" "$use_docker" generate '
./PromeFuzz.py --config "$HGB_PROMEFUZZ_RUN_DIR/config.toml" -F database/pugixml/latest/lib.toml generate --pool-size "${PROMEFUZZ_POOL_SIZE:-1}"
'

  run_stage "$run_dir" "$upstream_dir" "$image_name" "$use_docker" synthesize '
driver_dir="database/pugixml/latest/out/fuzz_driver"
test -d "$driver_dir"
cd "$driver_dir"
if [ ! -x ./synthesize_into_one ]; then
  echo "Missing executable synthesize_into_one in $PWD"
  find . -maxdepth 2 -type f | sort | head -80
  exit 2
fi
./synthesize_into_one
'

  run_stage "$run_dir" "$upstream_dir" "$image_name" "$use_docker" build_driver '
synth_dir="database/pugixml/latest/out/fuzz_driver/synthesized"
test -d "$synth_dir"
cd "$synth_dir"
if [ ! -x ./build_synthesized_driver.sh ]; then
  echo "Missing executable build_synthesized_driver.sh in $PWD"
  find . -maxdepth 2 -type f | sort | head -80
  exit 2
fi
./build_synthesized_driver.sh
'

  run_stage "$run_dir" "$upstream_dir" "$image_name" "$use_docker" run_driver '
synth_dir="database/pugixml/latest/out/fuzz_driver/synthesized"
test -d "$synth_dir"
cd "$synth_dir"
if [ ! -x ./synthesized_driver ]; then
  echo "Missing synthesized_driver in $PWD"
  find . -maxdepth 2 -type f | sort | head -80
  exit 2
fi
seed_dir="../../../in"
if [ ! -d "$seed_dir" ]; then
  seed_dir="../../../../in"
fi
if [ ! -d "$seed_dir" ]; then
  echo "No pugixml seed corpus found"
  exit 2
fi
timeout "${PROMEFUZZ_FUZZ_SECONDS:-60}" ./synthesized_driver -runs=100 "$seed_dir"
'

  run_stage "$run_dir" "$upstream_dir" "$image_name" "$use_docker" stats '
mkdir -p "$HGB_PROMEFUZZ_RUN_DIR/statistics"
./PromeFuzz.py --config "$HGB_PROMEFUZZ_RUN_DIR/config.toml" -F database/pugixml/latest/lib.toml stats -O "$HGB_PROMEFUZZ_RUN_DIR/statistics"
'

  artifact_dir="$run_dir/artifacts"
  copy_if_exists "$upstream_dir/database/pugixml/latest/out/fuzz_driver" "$artifact_dir/fuzz_driver"
  copy_if_exists "$upstream_dir/database/pugixml/latest/out/preprocessor/api.json" "$artifact_dir/api.json"
  copy_if_exists "$upstream_dir/database/pugixml/latest/out/comprehender/comp.json" "$artifact_dir/comp.json"
  copy_if_exists "$upstream_dir/database/pugixml/latest/out/generator/state.json" "$artifact_dir/state.json"

  end_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  write_metadata "$run_dir/metadata.json" "$upstream_dir" "$run_dir/config.toml" "$image_name" "$use_docker" "$start_time" "$end_time"

  bash "$SCRIPT_DIR/promefuzz_collect_report.sh" "$run_dir" >/dev/null

  stage_failed=0
  for stage in "${stages[@]}"; do
    if [[ "$(stage_code "$run_dir" "$stage")" != "0" ]]; then
      stage_failed=1
    fi
  done

  if [[ "$stage_failed" -ne 0 ]]; then
    printf 'PromeFuzz smoke recorded one or more stage failures. Run directory: %s\n' "$run_dir" >&2
    exit 1
  fi

  log "PromeFuzz smoke completed: $run_dir"
}

main "$@"
