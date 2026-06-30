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

container_running() {
  local name="$1"
  [[ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)" == "true" ]]
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
  local image="$2"
  local container="$3"
  local target="$4"
  local start_time="$5"
  local end_time="$6"
  local image_id repo_digests container_id
  local stages=(setup restart_after_setup download hf_config synth produce seed_cov afl copy_to_host)
  local stage

  image_id="$(docker image inspect -f '{{.Id}}' "$image" 2>/dev/null || true)"
  repo_digests="$(docker image inspect -f '{{join .RepoDigests ","}}' "$image" 2>/dev/null || true)"
  container_id="$(docker inspect -f '{{.Id}}' "$container" 2>/dev/null || true)"

  {
    printf '{\n'
    printf '  "image": "%s",\n' "$(json_escape "$image")"
    printf '  "image_id": "%s",\n' "$(json_escape "$image_id")"
    printf '  "repo_digests": "%s",\n' "$(json_escape "$repo_digests")"
    printf '  "container": "%s",\n' "$(json_escape "$container")"
    printf '  "container_id": "%s",\n' "$(json_escape "$container_id")"
    printf '  "target": "%s",\n' "$(json_escape "$target")"
    printf '  "evolution_iterations": "%s",\n' "$(json_escape "${ELFUZZ_EVOLUTION_ITERATIONS:-1}")"
    printf '  "produce_seconds": "%s",\n' "$(json_escape "${ELFUZZ_PRODUCE_SECONDS:-60}")"
    printf '  "afl_seconds": "%s",\n' "$(json_escape "${ELFUZZ_AFL_SECONDS:-300}")"
    printf '  "tgi_waiting_seconds": "%s",\n' "$(json_escape "${ELFUZZ_TGI_WAITING_SECONDS:-120}")"
    printf '  "start_time": "%s",\n' "$(json_escape "$start_time")"
    printf '  "end_time": "%s",\n' "$(json_escape "$end_time")"
    printf '  "stages": {\n'
    for stage in "${stages[@]}"; do
      printf '    "%s": "%s"' "$stage" "$(json_escape "$(stage_code "$(dirname "$metadata_file")" "$stage")")"
      if [[ "$stage" != "copy_to_host" ]]; then
        printf ','
      fi
      printf '\n'
    done
    printf '  }\n'
    printf '}\n'
  } >"$metadata_file"
}

run_stage() {
  local run_dir="$1"
  local container="$2"
  local stage="$3"
  local command_text="$4"
  local code=0
  local timeout_seconds="${ELFUZZ_STAGE_TIMEOUT_SECONDS:-7200}"
  local log_file="$run_dir/logs/$stage.log"

  printf '%s\n' "$command_text" >"$run_dir/commands/$stage.sh"
  {
    printf '\n===== %s =====\n' "$stage"
    printf 'Command: %s\n' "$command_text"
  } >>"$run_dir/run.log"

  timeout "$timeout_seconds" docker exec "$container" bash -lc "$command_text" >"$log_file" 2>&1 || code=$?
  printf '%s\n' "$code" >"$run_dir/logs/$stage.exit"
  sed 's/^/  /' "$log_file" >>"$run_dir/run.log" || true

  if [[ "$code" -ne 0 ]]; then
    log "ELFuzz stage '$stage' exited with $code; continuing to collect evidence"
  fi
}

run_secret_stage() {
  local run_dir="$1"
  local container="$2"
  local stage="$3"
  local code=0
  local timeout_seconds="${ELFUZZ_STAGE_TIMEOUT_SECONDS:-7200}"
  local log_file="$run_dir/logs/$stage.log"

  printf 'elfuzz config --set tgi.huggingface_token <redacted>\n' >"$run_dir/commands/$stage.sh"
  {
    printf '\n===== %s =====\n' "$stage"
    printf 'Command: elfuzz config --set tgi.huggingface_token <redacted>\n'
  } >>"$run_dir/run.log"

  timeout "$timeout_seconds" docker exec -e HF_TOKEN="$HF_TOKEN" "$container" bash -lc 'elfuzz config --set tgi.huggingface_token "$HF_TOKEN" >/dev/null 2>&1' >"$log_file" 2>&1 || code=$?
  printf '%s\n' "$code" >"$run_dir/logs/$stage.exit"
  printf '  Hugging Face token configuration exit code: %s\n' "$code" >>"$run_dir/run.log"

  if [[ "$code" -ne 0 ]]; then
    log "ELFuzz stage '$stage' exited with $code; continuing to collect evidence"
  fi
}

copy_summary_from_container() {
  local run_dir="$1"
  local container="$2"
  local target="$3"
  local code=0
  local command_text

  command_text='
set -euo pipefail
export ELFUZZ_TARGET="'"$target"'"
rm -rf /tmp/host/hgb-elfuzz-smoke
mkdir -p /tmp/host/hgb-elfuzz-smoke
cd /home/appuser/elmfuzz
for dir in analysis/rq1/results analysis/rq2/results analysis/rq3/results plot/fig plot/table evaluation/elmfuzzers evaluation/alt_elmfuzzers evaluation/nocomp_fuzzers evaluation/noinf_fuzzers evaluation/nospl_fuzzers extradata/produce_info; do
  if [ -d "$dir" ]; then
    find "$dir" -maxdepth 3 -type f \( -name "*.xlsx" -o -name "*.csv" -o -name "*.txt" -o -name "*.log" -o -name "*.tar.xz" -o -name "*.tar.zst" \) -size -50M -exec cp --parents {} /tmp/host/hgb-elfuzz-smoke/ \;
  fi
done
if [ -d "preset/$ELFUZZ_TARGET" ]; then
  find "preset/$ELFUZZ_TARGET" -path "*/seeds/*" -type f \( -name "*.py" -o -name "*.rs" -o -name "*.cc" -o -name "*.c" \) -size -5M -exec cp --parents {} /tmp/host/hgb-elfuzz-smoke/ \;
fi
find /tmp/host/hgb-elfuzz-smoke -type f | sort > /tmp/host/hgb-elfuzz-smoke/manifest.txt
'
  printf '%s\n' "$command_text" >"$run_dir/commands/copy_to_host.sh"
  docker exec "$container" bash -lc "$command_text" >"$run_dir/logs/copy_to_host.log" 2>&1 || code=$?
  printf '%s\n' "$code" >"$run_dir/logs/copy_to_host.exit"
  cp -a "$run_dir/../host-tmp/hgb-elfuzz-smoke" "$run_dir/artifacts" 2>/dev/null || true
}

main() {
  local root image container target timestamp run_dir start_time end_time stage_failed
  local stages=(setup restart_after_setup download hf_config synth produce seed_cov afl copy_to_host)
  local stage

  root="$(repo_root)"
  load_env
  require_cmd docker
  require_cmd timeout

  image="${ELFUZZ_IMAGE:-ghcr.io/osuseclab/elfuzz:25.08.0}"
  container="${ELFUZZ_CONTAINER:-elfuzz-hgb}"
  target="${ELFUZZ_TARGET:-jsoncpp}"
  [[ "${ELFUZZ_EVOLUTION_ITERATIONS:-1}" =~ ^[0-9]+$ ]] || die "ELFUZZ_EVOLUTION_ITERATIONS must be an integer"
  [[ "${ELFUZZ_PRODUCE_SECONDS:-60}" =~ ^[0-9]+$ ]] || die "ELFUZZ_PRODUCE_SECONDS must be an integer"
  [[ "${ELFUZZ_AFL_SECONDS:-300}" =~ ^[0-9]+$ ]] || die "ELFUZZ_AFL_SECONDS must be an integer"
  [[ "${ELFUZZ_STAGE_TIMEOUT_SECONDS:-7200}" =~ ^[0-9]+$ ]] || die "ELFUZZ_STAGE_TIMEOUT_SECONDS must be an integer"
  [[ "${ELFUZZ_TGI_WAITING_SECONDS:-120}" =~ ^[0-9]+$ ]] || die "ELFUZZ_TGI_WAITING_SECONDS must be an integer"

  if ! container_running "$container"; then
    log "ELFuzz container is not running; starting it first"
    bash "$SCRIPT_DIR/elfuzz_start_container.sh"
  fi
  container_running "$container" || die "ELFuzz container is not running: $container"

  timestamp="$(make_timestamp)"
  run_dir="$root/${HGB_RESULTS_DIR:-results}/elfuzz/smoke_$timestamp"
  ensure_dir "$run_dir/logs"
  ensure_dir "$run_dir/commands"
  ensure_dir "$run_dir/artifacts"
  : >"$run_dir/run.log"

  start_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  run_stage "$run_dir" "$container" setup 'sudo chown -R appuser /tmp/host/ || true; printf "y\n" | elfuzz setup'
  if [[ "$(stage_code "$run_dir" setup)" == "0" ]]; then
    docker restart "$container" >"$run_dir/logs/restart_after_setup.log" 2>&1 || printf '%s\n' "$?" >"$run_dir/logs/restart_after_setup.exit"
    [[ -f "$run_dir/logs/restart_after_setup.exit" ]] || printf '0\n' >"$run_dir/logs/restart_after_setup.exit"
  else
    printf 'not_run\n' >"$run_dir/logs/restart_after_setup.exit"
    printf 'setup failed; restart skipped\n' >"$run_dir/logs/restart_after_setup.log"
  fi

  if [[ "${ELFUZZ_SKIP_DOWNLOAD:-0}" == "1" ]]; then
    printf 'ELFUZZ_SKIP_DOWNLOAD=1; download skipped.\n' >"$run_dir/logs/download.log"
    printf '0\n' >"$run_dir/logs/download.exit"
  else
    run_stage "$run_dir" "$container" download 'elfuzz download'
  fi

  if [[ -n "${HF_TOKEN:-}" ]]; then
    run_secret_stage "$run_dir" "$container" hf_config
  else
    printf 'HF_TOKEN is not set; Hugging Face config skipped.\n' >"$run_dir/logs/hf_config.log"
    printf '0\n' >"$run_dir/logs/hf_config.exit"
  fi

  run_stage "$run_dir" "$container" synth "elfuzz synth -T fuzzer.elfuzz --use-small-model --tgi-waiting '${ELFUZZ_TGI_WAITING_SECONDS:-120}' --evolution-iterations '${ELFUZZ_EVOLUTION_ITERATIONS:-1}' '$target'"
  if [[ "$(stage_code "$run_dir" synth)" != "0" ]]; then
    docker exec "$container" bash -lc 'sudo docker stop tgi-server >/dev/null 2>&1 || true' >/dev/null 2>&1 || true
  fi
  run_stage "$run_dir" "$container" produce "elfuzz produce -T elfuzz --time '${ELFUZZ_PRODUCE_SECONDS:-60}' '$target'"
  run_stage "$run_dir" "$container" seed_cov "elfuzz run rq1.seed_cov -T elfuzz '$target'"
  run_stage "$run_dir" "$container" afl "elfuzz run rq1.afl --fuzzers elfuzz --repeat 1 --time '${ELFUZZ_AFL_SECONDS:-300}' '$target'"

  copy_summary_from_container "$run_dir" "$container" "$target"

  end_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  write_metadata "$run_dir/metadata.json" "$image" "$container" "$target" "$start_time" "$end_time"
  bash "$SCRIPT_DIR/elfuzz_copy_results.sh" "$run_dir" >/dev/null || true

  stage_failed=0
  for stage in "${stages[@]}"; do
    if [[ "$(stage_code "$run_dir" "$stage")" != "0" ]]; then
      stage_failed=1
    fi
  done
  if [[ "$stage_failed" -ne 0 ]]; then
    printf 'ELFuzz smoke recorded one or more stage failures. Run directory: %s\n' "$run_dir" >&2
    exit 1
  fi

  log "ELFuzz smoke completed: $run_dir"
}

main "$@"
