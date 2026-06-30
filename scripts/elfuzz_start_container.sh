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

container_exists() {
  local name="$1"
  [[ -n "$(docker ps -a --filter "name=^/${name}$" --format '{{.Names}}')" ]]
}

container_running() {
  local name="$1"
  [[ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)" == "true" ]]
}

remove_container_if_requested() {
  local name="$1"
  if [[ "${ELFUZZ_RECREATE_CONTAINER:-0}" == "1" ]]; then
    docker rm "$name" >/dev/null
    return 0
  fi
  return 1
}

write_metadata() {
  local metadata_file="$1"
  local image="$2"
  local container="$3"
  local host_tmp="$4"
  local cpus="$5"
  local storage_size="$6"
  local exit_code="$7"
  local command_text="$8"
  local start_time="$9"
  local end_time="${10}"
  local log_file="${11}"
  local image_id repo_digests container_id core_pattern

  image_id="$(docker image inspect -f '{{.Id}}' "$image" 2>/dev/null || true)"
  repo_digests="$(docker image inspect -f '{{join .RepoDigests ","}}' "$image" 2>/dev/null || true)"
  container_id="$(docker inspect -f '{{.Id}}' "$container" 2>/dev/null || true)"
  core_pattern="$(cat /proc/sys/kernel/core_pattern 2>/dev/null || true)"

  {
    printf '{\n'
    printf '  "image": "%s",\n' "$(json_escape "$image")"
    printf '  "image_id": "%s",\n' "$(json_escape "$image_id")"
    printf '  "repo_digests": "%s",\n' "$(json_escape "$repo_digests")"
    printf '  "container": "%s",\n' "$(json_escape "$container")"
    printf '  "container_id": "%s",\n' "$(json_escape "$container_id")"
    printf '  "host_tmp": "%s",\n' "$(json_escape "$host_tmp")"
    printf '  "cpus": "%s",\n' "$(json_escape "$cpus")"
    printf '  "storage_size": "%s",\n' "$(json_escape "$storage_size")"
    printf '  "core_pattern": "%s",\n' "$(json_escape "$core_pattern")"
    printf '  "start_exit_code": %s,\n' "$exit_code"
    printf '  "docker_run_command": "%s",\n' "$(json_escape "$command_text")"
    printf '  "start_time": "%s",\n' "$(json_escape "$start_time")"
    printf '  "end_time": "%s",\n' "$(json_escape "$end_time")"
    printf '  "log_file": "%s"\n' "$(json_escape "$log_file")"
    printf '}\n'
  } >"$metadata_file"
}

main() {
  local root image container cpus storage_size host_tmp timestamp out_dir metadata_file log_file
  local core_pattern start_time end_time run_exit_code command_text retry_without_storage
  local -a run_cmd run_cmd_no_storage

  root="$(repo_root)"
  load_env
  require_cmd docker

  image="${ELFUZZ_IMAGE:-ghcr.io/osuseclab/elfuzz:25.08.0}"
  container="${ELFUZZ_CONTAINER:-elfuzz-hgb}"
  cpus="${ELFUZZ_CPUS:-8}"
  storage_size="${ELFUZZ_STORAGE_SIZE:-100G}"
  retry_without_storage="${ELFUZZ_RETRY_WITHOUT_STORAGE_OPT:-1}"
  host_tmp="$root/${HGB_RESULTS_DIR:-results}/elfuzz/host-tmp"
  ensure_dir "$host_tmp"

  core_pattern="$(cat /proc/sys/kernel/core_pattern 2>/dev/null || true)"
  if [[ "$core_pattern" != "core" ]]; then
    printf 'WARNING: /proc/sys/kernel/core_pattern is `%s`, but ELFuzz/AFL++ expects `core`.\n' "$core_pattern" >&2
    printf "To change it, run: sudo sh -c 'echo core > /proc/sys/kernel/core_pattern'\n" >&2
  fi

  timestamp="$(make_timestamp)"
  out_dir="$root/${HGB_RESULTS_DIR:-results}/elfuzz/container_$timestamp"
  ensure_dir "$out_dir"
  metadata_file="$out_dir/metadata.json"
  log_file="$out_dir/docker_start.log"
  start_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  if container_exists "$container"; then
    if container_running "$container"; then
      printf 'Container `%s` is already running.\n' "$container" | tee "$log_file"
    elif remove_container_if_requested "$container"; then
      log "Removed stopped container because ELFUZZ_RECREATE_CONTAINER=1"
    else
      docker start "$container" >"$log_file" 2>&1
      sleep 2
      if ! container_running "$container"; then
        docker logs "$container" >>"$log_file" 2>&1 || true
        end_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
        write_metadata "$metadata_file" "$image" "$container" "$host_tmp" "$cpus" "$storage_size" 126 "start existing stopped container" "$start_time" "$end_time" "$log_file"
        die "Existing ELFuzz container did not stay running. Inspect $log_file, remove it with docker rm $container, or rerun with ELFUZZ_RECREATE_CONTAINER=1."
      fi
    fi
    if container_exists "$container"; then
      printf 'Re-enter with: docker exec -it %s bash\n' "$container" >&2
      end_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
      write_metadata "$metadata_file" "$image" "$container" "$host_tmp" "$cpus" "$storage_size" 0 "reuse/start existing container" "$start_time" "$end_time" "$log_file"
      log "Container metadata written to $metadata_file"
      return 0
    fi
  fi

  run_cmd=(
    docker run
    --name "$container"
    --storage-opt "size=$storage_size"
    --cpus "$cpus"
    --add-host=host.docker.internal:host-gateway
    -v "$host_tmp:/tmp/host"
    -v /var/run/docker.sock:/var/run/docker.sock
    -dit
    "$image"
    -lc "while true; do sleep 3600; done"
  )
  run_cmd_no_storage=(
    docker run
    --name "$container"
    --cpus "$cpus"
    --add-host=host.docker.internal:host-gateway
    -v "$host_tmp:/tmp/host"
    -v /var/run/docker.sock:/var/run/docker.sock
    -dit
    "$image"
    -lc "while true; do sleep 3600; done"
  )

  command_text="${run_cmd[*]}"
  run_exit_code=0
  "${run_cmd[@]}" >"$log_file" 2>&1 || run_exit_code=$?

  if [[ "$run_exit_code" -ne 0 && "$retry_without_storage" == "1" ]] && grep -qiE 'storage|quota|overlay|backing filesystem' "$log_file"; then
    log "Docker rejected --storage-opt; retrying without it"
    command_text="${run_cmd_no_storage[*]}"
    run_exit_code=0
    "${run_cmd_no_storage[@]}" >>"$log_file" 2>&1 || run_exit_code=$?
  fi

  end_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  write_metadata "$metadata_file" "$image" "$container" "$host_tmp" "$cpus" "$storage_size" "$run_exit_code" "$command_text" "$start_time" "$end_time" "$log_file"

  if [[ "$run_exit_code" -ne 0 ]]; then
    die "Failed to start ELFuzz container. Inspect $log_file and $metadata_file"
  fi

  printf 'Re-enter with: docker exec -it %s bash\n' "$container" >&2
  log "ELFuzz container running: $container"
  log "Container metadata written to $metadata_file"
}

main "$@"
