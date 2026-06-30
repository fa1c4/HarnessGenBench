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

write_metadata() {
  local metadata_file="$1"
  local upstream_dir="$2"
  local image_name="$3"
  local image_id="$4"
  local command_text="$5"
  local exit_code="$6"
  local start_time="$7"
  local end_time="$8"
  local readme_commands="$9"
  local log_file="${10}"
  local docker_version="${11}"
  local commit="unknown"

  if [[ -d "$upstream_dir/.git" ]]; then
    commit="$(git -C "$upstream_dir" rev-parse HEAD 2>/dev/null || printf 'unknown')"
  fi

  {
    printf '{\n'
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$commit")"
    printf '  "image_name": "%s",\n' "$(json_escape "$image_name")"
    printf '  "image_id": "%s",\n' "$(json_escape "$image_id")"
    printf '  "docker_version": "%s",\n' "$(json_escape "$docker_version")"
    printf '  "build_command": "%s",\n' "$(json_escape "$command_text")"
    printf '  "build_exit_code": %s,\n' "$exit_code"
    printf '  "start_time": "%s",\n' "$(json_escape "$start_time")"
    printf '  "end_time": "%s",\n' "$(json_escape "$end_time")"
    printf '  "readme_docker_commands_file": "%s",\n' "$(json_escape "$readme_commands")"
    printf '  "log_file": "%s"\n' "$(json_escape "$log_file")"
    printf '}\n'
  } >"$metadata_file"
}

main() {
  local root upstream_dir timestamp out_dir metadata_file readme_commands log_file
  local image_name build_exit_code image_id command_text start_time end_time docker_version

  root="$(repo_root)"
  load_env

  require_cmd git

  upstream_dir="$root/external/PromeFuzz"
  if [[ ! -d "$upstream_dir/.git" ]]; then
    log "external/PromeFuzz is missing; running scripts/clone_external.sh"
    bash "$SCRIPT_DIR/clone_external.sh"
  fi

  timestamp="$(make_timestamp)"
  out_dir="$root/${HGB_RESULTS_DIR:-results}/promefuzz/setup_$timestamp"
  ensure_dir "$out_dir"
  metadata_file="$out_dir/metadata.json"
  readme_commands="$out_dir/upstream_docker_commands.txt"
  log_file="$out_dir/docker_build.log"
  image_name="${PROMEFUZZ_DOCKER_IMAGE:-hgb-promefuzz:latest}"
  command_text="docker build -t $image_name ."
  start_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  docker_version="unavailable"

  if [[ ! -d "$upstream_dir/.git" ]]; then
    printf 'Missing official upstream checkout: %s\n' "$upstream_dir" >"$log_file"
    end_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    write_metadata "$metadata_file" "$upstream_dir" "$image_name" "" "$command_text" 127 "$start_time" "$end_time" "$readme_commands" "$log_file" "$docker_version"
    die "Expected upstream repository at $upstream_dir. Metadata written to $metadata_file"
  fi

  grep -nE 'docker (build|run)' "$upstream_dir/README.md" >"$readme_commands" 2>/dev/null || true

  if [[ ! -f "$upstream_dir/Dockerfile" ]]; then
    printf 'Upstream Dockerfile is missing in %s\n' "$upstream_dir" >"$log_file"
    end_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    write_metadata "$metadata_file" "$upstream_dir" "$image_name" "" "$command_text" 127 "$start_time" "$end_time" "$readme_commands" "$log_file" "$docker_version"
    die "Upstream Dockerfile is missing. Metadata written to $metadata_file"
  fi

  if ! command -v docker >/dev/null 2>&1; then
    printf 'Docker command not found on PATH.\n' >"$log_file"
    end_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    write_metadata "$metadata_file" "$upstream_dir" "$image_name" "" "$command_text" 127 "$start_time" "$end_time" "$readme_commands" "$log_file" "$docker_version"
    die "Docker is required for the default PromeFuzz reproduction. Metadata written to $metadata_file"
  fi

  docker_version="$(docker --version 2>&1 || true)"

  build_exit_code=0
  (
    cd "$upstream_dir"
    docker build -t "$image_name" .
  ) >"$log_file" 2>&1 || build_exit_code=$?

  image_id="$(docker image inspect -f '{{.Id}}' "$image_name" 2>/dev/null || true)"
  end_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  write_metadata "$metadata_file" "$upstream_dir" "$image_name" "$image_id" "$command_text" "$build_exit_code" "$start_time" "$end_time" "$readme_commands" "$log_file" "$docker_version"

  if [[ "$build_exit_code" -ne 0 ]]; then
    die "PromeFuzz Docker build failed. Inspect $log_file and $metadata_file"
  fi

  log "PromeFuzz Docker image ready: $image_name"
  log "Setup metadata written to $metadata_file"
}

main "$@"
