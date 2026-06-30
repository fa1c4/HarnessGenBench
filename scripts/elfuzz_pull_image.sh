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
  local image="$2"
  local image_id="$3"
  local repo_digests="$4"
  local docker_version="$5"
  local pull_exit_code="$6"
  local start_time="$7"
  local end_time="$8"
  local log_file="$9"

  {
    printf '{\n'
    printf '  "image": "%s",\n' "$(json_escape "$image")"
    printf '  "image_id": "%s",\n' "$(json_escape "$image_id")"
    printf '  "repo_digests": "%s",\n' "$(json_escape "$repo_digests")"
    printf '  "docker_version": "%s",\n' "$(json_escape "$docker_version")"
    printf '  "pull_exit_code": %s,\n' "$pull_exit_code"
    printf '  "start_time": "%s",\n' "$(json_escape "$start_time")"
    printf '  "end_time": "%s",\n' "$(json_escape "$end_time")"
    printf '  "log_file": "%s"\n' "$(json_escape "$log_file")"
    printf '}\n'
  } >"$metadata_file"
}

main() {
  local root image timestamp out_dir metadata_file log_file
  local start_time end_time docker_version pull_exit_code image_id repo_digests

  root="$(repo_root)"
  load_env
  require_cmd docker

  image="${ELFUZZ_IMAGE:-ghcr.io/osuseclab/elfuzz:25.08.0}"
  timestamp="$(make_timestamp)"
  out_dir="$root/${HGB_RESULTS_DIR:-results}/elfuzz/setup_$timestamp"
  ensure_dir "$out_dir"
  metadata_file="$out_dir/metadata.json"
  log_file="$out_dir/docker_pull.log"
  start_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  docker_version="$(docker --version 2>&1 || true)"

  pull_exit_code=0
  docker pull "$image" >"$log_file" 2>&1 || pull_exit_code=$?

  image_id="$(docker image inspect -f '{{.Id}}' "$image" 2>/dev/null || true)"
  repo_digests="$(docker image inspect -f '{{join .RepoDigests ","}}' "$image" 2>/dev/null || true)"
  end_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  write_metadata "$metadata_file" "$image" "$image_id" "$repo_digests" "$docker_version" "$pull_exit_code" "$start_time" "$end_time" "$log_file"

  if [[ "$pull_exit_code" -ne 0 ]]; then
    die "Failed to pull $image. Inspect $log_file and $metadata_file"
  fi

  log "ELFuzz image ready: $image"
  log "Pull metadata written to $metadata_file"
}

main "$@"
