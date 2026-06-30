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
  local pip_freeze_file="$3"
  local install_command="$4"
  local install_exit_code="$5"
  local commit python_version docker_version uname_value

  commit="$(git -C "$upstream_dir" rev-parse HEAD)"
  python_version="$(python3 --version 2>&1)"
  docker_version="$(docker --version 2>&1)"
  uname_value="$(uname -a)"

  {
    printf '{\n'
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$commit")"
    printf '  "python_version": "%s",\n' "$(json_escape "$python_version")"
    printf '  "docker_version": "%s",\n' "$(json_escape "$docker_version")"
    printf '  "host_uname": "%s",\n' "$(json_escape "$uname_value")"
    printf '  "venv": "%s",\n' "$(json_escape "$upstream_dir/.venv-hgb")"
    printf '  "install_command": "%s",\n' "$(json_escape "$install_command")"
    printf '  "install_exit_code": %s,\n' "$install_exit_code"
    printf '  "pip_freeze_file": "%s"\n' "$(json_escape "$pip_freeze_file")"
    printf '}\n'
  } >"$metadata_file"
}

main() {
  local root upstream_dir venv_dir results_base out_dir metadata_file pip_freeze_file
  local install_command install_exit_code timestamp

  root="$(repo_root)"
  load_env

  require_cmd git
  require_cmd python3
  require_cmd docker
  require_cmd c++filt
  require_cmd make

  if ! docker info >/dev/null 2>&1; then
    die "Docker is installed but not reachable. Start Docker or add this user to the docker group before running OSS-Fuzz-Gen."
  fi

  upstream_dir="$root/external/oss-fuzz-gen"
  if [[ ! -d "$upstream_dir/.git" ]]; then
    log "external/oss-fuzz-gen is missing; running scripts/clone_external.sh"
    bash "$SCRIPT_DIR/clone_external.sh"
  fi
  [[ -d "$upstream_dir/.git" ]] || die "Expected upstream repository at $upstream_dir"

  venv_dir="$upstream_dir/.venv-hgb"
  if [[ ! -d "$venv_dir" ]]; then
    log "Creating virtual environment: $venv_dir"
    python3 -m venv "$venv_dir"
  fi

  # shellcheck disable=SC1091
  source "$venv_dir/bin/activate"
  python -m pip --version >/dev/null

  install_command="python -m pip install -r requirements.txt"
  install_exit_code=0
  if [[ -f "$upstream_dir/requirements.txt" ]]; then
    log "Installing upstream requirements.txt"
    (
      cd "$upstream_dir"
      python -m pip install -r requirements.txt
    ) || install_exit_code=$?
  elif [[ -f "$upstream_dir/pyproject.toml" ]]; then
    install_command="python -m pip install -e ."
    log "Installing upstream pyproject package"
    (
      cd "$upstream_dir"
      python -m pip install -e .
    ) || install_exit_code=$?
  else
    install_command="none"
    log "No requirements.txt or pyproject.toml found; leaving venv with upgraded pip only"
  fi

  timestamp="$(make_timestamp)"
  results_base="$root/${HGB_RESULTS_DIR:-results}/oss-fuzz-gen"
  out_dir="$results_base/setup_$timestamp"
  ensure_dir "$out_dir"

  pip_freeze_file="$out_dir/pip_freeze.txt"
  python -m pip freeze >"$pip_freeze_file"
  metadata_file="$out_dir/metadata.json"
  write_metadata "$metadata_file" "$upstream_dir" "$pip_freeze_file" "$install_command" "$install_exit_code"

  if [[ "$install_exit_code" -ne 0 ]]; then
    die "Failed to install OSS-Fuzz-Gen dependencies. Metadata written to $metadata_file"
  fi

  log "OSS-Fuzz-Gen setup metadata written to $metadata_file"
}

main "$@"
