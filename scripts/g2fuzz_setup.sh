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
  local data_dir="$3"
  local venv_dir="$4"
  local pip_freeze_file="$5"
  local make_exit_code="$6"
  local install_exit_code="$7"
  local start_time="$8"
  local end_time="$9"
  local make_log="${10}"
  local install_log="${11}"
  local upstream_commit data_commit python_version

  upstream_commit="$(git -C "$upstream_dir" rev-parse HEAD 2>/dev/null || printf 'unknown')"
  data_commit="$(git -C "$data_dir" rev-parse HEAD 2>/dev/null || printf 'unknown')"
  python_version="$("$venv_dir/bin/python" --version 2>&1 || python3 --version 2>&1 || true)"

  {
    printf '{\n'
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$upstream_commit")"
    printf '  "data_commit": "%s",\n' "$(json_escape "$data_commit")"
    printf '  "python_version": "%s",\n' "$(json_escape "$python_version")"
    printf '  "venv": "%s",\n' "$(json_escape "$venv_dir")"
    printf '  "pip_freeze_file": "%s",\n' "$(json_escape "$pip_freeze_file")"
    printf '  "install_command": "python -m pip install openai==1.63.2",\n'
    printf '  "install_exit_code": %s,\n' "$install_exit_code"
    printf '  "make_command": "make source-only",\n'
    printf '  "make_exit_code": %s,\n' "$make_exit_code"
    printf '  "start_time": "%s",\n' "$(json_escape "$start_time")"
    printf '  "end_time": "%s",\n' "$(json_escape "$end_time")"
    printf '  "install_log": "%s",\n' "$(json_escape "$install_log")"
    printf '  "make_log": "%s"\n' "$(json_escape "$make_log")"
    printf '}\n'
  } >"$metadata_file"
}

main() {
  local root upstream_dir data_dir venv_dir timestamp out_dir metadata_file pip_freeze_file
  local make_log install_log start_time end_time install_exit_code make_exit_code

  root="$(repo_root)"
  load_env
  require_cmd git
  require_cmd python3
  require_cmd make

  upstream_dir="$root/external/G2FUZZ"
  data_dir="$root/external/G2FUZZ-DATA"
  if [[ ! -d "$upstream_dir/.git" || ! -d "$data_dir/.git" ]]; then
    log "G2FUZZ checkouts missing; running scripts/clone_external.sh"
    bash "$SCRIPT_DIR/clone_external.sh"
  fi
  [[ -d "$upstream_dir/.git" ]] || die "Expected upstream repository at $upstream_dir"

  timestamp="$(make_timestamp)"
  out_dir="$root/${HGB_RESULTS_DIR:-results}/g2fuzz/setup_$timestamp"
  ensure_dir "$out_dir"
  metadata_file="$out_dir/metadata.json"
  pip_freeze_file="$out_dir/pip_freeze.txt"
  install_log="$out_dir/pip_install.log"
  make_log="$out_dir/make_source_only.log"
  venv_dir="$upstream_dir/.venv-hgb"
  start_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

  if [[ ! -d "$venv_dir" ]]; then
    python3 -m venv "$venv_dir"
  fi

  install_exit_code=0
  "$venv_dir/bin/python" -m pip install openai==1.63.2 >"$install_log" 2>&1 || install_exit_code=$?
  "$venv_dir/bin/python" -m pip freeze >"$pip_freeze_file" 2>/dev/null || true

  make_exit_code=0
  (
    cd "$upstream_dir"
    make source-only
  ) >"$make_log" 2>&1 || make_exit_code=$?

  end_time="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  write_metadata "$metadata_file" "$upstream_dir" "$data_dir" "$venv_dir" "$pip_freeze_file" "$make_exit_code" "$install_exit_code" "$start_time" "$end_time" "$make_log" "$install_log"

  if [[ "$install_exit_code" -ne 0 ]]; then
    die "Failed to install G2FUZZ Python dependencies. Inspect $install_log and $metadata_file"
  fi
  if [[ "$make_exit_code" -ne 0 ]]; then
    die "G2FUZZ make source-only failed. Inspect $make_log and $metadata_file"
  fi

  log "G2FUZZ setup complete: $metadata_file"
}

main "$@"
