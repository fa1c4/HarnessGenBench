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

find_codeql() {
  local upstream_dir="$1"
  local candidate
  for candidate in \
    "$upstream_dir/docker_shared/codeql/codeql" \
    "$upstream_dir/docker_shared/codeql"; do
    if [[ -x "$candidate" && ! -d "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  if command -v codeql >/dev/null 2>&1; then
    command -v codeql
    return 0
  fi
  return 1
}

install_codeql() {
  local upstream_dir="$1"
  local version="${CKGFUZZER_CODEQL_VERSION:-v2.17.0}"
  local url="${CKGFUZZER_CODEQL_URL:-https://github.com/github/codeql-action/releases/download/codeql-bundle-${version}/codeql-bundle-linux64.tar.gz}"
  local archive="$upstream_dir/docker_shared/codeql-bundle-linux64.tar.gz"

  ensure_dir "$upstream_dir/docker_shared"
  if command -v curl >/dev/null 2>&1; then
    curl -L "$url" -o "$archive"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$archive" "$url"
  else
    die "CodeQL install requested, but neither curl nor wget is available"
  fi
  tar -xzf "$archive" -C "$upstream_dir/docker_shared"
  chmod +x "$upstream_dir/docker_shared/codeql/codeql"
}

write_smoke_requirements() {
  local file="$1"
  cat >"$file" <<'REQ'
beautifulsoup4==4.12.3
chardet==5.2.0
loguru==0.7.2
pandas==2.2.2
pyyaml==6.0.1
tqdm==4.66.4
sympy==1.12
tree-sitter==0.21.3
REQ
}

write_metadata() {
  local metadata_file="$1"
  local upstream_dir="$2"
  local install_mode="$3"
  local install_exit_code="$4"
  local codeql_path="$5"
  local codeql_status="$6"
  local pip_freeze_file="$7"
  local requirements_file="$8"
  local commit python_version docker_version uname_value

  commit="$(git -C "$upstream_dir" rev-parse HEAD)"
  python_version="$(python3 --version 2>&1)"
  docker_version="$(docker --version 2>&1 || true)"
  uname_value="$(uname -a)"

  {
    printf '{\n'
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$commit")"
    printf '  "python_version": "%s",\n' "$(json_escape "$python_version")"
    printf '  "docker_version": "%s",\n' "$(json_escape "$docker_version")"
    printf '  "host_uname": "%s",\n' "$(json_escape "$uname_value")"
    printf '  "venv": "%s",\n' "$(json_escape "$upstream_dir/.venv-hgb")"
    printf '  "install_mode": "%s",\n' "$(json_escape "$install_mode")"
    printf '  "install_exit_code": %s,\n' "$install_exit_code"
    printf '  "requirements_file": "%s",\n' "$(json_escape "$requirements_file")"
    printf '  "pip_freeze_file": "%s",\n' "$(json_escape "$pip_freeze_file")"
    printf '  "codeql_status": "%s",\n' "$(json_escape "$codeql_status")"
    printf '  "codeql_path": "%s"\n' "$(json_escape "$codeql_path")"
    printf '}\n'
  } >"$metadata_file"
}

main() {
  local install_codeql_flag=0
  if [[ "${1:-}" == "--install-codeql" ]]; then
    install_codeql_flag=1
    shift
  fi
  [[ "$#" -eq 0 ]] || die "Usage: bash scripts/ckgfuzzer_setup.sh [--install-codeql]"

  local root upstream_dir venv_dir timestamp out_dir metadata_file pip_freeze_file smoke_req
  local install_mode install_exit_code codeql_path codeql_status
  root="$(repo_root)"
  load_env

  require_cmd git
  require_cmd python3
  require_cmd docker

  upstream_dir="$root/external/CKGFuzzer"
  if [[ ! -d "$upstream_dir/.git" ]]; then
    log "external/CKGFuzzer is missing; running scripts/clone_external.sh"
    bash "$SCRIPT_DIR/clone_external.sh"
  fi
  [[ -d "$upstream_dir/.git" ]] || die "Expected upstream repository at $upstream_dir"

  venv_dir="$upstream_dir/.venv-hgb"
  if [[ ! -d "$venv_dir" ]]; then
    log "Creating virtual environment: $venv_dir"
    python3 -m venv "$venv_dir"
  fi

  timestamp="$(make_timestamp)"
  out_dir="$root/${HGB_RESULTS_DIR:-results}/ckgfuzzer/setup_$timestamp"
  ensure_dir "$out_dir"
  smoke_req="$out_dir/requirements-smoke.txt"
  write_smoke_requirements "$smoke_req"

  # shellcheck disable=SC1091
  source "$venv_dir/bin/activate"
  python -m pip --version >/dev/null

  install_mode="${CKGFUZZER_INSTALL_MODE:-smoke}"
  install_exit_code=0
  if [[ "${CKGFUZZER_SKIP_PIP_INSTALL:-0}" == "1" ]]; then
    install_mode="skipped"
    log "Skipping Python dependency installation because CKGFUZZER_SKIP_PIP_INSTALL=1"
  elif [[ "$install_mode" == "smoke" ]]; then
    log "Installing smoke dependency set derived from upstream Conda requirements"
    python -m pip install -r "$smoke_req" || install_exit_code=$?
  else
    install_exit_code=2
    log "Unsupported CKGFUZZER_INSTALL_MODE=$install_mode; use smoke or set CKGFUZZER_SKIP_PIP_INSTALL=1"
  fi

  codeql_path=""
  codeql_status="missing"
  if [[ "$install_codeql_flag" -eq 1 ]]; then
    install_codeql "$upstream_dir"
  fi
  if codeql_path="$(find_codeql "$upstream_dir")"; then
    codeql_status="found"
  fi

  pip_freeze_file="$out_dir/pip_freeze.txt"
  python -m pip freeze >"$pip_freeze_file"
  metadata_file="$out_dir/metadata.json"
  write_metadata "$metadata_file" "$upstream_dir" "$install_mode" "$install_exit_code" "$codeql_path" "$codeql_status" "$pip_freeze_file" "$smoke_req"

  if [[ "$install_exit_code" -ne 0 ]]; then
    die "Failed to install CKGFuzzer smoke dependencies. Metadata written to $metadata_file"
  fi
  if [[ "$codeql_status" != "found" && "${CKGFUZZER_ALLOW_MISSING_CODEQL:-0}" != "1" ]]; then
    printf 'CKGFuzzer setup metadata written to %s\n' "$metadata_file" >&2
    die "CodeQL CLI not found. Install it under external/CKGFuzzer/docker_shared/codeql/ or rerun with --install-codeql. Set CKGFUZZER_ALLOW_MISSING_CODEQL=1 only for wrapper smoke validation."
  fi

  log "CKGFuzzer setup metadata written to $metadata_file"
}

main "$@"
