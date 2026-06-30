#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

resolve_path() {
  local root="$1"
  local path="$2"
  if [[ "$path" = /* ]]; then
    printf '%s\n' "$path"
  else
    printf '%s/%s\n' "$root" "$path"
  fi
}

clone_or_fetch() {
  local key="$1"
  local url="$2"
  local abs_path="$3"

  if [[ -d "$abs_path/.git" ]]; then
    log "Fetching $key in $abs_path"
    git -C "$abs_path" fetch --all --tags --prune
  elif [[ -e "$abs_path" ]]; then
    die "$abs_path exists but is not a git repository"
  else
    log "Cloning $key from $url"
    git clone "$url" "$abs_path"
  fi
}

main() {
  local root external_dir metadata_dir tmp generated_at entry
  root="$(repo_root)"
  load_env

  external_dir="${HGB_EXTERNAL_DIR:-external}"
  metadata_dir="$root/metadata"
  ensure_dir "$(resolve_path "$root" "$external_dir")"
  ensure_dir "$metadata_dir"

  local repos=(
    "oss-fuzz-gen|https://github.com/google/oss-fuzz-gen.git|oss-fuzz-gen|engineering_artifact|false"
    "ckgfuzzer|https://github.com/security-pride/CKGFuzzer.git|CKGFuzzer|paper_artifact|false"
    "promefuzz|https://github.com/pvz122/PromeFuzz.git|PromeFuzz|paper_artifact|false"
    "elfuzz|https://github.com/OSUSecLab/elfuzz.git|elfuzz|paper_artifact|false"
    "g2fuzz|https://github.com/G2FUZZ/G2FUZZ.git|G2FUZZ|paper_artifact|false"
    "g2fuzz-data|https://github.com/G2FUZZ/G2FUZZ-DATA.git|G2FUZZ-DATA|dataset|true"
  )

  generated_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  tmp="$(mktemp "$metadata_dir/work_index.yaml.XXXXXX")"
  trap 'rm -f "$tmp"' EXIT

  printf 'generated_at: "%s"\n' "$generated_at" >"$tmp"
  printf 'works:\n' >>"$tmp"

  for entry in "${repos[@]}"; do
    local key url dir reference_type optional rel_path abs_path commit repo_date
    IFS='|' read -r key url dir reference_type optional <<<"$entry"
    rel_path="${external_dir%/}/$dir"
    abs_path="$(resolve_path "$root" "$rel_path")"

    clone_or_fetch "$key" "$url" "$abs_path"
    commit="$(git -C "$abs_path" rev-parse HEAD)"
    repo_date="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

    printf '  %s:\n' "$key" >>"$tmp"
    printf '    repo: "%s"\n' "$url" >>"$tmp"
    printf '    path: "%s"\n' "$rel_path" >>"$tmp"
    printf '    commit: "%s"\n' "$commit" >>"$tmp"
    printf '    date: "%s"\n' "$repo_date" >>"$tmp"
    printf '    reference_type: "%s"\n' "$reference_type" >>"$tmp"
    printf '    optional: %s\n' "$optional" >>"$tmp"
  done

  mv "$tmp" "$metadata_dir/work_index.yaml"
  trap - EXIT
  log "Updated metadata/work_index.yaml"
}

main "$@"
