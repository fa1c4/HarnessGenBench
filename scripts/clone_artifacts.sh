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

check_clean_or_force() {
  local key="$1"
  local path="$2"
  if [[ ! -d "$path/.git" ]]; then
    return 0
  fi
  if [[ -n "$(git -C "$path" status --porcelain)" ]]; then
    if [[ "${HGB_ARTIFACT_FORCE:-0}" == "1" ]]; then
      log "Resetting dirty artifact checkout because HGB_ARTIFACT_FORCE=1: $key"
      git -C "$path" reset --hard
      git -C "$path" clean -fdx
    else
      die "Artifact checkout is dirty: $path. Commit/stash it, or rerun with HGB_ARTIFACT_FORCE=1 to reset and clean it."
    fi
  fi
}

clone_or_fetch() {
  local key="$1"
  local url="$2"
  local path="$3"
  if [[ -d "$path/.git" ]]; then
    check_clean_or_force "$key" "$path"
    log "Fetching $key in $path"
    git -C "$path" fetch --all --tags --prune
  elif [[ -e "$path" ]]; then
    die "$path exists but is not a git repository"
  else
    log "Cloning $key from $url"
    git clone "$url" "$path"
  fi
}

upstream_head_commit() {
  local path="$1"
  local ref
  ref="$(git -C "$path" symbolic-ref -q refs/remotes/origin/HEAD 2>/dev/null || true)"
  if [[ -n "$ref" ]]; then
    git -C "$path" rev-parse "$ref"
    return 0
  fi
  git -C "$path" remote set-head origin --auto >/dev/null 2>&1 || true
  ref="$(git -C "$path" symbolic-ref -q refs/remotes/origin/HEAD 2>/dev/null || true)"
  if [[ -n "$ref" ]]; then
    git -C "$path" rev-parse "$ref"
    return 0
  fi
  git -C "$path" rev-parse HEAD
}

main() {
  local root artifacts_root metadata_dir tmp generated_at entry
  root="$(repo_root)"
  artifacts_root="${HGB_ARTIFACTS_DIR:-artifacts}"
  metadata_dir="$root/metadata"
  ensure_dir "$(resolve_path "$root" "$artifacts_root")"
  ensure_dir "$metadata_dir"

  local repos=(
    "fuzzbench|https://github.com/google/fuzzbench.git|fuzzbench|target_benchmark_suite|false"
    "oss-fuzz-gen|https://github.com/google/oss-fuzz-gen.git|oss-fuzz-gen|engineering_artifact|false"
    "ckgfuzzer|https://github.com/security-pride/CKGFuzzer.git|ckgfuzzer|paper_artifact|false"
    "promefuzz|https://github.com/pvz122/PromeFuzz.git|promefuzz|paper_artifact|false"
    "elfuzz|https://github.com/OSUSecLab/elfuzz.git|elfuzz|paper_artifact|false"
    "g2fuzz|https://github.com/G2FUZZ/G2FUZZ.git|g2fuzz|paper_artifact|false"
    "g2fuzz-data|https://github.com/G2FUZZ/G2FUZZ-DATA.git|g2fuzz-data|dataset|true"
  )

  generated_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  tmp="$(mktemp "$metadata_dir/work_index.yaml.XXXXXX")"
  trap 'rm -f "$tmp"' EXIT

  {
    printf 'generated_at: "%s"\n' "$generated_at"
    printf 'artifact_root: "%s"\n' "$artifacts_root"
    printf 'works:\n'
  } >"$tmp"

  for entry in "${repos[@]}"; do
    local key url dir reference_type optional rel_path abs_path commit
    IFS='|' read -r key url dir reference_type optional <<<"$entry"
    rel_path="${artifacts_root%/}/$dir"
    abs_path="$(resolve_path "$root" "$rel_path")"

    clone_or_fetch "$key" "$url" "$abs_path"
    check_clean_or_force "$key" "$abs_path"
    commit="$(upstream_head_commit "$abs_path")"
    log "Checking out $key at $commit"
    git -C "$abs_path" checkout --detach "$commit"
    if [[ -f "$abs_path/.gitmodules" ]]; then
      git -C "$abs_path" submodule update --init --recursive
    fi

    {
      printf '  %s:\n' "$key"
      printf '    repo: "%s"\n' "$url"
      printf '    path: "%s"\n' "$rel_path"
      printf '    commit: "%s"\n' "$commit"
      printf '    checkout_mode: "detached-pinned-current-upstream-head"\n'
      printf '    reference_type: "%s"\n' "$reference_type"
      printf '    optional: %s\n' "$optional"
    } >>"$tmp"
  done

  mv "$tmp" "$metadata_dir/work_index.yaml"
  trap - EXIT
  log "Updated metadata/work_index.yaml"
}

main "$@"
