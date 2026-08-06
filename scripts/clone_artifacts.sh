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

# Read a recorded commit for a work key from the existing work_index.yaml.
recorded_commit() {
  local file="$1" key="$2"
  [[ -f "$file" ]] || { printf ''; return 0; }
  python3 - "$file" "$key" <<'PY_REC'
import sys
import yaml
from pathlib import Path
try:
    data = yaml.safe_load(Path(sys.argv[1]).read_text(encoding="utf-8"))
except Exception:
    print("", end="")
    sys.exit(0)
works = (data or {}).get("works") or {}
entry = works.get(sys.argv[2]) or {}
print(entry.get("commit") or "", end="")
PY_REC
}

main() {
  local root artifacts_root metadata_dir tmp generated_at entry
  root="$(repo_root)"
  artifacts_root="${HGB_ARTIFACTS_DIR:-artifacts}"
  metadata_dir="$root/metadata"
  ensure_dir "$(resolve_path "$root" "$artifacts_root")"
  ensure_dir "$metadata_dir"

  # Repos: key|url|dir|reference_type|optional
  # oss-fuzz is pinned and must never be cloned as a floating branch; its
  # recorded commit is reused without refreshing to upstream HEAD.
  local repos=(
    "fuzzbench|https://github.com/google/fuzzbench.git|fuzzbench|target_benchmark_suite|false"
    "oss-fuzz-gen|https://github.com/google/oss-fuzz-gen.git|oss-fuzz-gen|engineering_artifact|false"
    "oss-fuzz|https://github.com/google/oss-fuzz.git|oss-fuzz|engineering_artifact|false"
    "ckgfuzzer|https://github.com/security-pride/CKGFuzzer.git|ckgfuzzer|paper_artifact|false"
    "promefuzz|https://github.com/pvz122/PromeFuzz.git|promefuzz|paper_artifact|false"
    "elfuzz|https://github.com/OSUSecLab/elfuzz.git|elfuzz|paper_artifact|false"
    "g2fuzz|https://github.com/G2FUZZ/G2FUZZ.git|g2fuzz|paper_artifact|false"
    "g2fuzz-data|https://github.com/G2FUZZ/G2FUZZ-DATA.git|g2fuzz-data|dataset|true"
  )

  local existing_index="$metadata_dir/work_index.yaml"
  generated_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  tmp="$(mktemp "$metadata_dir/work_index.yaml.XXXXXX")"
  trap 'rm -f "${tmp:-}"' EXIT

  {
    printf 'generated_at: "%s"\n' "$generated_at"
    printf 'artifact_root: "%s"\n' "$artifacts_root"
    printf 'works:\n'
  } >"$tmp"

  for entry in "${repos[@]}"; do
    local key url dir reference_type optional rel_path abs_path commit pinned
    IFS='|' read -r key url dir reference_type optional <<<"$entry"
    rel_path="${artifacts_root%/}/$dir"
    abs_path="$(resolve_path "$root" "$rel_path")"

    clone_or_fetch "$key" "$url" "$abs_path"
    check_clean_or_force "$key" "$abs_path"
    # Normal runs checkout the recorded commit without refreshing it, so the
    # work_index.yaml stays stable and reproducible. Set HGB_REFRESH_ARTIFACTS=1
    # to refresh non-pinned repos to the current upstream HEAD. oss-fuzz is
    # always pinned (immutable) regardless of the refresh flag.
    pinned="$(recorded_commit "$existing_index" "$key")"
    if [[ "$key" == "oss-fuzz" || "${HGB_REFRESH_ARTIFACTS:-0}" != "1" ]]; then
      if [[ -n "$pinned" && "$pinned" != "unknown" ]]; then
        commit="$pinned"
      else
        commit="$(upstream_head_commit "$abs_path")"
      fi
    else
      commit="$(upstream_head_commit "$abs_path")"
    fi
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
      if [[ "$key" == "oss-fuzz" ]]; then
        printf '    checkout_mode: "detached-pinned-immutable"\n'
      else
        printf '    checkout_mode: "detached-pinned-current-upstream-head"\n'
      fi
      printf '    reference_type: "%s"\n' "$reference_type"
      printf '    optional: %s\n' "$optional"
    } >>"$tmp"
  done

  # Idempotent update: only overwrite work_index.yaml when the works content
  # (commits) actually changed. This keeps `diff` after a re-run empty and
  # preserves the original generated_at when nothing changed.
  if [[ -f "$existing_index" ]]; then
    if python3 - "$existing_index" "$tmp" <<'PY_DIFF'; then
import sys
import yaml
from pathlib import Path
def works(path):
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    out = {}
    for key, entry in (data.get("works") or {}).items():
        out[key] = {k: v for k, v in (entry or {}).items() if k != "checkout_mode"}
    return out
old = works(sys.argv[1])
new = works(sys.argv[2])
sys.exit(0 if old == new else 1)
PY_DIFF
      log "work_index.yaml unchanged (commits match); keeping existing file"
      rm -f "$tmp"
      trap - EXIT
      return 0
    fi
  fi

  mv "$tmp" "$existing_index"
  trap - EXIT
  log "Updated metadata/work_index.yaml"
}

main "$@"
