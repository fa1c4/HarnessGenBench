#!/usr/bin/env bash
# Launch MAGMA-phase generation runs for one baseline over all nine targets.
#
# Each target uses the split package built by scripts/hgb_magma_targets.py and
# the committed entry API (generator_input/declared_api.json).  Runs are
# resumable: an existing result.json with status=evaluated/completed is kept.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat >&2 <<'EOF'
Usage: bash scripts/hgb_magma_generate.sh --generator NAME [options]

  --generator NAME   oss-fuzz-gen, ckgfuzzer, or promefuzz
  --targets "a b c"  subset (default: all nine MAGMA targets)
  --parallel N       concurrent runs (default: 2)
  --profile NAME     baseline profile (default: alpha)
  --timeout SECONDS  per-run generation timeout (default: 7200)
  --force            rerun even when result.json is terminal
EOF
}

generator=""
target_list="libpng libsndfile libtiff libxml2 lua openssl php poppler sqlite3"
parallel=2
profile="alpha"
timeout_seconds=7200
force=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --generator|-g) generator="${2:-}"; shift 2 ;;
    --targets) target_list="${2:-}"; shift 2 ;;
    --parallel) parallel="${2:-}"; shift 2 ;;
    --profile) profile="${2:-}"; shift 2 ;;
    --timeout) timeout_seconds="${2:-}"; shift 2 ;;
    --force) force=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[[ -n "$generator" ]] || { usage; exit 64; }
valid_hgb_generator "$generator" || die "unknown generator: $generator"
root="$(repo_root)"
export HGB_API_KEY_CONFIG="${HGB_API_KEY_CONFIG:-$HOME/api_keys/HarnessGenBench/set_api_key_magma.sh}"
load_hgb_config

run_one() {
  local target="$1"
  local pkg="$root/workspace/magma/targets/magma_${target}/pkg"
  local out_dir="$root/workspace/magma/generation/$generator/$target"
  local run_id
  run_id="$(make_timestamp)"
  mkdir -p "$out_dir"
  local log="$out_dir/${run_id}.log"
  if [[ "$force" != "1" && -f "$out_dir/current/result.json" ]]; then
    local status
    status="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("status",""))' "$out_dir/current/result.json" 2>/dev/null || true)"
    if [[ "$status" == "evaluated" || "$status" == "completed" || "$status" == "invalid" || "$status" == "not_applicable" ]]; then
      printf 'skip %s/%s: existing %s\n' "$generator" "$target" "$status"
      return 0
    fi
  fi
  printf 'start %s/%s -> %s\n' "$generator" "$target" "$log"
  local protocol="blind-project"
  bash "$SCRIPT_DIR/hgb_generate_harness.sh" \
    --generator "$generator" --target "magma_${target}" \
    --target-package "$pkg" --profile "$profile" --protocol "$protocol" \
    --run-id "$run_id" --timeout "$timeout_seconds" \
    >"$log" 2>&1 || true
  # hgb_generate_harness prints the run dir as its last line.
  local run_dir
  run_dir="$(tail -n1 "$log" 2>/dev/null || true)"
  if [[ -d "$run_dir" ]]; then
    rm -f "$out_dir/current"
    ln -s "$run_dir" "$out_dir/current"
    python3 - "$run_dir/result.json" "$out_dir/status.json" <<'PY' 2>/dev/null || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    raise SystemExit(0)
json.dump({"status": d.get("status"), "reason": d.get("reason"),
           "stages": d.get("stages"), "run_dir": str(__import__("pathlib").Path(sys.argv[1]).parent)},
          open(sys.argv[2], "w"), indent=2)
PY
  fi
  printf 'done %s/%s: %s\n' "$generator" "$target" "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("status"))' "$out_dir/status.json" 2>/dev/null || echo unknown)"
}

mkdir -p "$root/workspace/magma/generation/$generator"
pids=()
for target in $target_list; do
  run_one "$target" &
  pids+=($!)
  while [[ "$(jobs -rp | wc -l)" -ge "$parallel" ]]; do
    wait -n || true
  done
done
for pid in "${pids[@]}"; do wait "$pid" || true; done
printf 'generation batch finished for %s\n' "$generator"
