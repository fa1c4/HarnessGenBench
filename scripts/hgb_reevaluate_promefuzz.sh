#!/usr/bin/env bash
# Recheck finalized PromeFuzz drivers after evaluator-only fixes, without
# paying for another LLM generation round.
set -euo pipefail

[[ $# -ge 2 && $# -le 4 ]] || {
  echo "usage: $0 SOURCE_WORKSPACE RETRY_ID [MAX_CANDIDATES] [CANDIDATES_DIR]" >&2
  exit 64
}
source_workspace="$(realpath "$1")"
retry_id="$2"
max_candidates="${3:-4}"
candidates_source="${4:-$source_workspace/generated_harnesses}"
[[ "$retry_id" =~ ^[A-Za-z0-9_-]+$ && "$max_candidates" =~ ^[1-9][0-9]*$ ]] || exit 64
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -f "$source_workspace/host_command.txt" ]] || exit 66

field() {
  sed -n "s/^$1=//p" "$source_workspace/host_command.txt" | head -1
}
[[ "$(field generator)" == "promefuzz" ]] || exit 64
target_package="$(field target_package)"
image="$(field image)"
[[ -d "$target_package/generator_input" && -d "$target_package/evaluator_only" ]] || exit 66
[[ -d "$candidates_source" ]] || exit 66

readarray -t target_fields < <(python3 - "$target_package/generator_input/target_manifest.json" <<'PY'
import json,sys
manifest=json.load(open(sys.argv[1],encoding="utf-8"))
for key in ("target","project","fuzz_target"):
    print(manifest[key])
PY
)
target="${target_fields[0]}"
project="${target_fields[1]}"
fuzz_target="${target_fields[2]}"
retry_dir="$source_workspace/$retry_id"
candidates_dir="$retry_dir/candidates_input"
mkdir -p "$candidates_dir"
mapfile -t candidates < <(find "$candidates_source" -maxdepth 1 -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' \) | sort -V | head -n "$max_candidates")
[[ ${#candidates[@]} -gt 0 ]] || exit 66
python3 - "$source_workspace" "$retry_id" "$candidates_source" <<'PY_RETRY_STATS'
import fcntl
import json
import os
import sys
from pathlib import Path

workspace, retry_id, candidates_source = map(Path, sys.argv[1:4])
with (workspace / ".evaluation_retry_count.lock").open("a+") as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    path = workspace / "evaluation_retry_count.json"
    data = json.loads(path.read_text()) if path.is_file() else {"retry_ids": []}
    ids = data.setdefault("retry_ids", [])
    if str(retry_id) not in ids:
        ids.append(str(retry_id))
    data["count"] = len(ids)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    os.replace(temp, path)
    rounds = candidates_source / "driver_fix_rounds.txt"
    if rounds.is_file():
        count = int(rounds.read_text().strip())
        manual_path = workspace / "manual_driver_fix_rounds.json"
        manual = json.loads(manual_path.read_text()) if manual_path.is_file() else {}
        manual["count"] = max(int(manual.get("count") or 0), count)
        temp = manual_path.with_name(f".{manual_path.name}.{os.getpid()}.tmp")
        temp.write_text(json.dumps(manual, indent=2, sort_keys=True) + "\n")
        os.replace(temp, manual_path)
PY_RETRY_STATS
for candidate in "${candidates[@]}"; do
  cp "$candidate" "$candidates_dir/$(basename "$candidate")"
done
intended_apis=""
if [[ -f "$source_workspace/promefuzz_intended_apis.txt" ]]; then
  intended_apis="$(tr -d '\n' <"$source_workspace/promefuzz_intended_apis.txt")"
fi
python3 "$root/docker/common/hgb_record_statistics.py" --workspace "$source_workspace" \
  --baseline promefuzz --target "$target" --run-id "$(basename "$source_workspace")" \
  --status running

eval_code=0
docker run --rm --pull=never --init \
  -v "$source_workspace:/workspace" \
  -v "$source_workspace:$source_workspace" \
  -v "$target_package/generator_input:/target:ro" \
  -v "$target_package/evaluator_only:/evaluator:ro" \
  -v "$root/docker/common:/opt/hgb/bin:ro" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e "HGB_RUN_ID=$retry_id" \
  -e "HGB_TARGET=$target" \
  -e "HGB_WORKSPACE_HOST=$source_workspace" \
  -e "HGB_TARGET_PACKAGE_HOST=$target_package" \
  --entrypoint /opt/hgb/venv/bin/python "$image" \
  /opt/hgb/bin/hgb_harness_evaluator.py \
  --generator promefuzz --target-root /target --evaluator-root /evaluator \
  --candidates "/workspace/$retry_id/candidates_input" \
  --work-dir "/workspace/$retry_id/evaluation" \
  --project "$project" --fuzz-target "$fuzz_target" \
  --profile alpha --campaign-seconds 300 --build-timeout-seconds 2400 \
  --strict --build-coverage-image --intended-apis "$intended_apis" || eval_code=$?

source_status="$(python3 - "$source_workspace/metadata.json" <<'PY_SOURCE_STATUS'
import json,sys
try:
    print(json.load(open(sys.argv[1], encoding="utf-8")).get("status") or "reevaluation_complete")
except (OSError, ValueError):
    print("reevaluation_complete")
PY_SOURCE_STATUS
)"
python3 "$root/docker/common/hgb_record_statistics.py" --workspace "$source_workspace" \
  --baseline promefuzz --target "$target" --run-id "$(basename "$source_workspace")" \
  --exit-code "$eval_code" --status "$source_status"

printf '%s\n' "$retry_dir/evaluation/result.json"
exit "$eval_code"
