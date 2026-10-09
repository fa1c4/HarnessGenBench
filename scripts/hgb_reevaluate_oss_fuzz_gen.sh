#!/usr/bin/env bash
# Evaluate saved OSS-Fuzz-Gen candidates against the exact FuzzBench target
# without contacting an LLM provider or modifying the original generation run.
set -euo pipefail
[[ $# -ge 2 && $# -le 3 ]] || { echo "usage: $0 SOURCE_WORKSPACE RETRY_ID [CANDIDATES_DIR]" >&2; exit 64; }
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_workspace="$(realpath "$1")"
retry_id="$2"
candidates_source="$(realpath "${3:-$source_workspace/generated_harnesses}")"
[[ "$retry_id" =~ ^[A-Za-z0-9_-]+$ ]] || exit 64
[[ -f "$source_workspace/host_command.txt" && -d "$candidates_source" ]] || exit 66
field() { sed -n "s/^$1=//p" "$source_workspace/host_command.txt" | head -1; }
[[ "$(field generator)" == "oss-fuzz-gen" ]] || exit 64
target_package="$(field target_package)"
image="$(field image)"
[[ -d "$target_package/generator_input" && -d "$target_package/evaluator_only" ]] || exit 66
mapfile -t fields < <(python3 - "$target_package/generator_input/target_manifest.json" <<'PY'
import json,sys
manifest=json.load(open(sys.argv[1],encoding="utf-8"))
for key in ("target","project","fuzz_target"):
    print(manifest[key])
PY
)
target="${fields[0]}"
project="${fields[1]}"
fuzz_target="${fields[2]}"
retry_workspace="$root/workspace/oss-fuzz-gen/$target/$retry_id"
[[ ! -e "$retry_workspace" ]] || { echo "retry workspace already exists: $retry_workspace" >&2; exit 73; }
mkdir -p "$retry_workspace/generated_harnesses" "$retry_workspace/evaluation"
mkdir -p "$retry_workspace/api_traces"
cat >"$retry_workspace/api_traces/summary.json" <<'JSON'
{"usage_accounting_version":1,"total_count":0,"retry_count":0,"input_tokens":0,"output_tokens":0,"error_count":0}
JSON
printf '{"count":1,"retry_ids":["%s"]}\n' "$retry_id" >"$retry_workspace/evaluation_retry_count.json"
python3 "$root/docker/common/hgb_record_statistics.py" --workspace "$retry_workspace" \
  --baseline oss-fuzz-gen --target "$target" --run-id "$retry_id" --status running --exit-code 0
mapfile -t candidates < <(find "$candidates_source" -maxdepth 1 -type f \( -name '*.c' -o -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' \) | sort -V)
[[ ${#candidates[@]} -gt 0 ]] || { echo "no saved candidate source files" >&2; exit 66; }
for candidate in "${candidates[@]}"; do
  cp "$candidate" "$retry_workspace/generated_harnesses/$(basename "$candidate")"
done
intended_apis="$(python3 - "$source_workspace/benchmark/selection.json" <<'PY'
import json,sys
try:
    selection=json.load(open(sys.argv[1],encoding="utf-8"))
    print(",".join(str(item.get("name","")) for item in selection.get("selected",[]) if item.get("name")))
except (OSError,ValueError):
    print("")
PY
)"
python3 - "$retry_workspace" "$source_workspace" "$candidates_source" "$intended_apis" <<'PY'
import hashlib,json,sys
from pathlib import Path
workspace,source,candidate_dir=map(Path,sys.argv[1:4])
data={"run_type":"reevaluated_generated_drivers","source_run":str(source),"candidate_source_dir":str(candidate_dir),
      "intended_apis":sys.argv[4],"candidates":{}}
for path in sorted((workspace/"generated_harnesses").iterdir()):
    data["candidates"][path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
(workspace/"reevaluation_provenance.json").write_text(json.dumps(data,indent=2,sort_keys=True)+"\n")
PY

eval_code=0
docker run --rm --pull=never --init \
  -v "$retry_workspace:/workspace" \
  -v "$retry_workspace:$retry_workspace" \
  -v "$target_package/generator_input:/target:ro" \
  -v "$target_package/evaluator_only:/evaluator:ro" \
  -v "$root/docker/common:/opt/hgb/bin:ro" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e "HGB_RUN_ID=$retry_id" \
  -e "HGB_TARGET=$target" \
  -e "HGB_WORKSPACE_HOST=$retry_workspace" \
  -e "HGB_TARGET_PACKAGE_HOST=$target_package" \
  --entrypoint /opt/hgb/venv/bin/python "$image" \
  /opt/hgb/bin/hgb_harness_evaluator.py \
  --generator oss-fuzz-gen --target-root /target --evaluator-root /evaluator \
  --candidates /workspace/generated_harnesses --work-dir /workspace/evaluation \
  --project "$project" --fuzz-target "$fuzz_target" \
  --profile alpha --protocol blind-project --campaign-seconds 60 \
  --build-timeout-seconds 2400 --strict --build-coverage-image \
  --intended-apis "$intended_apis" >"$retry_workspace/evaluator.log" 2>&1 || eval_code=$?

python3 - "$source_workspace/metadata.json" "$retry_workspace" "$eval_code" <<'PY'
import json,sys
from pathlib import Path
source=Path(sys.argv[1]);workspace=Path(sys.argv[2]);code=int(sys.argv[3])
try: metadata=json.loads(source.read_text(encoding="utf-8"))
except (OSError,ValueError): metadata={}
try: evaluation=json.loads((workspace/"evaluation/result.json").read_text(encoding="utf-8"))
except (OSError,ValueError): evaluation={}
status=evaluation.get("status") or "infra_failure"
metadata.update({"status":status,"reason":evaluation.get("reason") or f"offline evaluator exited {code}",
                 "run_type":"reevaluated_generated_drivers","source_run":str(source.parent),
                 "exit_code":code,"stages":evaluation.get("stages",{}),"metrics":evaluation.get("metrics",{}),
                 "selected_candidate":evaluation.get("selected_candidate",{}),
                 "campaign":evaluation.get("campaign",{}),"coverage":evaluation.get("coverage",{})})
for name in ("metadata.json","result.json"):
    (workspace/name).write_text(json.dumps(metadata,indent=2,sort_keys=True)+"\n",encoding="utf-8")
PY
python3 "$root/docker/common/hgb_record_statistics.py" --workspace "$retry_workspace" \
  --baseline oss-fuzz-gen --target "$target" --run-id "$retry_id" \
  --exit-code "$eval_code"
printf '%s\n' "$retry_workspace/evaluation/result.json"
[[ "$(python3 - "$retry_workspace/evaluation/result.json" <<'PY'
import json,sys
try:
    print(json.load(open(sys.argv[1],encoding="utf-8")).get("status",""))
except (OSError,ValueError):
    print("")
PY
)" == evaluated ]] || exit 1
exit "$eval_code"
