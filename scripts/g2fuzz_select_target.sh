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

main() {
  local root upstream_dir data_dir selected_json note_file requested program formats reason afl_path cmp_path data_path

  root="$(repo_root)"
  load_env
  upstream_dir="$root/external/G2FUZZ"
  data_dir="$root/external/G2FUZZ-DATA"
  [[ -f "$upstream_dir/program_to_format.json" ]] || die "Missing $upstream_dir/program_to_format.json"

  selected_json="$root/${HGB_RESULTS_DIR:-results}/g2fuzz/selected_target.json"
  note_file="$root/repro/g2fuzz/target_selection.md"
  ensure_dir "$(dirname "$selected_json")"

  requested="${G2FUZZ_PROGRAM:-auto}"
  python3.12 - "$upstream_dir/program_to_format.json" "$requested" "$root" "$data_dir" "${HGB_RESULTS_DIR:-results}" >"$selected_json" <<'PY'
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

program_to_format = json.loads(Path(sys.argv[1]).read_text())
requested = sys.argv[2]
root = Path(sys.argv[3])
data_dir = Path(sys.argv[4])
results_dir = sys.argv[5]

def binary_candidates(program: str) -> tuple[str, str]:
    dirs = []
    env_dir = os.environ.get("G2FUZZ_TARGET_DIR")
    if env_dir:
        dirs.append(Path(env_dir))
    dirs.extend([
        root / results_dir / "g2fuzz" / "targets" / program,
        root / "external" / "G2FUZZ",
        data_dir,
    ])
    for d in dirs:
        afl = d / f"{program}.afl"
        cmp = d / f"{program}.cmp"
        if afl.exists() and cmp.exists():
            return str(afl), str(cmp)
    return "", ""

if requested != "auto":
    if requested not in program_to_format:
        raise SystemExit(f"Unknown G2FUZZ program: {requested}")
    program = requested
    reason = "requested by G2FUZZ_PROGRAM"
else:
    program = None
    reason = ""
    for candidate in program_to_format:
        afl, cmp = binary_candidates(candidate)
        if afl and cmp:
            program = candidate
            reason = "auto-selected because local .afl and .cmp binaries were found"
            break
    if program is None:
        program = "jhead" if "jhead" in program_to_format else next(iter(program_to_format))
        reason = "auto-selected as upstream README example and G2FUZZ-DATA reference target; local .afl/.cmp binaries are not bundled"

afl, cmp = binary_candidates(program)
data_path = data_dir / "unifuzz" / "G2FUZZ_GPT35" / program
out = {
    "program": program,
    "formats": program_to_format[program],
    "reason": reason,
    "afl_binary": afl,
    "cmp_binary": cmp,
    "afl_ready": bool(afl and cmp),
    "data_repo_comparison_path": str(data_path) if data_path.exists() else "",
}
print(json.dumps(out, indent=2))
PY

  program="$(sed -n 's/.*"program"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$selected_json" | head -n 1)"
  formats="$(python3.12 - "$selected_json" <<'PY'
import json, sys
data=json.load(open(sys.argv[1]))
print(", ".join(data["formats"]))
PY
)"
  reason="$(sed -n 's/.*"reason"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$selected_json" | head -n 1)"
  afl_path="$(sed -n 's/.*"afl_binary"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$selected_json" | head -n 1)"
  cmp_path="$(sed -n 's/.*"cmp_binary"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$selected_json" | head -n 1)"
  data_path="$(sed -n 's/.*"data_repo_comparison_path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$selected_json" | head -n 1)"

  {
    printf '# G2FUZZ Target Selection\n\n'
    printf -- '- Selected program: `%s`\n' "$program"
    printf -- '- Formats: `%s`\n' "$formats"
    printf -- '- Reason: %s\n' "$reason"
    printf -- '- AFL binary: `%s`\n' "${afl_path:-not found}"
    printf -- '- CMPLOG binary: `%s`\n' "${cmp_path:-not found}"
    printf -- '- Reference data path: `%s`\n' "${data_path:-not found}"
    printf '\nThe upstream README uses `jhead` as its seed-generation and AFL command example. The local source/data checkouts do not include target `.afl` and `.cmp` binaries, so `scripts/g2fuzz_smoke_afl.sh` will write `TARGET_BUILD_MISSING.md` unless you provide those binaries with `G2FUZZ_TARGET_DIR` or `results/g2fuzz/targets/%s/`.\n' "$program"
  } >"$note_file"

  log "Selected G2FUZZ target: $program"
  log "Selection written to $selected_json"
}

main "$@"
