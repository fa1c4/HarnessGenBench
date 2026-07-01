#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

main() {
  local root artifact data selected_json note_file requested
  root="$(repo_root)"
  load_hgb_config
  ensure_artifacts_present "$root" "g2fuzz" "g2fuzz-data"
  artifact="$(artifact_dir "g2fuzz" "$root")"
  data="$(artifact_dir "g2fuzz-data" "$root")"
  selected_json="$(hgb_workspace_dir "$root")/g2fuzz/selected_target.json"
  note_file="$root/repro/g2fuzz/target_selection.md"
  ensure_dir "$(dirname "$selected_json")"
  requested="${G2FUZZ_PROGRAM:-auto}"
  python3 - "$artifact/program_to_format.json" "$requested" "$data" >"$selected_json" <<'PYSEL'
import json, sys
from pathlib import Path
programs=json.loads(Path(sys.argv[1]).read_text())
requested=sys.argv[2]
data=Path(sys.argv[3])
if requested != 'auto':
    if requested not in programs:
        raise SystemExit(f'Unknown G2FUZZ program: {requested}')
    program=requested
    reason='requested by G2FUZZ_PROGRAM'
else:
    program='jhead' if 'jhead' in programs else next(iter(programs))
    reason='auto-selected as upstream README example and G2FUZZ-DATA reference target; local .afl/.cmp binaries are not bundled'
out={
  'program': program,
  'formats': programs[program],
  'reason': reason,
  'afl_ready': False,
  'data_repo_comparison_path': str(data / 'unifuzz' / 'G2FUZZ_GPT35' / program),
  'searched_target_paths': ['$G2FUZZ_TARGET_DIR', f'/workspace/targets/{program}/', '/opt/hgb/artifacts/g2fuzz/'],
}
print(json.dumps(out, indent=2))
PYSEL
  python3 - "$selected_json" "$note_file" <<'PYNOTE'
import json, sys
from pathlib import Path
sel=json.loads(Path(sys.argv[1]).read_text())
program=sel['program']
Path(sys.argv[2]).write_text(f"""# G2FUZZ Target Selection

- Selected program: `{program}`
- Formats: `{', '.join(sel['formats'])}`
- Reason: {sel['reason']}
- AFL binary: `not found`
- CMPLOG binary: `not found`
- Reference data path: `{sel['data_repo_comparison_path']}`

G2FUZZ AFL target binaries are not bundled in the pinned artifact checkout. Docker smoke runs search `$G2FUZZ_TARGET_DIR`, `/workspace/targets/{program}/`, and `/opt/hgb/artifacts/g2fuzz/`. Missing binaries soft-skip by default and write `TARGET_BUILD_MISSING.md`.
""")
PYNOTE
  log "G2FUZZ target selection written to $selected_json"
}
main "$@"
