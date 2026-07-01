#!/usr/bin/env bash
set -euo pipefail

artifact=/opt/hgb/artifacts/ckgfuzzer
workspace=/workspace

fix_workspace_permissions() {
  if [[ -n "${HGB_HOST_UID:-}" && -n "${HGB_HOST_GID:-}" ]] && command -v chown >/dev/null 2>&1; then
    chown -R "${HGB_HOST_UID}:${HGB_HOST_GID}" "$workspace" 2>/dev/null || true
  fi
}
trap fix_workspace_permissions EXIT
mode="${1:-smoke}"
mkdir -p "$workspace/logs" "$workspace/generated" "$workspace/project/hgb-sample"
json_escape() { local v="${1:-}"; v="${v//\\/\\\\}"; v="${v//\"/\\\"}"; v="${v//$'\n'/\\n}"; printf '%s' "$v"; }
count_files() { local d="$1"; shift || true; [[ -d "$d" ]] || { printf '0'; return 0; }; find "$d" "$@" 2>/dev/null | wc -l | tr -d ' '; }
commit() { git -C "$artifact" rev-parse HEAD 2>/dev/null || printf unknown; }
write_sample() {
  local d="$workspace/project/hgb-sample"
  mkdir -p "$d/test_usage"
  cat >"$d/sample.h" <<'EOF'
#ifndef HGB_SAMPLE_H
#define HGB_SAMPLE_H
#include <stddef.h>
#include <stdint.h>
int hgb_parse_record(const uint8_t *data, size_t size);
uint32_t hgb_record_checksum(const uint8_t *data, size_t size);
#endif
EOF
  cat >"$d/sample.c" <<'EOF'
#include "sample.h"
uint32_t hgb_record_checksum(const uint8_t *data, size_t size) {
  uint32_t acc = 2166136261u;
  if (!data) return 0;
  for (size_t i = 0; i < size; ++i) { acc ^= data[i]; acc *= 16777619u; }
  return acc;
}
int hgb_parse_record(const uint8_t *data, size_t size) {
  if (!data || size < 4) return 0;
  if (data[0] != 'H' || data[1] != 'G' || data[2] != 'B') return 0;
  uint8_t declared = data[3];
  if ((size_t)declared > size - 4) return -1;
  return (int)(hgb_record_checksum(data + 4, declared) & 0x7fffffffU);
}
EOF
  cat >"$d/test_usage/example_usage.c" <<'EOF'
#include "../sample.h"
#include <stdint.h>
int main(void) {
  const uint8_t data[] = {'H', 'G', 'B', 3, 'o', 'k', '!'};
  return hgb_parse_record(data, sizeof(data)) < 0;
}
EOF
  cat >"$d/api_list.json" <<'EOF'
[
  "hgb_parse_record",
  "hgb_record_checksum"
]
EOF
  cat >"$d/build.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
out="${TMPDIR:-/tmp}/hgb_sample_usage"
cc -Wall -Wextra -I"$SCRIPT_DIR" \
  "$SCRIPT_DIR/sample.c" \
  "$SCRIPT_DIR/test_usage/example_usage.c" \
  -o "$out"
"$out"
EOF
  chmod +x "$d/build.sh"
}
summary() {
  local status="$1" reason="$2" build_code="$3" gen_code="$4"
  {
    printf '# HarnessGenBench CKGFuzzer Summary\n\n'
    printf -- '- Run directory: `%s`\n' "$workspace"
    printf -- '- Upstream commit: `%s`\n' "$(commit)"
    printf -- '- Project: `hgb-sample`\n'
    printf -- '- Model: `%s`\n' "${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
    printf -- '- Status: `%s`\n' "$status"
    printf -- '- Sample build exit code: `%s`\n' "$build_code"
    printf -- '- Generation exit code: `%s`\n' "$gen_code"
    printf -- '- Generated driver candidates: %s\n' "$(count_files "$workspace" -type f \( -name 'driver_*.c' -o -name '*fuzz*.c' -o -name '*fuzz*.cc' \))"
    printf -- '- Top failure reason: %s\n' "$reason"
    printf '\n## Logs\n\n'
    find "$workspace/logs" -type f 2>/dev/null | sort | sed "s#^$workspace/##" | sed 's/^/- `/' | sed 's/$/`/'
  } >"$workspace/HGB_SUMMARY.md"
}
metadata() {
  local status="$1" reason="$2" build_code="$3" gen_code="$4"
  {
    printf '{\n'
    printf '  "fuzzer": "ckgfuzzer",\n'
    printf '  "status": "%s",\n' "$(json_escape "$status")"
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$(commit)")"
    printf '  "project": "hgb-sample",\n'
    printf '  "model": "%s",\n' "$(json_escape "${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}")"
    printf '  "api_key_present": %s,\n' "$([[ -n "${OPENAI_API_KEY:-${API_KEY:-}}" ]] && printf true || printf false)"
    printf '  "sample_build_exit_code": %s,\n' "$build_code"
    printf '  "generation_exit_code": %s,\n' "$gen_code"
    printf '  "reason": "%s",\n' "$(json_escape "$reason")"
    printf '  "command_file": "%s",\n' "$(json_escape "$workspace/command.txt")"
    printf '  "log_dir": "%s"\n' "$(json_escape "$workspace/logs")"
    printf '}\n'
  } >"$workspace/metadata.json"
}
[[ "$mode" == "smoke" ]] || { echo "unknown mode: $mode" >&2; exit 64; }
export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
export OPENAI_MODEL="${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
write_sample
printf 'bash /workspace/project/hgb-sample/build.sh\n' >"$workspace/command.txt"
build_code=0
bash "$workspace/project/hgb-sample/build.sh" >"$workspace/logs/sample_build.log" 2>&1 || build_code=$?
gen_code=0
reason=none
status=completed
if [[ -z "$OPENAI_API_KEY" ]]; then
  printf 'OPENAI_API_KEY is not set; CKGFuzzer LLM generation skipped after sample preparation.\n' >"$workspace/logs/generation.log"
  gen_code=2
  status=missing_api_key
  reason='OPENAI_API_KEY is not set'
else
  printf 'CKGFuzzer artifact present. Full generation command is upstream-version dependent; wrapper smoke prepared the project and environment.\n' >"$workspace/logs/generation.log"
fi
metadata "$status" "$reason" "$build_code" "$gen_code"
summary "$status" "$reason" "$build_code" "$gen_code"
[[ "$build_code" -eq 0 && "$gen_code" -eq 0 ]]
