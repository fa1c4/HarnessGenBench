#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

usage() {
  cat <<'EOF'
Usage: bash scripts/hgb_llm_preflight.sh [--live]

Resolves the configured OpenAI-compatible provider without printing credentials.
--live sends one minimal chat-completions request. Override the endpoint suffix
with HGB_LLM_CHAT_COMPLETIONS_PATH when a custom provider needs a different path.
EOF
}

live=0
case "${1:-}" in
  '') ;;
  --live) live=1 ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 64 ;;
esac

load_hgb_config
printf 'provider=%s\nbase_url=%s\nmodel=%s\napi_key_present=%s\n' \
  "$HGB_LLM_PROVIDER_RESOLVED" "$OPENAI_BASE_URL" "$OPENAI_MODEL" \
  "$([[ -n "$OPENAI_API_KEY" ]] && printf true || printf false)"

if [[ "$live" != 1 ]]; then
  exit 0
fi
[[ -n "$OPENAI_API_KEY" ]] || { printf 'ERROR: no API key is configured\n' >&2; exit 2; }
require_cmd curl

base_url="${OPENAI_BASE_URL%/}"
path="${HGB_LLM_CHAT_COMPLETIONS_PATH:-/chat/completions}"
[[ "$path" == /* ]] || path="/$path"
response_file="$(mktemp)"
trap 'rm -f "$response_file"' EXIT
code=0
curl --silent --show-error --fail-with-body --connect-timeout "${HGB_LLM_CONNECT_TIMEOUT_SECONDS:-15}" \
  --max-time "${HGB_LLM_PREFLIGHT_TIMEOUT_SECONDS:-60}" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d "{\"model\":\"$OPENAI_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with pong.\"}],\"temperature\":0}" \
  "$base_url$path" >"$response_file" || code=$?
if [[ "$code" -ne 0 ]]; then
  printf 'ERROR: provider request failed (curl exit %s); inspect provider status without exposing credentials.\n' "$code" >&2
  exit "$code"
fi
python3 - "$response_file" <<'PY'
import json
import sys
try:
    data = json.load(open(sys.argv[1], encoding='utf-8'))
    content = data['choices'][0]['message']['content']
except (OSError, ValueError, KeyError, IndexError, TypeError):
    raise SystemExit('ERROR: provider returned a response outside the OpenAI chat-completions shape')
if not isinstance(content, str) or not content.strip():
    raise SystemExit('ERROR: provider returned empty chat content')
print('status=ok')
PY
