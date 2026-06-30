#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

toml_quote() {
  python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

main() {
  local root upstream_dir template timestamp out_dir config_file selected_env notes_file
  local base_url generative_model embedding_model cloud_name embedding_name template_note

  root="$(repo_root)"
  load_env

  require_cmd git
  require_cmd python3

  upstream_dir="$root/external/PromeFuzz"
  if [[ ! -d "$upstream_dir/.git" ]]; then
    log "external/PromeFuzz is missing; running scripts/clone_external.sh"
    bash "$SCRIPT_DIR/clone_external.sh"
  fi
  [[ -d "$upstream_dir/.git" ]] || die "Expected upstream repository at $upstream_dir"

  template="$upstream_dir/config.template.toml"
  [[ -f "$template" ]] || die "Missing upstream config template: $template"

  base_url="${OPENAI_BASE_URL:-https://api.openai.com/v1/}"
  generative_model="${PROMEFUZZ_GENERATIVE_MODEL:-gpt-4o-mini}"
  embedding_model="${PROMEFUZZ_EMBEDDING_MODEL:-text-embedding-3-small}"
  cloud_name="hgb_cloud"
  embedding_name="hgb_embedding"

  timestamp="$(make_timestamp)"
  out_dir="$root/${HGB_RESULTS_DIR:-results}/promefuzz/config_$timestamp"
  ensure_dir "$out_dir"
  config_file="$out_dir/config.toml"
  selected_env="$root/${HGB_RESULTS_DIR:-results}/promefuzz/selected_config.env"
  notes_file="$root/repro/promefuzz/config_notes.md"
  template_note="${template#$root/}"

  python3 - "$template" "$config_file" "$base_url" "$generative_model" "$embedding_model" "$cloud_name" "$embedding_name" <<'PY'
from __future__ import annotations

import json
import sys
import tomllib
from pathlib import Path

template = Path(sys.argv[1])
out = Path(sys.argv[2])
base_url = sys.argv[3]
generative_model = sys.argv[4]
embedding_model = sys.argv[5]
cloud_name = sys.argv[6]
embedding_name = sys.argv[7]

section = None
lines: list[str] = []
for raw in template.read_text().splitlines():
    stripped = raw.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        section = stripped.strip("[]")
    if section == "comprehender" and stripped.startswith("embedding_llm"):
        raw = f"embedding_llm = {json.dumps(embedding_name)}"
    elif section == "comprehender" and stripped.startswith("comprehension_llm"):
        raw = f"comprehension_llm = {json.dumps(cloud_name)}"
    elif section == "generator" and stripped.startswith("generation_llm"):
        raw = f"generation_llm = {json.dumps(cloud_name)}"
    elif section == "analyzer" and stripped.startswith("analysis_llm"):
        raw = f"analysis_llm = {json.dumps(cloud_name)}"
    elif section == "llm" and stripped.startswith("default_llm"):
        raw = f"default_llm = {json.dumps(cloud_name)}"
    lines.append(raw)

lines.extend(
    [
        "",
        "# HarnessGenBench non-interactive LLM assignments.",
        f"[llm.{cloud_name}]",
        'llm_type = "openai"',
        f"base_url = {json.dumps(base_url)}",
        'api_key = ""',
        f"model = {json.dumps(generative_model)}",
        "temperature = 0.5",
        "max_tokens = -1",
        "timeout = 80",
        "retry_times = 3",
        "",
        f"[llm.{embedding_name}]",
        'llm_type = "openai"',
        f"base_url = {json.dumps(base_url)}",
        'api_key = ""',
        f"model = {json.dumps(embedding_model)}",
        "temperature = 0.0",
        "max_tokens = -1",
        "timeout = 80",
        "retry_times = 3",
    ]
)

content = "\n".join(lines) + "\n"
tomllib.loads(content)
out.write_text(content)
PY

  ensure_dir "$(dirname "$selected_env")"
  {
    printf 'PROMEFUZZ_CONFIG=%q\n' "$config_file"
    printf 'PROMEFUZZ_CONFIG_DIR=%q\n' "$out_dir"
    printf 'PROMEFUZZ_CONFIG_TEMPLATE=%q\n' "$template"
    printf 'PROMEFUZZ_LLM_NAME=%q\n' "$cloud_name"
    printf 'PROMEFUZZ_EMBEDDING_LLM_NAME=%q\n' "$embedding_name"
    printf 'PROMEFUZZ_GENERATIVE_MODEL=%q\n' "$generative_model"
    printf 'PROMEFUZZ_EMBEDDING_MODEL=%q\n' "$embedding_model"
    printf 'OPENAI_BASE_URL=%q\n' "$base_url"
  } >"$selected_env"

  {
    printf '# PromeFuzz Config Notes\n\n'
    printf 'Generated configs are copied from `%s` into `results/promefuzz/config_*/config.toml` and patched non-interactively.\n\n' "$template_note"
    printf 'No API key is written to the TOML file. `api_key = ""` is preserved so PromeFuzz reads `OPENAI_API_KEY` from the environment at runtime.\n\n'
    printf '```diff\n'
    printf '[comprehender]\n'
    printf -- '-embedding_llm = "embedding_llm"\n'
    printf -- '-comprehension_llm = ""\n'
    printf -- '+embedding_llm = "%s"\n' "$embedding_name"
    printf -- '+comprehension_llm = "%s"\n\n' "$cloud_name"
    printf '[generator]\n'
    printf -- '-generation_llm = ""\n'
    printf -- '+generation_llm = "%s"\n\n' "$cloud_name"
    printf '[analyzer]\n'
    printf -- '-analysis_llm = ""\n'
    printf -- '+analysis_llm = "%s"\n\n' "$cloud_name"
    printf '[llm]\n'
    printf -- '-default_llm = "cloud_llm"\n'
    printf -- '+default_llm = "%s"\n\n' "$cloud_name"
    printf -- '+[llm.%s]\n' "$cloud_name"
    printf -- '+llm_type = "openai"\n'
    printf -- '+base_url = "%s"\n' "$base_url"
    printf -- '+api_key = ""\n'
    printf -- '+model = "%s"\n\n' "$generative_model"
    printf -- '+[llm.%s]\n' "$embedding_name"
    printf -- '+llm_type = "openai"\n'
    printf -- '+base_url = "%s"\n' "$base_url"
    printf -- '+api_key = ""\n'
    printf -- '+model = "%s"\n' "$embedding_model"
    printf '```\n'
  } >"$notes_file"

  log "Generated PromeFuzz config: $config_file"
  log "Selected config environment written to $selected_env"
}

main "$@"
