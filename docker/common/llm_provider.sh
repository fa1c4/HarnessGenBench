#!/usr/bin/env bash
# Shared OpenAI-compatible provider resolution for HGB host scripts and images.
# This file deliberately never writes credentials to disk or output.

hgb_llm_profile_default_base_url() {
  case "${1:-}" in
    ustc) printf '%s\n' 'https://api.llm.ustc.edu.cn' ;;
    deepseek) printf '%s\n' 'https://api.deepseek.com' ;;
    *) printf '%s\n' 'https://api.openai.com/v1' ;;
  esac
}

hgb_llm_profile_default_model() {
  case "${1:-}" in
    ustc) printf '%s\n' 'glm-5.2' ;;
    deepseek) printf '%s\n' 'deepseek-v4-pro' ;;
    *) printf '%s\n' 'gpt-4o-mini' ;;
  esac
}

hgb_llm_detect_provider() {
  local base_url="${1:-}"
  case "$base_url" in
    *api.llm.ustc.edu.cn*) printf '%s\n' 'ustc' ;;
    *api.deepseek.com*) printf '%s\n' 'deepseek' ;;
    *) printf '%s\n' 'custom' ;;
  esac
}

hgb_resolve_llm_provider() {
  local requested resolved api_key base_url model
  requested="${HGB_LLM_PROVIDER:-auto}"
  requested="${requested,,}"
  case "$requested" in
    auto|ustc|deepseek|custom) ;;
    *)
      printf 'ERROR: HGB_LLM_PROVIDER must be one of auto, ustc, deepseek, or custom (got %s)\n' "$requested" >&2
      return 64
      ;;
  esac

  api_key="${HGB_LLM_API_KEY:-${USTC_API_KEY:-${OPENAI_API_KEY:-${API_KEY:-}}}}"
  base_url="${HGB_LLM_BASE_URL:-${USTC_BASE_URL:-${USTC_API_BASE:-${OPENAI_BASE_URL:-${BASE_URL:-}}}}}"
  model="${HGB_LLM_MODEL:-${OPENAI_MODEL:-${MODEL:-}}}"

  if [[ "$requested" == 'auto' ]]; then
    resolved="$(hgb_llm_detect_provider "$base_url")"
  else
    resolved="$requested"
  fi
  if [[ -z "$base_url" ]]; then
    base_url="$(hgb_llm_profile_default_base_url "$resolved")"
  fi
  if [[ -z "$model" ]]; then
    model="$(hgb_llm_profile_default_model "$resolved")"
  fi

  # Preserve the exact path configured by the provider. In particular, do not
  # append /v1: OpenAI-compatible deployments differ in their base-path rules.
  export HGB_LLM_PROVIDER_RESOLVED="$resolved"
  export OPENAI_API_KEY="$api_key"
  export OPENAI_BASE_URL="$base_url"
  export OPENAI_MODEL="$model"
  export API_KEY="$api_key"
  export BASE_URL="$base_url"
  export MODEL="$model"
}
