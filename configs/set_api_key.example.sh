#!/usr/bin/env bash
# Copy to configs/set_api_key.sh and fill locally. Do not commit that real file.
# The resolver maps these settings to OPENAI_* variables for every compatible generator.

# Select one of: ustc, deepseek, custom, or auto.
export HGB_LLM_PROVIDER="deepseek"

# Keep credentials local. API_KEY remains supported for backward compatibility.
export API_KEY=""

# Optional explicit overrides. These take precedence over provider defaults.
# export HGB_LLM_BASE_URL="https://api.deepseek.com"
# export HGB_LLM_MODEL="deepseek-v4-flash"
# export HGB_LLM_API_KEY="$API_KEY"

# Provider defaults:
#   ustc     -> https://api.llm.ustc.edu.cn, model glm-5.2
#   deepseek -> https://api.deepseek.com, model deepseek-v4-pro
#   custom   -> set HGB_LLM_BASE_URL and HGB_LLM_MODEL yourself
# The resolver preserves the base URL path exactly; do not add /v1 unless the
# selected provider requires it.

# Optional LLM API tracing controls. Defaults save the first call and every 10th call.
# export HGB_LLM_TRACE_ENABLED=1
# export HGB_LLM_TRACE_SAMPLE_RATE=10
# export HGB_LLM_TRACE_FIRST=1
