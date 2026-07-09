#!/usr/bin/env bash
# Copy to configs/set_api_key.sh and fill locally. Do not commit the real file.
export API_KEY=""
export BASE_URL="https://api.openai.com/v1"
export MODEL="gpt-4o-mini"

# Compatibility aliases used by upstream artifacts.
export OPENAI_API_KEY="$API_KEY"
export OPENAI_BASE_URL="$BASE_URL"
export OPENAI_MODEL="$MODEL"

# Optional LLM API tracing controls. Defaults save the first call and every 10th call.
# export HGB_LLM_TRACE_ENABLED=1
# export HGB_LLM_TRACE_SAMPLE_RATE=10
# export HGB_LLM_TRACE_FIRST=1
