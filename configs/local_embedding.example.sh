#!/usr/bin/env bash
# Example local embedding configuration for CKGFuzzer strict reproduction.
# Source this after configuring your chat LLM provider/key.

export CKGFUZZER_EMBEDDING_BACKEND="openai_compatible_local_tei_cpu"
export CKGFUZZER_EMBEDDING_MODEL="text-embeddings-inference"
export CKGFUZZER_EMBEDDING_BASE_URL="http://host.docker.internal:18080/v1"
export CKGFUZZER_EMBEDDING_API_KEY="-"
export CKGFUZZER_EMBEDDING_MODEL_SOURCE="Qwen/Qwen3-Embedding-0.6B"

# Host-side service defaults used by scripts/local_embedding_server.sh.
export HGB_EMBEDDING_CONTAINER_NAME="${HGB_EMBEDDING_CONTAINER_NAME:-hgb-local-embedding}"
export HGB_EMBEDDING_PORT="${HGB_EMBEDDING_PORT:-18080}"
export HGB_EMBEDDING_MODEL_DIR="${HGB_EMBEDDING_MODEL_DIR:-$PWD/models/Qwen3-Embedding-0.6B}"
export HGB_TEI_IMAGE="${HGB_TEI_IMAGE:-ghcr.io/huggingface/text-embeddings-inference:cpu-1.9}"
export HGB_EMBEDDING_OPENAI_MODEL="${HGB_EMBEDDING_OPENAI_MODEL:-text-embeddings-inference}"
