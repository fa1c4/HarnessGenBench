#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

HGB_EMBEDDING_CONTAINER_NAME="${HGB_EMBEDDING_CONTAINER_NAME:-hgb-local-embedding}"
HGB_EMBEDDING_PORT="${HGB_EMBEDDING_PORT:-18080}"
HGB_EMBEDDING_MODEL_DIR="${HGB_EMBEDDING_MODEL_DIR:-$ROOT/models/Qwen3-Embedding-0.6B}"
HGB_TEI_IMAGE="${HGB_TEI_IMAGE:-ghcr.io/huggingface/text-embeddings-inference:cpu-1.9}"
HGB_EMBEDDING_OPENAI_MODEL="${HGB_EMBEDDING_OPENAI_MODEL:-text-embeddings-inference}"
HGB_EMBEDDING_TIMEOUT_SECONDS="${HGB_EMBEDDING_TIMEOUT_SECONDS:-180}"
HGB_EMBEDDING_TOKENIZATION_WORKERS="${HGB_EMBEDDING_TOKENIZATION_WORKERS:-2}"
HGB_EMBEDDING_MAX_BATCH_TOKENS="${HGB_EMBEDDING_MAX_BATCH_TOKENS:-512}"
HGB_EMBEDDING_MAX_CLIENT_BATCH_SIZE="${HGB_EMBEDDING_MAX_CLIENT_BATCH_SIZE:-128}"
export HGB_EMBEDDING_CONTAINER_NAME HGB_EMBEDDING_PORT HGB_EMBEDDING_MODEL_DIR HGB_TEI_IMAGE HGB_EMBEDDING_OPENAI_MODEL
export HGB_EMBEDDING_TOKENIZATION_WORKERS HGB_EMBEDDING_MAX_BATCH_TOKENS HGB_EMBEDDING_MAX_CLIENT_BATCH_SIZE

usage() {
  cat >&2 <<'EOF'
Usage:
  bash scripts/local_embedding_server.sh start|stop|restart|status|logs|probe
EOF
}

log() {
  printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

container_exists() {
  docker ps -a --format '{{.Names}}' | grep -Fxq "$HGB_EMBEDDING_CONTAINER_NAME"
}

container_label() {
  docker inspect -f '{{ index .Config.Labels "hgb.service" }}' "$HGB_EMBEDDING_CONTAINER_NAME" 2>/dev/null || true
}

container_running() {
  [[ "$(docker inspect -f '{{.State.Running}}' "$HGB_EMBEDDING_CONTAINER_NAME" 2>/dev/null || true)" == "true" ]]
}

model_id_arg() {
  local model_name
  model_name="$(basename "$HGB_EMBEDDING_MODEL_DIR")"
  printf '/data/%s\n' "$model_name"
}

probe() {
  python3 "$ROOT/scripts/probe_openai_embedding.py" \
    --base-url "http://127.0.0.1:${HGB_EMBEDDING_PORT}/v1" \
    --model "$HGB_EMBEDDING_OPENAI_MODEL" \
    --api-key "-"
}

write_metadata() {
  mkdir -p "$ROOT/results"
  python3 - "$ROOT/results/local_embedding_service.json" <<'PY_HGB_EMBED_METADATA'
import json
import os
import time
import sys

path = sys.argv[1]
payload = {
    "container_name": os.environ["HGB_EMBEDDING_CONTAINER_NAME"],
    "port": int(os.environ["HGB_EMBEDDING_PORT"]),
    "model_dir": os.environ["HGB_EMBEDDING_MODEL_DIR"],
    "image": os.environ["HGB_TEI_IMAGE"],
    "openai_model_name": os.environ["HGB_EMBEDDING_OPENAI_MODEL"],
    "tokenization_workers": int(os.environ["HGB_EMBEDDING_TOKENIZATION_WORKERS"]),
    "max_batch_tokens": int(os.environ["HGB_EMBEDDING_MAX_BATCH_TOKENS"]),
    "max_client_batch_size": int(os.environ["HGB_EMBEDDING_MAX_CLIENT_BATCH_SIZE"]),
    "base_url": f"http://127.0.0.1:{os.environ['HGB_EMBEDDING_PORT']}/v1",
    "backend": "tei-cpu",
    "started_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, sort_keys=True)
    f.write("\n")
PY_HGB_EMBED_METADATA
}

start() {
  if [[ ! -d "$HGB_EMBEDDING_MODEL_DIR" ]]; then
    printf 'ERROR: model directory not found: %s\n' "$HGB_EMBEDDING_MODEL_DIR" >&2
    printf 'Run: python3 scripts/download_embedding_model.py --local-dir %s\n' "$HGB_EMBEDDING_MODEL_DIR" >&2
    exit 1
  fi
  if container_exists; then
    if [[ "$(container_label)" != "hgb-local-embedding" ]]; then
      printf 'ERROR: container name %s already exists and is not managed by this service.\n' "$HGB_EMBEDDING_CONTAINER_NAME" >&2
      exit 1
    fi
    docker rm -f "$HGB_EMBEDDING_CONTAINER_NAME" >/dev/null
  fi

  local model_id
  model_id="$(model_id_arg)"
  log "starting local embedding service: image=$HGB_TEI_IMAGE model_id=$model_id port=$HGB_EMBEDDING_PORT"
  docker run -d --name "$HGB_EMBEDDING_CONTAINER_NAME" \
    --label hgb.service=hgb-local-embedding \
    -p "${HGB_EMBEDDING_PORT}:80" \
    -v "$ROOT/models:/data:ro" \
    "$HGB_TEI_IMAGE" \
    --model-id "$model_id" \
    --served-model-name "$HGB_EMBEDDING_OPENAI_MODEL" \
    --tokenization-workers "$HGB_EMBEDDING_TOKENIZATION_WORKERS" \
    --max-batch-tokens "$HGB_EMBEDDING_MAX_BATCH_TOKENS" \
    --max-client-batch-size "$HGB_EMBEDDING_MAX_CLIENT_BATCH_SIZE" >/dev/null

  local deadline
  deadline=$((SECONDS + HGB_EMBEDDING_TIMEOUT_SECONDS))
  until probe >/tmp/hgb-local-embedding-probe.log 2>&1; do
    if (( SECONDS >= deadline )); then
      cat /tmp/hgb-local-embedding-probe.log >&2 || true
      docker logs --tail 200 "$HGB_EMBEDDING_CONTAINER_NAME" >&2 || true
      printf 'ERROR: local embedding service did not become ready within %s seconds.\n' "$HGB_EMBEDDING_TIMEOUT_SECONDS" >&2
      exit 1
    fi
    sleep 2
  done
  cat /tmp/hgb-local-embedding-probe.log
  write_metadata
  log "local embedding service ready: http://127.0.0.1:${HGB_EMBEDDING_PORT}/v1"
}

stop() {
  if ! container_exists; then
    log "local embedding service is not running"
    return 0
  fi
  if [[ "$(container_label)" != "hgb-local-embedding" ]]; then
    printf 'ERROR: container name %s exists and is not managed by this service.\n' "$HGB_EMBEDDING_CONTAINER_NAME" >&2
    exit 1
  fi
  docker rm -f "$HGB_EMBEDDING_CONTAINER_NAME" >/dev/null
  log "local embedding service stopped"
}

status() {
  if container_running; then
    printf 'running %s http://127.0.0.1:%s/v1\n' "$HGB_EMBEDDING_CONTAINER_NAME" "$HGB_EMBEDDING_PORT"
  elif container_exists; then
    printf 'stopped %s\n' "$HGB_EMBEDDING_CONTAINER_NAME"
  else
    printf 'not_found %s\n' "$HGB_EMBEDDING_CONTAINER_NAME"
  fi
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status) status ;;
  logs) docker logs --tail 200 "$HGB_EMBEDDING_CONTAINER_NAME" ;;
  probe) probe ;;
  -h|--help|"") usage; exit 0 ;;
  *) usage; exit 64 ;;
esac
