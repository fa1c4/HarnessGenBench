#!/usr/bin/env python3
"""Probe an OpenAI-compatible embeddings endpoint."""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from typing import Any


def _redact(text: str, api_key: str) -> str:
    secrets = [api_key] if api_key and api_key != "-" else []
    for secret in secrets:
        text = text.replace(secret, "[REDACTED]")
    return re.sub(r"sk-[A-Za-z0-9_\\-]{8,}", "[REDACTED]", text)


def _embeddings_url(base_url: str) -> str:
    url = base_url.rstrip("/")
    if url.endswith("/embeddings"):
        return url
    return url + "/embeddings"


def _extract_embedding(payload: dict[str, Any]) -> list[Any] | None:
    data = payload.get("data")
    if isinstance(data, list) and data:
        first = data[0]
        if isinstance(first, dict):
            emb = first.get("embedding")
            return emb if isinstance(emb, list) else None
        if isinstance(first, list):
            return first
    emb = payload.get("embedding")
    if isinstance(emb, list):
        return emb
    return None


def probe(base_url: str, model: str, api_key: str, text: str, timeout: float) -> tuple[bool, int, str]:
    body = json.dumps({
        "model": model,
        "input": text,
        "encoding_format": "float",
    }).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key and api_key != "-":
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(_embeddings_url(base_url), data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", "replace")
            status = getattr(response, "status", 200)
            if not 200 <= int(status) < 300:
                return False, 0, f"HTTP {status}: {_redact(raw, api_key)[:300]}"
    except urllib.error.HTTPError as exc:
        raw = ""
        try:
            raw = exc.read().decode("utf-8", "replace")
        except Exception:
            pass
        return False, 0, f"HTTP {exc.code} {exc.reason}: {_redact(raw, api_key)[:300]}"
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return False, 0, _redact(f"{type(exc).__name__}: {exc}", api_key)

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        return False, 0, f"invalid JSON response: {exc}"

    embedding = _extract_embedding(payload)
    if not isinstance(embedding, list) or not embedding:
        return False, 0, "embedding response missing non-empty data[0].embedding"
    sample = embedding[: min(len(embedding), 32)]
    if not all(isinstance(value, (int, float)) and not isinstance(value, bool) for value in sample):
        return False, 0, "embedding vector contains non-numeric values"
    return True, len(embedding), ""


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe an OpenAI-compatible /v1/embeddings endpoint")
    parser.add_argument("--base-url", default="http://127.0.0.1:18080/v1")
    parser.add_argument("--model", default="text-embeddings-inference")
    parser.add_argument("--api-key", default="-")
    parser.add_argument("--input", default="hello embedding")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    ok, dimension, error = probe(args.base_url, args.model, args.api_key, args.input, args.timeout)
    if ok:
        print(f"embedding-ok model={args.model} dimension={dimension}")
        return 0
    print(f"embedding-probe-failed model={args.model}: {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
