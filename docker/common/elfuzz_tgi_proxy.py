#!/usr/bin/env python3
"""TGI-to-OpenAI proxy for ELFuzz on GPU-less hosts.

ELFuzz's ``genvariants_parallel.py`` talks to a HuggingFace TGI server
(``POST /generate``, ``GET /info``).  On hosts without a GPU we cannot run
TGI locally, but a remote OpenAI-compatible API (e.g. USTC) is available.

This proxy listens on port 8192 (the default TGI port) and translates:
  POST /generate  ->  POST {OPENAI_BASE_URL}/v1/chat/completions
  GET  /info      ->  static JSON with the configured model id

Environment variables:
  OPENAI_BASE_URL  e.g. https://api.llm.ustc.edu.cn
  OPENAI_API_KEY   API key for the remote endpoint
  OPENAI_MODEL     e.g. deepseek-v4-pro
  ELFUZZ_TGI_PROXY_PORT  (default 8192)
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler


class TGIProxyHandler(BaseHTTPRequestHandler):
    def _json(self, code: int, body: dict | list) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/info":
            model = os.environ.get("ELFUZZ_TGI_PROXY_MODEL_ID", os.environ.get("OPENAI_MODEL", "Qwen/Qwen2.5-Coder-1.5B"))
            self._json(200, {"model_id": model, "model_dtype": "openai_proxy", "model_device": "remote"})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/generate":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            raw = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid json"})
            return
        inputs = raw.get("inputs", "")
        params = raw.get("parameters", {})
        base = os.environ.get("OPENAI_BASE_URL", "").rstrip("/")
        key = os.environ.get("OPENAI_API_KEY", "")
        model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        if not base or not key:
            self._json(503, {"error": "OPENAI_BASE_URL or OPENAI_API_KEY not set"})
            return
        chat_content = inputs
        sys_prompt = "You are a code completion engine. Output ONLY valid Python code. No explanation, no markdown fences, no comments about what you are doing. Just the code."
        if "<PRE>" in inputs and "<SUF>" in inputs and "<MID>" in inputs:
            pre, rest = inputs.split("<SUF>", 1)
            pre = pre.replace("<PRE>", "").strip()
            suf, _ = rest.split("<MID>", 1)
            suf = suf.strip()
            chat_content = f"Fill in the missing code between the prefix and suffix. Output ONLY the code that should replace <MID>. Do not output the prefix or suffix.\n\n--- PREFIX ---\n{pre}\n--- SUFFIX ---\n{suf}\n--- INSERT CODE HERE ---"
        elif "<|fim_prefix|>" in inputs and "<|fim_suffix|>" in inputs and "<|fim_middle|>" in inputs:
            pre, rest = inputs.split("<|fim_suffix|>", 1)
            pre = pre.replace("<|fim_prefix|>", "").strip()
            suf, _ = rest.split("<|fim_middle|>", 1)
            suf = suf.strip()
            chat_content = f"Fill in the missing code between the prefix and suffix. Output ONLY the code that should replace the middle. Do not output the prefix or suffix.\n\n--- PREFIX ---\n{pre}\n--- SUFFIX ---\n{suf}\n--- INSERT CODE HERE ---"
        else:
            chat_content = f"Continue the following Python code. Output ONLY the continuation, not the original code.\n\n{inputs}"
        oa_req: dict = {
            "model": model,
            "messages": [{"role": "system", "content": sys_prompt}, {"role": "user", "content": chat_content}],
            "max_tokens": int(params.get("max_new_tokens", 2048)),
            "temperature": float(params.get("temperature", 0.2)),
        }
        if "top_p" in params:
            oa_req["top_p"] = float(params["top_p"])
        if "stop" in params:
            oa_req["stop"] = params["stop"]
        url = f"{base}/v1/chat/completions"
        req = urllib.request.Request(url, data=json.dumps(oa_req).encode("utf-8"), method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {key}")
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                oa_resp = json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", "replace")[:2000]
            self._json(exc.code, {"error": err_body})
            return
        except Exception as exc:
            self._json(502, {"error": str(exc)})
            return
        text = ""
        choices = oa_resp.get("choices") or []
        if choices:
            text = choices[0].get("message", {}).get("content", "")
        oa_finish = choices[0].get("finish_reason", "") if choices else ""
        tgi_finish = {"stop": "stop_sequence", "length": "length"}.get(oa_finish, "length")
        self._json(200, {"generated_text": text, "details": {"finish_reason": tgi_finish}})

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(f"[tgi-proxy] {self.address_string()} - {fmt % args}\n")


def main() -> int:
    port = int(os.environ.get("ELFUZZ_TGI_PROXY_PORT", "8192"))
    server = ThreadingHTTPServer(("0.0.0.0", port), TGIProxyHandler)
    print(f"[tgi-proxy] listening on :{port}, forwarding to {os.environ.get('OPENAI_BASE_URL','?')} model={os.environ.get('OPENAI_MODEL','?')}", file=sys.stderr, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
