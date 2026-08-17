from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ckgfuzzer_model_config = _load_module(
    "ckgfuzzer_model_config_local_embedding",
    REPO_ROOT / "docker/common/ckgfuzzer_model_config.py",
)
profile = _load_module(
    "ckgfuzzer_profile_local_embedding",
    REPO_ROOT / "docker/common/ckgfuzzer_profile.py",
)


class _EmbeddingHandler(BaseHTTPRequestHandler):
    response_payload = {"data": [{"embedding": [0.1, 0.2, 0.3, 0.4]}]}

    def do_POST(self) -> None:
        _ = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(self.response_payload).encode("utf-8"))

    def log_message(self, fmt: str, *args) -> None:
        return


def _serve(payload: dict):
    class Handler(_EmbeddingHandler):
        response_payload = payload

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_probe_openai_embedding_accepts_fake_server() -> None:
    server = _serve({"data": [{"embedding": [0.1, 0.2, 0.3]}]})
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "scripts/probe_openai_embedding.py",
                "--base-url",
                f"http://127.0.0.1:{server.server_port}/v1",
                "--model",
                "text-embeddings-inference",
                "--api-key",
                "-",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
    finally:
        server.shutdown()
    assert proc.returncode == 0, proc.stderr
    assert "embedding-ok model=text-embeddings-inference dimension=3" in proc.stdout


def test_probe_openai_embedding_rejects_malformed_server() -> None:
    server = _serve({"data": [{"embedding": []}]})
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "scripts/probe_openai_embedding.py",
                "--base-url",
                f"http://127.0.0.1:{server.server_port}/v1",
                "--model",
                "text-embeddings-inference",
                "--api-key",
                "sk-test-secret-123456",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
    finally:
        server.shutdown()
    assert proc.returncode != 0
    assert "embedding-probe-failed" in proc.stderr
    assert "sk-test-secret-123456" not in proc.stderr


def test_model_config_separates_ustc_chat_from_local_embedding() -> None:
    config = ckgfuzzer_model_config.resolve_ckgfuzzer_model_config(
        {
            "HGB_LLM_PROVIDER": "ustc",
            "API_KEY": "chat-key",
            "OPENAI_BASE_URL": "https://api.llm.ustc.edu.cn/v1",
            "CKGFUZZER_LLM_MODEL": "deepseek-v4-pro",
            "CKGFUZZER_EMBEDDING_BACKEND": "openai_compatible_local_tei_cpu",
            "CKGFUZZER_EMBEDDING_MODEL": "text-embeddings-inference",
            "CKGFUZZER_EMBEDDING_BASE_URL": "http://host.docker.internal:18080/v1",
            "CKGFUZZER_EMBEDDING_API_KEY": "-",
        },
        profile="reproduction-theta",
    )
    assert config["provider"] == "ustc"
    assert config["chat_base_url"] == "https://api.llm.ustc.edu.cn/v1"
    assert config["embedding_base_url"] == "http://host.docker.internal:18080/v1"
    assert config["embedding_model"] == "text-embeddings-inference"
    assert config["embedding_base_url_kind"] == "host_local"


def test_model_config_full_preflight_uses_separate_embedding_endpoint() -> None:
    def chat_opener(req, timeout=None):
        assert req.full_url == "https://api.llm.ustc.edu.cn/v1/chat/completions"
        return _FakeResponse(200, {"choices": [{"message": {"content": "OK"}}]})

    def embedding_opener(req, timeout=None):
        assert req.full_url == "http://host.docker.internal:18080/v1/embeddings"
        return _FakeResponse(200, {"data": [{"embedding": [0.1, 0.2, 0.3, 0.4, 0.5]}]})

    result = ckgfuzzer_model_config.run_model_preflight(
        {
            "HGB_LLM_PROVIDER": "ustc",
            "API_KEY": "chat-key",
            "OPENAI_BASE_URL": "https://api.llm.ustc.edu.cn/v1",
            "CKGFUZZER_LLM_MODEL": "deepseek-v4-pro",
            "CKGFUZZER_EMBEDDING_BACKEND": "openai_compatible_local_tei_cpu",
            "CKGFUZZER_EMBEDDING_MODEL": "text-embeddings-inference",
            "CKGFUZZER_EMBEDDING_BASE_URL": "http://host.docker.internal:18080/v1",
            "CKGFUZZER_EMBEDDING_API_KEY": "-",
        },
        profile="reproduction-theta",
        chat_opener=chat_opener,
        embedding_opener=embedding_opener,
    )
    assert result["status"] == "ok"
    assert result["embedding_probe"]["dimension"] == 5
    assert result["model_config"]["embedding_backend"] == "openai_compatible_local_tei_cpu"


class _FakeResponse:
    def __init__(self, status: int, body: dict):
        self.status = status
        self._body = json.dumps(body).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None


def test_entrypoint_embedding_config_prefers_embedding_base_url() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert 'base_url: "${CKGFUZZER_EMBEDDING_BASE_URL:-${OPENAI_BASE_URL:-}}"' in entrypoint
    assert 'api_key: "${CKGFUZZER_EMBEDDING_API_KEY:-${OPENAI_API_KEY:-}}"' in entrypoint
    assert "CKGFuzzer embedding backend:" in entrypoint
    assert '"embedding_backend"' in entrypoint
    assert '"embedding_dimension"' in entrypoint


def test_common_sh_adds_host_gateway_for_local_embedding_url() -> None:
    common = (REPO_ROOT / "scripts/lib/common.sh").read_text(encoding="utf-8")
    assert "hgb_add_host_gateway_for_url" in common
    assert "--add-host=host.docker.internal:host-gateway" in common
    assert common.count("-e CKGFUZZER_EMBEDDING_BACKEND") == 2
    assert common.count("-e CKGFUZZER_EMBEDDING_DIMENSION") == 2


def test_profile_accepts_local_tei_backend_and_rejects_dummy_backends() -> None:
    valid = profile.validate_profile(
        "reproduction-theta",
        "blind-project",
        {
            "CKGFUZZER_EMBEDDING_MODEL": "text-embeddings-inference",
            "CKGFUZZER_EMBEDDING_BACKEND": "openai_compatible_local_tei_cpu",
            "HGB_TARGET_REQUIRE_SPLIT": "1",
        },
    )
    assert not valid
    for bad in ("mock", "hash", "local", "dummy"):
        violations = profile.validate_profile(
            "reproduction-theta",
            "blind-project",
            {
                "CKGFUZZER_EMBEDDING_MODEL": "text-embeddings-inference",
                "CKGFUZZER_EMBEDDING_BACKEND": bad,
                "HGB_TARGET_REQUIRE_SPLIT": "1",
            },
        )
        assert any("CKGFUZZER_EMBEDDING_BACKEND" in item for item in violations), bad


def test_runtime_patch_preserves_non_enum_embedding_model_name() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert "def _openai_embedding(real_model, api_key, api_base, embed_batch_size):" in entrypoint
    assert '"embed_batch_size": embed_batch_size' in entrypoint
    assert 'model="text-embedding-ada-002", model_name=real_model' in entrypoint


def test_matrix_local_embedding_preflight_runs_before_target_prep() -> None:
    matrix = (REPO_ROOT / "scripts/hgb_generate_matrix.sh").read_text(encoding="utf-8")
    call = 'if ckgfuzzer_preflight_local_embedding "$generator"'
    assert call in matrix
    preflight_pos = matrix.index(call)
    prepare_pos = matrix.index('prepare_shared_target_packages "${eligible_targets[@]}"', preflight_pos)
    assert preflight_pos < prepare_pos
    assert "ckgfuzzer_preflight_embedding_failed" in matrix
    assert "scripts/probe_openai_embedding.py" in matrix
