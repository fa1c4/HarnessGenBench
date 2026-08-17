from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_local_embedding_server_uses_cpu_tei_defaults() -> None:
    script = (REPO_ROOT / "scripts/local_embedding_server.sh").read_text(encoding="utf-8")
    assert "ghcr.io/huggingface/text-embeddings-inference:cpu-1.9" in script
    assert "HGB_EMBEDDING_PORT=\"${HGB_EMBEDDING_PORT:-18080}\"" in script
    assert "text-embeddings-inference" in script
    assert "--model-id \"$model_id\"" in script
    assert "--gpus" not in script
    assert "nvidia" not in script.lower()


def test_local_embedding_server_probes_and_writes_metadata() -> None:
    script = (REPO_ROOT / "scripts/local_embedding_server.sh").read_text(encoding="utf-8")
    assert "scripts/probe_openai_embedding.py" in script
    assert "results/local_embedding_service.json" in script
    assert "docker logs --tail 200 \"$HGB_EMBEDDING_CONTAINER_NAME\"" in script
    assert "--label hgb.service=hgb-local-embedding" in script


def test_local_embedding_example_exports_ckgfuzzer_embedding_env() -> None:
    example = (REPO_ROOT / "configs/local_embedding.example.sh").read_text(encoding="utf-8")
    assert 'CKGFUZZER_EMBEDDING_BACKEND="openai_compatible_local_tei_cpu"' in example
    assert 'CKGFUZZER_EMBEDDING_MODEL="text-embeddings-inference"' in example
    assert 'CKGFUZZER_EMBEDDING_BASE_URL="http://host.docker.internal:18080/v1"' in example
    assert 'CKGFUZZER_EMBEDDING_API_KEY="-"' in example
