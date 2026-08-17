from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_models_gitignore_keeps_weights_untracked() -> None:
    gitignore = (REPO_ROOT / "models/.gitignore").read_text(encoding="utf-8").splitlines()
    assert gitignore[0] == "*"
    assert "!.gitignore" in gitignore
    assert "!.gitkeep" in gitignore
    assert "!README.md" in gitignore
    assert "!embedding_manifest.example.json" in gitignore
    assert not any(line.startswith("!Qwen") for line in gitignore)


def test_download_embedding_model_help_does_not_import_huggingface_hub() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/download_embedding_model.py", "--help"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert "Qwen/Qwen3-Embedding-0.6B" in proc.stdout
    assert "huggingface_hub" not in proc.stderr


def test_download_script_has_manifest_contract() -> None:
    script = (REPO_ROOT / "scripts/download_embedding_model.py").read_text(encoding="utf-8")
    assert "snapshot_download" in script
    assert "python3 -m pip install -U huggingface_hub" in script
    assert '"backend": "tei-cpu"' in script
    assert '"openai_model_name": OPENAI_MODEL_NAME' in script
