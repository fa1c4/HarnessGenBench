#!/usr/bin/env python3
"""Download a local Hugging Face embedding model snapshot for HGB."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_REPO_ID = "Qwen/Qwen3-Embedding-0.6B"
DEFAULT_LOCAL_DIR = "models/Qwen3-Embedding-0.6B"
DEFAULT_MANIFEST = "models/embedding_manifest.json"
OPENAI_MODEL_NAME = "text-embeddings-inference"


def _validate_model_dir(path: Path) -> None:
    if not path.is_dir():
        raise RuntimeError(f"model directory does not exist: {path}")
    config_files = {"config.json", "modules.json", "sentence_bert_config.json"}
    tokenizer_prefixes = ("tokenizer", "vocab", "merges", "sentencepiece", "spiece")
    names = {item.name for item in path.iterdir() if item.is_file()}
    has_config = bool(names & config_files)
    has_tokenizer = any(name.startswith(tokenizer_prefixes) for name in names)
    if not has_config:
        raise RuntimeError(f"model directory lacks a recognizable config file: {path}")
    if not has_tokenizer:
        raise RuntimeError(f"model directory lacks recognizable tokenizer files: {path}")


def _write_manifest(path: Path, repo_id: str, revision: str, local_dir: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "repo_id": repo_id,
        "revision": revision,
        "local_dir": str(local_dir),
        "downloaded_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "backend": "tei-cpu",
        "openai_model_name": OPENAI_MODEL_NAME,
    }
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download the local embedding model used by CKGFuzzer reproduction runs",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--repo-id", default=DEFAULT_REPO_ID, help="Hugging Face model repository")
    parser.add_argument("--local-dir", default=DEFAULT_LOCAL_DIR, help="Local snapshot directory")
    parser.add_argument("--revision", default="", help="Optional Hugging Face revision")
    parser.add_argument("--force", action="store_true", help="Remove and re-download an existing local directory")
    parser.add_argument("--offline-ok", action="store_true", help="Accept an already-present local directory if dependencies are unavailable")
    parser.add_argument("--token-env", default="HF_TOKEN", help="Environment variable containing a Hugging Face token")
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST, help="Manifest path to write after validation")
    args = parser.parse_args()

    local_dir = Path(args.local_dir)
    manifest = Path(args.manifest)

    if local_dir.exists() and not args.force:
        try:
            _validate_model_dir(local_dir)
        except RuntimeError as exc:
            print(f"Existing model directory is incomplete: {exc}", file=sys.stderr)
            print("Re-run with --force after checking the path.", file=sys.stderr)
            return 1
        _write_manifest(manifest, args.repo_id, args.revision, local_dir)
        print(f"embedding-model-ready local_dir={local_dir} manifest={manifest}")
        return 0

    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        print("Missing dependency: huggingface_hub", file=sys.stderr)
        print("Install with: python3 -m pip install -U huggingface_hub", file=sys.stderr)
        if args.offline_ok and local_dir.exists():
            try:
                _validate_model_dir(local_dir)
            except RuntimeError as exc:
                print(f"offline-ok validation failed: {exc}", file=sys.stderr)
                return 1
            _write_manifest(manifest, args.repo_id, args.revision, local_dir)
            print(f"embedding-model-ready local_dir={local_dir} manifest={manifest}")
            return 0
        return 1

    if args.force and local_dir.exists():
        shutil.rmtree(local_dir)

    token = os.environ.get(args.token_env) or None
    try:
        snapshot_download(
            repo_id=args.repo_id,
            revision=args.revision or None,
            local_dir=str(local_dir),
            local_dir_use_symlinks=False,
            token=token,
        )
    except Exception as exc:
        print(f"Failed to download {args.repo_id}: {exc}", file=sys.stderr)
        return 1

    try:
        _validate_model_dir(local_dir)
    except RuntimeError as exc:
        print(f"Downloaded model validation failed: {exc}", file=sys.stderr)
        return 1
    _write_manifest(manifest, args.repo_id, args.revision, local_dir)
    print(f"embedding-model-ready local_dir={local_dir} manifest={manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
