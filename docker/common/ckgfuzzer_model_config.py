#!/usr/bin/env python3
"""CKGFuzzer model resolution and live preflight probes.

This module resolves the chat/embedding model configuration for CKGFuzzer
strict reproduction profiles (reproduction-theta and its aliases) against the
repository-local model registry (``metadata/llm_provider_models.yaml``). It
also performs live OpenAI-compatible chat/embedding probes so a run fails
early with a clear diagnostic instead of preparing all 20 target packages
and then failing each row with an opaque error.

The probe code is isolated and unit-testable with a fake local server or
monkeypatched ``urllib.request.urlopen``; it never calls the real network in
unit tests.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# Sentinel model names that are never valid in a strict profile.
INVALID_MODEL_SENTINELS = {"", "mock", "hash", "local", "fake", "none", "dummy", "hgb-hash-embedding"}
DEFAULT_PROVIDER_BASE_URLS = {
    "ustc": "https://api.llm.ustc.edu.cn",
    "deepseek": "https://api.deepseek.com",
    "openai": "https://api.openai.com/v1",
}

# Environment variable aliases for API key/base URL resolution. The first
# non-empty value wins. Chat and embedding endpoints may be different: for
# theta3 local TEI runs the chat LLM stays on USTC while embeddings use a
# host-local OpenAI-compatible endpoint.
CHAT_API_KEY_ALIASES = (
    "CKGFUZZER_API_KEY",
    "USTC_API_KEY",
    "HGB_OPENAI_API_KEY",
    "HGB_LLM_API_KEY",
    "OPENAI_API_KEY",
    "API_KEY",
)
EMBEDDING_API_KEY_ALIASES = (
    "CKGFUZZER_EMBEDDING_API_KEY",
    "CKGFUZZER_API_KEY",
    "USTC_API_KEY",
    "HGB_OPENAI_API_KEY",
    "HGB_LLM_API_KEY",
    "OPENAI_API_KEY",
    "API_KEY",
)
CHAT_BASE_URL_ALIASES = (
    "CKGFUZZER_BASE_URL",
    "USTC_BASE_URL",
    "USTC_API_BASE",
    "HGB_OPENAI_BASE_URL",
    "HGB_LLM_BASE_URL",
    "OPENAI_BASE_URL",
    "OPENAI_API_BASE",
    "BASE_URL",
)
EMBEDDING_BASE_URL_ALIASES = (
    "CKGFUZZER_EMBEDDING_BASE_URL",
    "CKGFUZZER_BASE_URL",
    "USTC_BASE_URL",
    "USTC_API_BASE",
    "HGB_OPENAI_BASE_URL",
    "HGB_LLM_BASE_URL",
    "OPENAI_BASE_URL",
    "OPENAI_API_BASE",
    "BASE_URL",
)

# Backward-compatible aliases used by older tests/importers.
API_KEY_ALIASES = CHAT_API_KEY_ALIASES
BASE_URL_ALIASES = CHAT_BASE_URL_ALIASES


class ModelConfigError(Exception):
    """Raised when CKGFuzzer model configuration is invalid for a strict profile."""


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def _registry_path() -> Path:
    # In the repository, the registry is at <repo>/metadata/llm_provider_models.yaml.
    # In the container, the module is at /opt/hgb/bin/ckgfuzzer_model_config.py and
    # the metadata is mounted at /opt/hgb/metadata/llm_provider_models.yaml.
    candidates = [
        _repo_root() / "metadata" / "llm_provider_models.yaml",
        Path(__file__).resolve().parent.parent / "metadata" / "llm_provider_models.yaml",
        Path("/opt/hgb/metadata/llm_provider_models.yaml"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def _parse_simple_yaml(text: str) -> dict[str, Any]:
    """Minimal YAML parser for the provider model registry.

    Supports top-level provider keys with nested ``chat_models``,
    ``embedding_models``, ``reranker_models``, and ``defaults`` sections.
    """
    result: dict[str, Any] = {}
    current_provider: str | None = None
    current_section: str | None = None
    in_defaults = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 0 and stripped.endswith(":"):
            current_provider = stripped[:-1]
            result[current_provider] = {
                "chat_models": [],
                "embedding_models": [],
                "reranker_models": [],
                "defaults": {},
            }
            current_section = None
            in_defaults = False
            continue
        if current_provider is None:
            continue
        if stripped == "defaults:":
            current_section = "defaults"
            in_defaults = True
            continue
        if in_defaults and ":" in stripped and not stripped.startswith("- "):
            key, value = stripped.split(":", 1)
            value = value.strip()
            if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
            result[current_provider]["defaults"][key.strip()] = value
            continue
        if stripped.startswith("- "):
            value = stripped[2:].strip()
            if current_section in ("chat_models", "embedding_models", "reranker_models"):
                result[current_provider][current_section].append(value)
            continue
        if stripped.endswith(":") and indent <= 2:
            section_name = stripped[:-1]
            if section_name in ("chat_models", "embedding_models", "reranker_models"):
                current_section = section_name
                in_defaults = False
            continue
    return result


def load_model_registry(path: str | Path | None = None) -> dict[str, Any]:
    """Load and return the provider model registry."""
    registry_path = Path(path) if path else _registry_path()
    if not registry_path.is_file():
        return {}
    return _parse_simple_yaml(registry_path.read_text(encoding="utf-8"))


def _resolve_env(env: dict[str, str], aliases: tuple[str, ...]) -> str:
    for name in aliases:
        value = (env.get(name) or "").strip()
        if value:
            return value
    return ""


def _api_key_is_present(value: str) -> bool:
    return bool(value.strip())


def _auth_api_key(value: str) -> str:
    value = value.strip()
    return "" if value == "-" else value


def _is_invalid_model(model: str) -> bool:
    return model.lower() in INVALID_MODEL_SENTINELS


def _detect_provider(base_url: str) -> str:
    if "api.llm.ustc.edu.cn" in base_url:
        return "ustc"
    if "api.deepseek.com" in base_url:
        return "deepseek"
    if "api.openai.com" in base_url:
        return "openai"
    return "custom"


def _base_url_kind(base_url: str) -> str:
    base = base_url.lower()
    if not base:
        return "unset"
    if "host.docker.internal" in base or "127.0.0.1" in base or "localhost" in base:
        return "host_local"
    return "remote"


def _embedding_endpoint_is_separate(chat_base_url: str, embedding_base_url: str, env: dict[str, str]) -> bool:
    explicit_embedding_url = bool((env.get("CKGFUZZER_EMBEDDING_BASE_URL") or "").strip())
    explicit_backend = bool((env.get("CKGFUZZER_EMBEDDING_BACKEND") or "").strip())
    return explicit_backend or (explicit_embedding_url and embedding_base_url.rstrip("/") != chat_base_url.rstrip("/"))


def resolve_ckgfuzzer_model_config(
    env: dict[str, str] | None = None,
    profile: str = "",
    *,
    registry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve CKGFuzzer chat/embedding model config for a strict profile.

    Returns a dict with ``provider``, ``chat_model``, ``embedding_model``,
    ``base_url``, ``api_key_present``, ``chat_probe_passed``,
    ``embedding_probe_passed``, ``embedding_dimension``, and ``errors``.

    Raises ``ModelConfigError`` when the resolved config is invalid for a
    strict profile (reproduction-theta and its aliases).
    """
    env = env if env is not None else dict(os.environ)
    registry = registry if registry is not None else load_model_registry()

    provider = (env.get("HGB_LLM_PROVIDER_RESOLVED") or env.get("HGB_LLM_PROVIDER") or "").strip().lower()
    chat_model = (env.get("CKGFUZZER_LLM_MODEL") or "").strip()
    embedding_model = (env.get("CKGFUZZER_EMBEDDING_MODEL") or "").strip()
    chat_base_url = _resolve_env(env, CHAT_BASE_URL_ALIASES)
    embedding_base_url = _resolve_env(env, EMBEDDING_BASE_URL_ALIASES)
    if provider in {"", "auto"}:
        provider = _detect_provider(chat_base_url)
    chat_api_key = _resolve_env(env, CHAT_API_KEY_ALIASES)
    embedding_api_key = _resolve_env(env, EMBEDDING_API_KEY_ALIASES)
    if not chat_base_url and provider in DEFAULT_PROVIDER_BASE_URLS:
        chat_base_url = DEFAULT_PROVIDER_BASE_URLS[provider]
    if not embedding_base_url:
        embedding_base_url = chat_base_url
    embedding_backend = (env.get("CKGFUZZER_EMBEDDING_BACKEND") or "").strip()
    if not embedding_backend and _base_url_kind(embedding_base_url) == "host_local":
        embedding_backend = "openai_compatible_local_tei_cpu"
    elif not embedding_backend and embedding_base_url:
        embedding_backend = "openai_compatible"
    embedding_model_source = (env.get("CKGFUZZER_EMBEDDING_MODEL_SOURCE") or "").strip()
    if not embedding_model_source and _base_url_kind(embedding_base_url) == "host_local":
        embedding_model_source = "Qwen/Qwen3-Embedding-0.6B"
    embedding_separate = _embedding_endpoint_is_separate(chat_base_url, embedding_base_url, env)

    is_strict = profile in {"reproduction-theta", "reproduction-eta", "reproduction-zeta", "reproduction-epsilon", "reproduction-delta"}

    errors: list[str] = []

    provider_entry = registry.get(provider, {}) if isinstance(registry, dict) else {}
    if not isinstance(provider_entry, dict):
        provider_entry = {}
    chat_models = provider_entry.get("chat_models", []) or []
    embedding_models = provider_entry.get("embedding_models", []) or []
    defaults = provider_entry.get("defaults", {}) or {}

    # Default model names from the registry when the user omits them.
    if not chat_model:
        default_chat = defaults.get("ckgfuzzer_chat", "") if isinstance(defaults, dict) else ""
        if default_chat:
            chat_model = default_chat
    if not embedding_model:
        default_emb = defaults.get("ckgfuzzer_embedding", "") if isinstance(defaults, dict) else ""
        if default_emb:
            embedding_model = default_emb
    if (
        not (env.get("CKGFUZZER_EMBEDDING_MODEL") or "").strip()
        and embedding_separate
        and _base_url_kind(embedding_base_url) == "host_local"
    ):
        embedding_model = "text-embeddings-inference"

    # Strict profiles reject sentinel/mock/empty models.
    if is_strict:
        if _is_invalid_model(chat_model):
            errors.append(
                f"CKGFuzzer strict preflight failed: chat model is not configured for provider {provider or 'unknown'}. "
                f"Set CKGFUZZER_LLM_MODEL or update metadata/llm_provider_models.yaml."
            )
        if _is_invalid_model(embedding_model):
            if provider == "ustc":
                errors.append(
                    "CKGFuzzer strict preflight failed: embedding model is not configured for provider ustc. "
                    "Set CKGFUZZER_EMBEDDING_MODEL=qwen3-embedding or update metadata/llm_provider_models.yaml."
                )
            else:
                errors.append(
                    f"CKGFuzzer strict preflight failed: embedding model is not configured for provider {provider or 'unknown'}. "
                    f"Set CKGFUZZER_EMBEDDING_MODEL or update metadata/llm_provider_models.yaml."
                )

    # Provider registry validation: if the provider has a non-empty model
    # list, the configured model must be in it (case-sensitive). This catches
    # OpenAI-only model names on USTC.
    if is_strict and provider and provider != "custom":
        if chat_model and chat_models and chat_model not in chat_models:
            available = ", ".join(chat_models)
            errors.append(
                f"CKGFuzzer strict preflight failed: {chat_model} is not registered for provider {provider}. "
                f"Available chat models: {available}."
            )
        if not embedding_separate and embedding_model and embedding_models and embedding_model not in embedding_models:
            available = ", ".join(embedding_models)
            errors.append(
                f"CKGFuzzer strict preflight failed: {embedding_model} is not registered for provider {provider}. "
                f"Available embedding models: {available}."
            )

    config = {
        "provider": provider,
        "chat_model": chat_model,
        "embedding_model": embedding_model,
        "base_url": chat_base_url,
        "chat_base_url": chat_base_url,
        "embedding_base_url": embedding_base_url,
        "embedding_backend": embedding_backend,
        "embedding_model_source": embedding_model_source,
        "embedding_base_url_kind": _base_url_kind(embedding_base_url),
        "api_key_present": _api_key_is_present(chat_api_key),
        "chat_api_key_present": _api_key_is_present(chat_api_key),
        "embedding_api_key_present": _api_key_is_present(embedding_api_key),
        "chat_probe_passed": False,
        "embedding_probe_passed": False,
        "embedding_dimension": 0,
        "errors": errors,
    }
    if errors:
        raise ModelConfigError("; ".join(errors))
    return config


def _redact(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


def _build_embeddings_url(base_url: str) -> str:
    url = base_url.rstrip("/")
    if url.endswith("/v1"):
        return url + "/embeddings"
    if "/v1/" in url:
        return url.rsplit("/v1/", 1)[0] + "/v1/embeddings"
    return url + "/v1/embeddings"


def _build_chat_url(base_url: str) -> str:
    url = base_url.rstrip("/")
    if url.endswith("/v1"):
        return url + "/chat/completions"
    if "/v1/" in url:
        return url.rsplit("/v1/", 1)[0] + "/v1/chat/completions"
    return url + "/v1/chat/completions"


def probe_embedding(
    *,
    base_url: str,
    api_key: str,
    model: str,
    timeout: float = 60.0,
    opener: Any = None,
) -> dict[str, Any]:
    """Probe an OpenAI-compatible embeddings endpoint.

    Returns a dict with ``ok`` (bool), ``dimension`` (int), and ``error``
    (str). ``opener`` is an optional callable matching
    ``urllib.request.urlopen`` (for unit tests).
    """
    if not model:
        return {"ok": False, "dimension": 0, "error": "embedding model is empty"}
    if not base_url:
        return {"ok": False, "dimension": 0, "error": "base_url is empty"}
    url = _build_embeddings_url(base_url)
    payload = json.dumps({"model": model, "input": "hgb"}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    auth_key = _auth_api_key(api_key)
    if auth_key:
        headers["Authorization"] = f"Bearer {auth_key}"
    req = urllib.request.Request(url, data=payload, headers=headers)
    urlopen = opener or urllib.request.urlopen
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            if resp.status != 200:
                return {"ok": False, "dimension": 0, "error": f"HTTP {resp.status}: {_redact(body, [auth_key])[:200]}"}
            data = json.loads(body)
            emb = data.get("data") or data.get("embedding") or data.get("embeddings")
            vector: Any = None
            if isinstance(emb, list) and emb:
                first = emb[0]
                if isinstance(first, dict):
                    vector = first.get("embedding")
                elif isinstance(first, list):
                    vector = first
                elif isinstance(first, (int, float)):
                    vector = emb
            elif isinstance(emb, list):
                vector = emb
            if not isinstance(vector, list) or not vector or not all(isinstance(v, (int, float)) for v in vector):
                return {"ok": False, "dimension": 0, "error": "embedding output is not a numeric non-empty vector"}
            return {"ok": True, "dimension": len(vector), "error": ""}
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")
        except Exception:
            pass
        return {"ok": False, "dimension": 0, "error": f"HTTP {exc.code} {exc.reason}: {_redact(body, [auth_key])[:200]}"}
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return {"ok": False, "dimension": 0, "error": f"{type(exc).__name__}: {_redact(str(exc), [auth_key])[:200]}"}
    except (json.JSONDecodeError, KeyError) as exc:
        return {"ok": False, "dimension": 0, "error": f"{type(exc).__name__}: {exc}"}


def probe_chat(
    *,
    base_url: str,
    api_key: str,
    model: str,
    timeout: float = 60.0,
    opener: Any = None,
) -> dict[str, Any]:
    """Probe an OpenAI-compatible chat completions endpoint.

    Returns a dict with ``ok`` (bool) and ``error`` (str).
    """
    if not model:
        return {"ok": False, "error": "chat model is empty"}
    if not base_url:
        return {"ok": False, "error": "base_url is empty"}
    url = _build_chat_url(base_url)
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": "Return OK."}],
        "max_tokens": 1,
        "temperature": 0,
    }).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    auth_key = _auth_api_key(api_key)
    if auth_key:
        headers["Authorization"] = f"Bearer {auth_key}"
    req = urllib.request.Request(url, data=payload, headers=headers)
    urlopen = opener or urllib.request.urlopen
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            if resp.status != 200:
                return {"ok": False, "error": f"HTTP {resp.status}: {_redact(body, [auth_key])[:200]}"}
            return {"ok": True, "error": ""}
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", "replace")
        except Exception:
            pass
        return {"ok": False, "error": f"HTTP {exc.code} {exc.reason}: {_redact(body, [auth_key])[:200]}"}
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {_redact(str(exc), [auth_key])[:200]}"}


def run_model_preflight(
    env: dict[str, str] | None = None,
    profile: str = "",
    *,
    registry: dict[str, Any] | None = None,
    chat_opener: Any = None,
    embedding_opener: Any = None,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """Run the full CKGFuzzer model preflight: resolve + probe.

    Returns a dict suitable for ``model_preflight.json``. On resolution
    failure, ``status`` is ``resolution_failed``. On probe failure,
    ``status`` is ``probe_failed`` and ``reason_code`` is set. On success,
    ``status`` is ``ok``.
    """
    env = env if env is not None else dict(os.environ)
    result: dict[str, Any] = {
        "status": "ok",
        "reason_code": "",
        "profile": profile,
        "timestamp": time.time(),
        "model_config": {},
        "chat_probe": {},
        "embedding_probe": {},
    }
    try:
        config = resolve_ckgfuzzer_model_config(env, profile, registry=registry)
    except ModelConfigError as exc:
        result["status"] = "resolution_failed"
        result["reason_code"] = "model_resolution_failed"
        result["model_config"] = {"errors": str(exc).split("; ")}
        return result

    result["model_config"] = {
        "provider": config["provider"],
        "chat_model": config["chat_model"],
        "embedding_model": config["embedding_model"],
        "base_url": config["base_url"],
        "chat_base_url": config["chat_base_url"],
        "embedding_base_url": config["embedding_base_url"],
        "embedding_backend": config["embedding_backend"],
        "embedding_model_source": config["embedding_model_source"],
        "embedding_base_url_kind": config["embedding_base_url_kind"],
        "api_key_present": config["api_key_present"],
        "chat_api_key_present": config["chat_api_key_present"],
        "embedding_api_key_present": config["embedding_api_key_present"],
    }

    chat_api_key = _resolve_env(env, CHAT_API_KEY_ALIASES)
    embedding_api_key = _resolve_env(env, EMBEDDING_API_KEY_ALIASES)
    chat_base_url = config["chat_base_url"]
    embedding_base_url = config["embedding_base_url"]

    if not config["chat_api_key_present"]:
        result["status"] = "probe_failed"
        result["reason_code"] = "missing_api_key"
        result["model_config"]["errors"] = ["Chat API key is not configured for the selected provider"]
        return result

    # Chat probe.
    chat_result = probe_chat(
        base_url=chat_base_url, api_key=chat_api_key, model=config["chat_model"],
        timeout=timeout, opener=chat_opener,
    )
    result["chat_probe"] = {"ok": chat_result["ok"], "error": chat_result.get("error", "")}
    result["model_config"]["chat_probe_passed"] = chat_result["ok"]
    if not chat_result["ok"]:
        result["status"] = "probe_failed"
        result["reason_code"] = "chat_probe_failed"
        return result

    # Embedding probe.
    emb_result = probe_embedding(
        base_url=embedding_base_url, api_key=embedding_api_key, model=config["embedding_model"],
        timeout=timeout, opener=embedding_opener,
    )
    result["embedding_probe"] = {
        "ok": emb_result["ok"], "dimension": emb_result.get("dimension", 0),
        "error": emb_result.get("error", ""),
    }
    result["model_config"]["embedding_probe_passed"] = emb_result["ok"]
    result["model_config"]["embedding_dimension"] = emb_result.get("dimension", 0)
    if not emb_result["ok"]:
        result["status"] = "probe_failed"
        result["reason_code"] = "embedding_probe_failed"
        return result

    return result


def write_model_preflight(result: dict[str, Any], path: str | Path) -> None:
    """Write the model preflight result to ``path`` with API keys redacted."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Deep-redact any string value that might contain a key.
    safe = json.loads(json.dumps(result))
    text = json.dumps(safe, indent=2, sort_keys=True)
    # Best-effort: redact common API key patterns.
    text = re.sub(r"(sk-[A-Za-z0-9]{10,})", "[REDACTED]", text)
    path.write_text(text + "\n", encoding="utf-8")


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="CKGFuzzer model resolution and preflight")
    sub = parser.add_subparsers(dest="command")

    resolve_p = sub.add_parser("resolve", help="Resolve model config and print JSON")
    resolve_p.add_argument("--profile", default="")
    resolve_p.add_argument("--env-file", help="JSON file of env vars")

    probe_p = sub.add_parser("preflight", help="Run live model preflight probes")
    probe_p.add_argument("--profile", default="")
    probe_p.add_argument("--env-file", help="JSON file of env vars")
    probe_p.add_argument("--out", default="", help="Write preflight JSON to this path")
    probe_p.add_argument("--timeout", type=float, default=60.0)

    args = parser.parse_args()
    env: dict[str, str] = dict(os.environ)
    if args.env_file:
        env = json.loads(Path(args.env_file).read_text(encoding="utf-8"))
    if args.command == "resolve":
        try:
            config = resolve_ckgfuzzer_model_config(env, args.profile)
            print(json.dumps(config, indent=2, sort_keys=True))
            return 0
        except ModelConfigError as exc:
            print(json.dumps({"errors": str(exc).split("; ")}, indent=2), file=sys.stderr)
            return 1
    if args.command == "preflight":
        result = run_model_preflight(env, args.profile, timeout=args.timeout)
        if args.out:
            write_model_preflight(result, args.out)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "ok" else 1
    parser.print_help()
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
