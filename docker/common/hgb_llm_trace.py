#!/usr/bin/env python3
"""Best-effort sampled LLM request/response tracing for HGB generators."""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
_LOCK = threading.Lock()
_SEQUENCE = 0


def enabled() -> bool:
    return os.environ.get("HGB_LLM_TRACE_ENABLED", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def trace_dir() -> Path:
    return Path(os.environ.get("HGB_LLM_TRACE_DIR") or "/workspace/api_traces")


def _warn(message: str) -> None:
    print(f"hgb_llm_trace: {message}", file=sys.stderr)


def _secret_values() -> list[str]:
    names = (
        "OPENAI_API_KEY",
        "API_KEY",
        "DEEPSEEK_API_KEY",
        "HF_TOKEN",
        "CKGFUZZER_EMBEDDING_API_KEY",
        "PROME_FUZZ_EMBEDDING_API_KEY",
    )
    return [value for value in (os.environ.get(name, "") for name in names) if value]


def redact(value: Any) -> Any:
    """Recursively redact secrets while preserving inspectable structure."""
    try:
        if isinstance(value, dict):
            redacted = {}
            for key, item in value.items():
                key_str = str(key)
                if key_str.lower() in {"api_key", "apikey", "authorization"}:
                    redacted[key_str] = "[REDACTED]"
                else:
                    redacted[key_str] = redact(item)
            return redacted
        if isinstance(value, (list, tuple, set)):
            return [redact(item) for item in value]
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        if isinstance(value, str):
            text = value
            for secret in _secret_values():
                text = text.replace(secret, "[REDACTED]")
            text = re.sub(
                r"(authorization\s*:\s*bearer\s+)[^\s,}'\"]+",
                r"\1[REDACTED]",
                text,
                flags=re.I,
            )
            text = re.sub(
                r'("api_key"\s*:\s*")[^"]+(")',
                r"\1[REDACTED]\2",
                text,
                flags=re.I,
            )
            text = re.sub(
                r"('api_key'\s*:\s*')[^']+(')",
                r"\1[REDACTED]\2",
                text,
                flags=re.I,
            )
            text = re.sub(
                r"(api_key\s*[:=]\s*)[^\s,}'\"]+",
                r"\1[REDACTED]",
                text,
                flags=re.I,
            )
            return text
        return value
    except Exception as exc:  # noqa: BLE001 - tracing must not break generation.
        _warn(f"redaction failed: {exc}")
        return "[HGB_TRACE_REDACTION_FAILED]"


def _json_default(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        try:
            return value.model_dump()
        except Exception:
            pass
    if hasattr(value, "dict"):
        try:
            return value.dict()
        except Exception:
            pass
    if hasattr(value, "to_dict"):
        try:
            return value.to_dict()
        except Exception:
            pass
    if hasattr(value, "__dict__"):
        try:
            return {
                key: item
                for key, item in vars(value).items()
                if not key.startswith("_")
            }
        except Exception:
            pass
    return str(value)


def safe_serialize(value: Any) -> Any:
    """Convert provider objects to JSON-compatible redacted data."""
    try:
        text = json.dumps(value, default=_json_default, ensure_ascii=False)
        return redact(json.loads(text))
    except Exception:
        return redact(str(value))


def _next_sequence() -> int:
    global _SEQUENCE
    with _LOCK:
        _SEQUENCE += 1
        return _SEQUENCE


def sample_decision(sequence: int) -> str:
    """Return sample reason or empty string."""
    if not enabled():
        return ""
    if os.environ.get("HGB_LLM_TRACE_FIRST", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    } and sequence == 1:
        return "first"
    try:
        rate = int(os.environ.get("HGB_LLM_TRACE_SAMPLE_RATE", "100") or "100")
    except ValueError:
        rate = 100
    if rate <= 0:
        return ""
    if sequence % rate == 0:
        return f"every_{rate}"
    return ""


def _summary_path(root: Path) -> Path:
    return root / "summary.json"


def _samples_path(root: Path) -> Path:
    return root / "llm_api_samples.jsonl"


def _read_summary(root: Path) -> dict[str, Any]:
    path = _summary_path(root)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "schema_version": SCHEMA_VERSION,
            "total_count": 0,
            "sample_count": 0,
            "sample_rate": os.environ.get("HGB_LLM_TRACE_SAMPLE_RATE", "100"),
            "trace_file": str(_samples_path(root)),
        }


def _write_summary(root: Path, sampled: bool) -> None:
    summary = _read_summary(root)
    summary["schema_version"] = SCHEMA_VERSION
    summary["total_count"] = int(summary.get("total_count") or 0) + 1
    if sampled:
        summary["sample_count"] = int(summary.get("sample_count") or 0) + 1
    summary["sample_rate"] = os.environ.get("HGB_LLM_TRACE_SAMPLE_RATE", "100")
    summary["trace_file"] = str(_samples_path(root))
    summary["updated_at"] = datetime.now(timezone.utc).isoformat()
    _summary_path(root).write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def usage_from_response(response: Any) -> Any:
    if response is None:
        return None
    for attr in ("usage",):
        usage = getattr(response, attr, None)
        if usage is not None:
            return safe_serialize(usage)
    if isinstance(response, dict) and "usage" in response:
        return safe_serialize(response.get("usage"))
    return None


def content_from_response(response: Any) -> Any:
    """Keep useful full response content while handling provider objects."""
    return safe_serialize(response)


def record(
    *,
    stage: str,
    provider: str,
    operation: str,
    model: str = "",
    request: Any = None,
    response: Any = None,
    error: BaseException | str | None = None,
    started_at: float | None = None,
    usage: Any = None,
) -> None:
    """Record one attempted API interaction, sampling full payloads."""
    if not enabled():
        return
    sequence = _next_sequence()
    reason = sample_decision(sequence)
    root = trace_dir()
    try:
        root.mkdir(parents=True, exist_ok=True)
        _write_summary(root, bool(reason))
        if not reason:
            return
        now = time.time()
        start = started_at if started_at is not None else now
        if error is not None:
            error_payload = {
                "type": type(error).__name__ if not isinstance(error, str) else "Error",
                "message": str(error),
            }
            if not isinstance(error, str):
                error_payload["traceback"] = "".join(
                    traceback.format_exception(type(error), error, error.__traceback__)
                )
        else:
            error_payload = None
        payload = {
            "schema_version": SCHEMA_VERSION,
            "trace_id": str(uuid.uuid4()),
            "sequence": sequence,
            "sample_reason": reason,
            "generator": os.environ.get("HGB_GENERATOR", ""),
            "target": os.environ.get("HGB_TARGET", ""),
            "stage": stage,
            "provider": provider,
            "operation": operation,
            "model": model,
            "started_at": datetime.fromtimestamp(start, timezone.utc).isoformat(),
            "duration_ms": int(max(0.0, now - start) * 1000),
            "status": "error" if error is not None else "ok",
            "request": safe_serialize(request),
            "response": content_from_response(response) if error is None else None,
            "error": safe_serialize(error_payload) if error is not None else None,
            "usage": safe_serialize(usage) if usage is not None else usage_from_response(response),
        }
        with _samples_path(root).open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    except Exception as exc:  # noqa: BLE001 - tracing must not break generation.
        _warn(f"write failed: {exc}")


def trace_call(
    func: Any,
    *,
    stage: str,
    provider: str,
    operation: str,
    model: str = "",
    request: Any = None,
):
    """Call func and trace the sampled request/response or error."""
    started = time.time()
    try:
        response = func()
    except Exception as exc:  # noqa: BLE001
        record(
            stage=stage,
            provider=provider,
            operation=operation,
            model=model,
            request=request,
            error=exc,
            started_at=started,
        )
        raise
    record(
        stage=stage,
        provider=provider,
        operation=operation,
        model=model,
        request=request,
        response=response,
        started_at=started,
    )
    return response


def summary_counts(root: str | Path | None = None) -> tuple[int, int]:
    base = Path(root) if root else trace_dir()
    data = _read_summary(base)
    return int(data.get("total_count") or 0), int(data.get("sample_count") or 0)

