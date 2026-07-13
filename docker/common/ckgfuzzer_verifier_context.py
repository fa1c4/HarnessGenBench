#!/usr/bin/env python3
"""Build a sealed CKGFuzzer candidate-verification Docker context.

FuzzBench Dockerfiles routinely acquire source with unpinned ``git clone``
commands.  Replaying those commands during verification tests a moving
upstream revision rather than the source that was analysed.  This helper
builds a local Docker context from the prepared ``source_input`` snapshots and
removes only the Dockerfile acquisition commands that would replace them.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


_SYNTHETIC_BUILD_SCRIPT_MARKER = "FuzzBench benchmark did not include a top-level build.sh"
_SHELL_SEPARATORS = re.compile(r"\s*(?:&&|;)\s*")


@dataclass(frozen=True)
class VerificationContext:
    context_dir: str
    dockerfile: str
    mode: str
    removed_acquisition_commands: int
    excluded_synthetic_build_script: bool


class VerificationContextError(RuntimeError):
    """The target package cannot provide a reproducible verifier context."""


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationContextError(f"invalid JSON metadata: {path}: {exc}") from exc


def _source_records(target_root: Path) -> list[dict[str, Any]]:
    path = target_root / "source_repos.json"
    if path.is_file():
        data = _read_json(path)
        if isinstance(data, list):
            return [record for record in data if isinstance(record, dict)]
    manifest_path = target_root / "target_manifest.json"
    if manifest_path.is_file():
        data = _read_json(manifest_path)
        records = data.get("source_repos", []) if isinstance(data, dict) else []
        if isinstance(records, list):
            return [record for record in records if isinstance(record, dict)]
    raise VerificationContextError("target package does not provide source repository provenance")


def _assert_reproducible_sources(target_root: Path) -> None:
    source_input = target_root / "source_input"
    if not source_input.is_dir() or not any(source_input.iterdir()):
        raise VerificationContextError("target package has no source_input snapshot")

    unresolved: list[str] = []
    for record in _source_records(target_root):
        location = str(record.get("url") or record.get("dest") or "unknown source")
        kind = str(record.get("kind", "git"))
        copy_status = str(record.get("copy_status", ""))
        materialize_status = str(record.get("materialize_status", ""))
        checkout_status = str(record.get("checkout_status", ""))
        revision_status = str(record.get("revision_status", ""))
        if copy_status not in {"copied_to_source_input", "copied_to_package"}:
            unresolved.append(f"{location}: source snapshot was not copied ({copy_status or materialize_status or 'unknown'})")
            continue
        if revision_status and revision_status not in {"resolved", "resolved_url"}:
            unresolved.append(f"{location}: source revision is {revision_status}")
            continue
        if kind == "git" and checkout_status in {"", "kept_head_no_commit", "commit_not_found_kept_head"}:
            unresolved.append(f"{location}: repository revision is not pinned ({checkout_status or 'unknown'})")
    if unresolved:
        raise VerificationContextError("; ".join(unresolved))


def _logical_dockerfile_lines(dockerfile: Path) -> list[str]:
    logical: list[str] = []
    current = ""
    for raw in dockerfile.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        if not current and stripped.startswith("#"):
            logical.append(stripped)
            continue
        if stripped.endswith("\\"):
            current += stripped[:-1].rstrip() + " "
            continue
        current += stripped
        logical.append(current)
        current = ""
    if current:
        logical.append(current)
    return logical


def _is_source_acquisition(command: str) -> bool:
    compact = command.strip()
    return bool(
        re.match(r"^git\s+(?:-[^\s]+(?:\s+[^\s]+)?\s+)*clone\b", compact)
        or re.match(r"^git\s+-C\s+\S+\s+(?:checkout|fetch)\b", compact)
        or re.match(r"^git\s+(?:checkout|fetch)\b", compact)
    )


def _rewrite_run_instruction(line: str) -> tuple[str, int]:
    if not line.upper().startswith("RUN "):
        return line, 0
    command = line[4:].strip()
    # Keep the non-git setup portions of a compound RUN. Dockerfiles with
    # shell OR/pipe control flow are intentionally left unchanged: silently
    # changing that control flow would be less reproducible than rejecting the
    # context at build time.
    if "||" in command or "|" in command:
        return line, 0
    pieces = _SHELL_SEPARATORS.split(command)
    kept = [piece for piece in pieces if piece and not _is_source_acquisition(piece)]
    removed = len(pieces) - len(kept)
    if not removed:
        return line, 0
    return "RUN " + (" && ".join(kept) if kept else "true"), removed


def _rewrite_dockerfile(dockerfile: Path) -> tuple[str, int]:
    output: list[str] = []
    inserted_snapshot = False
    removed = 0
    for line in _logical_dockerfile_lines(dockerfile):
        rewritten, count = _rewrite_run_instruction(line)
        output.append(rewritten)
        removed += count
        if not inserted_snapshot and rewritten.upper().startswith("FROM "):
            output.extend(
                [
                    "# HGB sealed verifier source snapshot.",
                    "ENV HGB_SEALED_VERIFIER=1",
                    "COPY source_input/ /src/",
                ]
            )
            inserted_snapshot = True
    if not inserted_snapshot:
        raise VerificationContextError("benchmark Dockerfile has no FROM instruction")
    return "\n".join(output) + "\n", removed


def _copytree(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination, symlinks=True, dirs_exist_ok=False)


def prepare_verification_context(target_root: Path, work_dir: Path) -> dict[str, Any]:
    """Create a Docker context whose sources are the target-package snapshot."""

    _assert_reproducible_sources(target_root)
    benchmark = target_root / "fuzzbench_benchmark"
    dockerfile = benchmark / "Dockerfile"
    if not dockerfile.is_file():
        raise VerificationContextError(f"missing FuzzBench Dockerfile: {dockerfile}")

    context = work_dir / "sealed_context"
    if context.exists():
        shutil.rmtree(context)
    _copytree(benchmark, context)
    _copytree(target_root / "source_input", context / "source_input")

    synthetic_build = context / "build.sh"
    excluded_synthetic_build = False
    if synthetic_build.is_file() and _SYNTHETIC_BUILD_SCRIPT_MARKER in synthetic_build.read_text(
        encoding="utf-8", errors="replace"
    ):
        synthetic_build.unlink()
        excluded_synthetic_build = True

    rewritten, removed = _rewrite_dockerfile(dockerfile)
    sealed_dockerfile = context / "Dockerfile"
    sealed_dockerfile.write_text(rewritten, encoding="utf-8")
    result = VerificationContext(
        context_dir=str(context),
        dockerfile=str(sealed_dockerfile),
        mode="sealed_source_snapshot",
        removed_acquisition_commands=removed,
        excluded_synthetic_build_script=excluded_synthetic_build,
    )
    return asdict(result)
