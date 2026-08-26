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
_ARCHIVE_URL_RE = re.compile(r"https?://[^\s'\"]+(?:\.tar(?:\.[A-Za-z0-9]+)?|\.tgz|\.zip)(?:\?[^\s'\"]*)?")
SEALED_ENV_DEFAULTS: dict[str, str] = {"MERGE_WITH_OSS_FUZZ_CORPORA": "0"}


@dataclass(frozen=True)
class VerificationContext:
    context_dir: str
    dockerfile: str
    mode: str
    removed_acquisition_commands: int
    excluded_synthetic_build_script: bool
    captured_unpinned_source_count: int
    build_tool_fallbacks: int
    sealed_env_defaults: dict[str, str]


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
        if revision_status and revision_status not in {"resolved", "resolved_url", "captured_unpinned"}:
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
        if stripped.startswith("#"):
            # A comment can appear in a continued RUN instruction. It must not
            # terminate that instruction: doing so made the next `sed` line in
            # the systemd Dockerfile look like a Dockerfile instruction.
            if not current:
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


def _split_shell_commands(command: str) -> list[str]:
    """Split top-level shell commands without breaking quoted semicolons.

    Dockerfiles are shell-form instructions. ``str.split(';')`` corrupts
    arguments such as systemd's ``sed -i '119d;126d'``; a small scanner is
    sufficient for the command forms used by FuzzBench recipes.
    """

    pieces: list[str] = []
    start = 0
    quote = ""
    escaped = False
    parentheses = 0
    index = 0
    while index < len(command):
        char = command[index]
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = ""
        elif char in {"'", '"'}:
            quote = char
        elif char == "(":
            parentheses += 1
        elif char == ")" and parentheses:
            parentheses -= 1
        elif not parentheses and char == ";":
            pieces.append(command[start:index].strip())
            start = index + 1
        elif not parentheses and command.startswith("&&", index):
            pieces.append(command[start:index].strip())
            start = index + 2
            index += 1
        index += 1
    pieces.append(command[start:].strip())
    return [piece for piece in pieces if piece]


def _archive_names(command: str) -> set[str]:
    names = {
        Path(match.group(0).split("?", 1)[0]).name
        for match in _ARCHIVE_URL_RE.finditer(command)
    }
    output = re.search(r"(?:^|\s)-o\s+([^\s]+)", command)
    if output:
        names.add(output.group(1).strip("'\""))
    return {name for name in names if name}


def _is_archive_download(command: str) -> bool:
    return bool(re.match(r"^(?:curl|wget)\b", command.strip()) and _ARCHIVE_URL_RE.search(command))


def _is_archive_extract(command: str) -> bool:
    compact = command.strip()
    return bool(re.match(r"^tar\b", compact) and ".tar" in compact)


def _is_archive_cleanup(command: str, archive_names: set[str]) -> bool:
    compact = command.strip()
    if not re.match(r"^rm\b", compact):
        return False
    return ".tar" in compact or any(name in compact for name in archive_names)


def _make_mkdir_idempotent(command: str) -> str:
    """Allow source snapshots to pre-create a directory a recipe makes."""

    compact = command.strip()
    if not compact.startswith("mkdir ") or re.search(r"(?:^|\s)-p(?:\s|$)", compact):
        return command
    return re.sub(r"^\s*mkdir\s+", "mkdir -p ", command, count=1)


def _rewrite_run_instruction(line: str) -> tuple[str, int]:
    if not line.upper().startswith("RUN "):
        return line, 0
    command = line[4:].strip()
    # A branch loop that only clones sources is replaced wholesale. Its branch
    # inputs are captured into source_input by target packaging, so retaining
    # the loop would both reintroduce a moving dependency and collide with the
    # snapshot directory (libjpeg-turbo).
    clone_count = len(re.findall(r"\bgit\s+(?:-[^\s]+\s+)?clone\b", command))
    if clone_count and ("while " in command or "|" in command):
        return "RUN true", clone_count
    # Keep compound OR/pipe control flow unchanged unless it is the explicit
    # source-only clone loop above. Rewriting it without a shell AST is unsafe.
    if "||" in command or "|" in command:
        return line, 0
    archive_names: set[str] = set()
    kept: list[str] = []
    removed = 0
    for piece in _split_shell_commands(command):
        if _is_source_acquisition(piece):
            removed += 1
            continue
        if _is_archive_download(piece):
            archive_names.update(_archive_names(piece))
            removed += 1
            continue
        if _is_archive_extract(piece) or _is_archive_cleanup(piece, archive_names):
            removed += 1
            continue
        kept.append(_make_mkdir_idempotent(piece))
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
                    "ARG FUZZING_ENGINE=libfuzzer",
                    "ARG SANITIZER=address",
                    "ARG ARCHITECTURE=x86_64",
                    "ARG FUZZING_LANGUAGE=c++",
                    "ENV FUZZING_ENGINE=${FUZZING_ENGINE}",
                    "ENV SANITIZER=${SANITIZER}",
                    "ENV ARCHITECTURE=${ARCHITECTURE}",
                    "ENV FUZZING_LANGUAGE=${FUZZING_LANGUAGE}",
                    "ENV HGB_SEALED_VERIFIER=1",
                    "ENV MERGE_WITH_OSS_FUZZ_CORPORA=0",
                    "COPY source_input/ /src/",
                    "COPY hgb_reference_harnesses/ /src/",
                    # HarfBuzz and Mbed TLS use historical Python 3.8/pip
                    # bootstraps that can no longer resolve their dependencies
                    # reliably. Supply the stable distro tools and patch only
                    # those exact bootstraps in the copied build script below.
                    "RUN apt-get -o Acquire::Retries=5 update && apt-get -o Acquire::Retries=5 install -y --fix-missing meson ninja-build python3-pip python3-jinja2 python3-jsonschema m4",
                ]
            )
            inserted_snapshot = True
    if not inserted_snapshot:
        raise VerificationContextError("benchmark Dockerfile has no FROM instruction")
    return "\n".join(output) + "\n", removed


def _copytree(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination, symlinks=True, dirs_exist_ok=False)


def _merge_copytree(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination, symlinks=True, dirs_exist_ok=True)


def _copy_reference_harnesses(target_root: Path, context: Path) -> None:
    """Restore all stripped source harnesses in the verifier-only context.

    ``strip_reference_harnesses`` keeps files directly under
    ``reference_harnesses``. The ``selected`` directory is only metadata for
    choosing the candidate destination and is not a complete source backup.
    Native builds such as Mbed TLS and OpenSSL compile their other fuzzers as
    well, so they require every stripped file before the selected one is
    overlaid with the candidate.
    """

    destination = context / "hgb_reference_harnesses"
    destination.mkdir(parents=True, exist_ok=True)
    references = target_root / "reference_harnesses"
    if not references.is_dir():
        return
    for child in references.iterdir():
        if child.name == "selected":
            continue
        target = destination / child.name
        if child.is_dir() and not child.is_symlink():
            _merge_copytree(child, target)
        elif child.is_file() or child.is_symlink():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(child, target, follow_symlinks=False)

    # Packages created before stripping metadata existed may only have the
    # selected copy. Merge it as a compatibility fallback without exposing the
    # selection-directory name inside /src.
    selected = references / "selected"
    if selected.is_dir():
        for label in selected.iterdir():
            if label.is_dir():
                _merge_copytree(label, destination)


def _patch_legacy_build_tool_bootstrap(context: Path) -> int:
    """Use sealed-image dependencies when historical pip bootstraps fail."""

    build_script = context / "build.sh"
    if not build_script.is_file():
        return 0
    original = build_script.read_text(encoding="utf-8", errors="replace")
    harfbuzz_legacy = "python3.8 -m pip install ninja meson==0.56.0"
    harfbuzz_replacement = (
        "# HGB sealed verifier: install a Meson/Ninja pair new enough for the "
        "captured HarfBuzz source without relying on Python 3.8's stale pip.\n"
        "python3 -m pip install --no-cache-dir 'meson==0.56.0' 'ninja==1.10.2.4'\n"
        "hash -r"
    )
    mbedtls_legacy = "pip3 install -r $SRC/mbedtls/scripts/basic.requirements.txt"
    openssl_fuzzer_guard = 'if [ "$FUZZER" = "centipede" ]'
    openssl_fuzzer_replacement = ': "${FUZZER:=${FUZZING_ENGINE:-libfuzzer}}"\nif [ "$FUZZER" = "centipede" ]'
    mbedtls_replacement = (
        "# HGB sealed verifier: generated Mbed TLS wrappers only require the "
        "Ubuntu jsonschema package; avoid an unpinned pip/Rust bootstrap.\n"
        "export PYTHONPATH=/usr/lib/python3/dist-packages${PYTHONPATH:+:$PYTHONPATH}\n"
        "python3.8 -c 'import jsonschema'"
    )
    freetype_archive = "tar xf libarchive-3.4.3.tar.xz"
    freetype_replacement = (
        "# HGB sealed verifier: the source snapshot already contains the "
        "extracted libarchive tree, while the downloaded tarball is removed.\n"
        "[ -d libarchive-3.4.3 ] || tar xf libarchive-3.4.3.tar.xz"
    )
    patched = original.replace(harfbuzz_legacy, harfbuzz_replacement)
    patched = patched.replace(mbedtls_legacy, mbedtls_replacement)
    patched = patched.replace(openssl_fuzzer_guard, openssl_fuzzer_replacement)
    patched = patched.replace(freetype_archive, freetype_replacement)
    fuzzer_lib_fallback = (
        "# HGB sealed verifier: older OSS-Fuzz scripts link $FUZZER_LIB; "
        "prefer the current libFuzzer driver flag when that engine is active.\n"
        'if [ "${FUZZING_ENGINE:-libfuzzer}" = "libfuzzer" ]; then\n'
        '  : "${FUZZER_LIB:=${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}}"\n'
        'else\n'
        '  : "${FUZZER_LIB:=${LIB_FUZZING_ENGINE_DEPRECATED:-/usr/lib/libFuzzingEngine.a}}"\n'
        'fi\n'
        "export FUZZER_LIB"
    )
    fuzzer_lib_needs_alias = (
        "FUZZER_LIB" in original
        and "HGB sealed verifier: older OSS-Fuzz scripts link $FUZZER_LIB" not in original
        and not re.search(r"(?m)^\s*(?:export\s+)?FUZZER_LIB=", original)
    )
    if fuzzer_lib_needs_alias:
        patched_lines = patched.splitlines()
        insert_at = 1 if patched_lines and patched_lines[0].startswith("#!") else 0
        patched_lines[insert_at:insert_at] = fuzzer_lib_fallback.splitlines()
        patched = "\n".join(patched_lines) + ("\n" if patched.endswith("\n") or original.endswith("\n") else "")
    if patched == original:
        return 0
    build_script.write_text(patched, encoding="utf-8")
    return (
        int(harfbuzz_legacy in original)
        + int(mbedtls_legacy in original)
        + int(openssl_fuzzer_guard in original)
        + int(freetype_archive in original)
        + int(fuzzer_lib_needs_alias)
    )


def prepare_verification_context(target_root: Path, work_dir: Path) -> dict[str, Any]:
    """Create a Docker context whose sources are the target-package snapshot."""

    _assert_reproducible_sources(target_root)
    captured_unpinned_source_count = sum(
        1
        for record in _source_records(target_root)
        if record.get("revision_status") == "captured_unpinned"
    )
    benchmark = target_root / "fuzzbench_benchmark"
    dockerfile = benchmark / "Dockerfile"
    if not dockerfile.is_file():
        raise VerificationContextError(f"missing FuzzBench Dockerfile: {dockerfile}")

    context = work_dir / "sealed_context"
    if context.exists():
        shutil.rmtree(context)
    _copytree(benchmark, context)
    _copytree(target_root / "source_input", context / "source_input")
    _copy_reference_harnesses(target_root, context)

    synthetic_build = context / "build.sh"
    excluded_synthetic_build = False
    if synthetic_build.is_file() and _SYNTHETIC_BUILD_SCRIPT_MARKER in synthetic_build.read_text(
        encoding="utf-8", errors="replace"
    ):
        synthetic_build.unlink()
        excluded_synthetic_build = True

    build_tool_fallbacks = _patch_legacy_build_tool_bootstrap(context)

    rewritten, removed = _rewrite_dockerfile(dockerfile)
    sealed_dockerfile = context / "Dockerfile"
    sealed_dockerfile.write_text(rewritten, encoding="utf-8")
    result = VerificationContext(
        context_dir=str(context),
        dockerfile=str(sealed_dockerfile),
        mode="sealed_source_snapshot",
        removed_acquisition_commands=removed,
        excluded_synthetic_build_script=excluded_synthetic_build,
        captured_unpinned_source_count=captured_unpinned_source_count,
        build_tool_fallbacks=build_tool_fallbacks,
        sealed_env_defaults=dict(SEALED_ENV_DEFAULTS),
    )
    return asdict(result)
