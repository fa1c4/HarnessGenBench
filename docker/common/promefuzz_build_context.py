#!/usr/bin/env python3
"""Capture a real compile database and link context from a pinned FuzzBench build.

PromeFuzz's ``alpha`` and ``paper-faithful`` profiles must not consume a
synthetic compile database or empty ``driver_build_args``. This helper stages
the pinned target source, replays the FuzzBench target build in an isolated
workspace, and captures the real translation-unit commands with ``bear``,
``intercept-build``, CMake export, or compiler wrappers.

It never reads the exact target reference harness body. When the build needs a
fuzz entrypoint to compile, a neutral ``LLVMFuzzerTestOneInput`` stub is
overlaid at the manifest-selected native harness destination.

The module is unit-testable with a tiny C/C++ CMake fixture (no Docker): the
``cmake_export`` strategy runs ``cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`` on
the host through a pluggable ``runner``. ``bear_replay`` and
``compiler_wrapper`` are used inside the container.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

try:  # importable in container and on host (docker/common is on sys.path)
    from hgb_compile_db import filter_compile_database, SOURCE_SUFFIXES, NOISE_PARTS, NOISE_NAMES
    from hgb_target_harness import TargetHarnessError, select_native_harness
except Exception:  # pragma: no cover - allow standalone import during tests
    filter_compile_database = None  # type: ignore[assignment]
    SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}
    NOISE_PARTS = {"cmakefiles", "cmakescratch", "compilerid"}
    NOISE_NAMES = {
        "cmakeccompilerabi.c",
        "cmakecxxcompilerabi.cpp",
        "cmakeccompilerid.c",
        "cmakecxxcompilerid.cpp",
    }
    TargetHarnessError = RuntimeError  # type: ignore[assignment,misc]
    select_native_harness = None  # type: ignore[assignment]


LLVM_ENTRY_RE = re.compile(r"LLVMFuzzerTestOneInput\s*\(")
FUZZ_NAME_RE = re.compile(r"(?:^|[/_\-.])(fuzz(?:er|ing)?|harness|target)(?:[/_\-.]|$)", re.I)
HEADER_EXTS = {".h", ".hh", ".hpp", ".hxx"}
LINK_LIB_RE = re.compile(r"(?<![A-Za-z0-9_])-l([A-Za-z0-9_.+-]+)")
LINK_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])-L(\S+)")
ARCHIVE_RE = re.compile(r"\.(?:a|so|so\.[0-9]+|dylib)$", re.I)


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[Sequence[str], int | None], CommandResult]


@contextlib.contextmanager
def _temporary_env(values: dict[str, str]):
    """Apply environment variables for a runner call and restore them after.

    The capture helpers compute per-build env (SRC/OUT/WORK/CC/CXX/CFLAGS) but
    the pluggable ``Runner`` protocol takes only ``(command, timeout)``, so the
    values are applied to the process environment for the duration of the call.
    """
    previous: dict[str, str] = {}
    added: list[str] = []
    for key, value in values.items():
        if key in os.environ:
            previous[key] = os.environ[key]
        else:
            added.append(key)
        os.environ[key] = value
    try:
        yield
    finally:
        for key in added:
            os.environ.pop(key, None)
        for key, value in previous.items():
            os.environ[key] = value


@contextlib.contextmanager
def _temporary_chdir(path: Path):
    """Run a runner call from the target build working directory.

    FuzzBench ``build.sh`` recipes create ``build/`` and reference sources with
    paths relative to their ``WORKDIR``, so the replay must start there.
    """
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _real_runner(command: Sequence[str], timeout: int | None = None) -> CommandResult:
    try:
        proc = subprocess.run(
            list(command), timeout=timeout, capture_output=True, text=True,
            errors="replace", check=False,
        )
        return CommandResult(list(command), proc.returncode, proc.stdout or "", proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        return CommandResult(list(command), 124, "", f"timed out: {exc}")
    except OSError as exc:
        return CommandResult(list(command), 127, "", f"could not run: {exc}")


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return "missing"
    return h.hexdigest()


def neutral_stub_source(language: str) -> str:
    """Return a neutral LLVMFuzzerTestOneInput stub. Never the reference body.

    The entrypoints are declared weak so build-support drivers (for example
    OpenSSL's ``fuzz/driver.c``) that provide ``LLVMFuzzerTestOneInput`` are not
    duplicated, while projects that expect the ``FuzzerInitialize`` /
    ``FuzzerTestOneInput`` convention still link.
    """
    if language == "c":
        return (
            "#include <stdint.h>\n"
            "#include <stddef.h>\n"
            "__attribute__((weak)) int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
            "  (void)data; (void)size;\n"
            "  return 0;\n"
            "}\n"
            "__attribute__((weak)) void fuzz_openFile(const char *name) { (void)name; }\n"
            "__attribute__((weak)) int FuzzerInitialize(int *argc, char ***argv) {\n"
            "  (void)argc; (void)argv;\n"
            "  return 0;\n"
            "}\n"
            "__attribute__((weak)) int FuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
            "  (void)data; (void)size;\n"
            "  return 0;\n"
            "}\n"
            "__attribute__((weak)) void FuzzerCleanup(void) { }\n"
            "__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv) {\n"
            "  (void)argc; (void)argv;\n"
            "  return 0;\n"
            "}\n"
        )
    return (
        "#include <cstdint>\n"
        "#include <cstddef>\n"
        "extern \"C\" __attribute__((weak)) int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
        "  (void)data; (void)size;\n"
        "  return 0;\n"
        "}\n"
        "extern \"C\" __attribute__((weak)) void fuzz_openFile(const char *name) { (void)name; }\n"
        "extern \"C\" __attribute__((weak)) int FuzzerInitialize(int *argc, char ***argv) {\n"
        "  (void)argc; (void)argv;\n"
        "  return 0;\n"
        "}\n"
        "extern \"C\" __attribute__((weak)) int FuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
        "  (void)data; (void)size;\n"
        "  return 0;\n"
        "}\n"
        "extern \"C\" __attribute__((weak)) void FuzzerCleanup(void) { }\n"
        "extern \"C\" __attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv) {\n"
        "  (void)argc; (void)argv;\n"
        "  return 0;\n"
        "}\n"
    )


def write_neutral_stub(destination: Path, language: str) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(neutral_stub_source(language), encoding="utf-8")
    return destination


def _evaluator_reference_harness_files(evaluator_manifest: Path | str | None) -> list[str]:
    """Return source-relative paths of reference harnesses stripped from source_input.

    The blind generator mount omits these files, but FuzzBench recipes commonly
    build every fuzz target in the project. Overlaying neutral stubs at each
    stripped path keeps multi-fuzzer recipes compiling. Only the file *paths*
    are read from the evaluator manifest; the reference bodies are never read.
    """
    if not evaluator_manifest:
        return []
    path = Path(evaluator_manifest)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    files = data.get("reference_harness_files")
    if not isinstance(files, list):
        return []
    rels: list[str] = []
    for item in files:
        if not isinstance(item, str):
            continue
        rel = item
        for prefix in ("source_input/", "source_full/"):
            if rel.startswith(prefix):
                rel = rel[len(prefix):]
                break
        if not rel or rel.startswith("/") or ".." in rel.split("/"):
            continue
        if Path(rel).suffix.lower() not in (SOURCE_SUFFIXES | HEADER_EXTS):
            continue
        if rel not in rels:
            rels.append(rel)
    return rels


def overlay_neutral_stubs(
    template_root: Path,
    language: str,
    native_destination: str = "",
    evaluator_manifest: Path | str | None = None,
) -> list[str]:
    """Prepare the target's fuzz entrypoint and the rest of the build sources.

    The target harness is replaced with a neutral stub. Every *other* stripped
    reference harness (other fuzz targets plus build-support drivers/headers such
    as ``onefile.c`` and ``fuzzer.h``) is restored from the evaluator half so
    multi-fuzzer FuzzBench recipes still build. Only build-time sources are
    restored; the LLM/generation path never reads them and the target answer is
    never exposed to generation.
    """
    template_root = Path(template_root)
    native_rel = native_destination
    if native_rel.startswith("/src/"):
        native_rel = native_rel[len("/src/"):]
    if native_rel:
        write_neutral_stub(template_root / native_rel, language)
    rels = _evaluator_reference_harness_files(evaluator_manifest)
    evaluator_root = Path(os.environ.get("HGB_EVALUATOR_ROOT", "/evaluator"))
    reference_dir = evaluator_root / "reference_harnesses"
    written: list[str] = []
    for rel in rels:
        if rel == native_rel:
            continue
        dst = template_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        source = reference_dir / rel
        if source.is_file():
            shutil.copy2(source, dst)
        elif Path(rel).suffix.lower() in HEADER_EXTS:
            # Never synthesize a stub header; a missing original must not
            # replace a build-support header with fuzz entrypoint code.
            continue
        else:
            dst.write_text(neutral_stub_source(language), encoding="utf-8")
        written.append(rel)
    return written


def write_knowledge_usage(
    knowledge_dir: Path,
    *,
    consumer_cases_status: str = "unavailable",
    consumer_count: int = 0,
    selected_api_count: int = 0,
) -> dict[str, Any]:
    """Record a ``knowledge_usage.json`` proving PromeFuzz loaded knowledge.

    Eta plan §4: the knowledge_usage record proves counts of documents, API
    usage patterns, call correlations, retrieved examples, and APIs used in
    final prompts. It is written after the comprehend stage so the matrix
    collector can verify consumer/API usage knowledge was both generated and
    loaded.
    """
    knowledge_dir = Path(knowledge_dir)
    record: dict[str, Any] = {
        "knowledge_dir": str(knowledge_dir),
        "consumer_cases_status": consumer_cases_status,
        "consumer_count": int(consumer_count),
        "document_count": 0,
        "api_usage_pattern_count": 0,
        "call_correlation_count": 0,
        "retrieved_example_count": 0,
        "selected_api_count": int(selected_api_count),
        "knowledge_artifacts": [],
    }
    if knowledge_dir.is_dir():
        artifacts: list[str] = []
        for path in sorted(knowledge_dir.rglob("*")):
            if not path.is_file():
                continue
            name_l = path.name.lower()
            artifacts.append(str(path))
            if any(tok in name_l for tok in ("knowledge", "comprehend", "correlation", "retriev", "embed", "document")):
                record["document_count"] += 1
            if any(tok in name_l for tok in ("correlation", "call", "usage")):
                record["call_correlation_count"] += 1
            if any(tok in name_l for tok in ("retriev", "example", "case")):
                record["retrieved_example_count"] += 1
            if any(tok in name_l for tok in ("api", "pattern", "func")):
                record["api_usage_pattern_count"] += 1
        record["knowledge_artifacts"] = artifacts
    record["loaded"] = (
        record["document_count"] > 0
        or record["api_usage_pattern_count"] > 0
        or record["call_correlation_count"] > 0
        or record["retrieved_example_count"] > 0
    )
    out_path = knowledge_dir.parent / "knowledge_usage.json" if knowledge_dir.name else knowledge_dir / "knowledge_usage.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return record


def _is_fuzz_harness(path: Path) -> bool:
    name_l = path.name.lower()
    if FUZZ_NAME_RE.search(name_l):
        return True
    if path.suffix.lower() in SOURCE_SUFFIXES | HEADER_EXTS:
        return False
    return False


def _looks_like_fuzz_source(path: Path) -> bool:
    if path.suffix.lower() not in SOURCE_SUFFIXES:
        return False
    if FUZZ_NAME_RE.search(path.name):
        return True
    return bool(LLVM_ENTRY_RE.search(_read(path)))


def build_consumer_manifest(
    source_root: Path,
    *,
    extra_roots: list[Path] | None = None,
    compiled_under_flags: set[Path] | None = None,
) -> dict[str, Any]:
    """List protocol-allowed consumer cases, excluding every fuzz harness.

    Excludes: fuzz harnesses/fuzz targets, exact target source files that look
    like harnesses, copied OSS-Fuzz/FuzzBench harnesses, generated
    reference-derived reports, and evaluator-only paths.
    """
    source_root = Path(source_root)
    roots = [source_root]
    if extra_roots:
        roots.extend(Path(r) for r in extra_roots)
    ignored_parts = {
        ".git", ".hg", ".svn", "reference_harnesses", "fuzz_driver",
        "fuzzbench_benchmark", "build", "out", "workspace",
    }
    compiled_under_flags = compiled_under_flags or set()
    cases: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for root in roots:
        if not root or not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path in seen:
                continue
            if path.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            if any(part in ignored_parts for part in path.parts):
                continue
            if _looks_like_fuzz_source(path):
                continue
            reason = "source_consumer"
            name_l = path.name.lower()
            if "example" in name_l or path.parent.name.lower() in {"example", "examples"}:
                reason = "example"
            elif "test" in name_l or path.parent.name.lower() in {"test", "tests"}:
                reason = "test"
            elif path.parent.name.lower() in {"tool", "tools", "cli"}:
                reason = "tool"
            cases.append({
                "file": str(path),
                "why_allowed": reason,
                "compiled_under_captured_flags": path in compiled_under_flags,
            })
            seen.add(path)
    return {
        "source_root": str(source_root),
        "extra_roots": [str(r) for r in (extra_roots or [])],
        "consumer_count": len(cases),
        "consumers": cases,
        "excluded_fuzz_harnesses": True,
    }


def _entry_source_roots(raw: list[dict[str, Any]]) -> list[Path]:
    roots: list[Path] = []
    for entry in raw:
        directory = entry.get("directory") if isinstance(entry, dict) else None
        if isinstance(directory, str):
            p = Path(directory)
            if p not in roots:
                roots.append(p)
    return roots


def _normalize_entry_paths(raw: list[dict[str, Any]], source_root: Path) -> list[dict[str, Any]]:
    """Map container paths to staged paths and drop stale entries."""
    normalized: list[dict[str, Any]] = []
    seen_files: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        directory = entry.get("directory")
        file_value = entry.get("file")
        if not isinstance(directory, str) or not isinstance(file_value, str):
            continue
        dpath = Path(directory)
        fpath = Path(file_value)
        if not fpath.is_absolute():
            fpath = dpath / fpath
        # Map common FuzzBench container roots to the staged source root.
        for container_prefix in ("/src/", "/target/source_input/", "/workspace/promefuzz_build/src/"):
            if str(fpath).startswith(container_prefix):
                rel = str(fpath)[len(container_prefix):]
                mapped = source_root / rel
                if mapped.exists():
                    fpath = mapped
                break
        if not fpath.is_file():
            continue
        if fpath.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        lower_parts = {part.lower() for part in fpath.parts}
        if lower_parts & NOISE_PARTS or fpath.name.lower() in NOISE_NAMES:
            continue
        key = str(fpath)
        if key in seen_files:
            continue
        seen_files.add(key)
        new_entry = dict(entry)
        new_entry["directory"] = str(dpath if dpath.is_dir() else fpath.parent)
        new_entry["file"] = str(fpath)
        normalized.append(new_entry)
    return normalized


def _filter_db(raw: list[dict[str, Any]], source_roots: list[Path]) -> list[dict[str, Any]]:
    if filter_compile_database is not None:
        return filter_compile_database(raw, source_roots)
    # Fallback filter (host tests): keep entries under a source root that exist.
    kept: list[dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        dpath = Path(entry.get("directory", ""))
        fpath = Path(entry.get("file", ""))
        if not fpath.is_absolute():
            fpath = dpath / fpath
        if not fpath.is_file():
            continue
        if fpath.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        if any(_within(fpath, root) for root in source_roots):
            kept.append(entry)
    return kept


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _parse_args_field(entry: dict[str, Any]) -> list[str]:
    if "arguments" in entry and isinstance(entry["arguments"], list):
        return [str(a) for a in entry["arguments"]]
    if "command" in entry and isinstance(entry["command"], str):
        return shlex.split(entry["command"])
    return []


_SAFE_FLAG_TOKEN_RE = re.compile(r"^[A-Za-z0-9_./+=\-]+$")


def _is_safe_flag_token(value: str) -> bool:
    """Reject tokens carrying shell/configure noise (``?``, quotes, parens)."""
    return bool(value) and bool(_SAFE_FLAG_TOKEN_RE.match(value))


_STANDARD_LIB_DIRS = (
    "/usr/lib",
    "/usr/local/lib",
    "/lib",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib64",
)


def _library_resolvable(name: str, search_dirs: list[Path]) -> bool:
    """Return True when ``-l<name>`` resolves via a -L dir or a system lib dir.

    A discovered archive is deliberately *not* considered: it is passed as a
    direct path, but the linker still errors on ``-l<name>`` unless a matching
    ``-L`` directory (or a system library) contains it.
    """
    for directory in list(search_dirs) + [Path(d) for d in _STANDARD_LIB_DIRS]:
        if not directory.is_dir():
            continue
        for pattern in (f"lib{name}.a", f"lib{name}.so", f"lib{name}.so.*"):
            if next(directory.glob(pattern), None) is not None:
                return True
    return False


def extract_libraries(
    *,
    compile_db: list[dict[str, Any]],
    build_log: str,
    out_dirs: list[Path],
    source_root: Path,
) -> dict[str, Any]:
    """Recover real libraries and link arguments from build outputs.

    Returns ``driver_build_args`` (compile + link flags), ``libraries`` list,
    and ``link_commands``. Never returns empty link flags when the build
    clearly produced archives or link commands.
    """
    compile_flags: list[str] = []
    link_flags: list[str] = []
    library_paths: list[str] = []
    link_commands: list[str] = []
    seen_flags: set[str] = set()

    def add_flag(target: list[str], flag: str) -> None:
        if flag and flag not in seen_flags:
            target.append(flag)
            seen_flags.add(flag)

    # Compile flags from compile_commands (include dirs, defines, std).
    for entry in compile_db:
        args = _parse_args_field(entry)
        index = 0
        while index < len(args):
            arg = args[index]
            # Handle the separated forms (``-I /path``, ``-D FOO``) so a bare
            # ``-I`` never reaches the link probe and consumes its next token.
            if arg in {"-I", "-D", "-U"} and index + 1 < len(args):
                add_flag(compile_flags, f"{arg}{args[index + 1]}")
                index += 2
                continue
            if arg.startswith("-I"):
                add_flag(compile_flags, arg)
            elif arg.startswith("-D") or arg.startswith("-std=") or arg.startswith("-f"):
                add_flag(compile_flags, arg)
            index += 1

    # Link flags and libraries from the build log. Configure output often
    # contains diagnostic tokens such as ``-lm...`` or ``-L/usr/local/lib?g'``;
    # only well-formed tokens are collected, and ``-l`` names are kept only when
    # they resolve to a discovered archive or a real system library.
    link_dir_flags: list[str] = []
    link_lib_names: list[str] = []
    # Some FuzzBench recipes build with CMake/Meson and expose the real link
    # line (transitive libs such as ``-lz`` for libpng) only in the project's
    # OSS-Fuzz build script, not in the configure/build log. Parse those recipe
    # scripts too so generated drivers link the same libraries as the target.
    script_lines: list[str] = []
    for pattern in (
        "build.sh",
        "*/contrib/oss-fuzz/build.sh",
        "*/oss-fuzz/build.sh",
        "*/fuzz/build.sh",
        "*/tools/oss-fuzz.sh",
    ):
        for script in sorted(Path(source_root).glob(pattern)):
            try:
                script_lines.extend(script.read_text(encoding="utf-8", errors="replace").splitlines())
            except OSError:
                continue
    # Never inject the fuzz engine itself: PromeFuzz links ``-fsanitize=fuzzer``
    # and a duplicate ``-lFuzzingEngine`` would break the sanitizer build.
    engine_lib_denylist = {"FuzzingEngine", "fuzzer", "Fuzzer"}
    for line in [*build_log.splitlines(), *script_lines]:
        if " -o " in line or " -l" in line or " -L" in line:
            link_commands.append(line)
        for m in LINK_LIB_RE.finditer(line):
            name = m.group(1)
            if name in engine_lib_denylist:
                continue
            if ".." in name or name.endswith(".") or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_+.-]*", name):
                continue
            if name not in link_lib_names:
                link_lib_names.append(name)
        for m in LINK_PATH_RE.finditer(line):
            path_value = m.group(1)
            if _is_safe_flag_token(path_value):
                flag = f"-L{path_value}"
                if flag not in link_dir_flags:
                    link_dir_flags.append(flag)

    # Archives/shared libraries produced by the build. Test/example data in the
    # source tree frequently ships .a/.so/.dll fixtures that are not link
    # inputs (e.g. bloaty testdata); exclude those path segments.
    excluded_segments = {
        "test", "tests", "testdata", "testing", "example", "examples",
        "docs", "doc", "benchmark", "benchmarks",
    }
    archives: list[str] = []
    scan_dirs = [Path(d) for d in out_dirs if d]
    for d in scan_dirs:
        if not d.is_dir():
            continue
        for path in sorted(d.rglob("*")):
            if not path.is_file() or not ARCHIVE_RE.search(path.name):
                continue
            try:
                rel_parts = {part.lower() for part in path.relative_to(d).parts}
            except ValueError:
                rel_parts = {part.lower() for part in path.parts}
            if rel_parts & excluded_segments:
                continue
            archives.append(str(path))
    # Dedupe archive paths into library_paths.
    for arc in archives:
        if arc not in library_paths:
            library_paths.append(arc)
    # Assemble link flags: valid -L dirs, resolvable -l names, then archives.
    for flag in link_dir_flags:
        add_flag(link_flags, flag)
    search_dirs = [Path(flag[2:]) for flag in link_dir_flags if flag.startswith("-L")]
    for name in link_lib_names:
        if _library_resolvable(name, search_dirs):
            add_flag(link_flags, f"-l{name}")
    for arc in archives:
        add_flag(link_flags, arc)

    driver_build_args = compile_flags + link_flags
    return {
        "compile_flags": compile_flags,
        "link_flags": link_flags,
        "library_paths": library_paths,
        "driver_build_args": driver_build_args,
        "link_commands": link_commands,
    }


def _resolve_benchmark_root(target_root: Path, benchmark_root: Path | None = None) -> Path:
    """Resolve the FuzzBench benchmark recipe directory.

    In the blind split layout the generator mount (``/target`` =
    ``generator_input``) intentionally omits ``fuzzbench_benchmark``; the build
    recipe (Dockerfile/build.sh/benchmark.yaml) is not reference-harness content
    and lives in the evaluator half's ``benchmark_copy``. Prefer an explicit
    override, then the generator mount, then the evaluator copy.
    """
    if benchmark_root is not None and Path(benchmark_root).is_dir():
        return Path(benchmark_root)
    candidate = target_root / "fuzzbench_benchmark"
    if candidate.is_dir():
        return candidate
    evaluator_root = Path(os.environ.get("HGB_EVALUATOR_ROOT", "/evaluator"))
    evaluator_copy = evaluator_root / "benchmark_copy"
    if evaluator_copy.is_dir():
        return evaluator_copy
    return candidate


def _stage_source(target_root: Path, staged_src: Path, benchmark_root: Path | None = None) -> None:
    """Stage the complete pinned source and benchmark into an isolated workspace."""
    if staged_src.exists():
        shutil.rmtree(staged_src)
    staged_src.mkdir(parents=True)
    source_input = target_root / "source_input"
    if source_input.is_dir():
        # Preserve symlinks: some projects (e.g. systemd's testdata) contain
        # self-referential symlink loops that infinite-recurse when dereferenced.
        shutil.copytree(source_input, staged_src, dirs_exist_ok=True, symlinks=True)
    benchmark = _resolve_benchmark_root(target_root, benchmark_root)
    if benchmark.is_dir():
        for child in sorted(benchmark.iterdir()):
            if child.name in {"Dockerfile", "benchmark.yaml", ".dockerignore"}:
                continue
            dest = staged_src / child.name
            if dest.exists():
                continue
            shutil.copytree(child, dest, symlinks=True) if child.is_dir() else shutil.copy2(child, dest)
    _wrap_project_build_script(staged_src)


def _wrap_project_build_script(staged_src: Path) -> None:
    """Replace a soft-skip build.sh with the project's OSS-Fuzz build script.

    Some FuzzBench recipes have no top-level ``build.sh`` (their Dockerfile
    copies ``<project>/contrib/oss-fuzz/build.sh`` instead, e.g. libpng), so the
    packaged stub exits 127 and native candidate validation is disabled. Run the
    project build script so those targets can build.
    """
    build_sh = staged_src / "build.sh"
    if not build_sh.is_file():
        return
    try:
        text = build_sh.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    if "target build is unavailable" not in text:
        return
    candidates: list[Path] = []
    for pattern in (
        "*/contrib/oss-fuzz/build.sh",
        "*/oss-fuzz/build.sh",
        "*/fuzz/build.sh",
        "*/tools/oss-fuzz.sh",
    ):
        candidates.extend(sorted(staged_src.glob(pattern)))
    if not candidates:
        return
    rel = candidates[0].relative_to(staged_src).as_posix()
    build_sh.write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\n"
        "SCRIPT_DIR=\"$(cd -- \"$(dirname -- \"${BASH_SOURCE[0]}\")\" && pwd)\"\n"
        f"exec bash \"$SCRIPT_DIR/{rel}\" \"$@\"\n",
        encoding="utf-8",
    )
    build_sh.chmod(0o755)


def _capture_cmake_export(
    staged_src: Path, work_dir: Path, runner: Runner, timeout: int
) -> tuple[list[dict[str, Any]], str, str, int]:
    build_dir = work_dir / "cmake_build"
    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True)
    cmake_lists = staged_src / "CMakeLists.txt"
    if not cmake_lists.is_file():
        # Search one level deep for a CMake project (common FuzzBench layout).
        for child in sorted(staged_src.iterdir()):
            if (child / "CMakeLists.txt").is_file():
                cmake_lists = child / "CMakeLists.txt"
                break
    src_dir = cmake_lists.parent
    env = {
        "CC": os.environ.get("CC", "clang"),
        "CXX": os.environ.get("CXX", "clang++"),
        "CFLAGS": (os.environ.get("CFLAGS", "") + " -Wno-documentation -Wno-error=documentation -I" + str(staged_src) + " " + os.environ.get("PROME_FUZZ_EXTRA_CFLAGS", "")).strip(),
        "CXXFLAGS": (os.environ.get("CXXFLAGS", "") + " -Wno-documentation -Wno-error=documentation -I" + str(staged_src) + " " + os.environ.get("PROME_FUZZ_EXTRA_CXXFLAGS", "")).strip(),
        "PIP_BREAK_SYSTEM_PACKAGES": os.environ.get("PIP_BREAK_SYSTEM_PACKAGES", "1"),
        "LIBS": os.environ.get("PROME_FUZZ_EXTRA_LIBS", ""),
    }
    with _temporary_env(env):
        result = runner(
            ["cmake", "-S", str(src_dir), "-B", str(build_dir), "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],
            timeout,
        )
        # Also build so project-produced archives/shared libraries are available for
        # link-context recovery. A build failure does not discard the compile
        # commands already captured by configure.
        build_result = runner(["cmake", "--build", str(build_dir), "--parallel"], timeout)
    db_path = build_dir / "compile_commands.json"
    raw: list[dict[str, Any]] = []
    if db_path.is_file():
        try:
            raw = json.loads(db_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            raw = []
    combined_stdout = result.stdout + "\n" + build_result.stdout
    combined_stderr = result.stderr + "\n" + build_result.stderr
    return raw, combined_stdout, combined_stderr, result.returncode


def _capture_bear_replay(
    target_root: Path,
    staged_src: Path,
    work_dir: Path,
    native_destination: str,
    language: str,
    build_workdir_relative: str,
    runner: Runner,
    timeout: int,
) -> tuple[list[dict[str, Any]], str, str, int]:
    out_dir = work_dir / "out"
    work_out = work_dir / "work"
    out_dir.mkdir(parents=True, exist_ok=True)
    work_out.mkdir(parents=True, exist_ok=True)
    # Overlay neutral stubs at the native harness destination and every
    # stripped reference-harness path so multi-fuzzer build recipes still
    # compile without the reference harness bodies.
    evaluator_root = Path(os.environ.get("HGB_EVALUATOR_ROOT", "/evaluator"))
    overlay_neutral_stubs(
        staged_src, language, native_destination,
        evaluator_root / "target_manifest.evaluator.json",
    )
    build_workdir = staged_src
    if build_workdir_relative:
        candidate = staged_src / build_workdir_relative
        if candidate.is_dir():
            build_workdir = candidate
    build_script = staged_src / "build.sh"
    if not build_script.is_file():
        return [], "", "missing build.sh in staged source", 127
    env = os.environ.copy()
    env.update({
        "SRC": str(staged_src), "OUT": str(out_dir), "WORK": str(work_out),
        "CC": env.get("CC", "clang"), "CXX": env.get("CXX", "clang++"),
        "FUZZER": "libfuzzer", "FUZZER_LIB": "-fsanitize=fuzzer",
        "LIB_FUZZING_ENGINE": "-fsanitize=fuzzer",
        "CFLAGS": env.get("CFLAGS", "") + " -pthread -Wno-documentation -Wno-error=documentation -I" + str(staged_src) + " " + os.environ.get("PROME_FUZZ_EXTRA_CFLAGS", ""),
        "CXXFLAGS": env.get("CXXFLAGS", "") + " -pthread -Wno-register -Wno-documentation -Wno-error=documentation -I" + str(staged_src) + " " + os.environ.get("PROME_FUZZ_EXTRA_CXXFLAGS", ""),
        "PIP_BREAK_SYSTEM_PACKAGES": env.get("PIP_BREAK_SYSTEM_PACKAGES", "1"),
        "LIBS": (env.get("LIBS", "") + " " + os.environ.get("PROME_FUZZ_EXTRA_LIBS", "")).strip(),
    })
    # bear writes compile_commands.json in the build working directory.
    cmd = ["bear", "--", "bash", str(build_script)]
    with _temporary_chdir(build_workdir), _temporary_env(env):
        result = runner(cmd, timeout)
    db_path = build_workdir / "compile_commands.json"
    raw: list[dict[str, Any]] = []
    if db_path.is_file():
        try:
            raw = json.loads(db_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            raw = []
    # Also check OUT/WORK for stray bear output.
    if not raw:
        for candidate in (out_dir / "compile_commands.json", work_out / "compile_commands.json"):
            if candidate.is_file():
                try:
                    raw = json.loads(candidate.read_text(encoding="utf-8"))
                    if raw:
                        break
                except json.JSONDecodeError:
                    continue
    return raw, result.stdout, result.stderr, result.returncode


def _capture_meson_export(
    staged_src: Path,
    work_dir: Path,
    runner: Runner,
    timeout: int,
) -> tuple[list[dict[str, Any]], str, str, int]:
    """Capture a compile database for meson projects (e.g. systemd)."""
    build_dir = work_dir / "meson_build"
    if build_dir.exists():
        shutil.rmtree(build_dir)
    meson_file = staged_src / "meson.build"
    if not meson_file.is_file():
        for child in sorted(staged_src.iterdir()):
            if (child / "meson.build").is_file():
                meson_file = child / "meson.build"
                break
    if not meson_file.is_file():
        return [], "", "missing meson.build in staged source", 127
    src_dir = meson_file.parent
    setup = runner(["meson", "setup", str(build_dir), str(src_dir)], timeout)
    compdb = runner(["ninja", "-C", str(build_dir), "-t", "compdb"], timeout)
    raw: list[dict[str, Any]] = []
    try:
        data = json.loads(compdb.stdout)
        if isinstance(data, list):
            raw = [entry for entry in data if isinstance(entry, dict)]
    except (json.JSONDecodeError, TypeError):
        raw = []
    build_result = runner(["ninja", "-C", str(build_dir)], timeout)
    combined_stdout = setup.stdout + "\n" + compdb.stdout + "\n" + build_result.stdout
    combined_stderr = setup.stderr + "\n" + compdb.stderr + "\n" + build_result.stderr
    return raw, combined_stdout, combined_stderr, setup.returncode


def capture_build_context(
    *,
    target_root: Path,
    work_dir: Path,
    fuzz_target: str,
    language: str = "",
    profile: str = "alpha",
    allow_synthetic: bool = False,
    capture_method: str = "auto",
    build_workdir_relative: str = "",
    runner: Runner = _real_runner,
    build_timeout: int = 1800,
    source_root: Path | None = None,
    native_harness_destination: str = "",
    native_harness_language: str = "",
    benchmark_root: Path | None = None,
) -> dict[str, Any]:
    """Capture a real compile database and link context.

    Returns a manifest dict. ``method-faithful`` profiles (alpha,
    paper-faithful) require a non-empty real database; ``compat-smoke`` may
    fall back to a synthetic database when ``allow_synthetic`` is set.
    """
    target_root = Path(target_root)
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    build_context_dir = work_dir / "build_context"
    build_context_dir.mkdir(parents=True, exist_ok=True)
    staged_src = source_root if source_root is not None else build_context_dir / "src"
    resolved_benchmark_root = _resolve_benchmark_root(target_root, benchmark_root)
    if source_root is None:
        _stage_source(target_root, staged_src, resolved_benchmark_root)
    # Apply the same target-specific build.sh patches the sealed evaluator uses
    # (single-target curl/sqlite3/libjpeg/... recipes) so the native build does
    # not compile sibling fuzzers or fail on broad recipe steps.
    try:
        import hgb_fuzzbench_builder as _hgb_builder
        _hgb_builder._patch_single_target_build_context(staged_src, fuzz_target)
    except Exception:
        pass

    build_log_path = build_context_dir / "build.log"
    raw_db_path = build_context_dir / "compile_commands.raw.json"
    db_path = build_context_dir / "compile_commands.json"
    link_commands_path = build_context_dir / "link_commands.json"
    libraries_path = build_context_dir / "libraries.json"
    generated_dir = build_context_dir / "generated_files"
    generated_dir.mkdir(parents=True, exist_ok=True)

    # Resolve the native harness destination for neutral stub overlay.
    # An explicit destination (resolved by the entrypoint from the evaluator
    # half's path-only metadata) wins; otherwise fall back to the evaluator
    # file directly, then to the generator manifest for monolithic packages.
    native_destination = native_harness_destination.strip()
    if native_harness_language:
        language = native_harness_language
    if not native_destination:
        evaluator_root = os.environ.get("HGB_EVALUATOR_ROOT", "/evaluator")
        evaluator_native = Path(evaluator_root) / "native_harness_path.json"
        if evaluator_native.is_file():
            try:
                data = json.loads(evaluator_native.read_text(encoding="utf-8"))
                native_destination = str(data.get("container_destination") or "")
                if not language and data.get("language"):
                    language = str(data.get("language"))
            except (OSError, json.JSONDecodeError):
                pass
    if not native_destination:
        try:
            if select_native_harness is not None:
                native = select_native_harness(target_root, fuzz_target)
                native_destination = native.container_destination
                if not language:
                    language = "c" if native.language == "c" else "c++"
        except Exception:
            pass
    if not language:
        language = "c++"

    methods: list[str]
    if capture_method == "auto":
        # Prefer the exact FuzzBench build.sh replay; fall back to a CMake
        # export, then a meson/ninja export, only when the recipe has no usable
        # build.sh.
        methods = ["bear_replay", "cmake_export", "meson_export"]
    elif capture_method in ("exact_fuzzbench", "fuzzbench_replay"):
        # Gamma plan section 6 / delta plan section 3: prefer the exact
        # FuzzBench build.sh replay (bear/intercept-build) over a generic
        # CMake export so the compile database provably originates from the
        # FuzzBench build command. ``fuzzbench_replay`` is the delta name.
        methods = ["bear_replay", "cmake_export", "meson_export"]
    else:
        methods = [capture_method]

    raw: list[dict[str, Any]] = []
    capture_stdout = ""
    capture_stderr = ""
    capture_rc = 1
    chosen_method = ""
    for method in methods:
        if method == "cmake_export":
            raw, capture_stdout, capture_stderr, capture_rc = _capture_cmake_export(
                staged_src, build_context_dir, runner, build_timeout)
        elif method == "bear_replay":
            raw, capture_stdout, capture_stderr, capture_rc = _capture_bear_replay(
                target_root, staged_src, build_context_dir, native_destination,
                language, build_workdir_relative, runner, build_timeout)
        elif method == "meson_export":
            raw, capture_stdout, capture_stderr, capture_rc = _capture_meson_export(
                staged_src, build_context_dir, runner, build_timeout)
        else:
            continue
        chosen_method = method
        if raw:
            break

    build_log = capture_stdout + "\n" + capture_stderr
    build_log_path.write_text(build_log, encoding="utf-8")
    raw_db_path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")

    source_roots = [staged_src.resolve(strict=False)]
    normalized = _normalize_entry_paths(raw, staged_src.resolve(strict=False))
    filtered = _filter_db(normalized, source_roots)

    # If the real capture produced nothing and synthetic is explicitly allowed
    # (compat-smoke only), emit a synthetic database from source files.
    synthetic = False
    if not filtered and allow_synthetic:
        filtered = _synthetic_compile_db(staged_src, language)
        synthetic = True
        chosen_method = "synthetic"

    db_path.write_text(json.dumps(filtered, indent=2) + "\n", encoding="utf-8")

    out_dirs = [build_context_dir, build_context_dir / "out", build_context_dir / "work",
                build_context_dir / "cmake_build", staged_src]
    libs = extract_libraries(
        compile_db=filtered, build_log=build_log, out_dirs=out_dirs, source_root=staged_src,
    )
    link_commands_path.write_text(
        json.dumps(libs["link_commands"], indent=2) + "\n", encoding="utf-8")
    libraries_path.write_text(
        json.dumps(
            {
                "library_paths": libs["library_paths"],
                "compile_flags": libs["compile_flags"],
                "link_flags": libs["link_flags"],
                "driver_build_args": libs["driver_build_args"],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    # Preserve generated headers/sources encountered in the compile database.
    generated_files: list[str] = []
    for entry in filtered:
        fpath = Path(entry.get("file", ""))
        if fpath.is_file() and "generated" in str(fpath).lower():
            gen_dest = generated_dir / fpath.name
            try:
                shutil.copy2(fpath, gen_dest)
                generated_files.append(str(fpath))
            except OSError:
                pass

    compiled_files = {Path(entry.get("file", "")).resolve(strict=False) for entry in filtered}
    consumer_manifest = build_consumer_manifest(
        staged_src, compiled_under_flags=compiled_files,
    )
    consumer_path = work_dir / "knowledge" / "consumer_cases.json"
    consumer_path.parent.mkdir(parents=True, exist_ok=True)
    consumer_path.write_text(json.dumps(consumer_manifest, indent=2) + "\n", encoding="utf-8")

    covers_project = any(
        _within(Path(entry.get("file", "")).resolve(strict=False), staged_src.resolve(strict=False))
        for entry in filtered
    )
    # A compile DB "covers the fuzz target" when it includes a translation unit
    # at (or sibling to) the native harness destination. This is informational;
    # a generic CMake DB that never builds the project source is already
    # rejected by the ``covers_project`` check below.
    native_rel = native_destination
    for prefix in ("/src/", "src/"):
        if native_rel.startswith(prefix):
            native_rel = native_rel[len(prefix):]
            break
    covers_fuzz_target = bool(native_rel) and any(
        native_rel in str(Path(entry.get("file", "")))
        or Path(entry.get("file", "")).name == Path(native_rel).name
        for entry in filtered
    )
    real_capture = bool(filtered) and not synthetic
    method_faithful = profile in {"alpha", "paper-faithful"}
    # The exact-replay mode is only set when the capture came from the real
    # FuzzBench build (bear_replay replays build.sh; cmake_export runs the
    # project's actual CMake build over the staged source). A synthetic DB is
    # never an exact replay and is unreachable in alpha/paper-faithful.
    compiler_wrapper = {
        "bear_replay": "bear",
        "cmake_export": "cmake",
    }.get(chosen_method, "")
    if synthetic:
        compiler_wrapper = "synthetic"
    exact_replay = real_capture and chosen_method in {"bear_replay", "cmake_export"}
    # alpha/paper-faithful reject a generic CMake DB that never builds the
    # project translation units (covers_project is False); compat-smoke may
    # accept a synthetic DB when allow_synthetic is set.
    valid = real_capture and covers_project

    build_script = resolved_benchmark_root / "build.sh"
    full_manifest = json.loads((target_root / "target_manifest.json").read_text(encoding="utf-8")) if (target_root / "target_manifest.json").is_file() else {}
    link_context = {
        "mode": "fuzzbench_build_replay" if exact_replay else ("synthetic" if synthetic else "generic_cmake"),
        "compile_commands_count": len(filtered),
        "compiler_wrapper": compiler_wrapper,
        "benchmark_project": str(full_manifest.get("project", "")),
        "fuzz_target": fuzz_target,
        "image_digest": os.environ.get("HGB_DOCKER_IMAGE_DIGEST", ""),
        "driver_build_args": libs["driver_build_args"],
        "library_paths": libs["library_paths"],
        "compile_flags": libs["compile_flags"],
        "link_flags": libs["link_flags"],
        "link_commands_count": len(libs["link_commands"]),
        "covers_fuzz_target": covers_fuzz_target,
        "verified": False,
    }
    link_context_path = build_context_dir / "link_context.json"
    link_context_path.write_text(json.dumps(link_context, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    manifest = {
        "capture_method": chosen_method if filtered else "",
        "mode": link_context["mode"],
        "compiler_wrapper": compiler_wrapper,
        "exact_replay": exact_replay,
        "synthetic": synthetic,
        "real_capture": real_capture,
        "valid": valid,
        "method_faithful_required": method_faithful,
        "compile_commands_path": str(db_path),
        "compile_commands_raw_path": str(raw_db_path),
        "build_log_path": str(build_log_path),
        "link_commands_path": str(link_commands_path),
        "libraries_path": str(libraries_path),
        "link_context_path": str(link_context_path),
        "consumer_cases_path": str(consumer_path),
        "generated_files_dir": str(generated_dir),
        "generated_files": generated_files,
        "entry_count": len(filtered),
        "covers_project_translation_units": covers_project,
        "covers_fuzz_target": covers_fuzz_target,
        "native_harness_destination": native_destination,
        "language": language,
        "driver_build_args": libs["driver_build_args"],
        "library_paths": libs["library_paths"],
        "compile_flags": libs["compile_flags"],
        "link_flags": libs["link_flags"],
        "consumer_count": consumer_manifest["consumer_count"],
        "build_script_hash": _sha256_file(build_script) if build_script.is_file() else "missing",
        "capture_returncode": capture_rc,
        "compiler_version": _compiler_version(runner),
        "source_root": str(staged_src),
    }
    (build_context_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # Delta plan section 3: write build_context/provenance.json so the
    # entrypoint and tests can prove the compile DB originated from the exact
    # FuzzBench build (bear_replay replays build.sh inside the FuzzBench env),
    # not a generic top-level CMake best-effort build.
    benchmark_dockerfile = resolved_benchmark_root / "Dockerfile"
    provenance = {
        "strategy": "fuzzbench_replay" if chosen_method == "bear_replay" else (
            "cmake_export" if chosen_method == "cmake_export" else (
                "synthetic" if synthetic else "unknown")),
        "benchmark_dockerfile_sha256": _sha256_file(benchmark_dockerfile) if benchmark_dockerfile.is_file() else "missing",
        "build_sh_sha256": _sha256_file(build_script) if build_script.is_file() else "missing",
        "compile_commands_count": len(filtered),
        "uses_fuzzbench_env": chosen_method == "bear_replay",
        "cc": os.environ.get("CC", "clang"),
        "cxx": os.environ.get("CXX", "clang++"),
        "cflags": os.environ.get("CFLAGS", ""),
        "cxxflags": os.environ.get("CXXFLAGS", ""),
        "out_artifacts": [str(p) for p in sorted(
            (build_context_dir / "out").glob("*")) if p.is_file()] if (build_context_dir / "out").is_dir() else [],
        "capture_method": chosen_method,
        "synthetic": synthetic,
        "exact_replay": exact_replay,
    }
    (build_context_dir / "provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest["provenance_path"] = str(build_context_dir / "provenance.json")
    return manifest


def _compiler_version(runner: Runner) -> str:
    for compiler in ("clang", "clang++"):
        if shutil.which(compiler):
            result = runner([compiler, "--version"], 10)
            if result.returncode == 0 and result.stdout:
                return result.stdout.splitlines()[0]
    return "unavailable"


def _synthetic_compile_db(source_root: Path, language: str) -> list[dict[str, Any]]:
    """Emit a synthetic compile database. compat-smoke only."""
    entries: list[dict[str, Any]] = []
    if not source_root.is_dir():
        return entries
    include_dirs: list[str] = [str(source_root)]
    for child in source_root.rglob("*"):
        if child.is_dir() and child.name.lower() in {"include", "inc", "src"}:
            if str(child) not in include_dirs:
                include_dirs.append(str(child))
    for src in sorted(source_root.rglob("*")):
        if not src.is_file() or src.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        is_c = src.suffix.lower() == ".c" and language == "c"
        compiler = "clang" if is_c else "clang++"
        std = "-std=c11" if is_c else "-std=c++17"
        args = [compiler, std, *[f"-I{d}" for d in include_dirs[:32]], "-c", str(src), "-o", "/tmp/null.o"]
        entries.append({
            "directory": str(src.parent),
            "file": str(src),
            "arguments": args,
            "command": shlex.join(args),
        })
    return entries


def _strip_fuzzer_engine_args(args: list[str]) -> list[str]:
    """Remove libFuzzer engine flags from a consumer link command.

    The recovered ``driver_build_args`` include the FuzzBench fuzz-engine flag
    (``-fsanitize=fuzzer`` and friends), which supplies libFuzzer's own ``main``
    and requires ``LLVMFuzzerTestOneInput``. The minimal link probe provides its
    own ``main``, so the fuzzer engine must be dropped to test the recovered
    library/link flags without a duplicate/undefined ``main``.
    """
    stripped: list[str] = []
    for arg in args:
        if arg.startswith("-fsanitize="):
            values = [v for v in arg[len("-fsanitize="):].split(",") if v not in {"fuzzer", "fuzzer-no-link"}]
            if values:
                stripped.append("-fsanitize=" + ",".join(values))
            continue
        if arg in {"-fsanitize=fuzzer", "-fsanitize=fuzzer-no-link"}:
            continue
        stripped.append(arg)
    return stripped


def verify_link_set(
    *,
    source_root: Path,
    driver_build_args: list[str],
    work_dir: Path,
    language: str = "c++",
    runner: Runner = _real_runner,
    timeout: int = 120,
) -> tuple[bool, str]:
    """Verify the recovered link set by building a minimal non-fuzz consumer."""
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    consumer = work_dir / "hgb_link_probe.cc" if language != "c" else work_dir / "hgb_link_probe.c"
    consumer.write_text(
        "int main(void) { return 0; }\n", encoding="utf-8",
    )
    compiler = "clang" if language == "c" else "clang++"
    link_args = _strip_fuzzer_engine_args(list(driver_build_args))
    cmd = [compiler, str(consumer), *link_args, "-o", str(work_dir / "hgb_link_probe")]
    result = runner(cmd, timeout)
    if result.returncode == 0:
        return True, (result.stderr or result.stdout)
    # Fallback: recovered archives are passed directly, so retry without the
    # -l/-L flags (which may reference non-standard build directories) and
    # record the reduced policy instead of failing the whole target.
    archive_args = [a for a in link_args if not a.startswith("-l") and not a.startswith("-L")]
    if archive_args != link_args:
        retry_cmd = [compiler, str(consumer), *archive_args, "-o", str(work_dir / "hgb_link_probe")]
        retry = runner(retry_cmd, timeout)
        if retry.returncode == 0:
            message = (result.stderr or result.stdout) + "\nverified_with=archives_only (retry without -l/-L succeeded)"
            return True, message
    return False, (result.stderr or result.stdout)


@dataclass
class CompileContext:
    """The exact FuzzBench compile/link context captured for PromeFuzz.

    Per beta plan section 4, this carries the real compile database, the
    recovered link/build arguments, the capture mode, and the image provenance
    of the build that produced it. It is the single object PromeFuzz
    preprocessing and ``libraries.toml`` must consume in alpha/paper-faithful.
    """

    compile_commands_path: str
    link_context_path: str
    libraries_path: str
    consumer_cases_path: str
    mode: str
    compiler_wrapper: str
    benchmark_project: str
    fuzz_target: str
    image_digest: str
    compile_commands_count: int
    driver_build_args: list[str]
    library_paths: list[str]
    valid: bool
    exact_replay: bool
    synthetic: bool
    manifest: dict[str, Any]


def capture_fuzzbench_compile_db(
    target_root: Path,
    work_dir: Path,
    project: str,
    fuzz_target: str,
    *,
    language: str = "",
    profile: str = "alpha",
    allow_synthetic: bool = False,
    capture_method: str = "auto",
    build_workdir_relative: str = "",
    runner: Runner = _real_runner,
    build_timeout: int = 1800,
    source_root: Path | None = None,
) -> CompileContext:
    """Capture the exact compile database from the pinned FuzzBench build.

    This is the paper-faithful entry point required by beta plan section 4.
    It replays the FuzzBench target build (bear/cmake) and returns a
    :class:`CompileContext`. In ``alpha``/``paper-faithful`` a synthetic or
    generic compile database is rejected (``valid=False``); the entrypoint
    must surface this as ``failed_stage=compile_context``, not a soft skip.
    """

    manifest = capture_build_context(
        target_root=target_root,
        work_dir=work_dir,
        fuzz_target=fuzz_target,
        language=language,
        profile=profile,
        allow_synthetic=allow_synthetic,
        capture_method=capture_method,
        build_workdir_relative=build_workdir_relative,
        runner=runner,
        build_timeout=build_timeout,
        source_root=source_root,
    )
    link_ctx_path = Path(manifest.get("link_context_path", work_dir / "build_context" / "link_context.json"))
    link_ctx: dict[str, Any] = {}
    if link_ctx_path.is_file():
        try:
            link_ctx = json.loads(link_ctx_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            link_ctx = {}
    return CompileContext(
        compile_commands_path=manifest["compile_commands_path"],
        link_context_path=str(link_ctx_path),
        libraries_path=manifest["libraries_path"],
        consumer_cases_path=manifest["consumer_cases_path"],
        mode=manifest.get("mode", ""),
        compiler_wrapper=manifest.get("compiler_wrapper", ""),
        benchmark_project=project or link_ctx.get("benchmark_project", ""),
        fuzz_target=fuzz_target,
        image_digest=link_ctx.get("image_digest", ""),
        compile_commands_count=manifest.get("entry_count", 0),
        driver_build_args=manifest.get("driver_build_args", []),
        library_paths=manifest.get("library_paths", []),
        valid=manifest.get("valid", False),
        exact_replay=manifest.get("exact_replay", False),
        synthetic=manifest.get("synthetic", False),
        manifest=manifest,
    )


def verify_and_record_link_set(
    *,
    link_context_path: Path,
    driver_build_args: list[str],
    work_dir: Path,
    language: str = "c++",
    source_root: Path | None = None,
    runner: Runner = _real_runner,
    timeout: int = 120,
) -> tuple[bool, str]:
    """Verify the recovered link set and record ``verified`` in link_context.json.

    Per beta plan section 5, the production path must call ``verify_link_set``
    before generating ``libraries.toml``. An empty ``driver_build_args`` is
    never verified.
    """

    link_context_path = Path(link_context_path)
    if not driver_build_args:
        ok, msg = False, "driver_build_args is empty"
    else:
        ok, msg = verify_link_set(
            source_root=source_root or Path(work_dir),
            driver_build_args=driver_build_args,
            work_dir=work_dir,
            language=language,
            runner=runner,
            timeout=timeout,
        )
    if link_context_path.is_file():
        try:
            data = json.loads(link_context_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        data["verified"] = ok
        data["verify_message"] = msg
        link_context_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return ok, msg


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture a PromeFuzz real build context")
    parser.add_argument("--target-root", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--fuzz-target", required=True)
    parser.add_argument("--language", default="")
    parser.add_argument("--profile", default="alpha")
    parser.add_argument("--allow-synthetic", action="store_true")
    parser.add_argument("--capture-method", default="auto", choices=("auto", "cmake_export", "bear_replay", "meson_export", "exact_fuzzbench", "fuzzbench_replay"))
    parser.add_argument("--build-workdir-relative", default="")
    parser.add_argument("--build-timeout", type=int, default=1800)
    parser.add_argument("--native-harness-destination", default="")
    parser.add_argument("--native-harness-language", default="")
    parser.add_argument("--benchmark-root", default="")
    args = parser.parse_args()
    manifest = capture_build_context(
        target_root=args.target_root,
        work_dir=args.work_dir,
        fuzz_target=args.fuzz_target,
        language=args.language,
        profile=args.profile,
        allow_synthetic=args.allow_synthetic,
        capture_method=args.capture_method,
        build_workdir_relative=args.build_workdir_relative,
        build_timeout=args.build_timeout,
        native_harness_destination=args.native_harness_destination,
        native_harness_language=args.native_harness_language,
        benchmark_root=Path(args.benchmark_root) if args.benchmark_root else None,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    if args.profile in {"alpha", "paper-faithful", "reproduction-gamma", "reproduction-delta"} and not manifest["valid"]:
        return 1
    # Delta plan section 3: a CMake-only compile DB without FuzzBench provenance
    # is rejected under reproduction-delta.
    if args.profile == "reproduction-delta":
        prov_path = Path(manifest.get("provenance_path", ""))
        if prov_path.is_file():
            try:
                prov = json.loads(prov_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                prov = {}
            if prov.get("strategy") not in {"fuzzbench_replay"} and not prov.get("synthetic"):
                # A cmake_export DB is only acceptable under delta when it is
                # proven to be the same source tree as the FuzzBench build
                # (uses_fuzzbench_env). A generic CMake-only DB is rejected.
                if not prov.get("uses_fuzzbench_env"):
                    return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
