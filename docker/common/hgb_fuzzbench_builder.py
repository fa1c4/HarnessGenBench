#!/usr/bin/env python3
"""Deterministic FuzzBench builder/smoke/campaign/coverage runner.

The evaluator builds the target image once with a deterministic tag and reuses
it for build, smoke, campaign, and coverage so a candidate is never evaluated
against a different image than the one that built it.

All Docker invocations go through a ``runner`` callable so the offline pytest
suite can substitute fake runners without touching Docker.
"""

from __future__ import annotations

import hashlib
import re
import shlex
import subprocess
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Sequence

Runner = Callable[[Sequence[str], int], "CommandResult"]

# Container-side marker emitted to stderr before the target binary execs. A
# smoke/campaign/coverage phase is only considered to have executed the target
# if this marker appears in the captured logs AND the required ``docker cp``
# input copy succeeded (zeta plan §2).
HGB_TARGET_START_MARKER = "HGB_TARGET_START"


@dataclass
class CommandResult:
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    # Phased copy/execution audit (zeta plan §2). These are attached by
    # ``_container_run`` so smoke/campaign/coverage callers can prove the
    # required ``docker cp`` inputs/outputs succeeded and the target actually
    # started, rather than inferring execution from an exit code alone.
    copy_in_ok: bool = True
    start_exit_code: int | None = None
    copy_out_ok: bool = True


def _run(command: Sequence[str], timeout_seconds: int) -> CommandResult:
    completed = subprocess.run(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        check=False,
        timeout=timeout_seconds,
    )
    return CommandResult(list(command), completed.returncode, completed.stdout or "", completed.stderr or "")


def safe_token(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "-", value)


def deterministic_image_tag(
    run_id: str,
    target: str,
    candidate_id: str,
    *,
    generator: str = "ckgfuzzer",
) -> str:
    """Return ``hgb-<generator>-<run-id>-<target>-<candidate-id>``.

    The tag is stable for a given (generator, run, target, candidate) tuple so
    the same image is used for build, smoke, campaign, and coverage. A
    consistent tag across all evaluator stages is required by the beta
    reproduction contract: build/run image tags must never differ.
    """

    run = safe_token(run_id or "run")[:32]
    tgt = safe_token(target or "target")[:40]
    cand = safe_token(candidate_id or "cand")[:24]
    gen = safe_token(generator or "ckgfuzzer")[:24]
    digest = hashlib.sha256(f"{generator}|{run_id}|{target}|{candidate_id}".encode()).hexdigest()[:8]
    return f"hgb-{gen}-{run}-{tgt}-{cand}-{digest}"


@dataclass
class BuildResult:
    image_tag: str
    image_digest: str
    binary_path: str
    binary_sha256: str
    build_exit_code: int
    log: str
    compiler: str
    sanitizer: str
    engine: str
    binary_verified: bool = False
    overlay_audit: dict = None


def _run_phase(runner: Runner, command: Sequence[str], timeout_seconds: int, phase: str) -> CommandResult:
    try:
        return runner(command, timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(list(command), 124, "", f"{phase} timed out: {exc}")
    except OSError as exc:
        return CommandResult(list(command), 127, "", f"could not {phase}: {exc}")


def _write_log(path: Path, result: CommandResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "$ " + " ".join(shlex.quote(c) for c in result.command)
        + "\n\n[stdout]\n" + result.stdout + "\n[stderr]\n" + result.stderr
        + f"\n[exit]\n{result.exit_code}\n",
        encoding="utf-8",
    )


def _normalize_candidate_for_native_path(candidate: Path, native_destination: str, work_dir: Path) -> Path:
    """Return a staged candidate with native-path ABI compatibility.

    CKGFuzzer often emits C++ wrappers even when the FuzzBench native harness
    path is a C translation unit, and sometimes omits C linkage for libFuzzer
    entrypoints in C++ files. The evaluator overlays by native path, so small
    syntax/ABI normalizations avoid deterministic compiler or linker failures
    while preserving the generated harness logic.
    """

    suffix = Path(native_destination).suffix.lower()
    if not candidate.is_file():
        return candidate
    text = candidate.read_text(encoding="utf-8", errors="replace")
    normalized = text
    staged_suffix = candidate.suffix or suffix or ".cc"
    if suffix == ".c":
        normalized = normalized.replace('extern "C" ', "")
        normalized = normalized.replace('extern "C"\n', "")
        normalized = normalized.replace("nullptr", "NULL")
        normalized = re.sub(r"(?m)^(\s*)void\s+log_set_max_level\s*\(", r"\1static void log_set_max_level(", normalized)
        if "LLVMFuzzerTestOneInput" in normalized and "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);" not in normalized:
            normalized = (
                "#include <stdint.h>\n"
                "#include <stddef.h>\n"
                "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);\n"
                + normalized
            )
        staged_suffix = ".c"
    elif suffix in {".cc", ".cpp", ".cxx"} and "LLVMFuzzerTestOneInput" in normalized:
        if 'extern "C" int LLVMFuzzerTestOneInput' not in normalized:
            normalized = re.sub(
                r"(?m)^(\s*)int\s+LLVMFuzzerTestOneInput\s*\(",
                r'\1extern "C" int LLVMFuzzerTestOneInput(',
                normalized,
                count=1,
            )
    if normalized == text:
        return candidate
    staged_dir = work_dir / "hgb_normalized_candidate"
    staged_dir.mkdir(parents=True, exist_ok=True)
    staged = staged_dir / (candidate.stem + staged_suffix)
    staged.write_text(normalized, encoding="utf-8")
    return staged


def _patch_single_target_build_context(context_dir: Path, fuzz_target: str) -> None:
    """Constrain build scripts that otherwise compile sibling fuzzers too.

    Curl's historical ossfuzz.sh builds every curl-fuzzer target. Replacing the
    selected source file can remove helper symbols required by sibling binaries,
    so the evaluator should compile only the requested FuzzBench target.
    """

    curl_root = context_dir / "source_input" / "curl_fuzzer"
    fuzz_targets = curl_root / "scripts" / "fuzz_targets"
    if fuzz_targets.is_file() and fuzz_target.startswith("curl_fuzzer"):
        text = fuzz_targets.read_text(encoding="utf-8", errors="replace")
        rewritten = re.sub(r'export\s+FUZZ_TARGETS="[^"]*"', f'export FUZZ_TARGETS="{fuzz_target}"', text)
        if rewritten != text:
            fuzz_targets.write_text(rewritten, encoding="utf-8")
    compile_fuzzer = curl_root / "scripts" / "compile_fuzzer.sh"
    if compile_fuzzer.is_file() and fuzz_target.startswith("curl_fuzzer"):
        text = compile_fuzzer.read_text(encoding="utf-8", errors="replace")
        rewritten = text.replace("\nmake || exit 4\n", "\nmake ${FUZZ_TARGETS} || exit 4\n")
        rewritten = rewritten.replace(
            "\nmake check || exit 5\n",
            "\ntrue # HGB sealed evaluator: skip broad curl make check for single-target builds.\n",
        )
        if rewritten != text:
            compile_fuzzer.write_text(rewritten, encoding="utf-8")
    ossfuzz = curl_root / "ossfuzz.sh"
    if ossfuzz.is_file() and fuzz_target.startswith("curl_fuzzer"):
        text = ossfuzz.read_text(encoding="utf-8", errors="replace")
        rewritten = text
        rewritten = re.sub(
            r"(?m)^\$\{SCRIPTDIR\}/handle_x\.sh zlib .*\|\| exit 1$",
            "true # HGB sealed evaluator: use curl without downloaded zlib source",
            rewritten,
        )
        rewritten = re.sub(
            r"(?s)# For the memory sanitizer build, turn off OpenSSL.*?fi\n",
            "true # HGB sealed evaluator: avoid downloading OpenSSL; install_curl.sh will configure --without-ssl.\n",
            rewritten,
            count=1,
        )
        rewritten = re.sub(
            r"(?m)^\$\{SCRIPTDIR\}/handle_x\.sh nghttp2 .*\|\| exit 1$",
            "true # HGB sealed evaluator: use curl without downloaded nghttp2 source",
            rewritten,
        )
        rewritten = rewritten.replace(
            "make zip\n",
            "for TARGET in $FUZZ_TARGETS; do make ${TARGET}_seed_corpus.zip || touch ${TARGET}_seed_corpus.zip; done\n",
        )
        if rewritten != text:
            ossfuzz.write_text(rewritten, encoding="utf-8")

    if fuzz_target == "ftfuzzer":
        # libarchive 3.4.3 configure runs a sanitizer-built iconv conftest that
        # can spin indefinitely under the sealed evaluator. Preseed the
        # autotools cache with the same outcome the probe reaches on this base
        # image so candidate/coverage builds remain deterministic.
        for build_sh in (context_dir / "build.sh", context_dir / "fuzzbench_benchmark" / "build.sh"):
            if not build_sh.is_file():
                continue
            text = build_sh.read_text(encoding="utf-8", errors="replace")
            marker = "# HGB sealed evaluator: avoid sanitizer-built libarchive iconv conftest."
            if marker in text:
                continue
            lines = text.splitlines()
            injection = [
                marker,
                "export am_cv_func_iconv=yes",
                "export am_cv_lib_iconv=no",
                "export am_cv_func_iconv_works=yes",
            ]
            if lines and lines[0].startswith("#!"):
                lines = [lines[0], *injection, *lines[1:]]
            else:
                lines = [*injection, *lines]
            build_sh.write_text("\n".join(lines) + "\n", encoding="utf-8")

    makefile = curl_root / "Makefile.am"
    if makefile.is_file() and fuzz_target.startswith("curl_fuzzer"):
        text = makefile.read_text(encoding="utf-8", errors="replace")
        rewritten = re.sub(
            rf"(?m)^({re.escape(fuzz_target)}_SOURCES\s*=\s*)\$\(COMMON_SOURCES\)$",
            rf"\1curl_fuzzer.cc",
            text,
        )
        if rewritten != text:
            makefile.write_text(rewritten, encoding="utf-8")


def _sealed_compile_block() -> str:
    """Return the final evaluator compile block appended to sealed Dockerfiles."""

    return (
        "# HGB sealed evaluator candidate build.\n"
        "ARG FUZZING_ENGINE=libfuzzer\n"
        "ARG SANITIZER=address\n"
        "ARG ARCHITECTURE=x86_64\n"
        "ARG FUZZING_LANGUAGE=c++\n"
        "ARG HGB_FUZZING_ENGINE=libfuzzer\n"
        "ARG HGB_SANITIZER=address\n"
        "ARG HGB_ARCHITECTURE=x86_64\n"
        "ARG HGB_FUZZING_LANGUAGE=c++\n"
        "ARG HGB_BUILD_VARIANT=default\n"
        "RUN printf '%s\\n' \"$HGB_SANITIZER:$HGB_FUZZING_ENGINE:$HGB_BUILD_VARIANT\" > /tmp/hgb_build_variant\n"
        "ENV FUZZING_ENGINE=${HGB_FUZZING_ENGINE}\n"
        "ENV SANITIZER=${HGB_SANITIZER}\n"
        "ENV ARCHITECTURE=${HGB_ARCHITECTURE}\n"
        "ENV FUZZING_LANGUAGE=${HGB_FUZZING_LANGUAGE}\n"
        "RUN if [ \"$HGB_FUZZING_ENGINE\" = \"libfuzzer\" ]; then "
        "export FUZZER_LIB=\"${FUZZER_LIB:--fsanitize=fuzzer}\"; "
        "else export FUZZER_LIB=\"${FUZZER_LIB:-${LIB_FUZZING_ENGINE_DEPRECATED:-/usr/lib/libFuzzingEngine.a}}\"; fi; "
        "FUZZING_ENGINE=\"$HGB_FUZZING_ENGINE\" SANITIZER=\"$HGB_SANITIZER\" "
        "ARCHITECTURE=\"$HGB_ARCHITECTURE\" FUZZING_LANGUAGE=\"$HGB_FUZZING_LANGUAGE\" compile\n"
    )


def build_candidate_image(
    *,
    context_dir: Path,
    dockerfile: Path,
    image_tag: str,
    fuzz_target: str,
    staged_candidate_host: Path,
    native_destination: str,
    work_dir: Path,
    runner: Runner = _run,
    timeout_seconds: int = 1800,
    sanitizer: str = "address",
    engine: str = "libfuzzer",
) -> BuildResult:
    """Build the sealed target image with the candidate overlaid at build time.

    The candidate is copied into the Docker context at the native destination
    path before the image build, so the FuzzBench ``build.sh`` compiles the
    candidate (not the reference).  The image is then reused for smoke,
    campaign, and coverage.
    """

    work_dir.mkdir(parents=True, exist_ok=True)
    # Resolve the relative native path inside the source_input tree.
    rel = native_destination
    for prefix in ("/src/", "src/"):
        if rel.startswith(prefix):
            rel = rel[len(prefix):]
            break
    rel = rel.lstrip("/")
    # Overlay the candidate into the context at the native destination so
    # COPY source_input/ /src/ restores it.
    dest_in_context = context_dir / "source_input" / rel
    dest_in_context.parent.mkdir(parents=True, exist_ok=True)
    staged_candidate_host = Path(staged_candidate_host)
    staged_candidate_host = _normalize_candidate_for_native_path(staged_candidate_host, native_destination, work_dir)
    _patch_single_target_build_context(context_dir, fuzz_target)
    candidate_sha256 = ""
    if staged_candidate_host.is_file():
        import shutil

        shutil.copy2(staged_candidate_host, dest_in_context)
        candidate_sha256 = _sha256_file(staged_candidate_host)
        # Also stage the candidate into hgb_candidate_overlay so the rewritten
        # Dockerfile can COPY it as the final write at the native path, after
        # any non-target sibling harness restore (reproduction-delta section 3).
        overlay_dir = context_dir / "hgb_candidate_overlay" / rel
        overlay_dir.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(staged_candidate_host, overlay_dir)
        # Append the final candidate-overlay COPY to the Dockerfile so the
        # candidate is the last write at the native harness path.
        df = Path(dockerfile)
        if df.is_file():
            text = df.read_text(encoding="utf-8", errors="replace")
            overlay_copy = f"COPY hgb_candidate_overlay/{rel} /src/{rel}"
            if overlay_copy not in text:
                text = text.rstrip() + "\n" + overlay_copy + "\n"
            compile_marker = "# HGB sealed evaluator candidate build."
            if compile_marker not in text:
                text = text.rstrip() + "\n" + _sealed_compile_block()
            else:
                compile_tail = text[text.rfind(compile_marker):]
                if (
                    "RUN FUZZING_ENGINE=\"$HGB_FUZZING_ENGINE\" SANITIZER=\"$HGB_SANITIZER\"" not in compile_tail
                    or "FUZZER_LIB" not in compile_tail
                ):
                    # Older sealed contexts only changed HGB_BUILD_VARIANT before
                    # compile. Use unique HGB_* args plus inline env assignments so
                    # the compile process sees SANITIZER=coverage even if legacy
                    # Docker reuses earlier ENV layers from the ASan candidate build.
                    text = text[:text.rfind(compile_marker)].rstrip() + "\n" + _sealed_compile_block()
            df.write_text(text, encoding="utf-8")

    build_command = [
        "docker", "build",
        "--build-arg", f"FUZZING_ENGINE={engine}",
        "--build-arg", f"SANITIZER={sanitizer}",
        "--build-arg", "ARCHITECTURE=x86_64",
        "--build-arg", "FUZZING_LANGUAGE=c++",
        "--build-arg", f"HGB_FUZZING_ENGINE={engine}",
        "--build-arg", f"HGB_SANITIZER={sanitizer}",
        "--build-arg", "HGB_ARCHITECTURE=x86_64",
        "--build-arg", "HGB_FUZZING_LANGUAGE=c++",
        "--build-arg", f"HGB_BUILD_VARIANT={sanitizer}-{engine}",
        "--file", str(dockerfile),
        "--tag", image_tag,
        str(context_dir),
    ]
    build_result = _run_phase(runner, build_command, timeout_seconds, "build candidate image")
    _write_log(work_dir / "image_build.log", build_result)

    image_digest = ""
    binary_sha256 = ""
    binary_verified = False
    overlay_audit: dict = {
        "candidate_sha256": candidate_sha256,
        "container_native_sha256": "",
        "matches_candidate": False,
        "matches_reference": False,
    }
    if build_result.exit_code == 0:
        inspect = _run_phase(runner, ["docker", "image", "inspect", "-f", "{{.Id}}", image_tag], 60, "inspect image")
        image_digest = inspect.stdout.strip()
        # Section 5.1: verify /out/<fuzz_target> exists and is executable.
        binary_path = f"/out/{Path(fuzz_target).stem}"
        verify_cmd = [
            "docker", "run", "--rm", image_tag,
            "sh", "-lc", f"test -x {binary_path} && sha256sum {binary_path}",
        ]
        verify = _run_phase(runner, verify_cmd, 120, "verify candidate binary")
        _write_log(work_dir / "binary_verify.log", verify)
        if verify.exit_code == 0:
            binary_verified = True
            line = (verify.stdout or "").strip().splitlines()
            if line:
                binary_sha256 = line[0].split()[0]
        # Section 3.4: overlay audit. Compare the source file compiled at the
        # native path with the candidate SHA256 to prove the candidate (not the
        # reference) was the final write at the native harness path.
        if rel and candidate_sha256:
            audit_cmd = [
                "docker", "run", "--rm", image_tag,
                "sh", "-lc", f"sha256sum /src/{rel} 2>/dev/null || true",
            ]
            audit = _run_phase(runner, audit_cmd, 120, "overlay audit")
            audit_line = (audit.stdout or "").strip().splitlines()
            container_sha = audit_line[0].split()[0] if audit_line and audit_line[0].split() else ""
            overlay_audit["container_native_sha256"] = container_sha
            overlay_audit["matches_candidate"] = bool(container_sha) and container_sha == candidate_sha256

    binary_path = f"/out/{Path(fuzz_target).stem}"
    return BuildResult(
        image_tag=image_tag,
        image_digest=image_digest,
        binary_path=binary_path,
        binary_sha256=binary_sha256,
        build_exit_code=build_result.exit_code,
        log=str(work_dir / "image_build.log"),
        compiler="clang/clang++",
        sanitizer=sanitizer,
        engine=engine,
        binary_verified=binary_verified,
        overlay_audit=overlay_audit,
    )


def build_coverage_image(
    *,
    context_dir: Path,
    dockerfile: Path,
    image_tag: str,
    fuzz_target: str,
    work_dir: Path,
    runner: Runner = _run,
    timeout_seconds: int = 1800,
    sanitizer: str = "coverage",
) -> BuildResult:
    """Build a separate coverage-instrumented image for source-based coverage.

    The coverage image reuses the same sealed candidate overlay context but is
    built with ``SANITIZER=coverage`` so the FuzzBench compile script
    instruments with ``-fprofile-instr-generate -fcoverage-mapping``. An
    address/libFuzzer image must NOT be reused for coverage unless it was
    explicitly built with source-based coverage instrumentation.  A sanitizer
    build-variant key is written immediately before ``RUN compile`` so Docker
    can reuse package-install layers without reusing the wrong compiled binary.
    """

    work_dir.mkdir(parents=True, exist_ok=True)
    build_command = [
        "docker", "build",
        "--build-arg", "FUZZING_ENGINE=libfuzzer",
        "--build-arg", f"SANITIZER={sanitizer}",
        "--build-arg", "ARCHITECTURE=x86_64",
        "--build-arg", "FUZZING_LANGUAGE=c++",
        "--build-arg", "HGB_FUZZING_ENGINE=libfuzzer",
        "--build-arg", f"HGB_SANITIZER={sanitizer}",
        "--build-arg", "HGB_ARCHITECTURE=x86_64",
        "--build-arg", "HGB_FUZZING_LANGUAGE=c++",
        "--build-arg", f"HGB_BUILD_VARIANT={sanitizer}-libfuzzer",
        "--file", str(dockerfile),
        "--tag", image_tag,
        str(context_dir),
    ]
    build_result = _run_phase(runner, build_command, timeout_seconds, "build coverage image")
    _write_log(work_dir / "image_build.log", build_result)
    image_digest = ""
    binary_verified = False
    binary_sha256 = ""
    if build_result.exit_code == 0:
        inspect = _run_phase(runner, ["docker", "image", "inspect", "-f", "{{.Id}}", image_tag], 60, "inspect coverage image")
        image_digest = inspect.stdout.strip()
        binary_path = f"/out/{Path(fuzz_target).stem}"
        verify_cmd = [
            "docker", "run", "--rm", image_tag,
            "sh", "-lc", f"test -x {binary_path} && sha256sum {binary_path}",
        ]
        verify = _run_phase(runner, verify_cmd, 120, "verify coverage binary")
        _write_log(work_dir / "binary_verify.log", verify)
        if verify.exit_code == 0:
            binary_verified = True
            line = (verify.stdout or "").strip().splitlines()
            if line:
                binary_sha256 = line[0].split()[0]
    return BuildResult(
        image_tag=image_tag,
        image_digest=image_digest,
        binary_path=f"/out/{Path(fuzz_target).stem}",
        binary_sha256=binary_sha256,
        build_exit_code=build_result.exit_code,
        log=str(work_dir / "image_build.log"),
        compiler="clang/clang++",
        sanitizer=sanitizer,
        engine="coverage",
        binary_verified=binary_verified,
        overlay_audit=None,
    )


def _container_run(
    *,
    image_tag: str,
    work_dir: Path,
    runner: Runner,
    timeout_seconds: int,
    command: list[str],
    phase: str,
    copy_out: tuple[str, Path] | None = None,
    copy_in: list[tuple[Path, str]] | None = None,
    env: list[str] | None = None,
) -> CommandResult:
    """Run a one-shot container with the candidate image and capture logs.

    ``copy_in`` is a list of ``(host_path, container_path)`` tuples copied into
    the container *before* it starts (so smoke/campaign samples are present).
    ``copy_out`` is a ``(container_path, host_path)`` tuple.  The container
    path is prefixed with the generated container name so ``docker cp``
    receives a valid ``<name>:<path>`` source.  Earlier versions passed a
    malformed ``hgb-eval-<phase>-:container:`` literal which never copied real
    artifacts out of the container, and smoke samples were never copied in.
    """
    work_dir.mkdir(parents=True, exist_ok=True)
    container_name = f"hgb-eval-{phase}-{uuid.uuid4().hex[:12]}"
    create = ["docker", "create", "--name", container_name]
    if env:
        for pair in env:
            create.extend(["-e", pair])
    create.append(image_tag)
    create.extend(command)
    phases: list[tuple[str, CommandResult]] = []
    create_result = _run_phase(runner, create, timeout_seconds, f"create {phase}")
    phases.append(("create", create_result))
    result = create_result
    # Track the phased copy/execution audit (zeta plan §2). A required
    # ``docker cp`` input that fails must fail the whole phase: the target
    # cannot be considered executed if its input was never copied in.
    copy_in_ok = True
    start_exit_code: int | None = None
    copy_out_ok = True
    try:
        if create_result.exit_code == 0:
            for host_path, container_path in (copy_in or []):
                host_p = Path(host_path)
                if not host_p.is_file():
                    # A required input that does not exist on the host is a
                    # failed copy_in; the target cannot run on the intended
                    # input.
                    copy_in_ok = False
                    continue
                cp_in = _run_phase(
                    runner,
                    ["docker", "cp", str(host_p), f"{container_name}:{container_path}"],
                    timeout_seconds,
                    f"copy_in {phase}",
                )
                phases.append(("copy_in", cp_in))
                if cp_in.exit_code != 0:
                    copy_in_ok = False
            # If a required input copy failed, do not start the target: the
            # phase is failed and the marker can never legitimately appear.
            if copy_in_ok:
                start_result = _run_phase(runner, ["docker", "start", "-a", container_name], timeout_seconds, f"run {phase}")
                phases.append(("run", start_result))
                result = start_result
                start_exit_code = start_result.exit_code
            else:
                start_result = CommandResult(list(command), 1, "", f"copy_in failed for {phase}; target not started")
                phases.append(("run", start_result))
                result = start_result
                start_exit_code = 1
            if copy_out:
                container_src, dst = copy_out
                docker_cp_src = f"{container_name}:{container_src}"
                dst.parent.mkdir(parents=True, exist_ok=True)
                cp = _run_phase(runner, ["docker", "cp", docker_cp_src, str(dst)], timeout_seconds, f"copy {phase}")
                phases.append(("copy", cp))
                if cp.exit_code != 0:
                    copy_out_ok = False
    finally:
        rm = _run_phase(runner, ["docker", "rm", "-f", container_name], 60, f"cleanup {phase}")
        phases.append(("cleanup", rm))
    log_path = work_dir / f"{phase}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    chunks = []
    for label, res in phases:
        chunks.append(
            f"## {label}\n$ " + " ".join(shlex.quote(c) for c in res.command)
            + "\n\n[stdout]\n" + res.stdout + "\n[stderr]\n" + res.stderr
            + f"\n[exit]\n{res.exit_code}\n"
        )
    log_path.write_text("\n\n".join(chunks), encoding="utf-8")
    result.command = [image_tag, *command]
    # Attach the phased audit so callers can distinguish "the container ran"
    # from "the target actually executed on the copied input" (zeta plan §2).
    try:
        result.copy_in_ok = copy_in_ok
        result.start_exit_code = start_exit_code
        result.copy_out_ok = copy_out_ok
    except AttributeError:
        pass
    return result


def run_smoke(
    *,
    image_tag: str,
    binary_path: str,
    seeds: list[Path],
    work_dir: Path,
    runner: Runner = _run,
    timeout_seconds: int = 120,
) -> dict:
    """Run the built binary on empty input and available seeds (sanitizer smoke).

    Each sample file is copied into the container before the binary runs so the
    target actually executes on real input.  A smoke run that never executed
    the target (e.g. missing input) is reported as ``executed=false``.
    """
    work_dir.mkdir(parents=True, exist_ok=True)
    samples: list[dict] = []
    # Empty input sample.
    empty = work_dir / "empty_input"
    empty.write_bytes(b"")
    invocations = [(empty, "empty")]
    for seed in seeds:
        if Path(seed).is_file():
            invocations.append((Path(seed), Path(seed).name))
    misuse_crash = False
    any_executed = False
    for host_input, label in invocations:
        container_input = f"/tmp/smoke_{label}"
        # The container echoes the start marker to stderr, then execs the
        # target on the copied input. Execution is proven ONLY by the marker
        # plus a successful input copy -- never by the exit code or nonempty
        # stderr alone (zeta plan §2).
        result = _container_run(
            image_tag=image_tag,
            work_dir=work_dir / "smoke" / label,
            runner=runner,
            timeout_seconds=timeout_seconds,
            command=["sh", "-lc", f"echo {HGB_TARGET_START_MARKER} >&2; exec {binary_path} {container_input}"],
            phase=f"smoke_{label}",
            copy_in=[(host_input, container_input)],
        )
        copy_in_ok = bool(getattr(result, "copy_in_ok", True))
        combined_log = (result.stderr or "") + (result.stdout or "")
        marker_seen = HGB_TARGET_START_MARKER in combined_log
        executed = copy_in_ok and marker_seen
        # A sanitizer-misuse crash is indicated by a non-zero exit (libFuzzer
        # returns 77 for a misuse crash on a single input).  Timeouts (124)
        # are not crashes.
        crashed = result.exit_code not in (0, 1, 124)
        if "AddressSanitizer" in result.stderr or "UndefinedBehaviorSanitizer" in result.stderr:
            crashed = True
        if crashed:
            misuse_crash = True
        if executed:
            any_executed = True
        samples.append({
            "label": label,
            "exit_code": result.exit_code,
            "crashed": crashed,
            "executed": executed,
            "copy_in_ok": copy_in_ok,
            "marker_seen": marker_seen,
            "stderr": result.stderr[:4000],
        })
    return {"samples": samples, "misuse_crash": misuse_crash, "any_executed": any_executed}


def run_campaign(
    *,
    image_tag: str,
    binary_path: str,
    corpus_dir: Path,
    work_dir: Path,
    campaign_seconds: int,
    runner: Runner = _run,
    timeout_seconds: int | None = None,
) -> dict:
    """Run a fixed-budget libFuzzer campaign and parse execs_done from the log.

    Seed corpus files are copied into the container before the campaign starts.
    After the campaign the final corpus, crashes, and fuzzer stats are copied
    out so the coverage stage can replay the real corpus.
    """
    work_dir.mkdir(parents=True, exist_ok=True)
    corpus_dir.mkdir(parents=True, exist_ok=True)
    artifact_dir = work_dir / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    budget = max(1, int(campaign_seconds))
    run_count = max(1, min(10000, budget * 256))
    fuzzer_timeout = budget + 5
    # Build copy_in list for seed corpus files.
    copy_in: list[tuple[Path, str]] = []
    seed_index = 0
    for seed in sorted(corpus_dir.iterdir()) if corpus_dir.is_dir() else []:
        if seed.is_file():
            # docker cp cannot create missing parent directories inside a
            # stopped container. Stage seeds under /tmp, then move them into
            # /tmp/corpus after the campaign command creates the directory.
            copy_in.append((seed, f"/tmp/hgb_campaign_seed_{seed_index:04d}"))
            seed_index += 1
    seed_stage = (
        'mkdir -p /tmp/corpus /tmp/artifacts; '
        'for f in /tmp/hgb_campaign_seed_*; do '
        '[ -e "$f" ] || continue; cp "$f" "/tmp/corpus/$(basename "$f")"; '
        'done; '
    )
    cmd = [
        "sh",
        "-lc",
        f'{seed_stage}timeout -s INT -k 5s {fuzzer_timeout}s {binary_path} '
        f'-runs={run_count} -max_total_time={budget} -artifact_prefix=/tmp/artifacts/ /tmp/corpus '
        f'> /tmp/campaign.log 2>&1; '
        f'fuzzer_rc=$?; echo "HGB_FUZZER_EXIT_CODE=$fuzzer_rc"; '
        f'echo "---STATS---"; '
        f'ls /tmp/corpus | wc -l; '
        f'ls /tmp/artifacts 2>/dev/null | wc -l; '
        f'cat /tmp/campaign.log; '
        f'cd /tmp && tar -cf /tmp/corpus.tar corpus 2>/dev/null || true',
    ]
    timeout = timeout_seconds or (budget + 60)
    campaign_work = work_dir / "campaign"
    final_corpus_dir = work_dir / "corpus"
    final_corpus_dir.mkdir(parents=True, exist_ok=True)
    result = _container_run(
        image_tag=image_tag,
        work_dir=campaign_work,
        runner=runner,
        timeout_seconds=timeout,
        command=cmd,
        phase="campaign",
        copy_in=copy_in if copy_in else None,
        copy_out=("/tmp/corpus.tar", campaign_work / "corpus.tar"),
    )
    # Extract the final campaign corpus so the coverage stage can replay it.
    # The tar contains a top-level ``corpus/`` directory; strip that component
    # so the final corpus files land directly in final_corpus_dir and are
    # counted recursively (zeta plan §2: the old extraction left files under
    # ``corpus/`` while queue_count only counted top-level files).
    import tarfile
    corpus_tar = campaign_work / "corpus.tar"
    if corpus_tar.is_file():
        try:
            with tarfile.open(corpus_tar) as tf:
                for member in tf.getmembers():
                    name = member.name
                    # Strip the leading directory component (``corpus/``).
                    if "/" in name:
                        name = name.split("/", 1)[1]
                    if not name or name.endswith("/"):
                        continue
                    stripped = member.replace(name=name)
                    try:
                        tf.extract(stripped, final_corpus_dir, filter="data")
                    except TypeError:
                        tf.extract(stripped, final_corpus_dir)
        except (OSError, tarfile.TarError):
            pass
    (campaign_work / "campaign.log").write_text(result.stdout + "\n" + result.stderr, encoding="utf-8")
    log = result.stdout + "\n" + result.stderr
    execs_done = _parse_execs_done(log)
    new_units = _parse_new_units(log)
    crashes = int("SUMMARY: AddressSanitizer" in log or "SUMMARY: UndefinedBehaviorSanitizer" in log)
    final_corpus_file_count = 0
    if final_corpus_dir.is_dir():
        final_corpus_file_count = sum(1 for p in final_corpus_dir.rglob("*") if p.is_file())
    copy_out_ok = bool(getattr(result, "copy_out_ok", True))
    fuzzer_timed_out = "HGB_FUZZER_EXIT_CODE=124" in log
    return {
        "execs_done": execs_done,
        "new_units": new_units,
        "crashes": crashes,
        "timeouts": int(result.exit_code == 124 or fuzzer_timed_out),
        "ooms": int("out-of-memory" in log.lower() or "SUMMARY: libFuzzer: out-of-memory" in log),
        "peak_rss_mb": _parse_peak_rss(log),
        "exit_code": result.exit_code,
        "log": str(campaign_work / "campaign.log"),
        "corpus_dir": str(final_corpus_dir),
        "final_corpus_dir": str(final_corpus_dir),
        "queue_count": final_corpus_file_count,
        "final_corpus_file_count": final_corpus_file_count,
        "copy_out_ok": copy_out_ok,
    }


def _parse_execs_done(log: str) -> int:
    import re

    for pattern in (r"#(\d+)\s+INITED", r"#(\d+)\s+DONE", r"stat::number_of_executed_units:\s*(\d+)", r"execs_done:\s*(\d+)"):
        m = re.search(pattern, log)
        if m:
            return int(m.group(1))
    return 0


def _parse_new_units(log: str) -> int:
    import re

    m = re.search(r"stat::new_units_added:\s*(\d+)", log)
    if m:
        return int(m.group(1))
    m = re.search(r"#(\d+)\s+NEW", log)
    return int(m.group(1)) if m else 0


def _parse_peak_rss(log: str) -> int:
    import re

    m = re.search(r"stat::peak_rss_mb:\s*(\d+)", log)
    return int(m.group(1)) if m else 0


def run_coverage(
    *,
    image_tag: str,
    binary_path: str,
    corpus_dir: Path,
    work_dir: Path,
    runner: Runner = _run,
    timeout_seconds: int = 600,
    require_coverage_report: bool = False,
) -> dict:
    """Replay the final corpus under a coverage-instrumented binary.

    Returns a dict with the raw coverage text path and exit code.  The caller
    parses it with :mod:`hgb_coverage`.  This never fabricates coverage: if the
    coverage report is missing or empty, the evaluator must mark coverage as
    failed.  The export includes per-function detail (not ``-summary-only``)
    so the evaluator can match intended API symbols to covered functions for
    real API reachability evidence.

    When ``require_coverage_report`` is true (strict eta), the coverage report
    must be a real ``coverage.json`` copied out of the container; the
    stdout-only ``report_exists`` fallback is removed.  The replay command
    executes every copied corpus file in a per-file loop (one process per
    input) and writes ``HGB_INPUTS_REPLAYED=<n>`` to stderr so the caller can
    prove the corpus was actually replayed; the loop fails when zero files are
    executed (eta plan §2/§6).
    """
    work_dir.mkdir(parents=True, exist_ok=True)
    # Build copy_in list for corpus files to replay.
    copy_in: list[tuple[Path, str]] = []
    seed_index = 0
    for seed in sorted(corpus_dir.iterdir()) if corpus_dir.is_dir() else []:
        if seed.is_file():
            # Stage under /tmp because docker cp cannot create /tmp/corpus in a
            # stopped container. The replay script moves staged files after it
            # creates the directory.
            copy_in.append((seed, f"/tmp/hgb_coverage_seed_{seed_index:04d}"))
            seed_index += 1
    coverage_seed_stage = (
        'mkdir -p /tmp/corpus; '
        'for f in /tmp/hgb_coverage_seed_*; do '
        '[ -e "$f" ] || continue; cp "$f" "/tmp/corpus/cov_${f##*_}"; '
        'done; '
    )
    cov_work = work_dir / "coverage"
    if require_coverage_report:
        # Eta replay: execute every copied corpus file once in a per-file loop
        # (one process per input, one profraw per input via the %p pattern), so
        # the replay demonstrably executes all copied corpus files.  Fail when
        # zero files are executed.  The coverage report is a copied
        # coverage.json; stdout is not a fallback (eta plan §6).
        replay_script = (
            'set -e; mkdir -p /tmp/cov; ' + coverage_seed_stage +
            'n=0; '
            'for f in /tmp/corpus/*; do '
            '[ -f "$f" ] || continue; '
            f'LLVM_PROFILE_FILE=/tmp/cov/coverage-%p.profraw {binary_path} "$f" >/dev/null 2>&1 || true; '
            'n=$((n+1)); '
            'done; '
            'printf "HGB_INPUTS_REPLAYED=%s\\n" "$n" >&2; '
            'test "$n" -gt 0; '
            f'llvm-profdata merge -o /tmp/cov/merged.profdata /tmp/cov/coverage-*.profraw && '
            f'llvm-cov export -format=text {binary_path} -instr-profile=/tmp/cov/merged.profdata '
            f'> /tmp/cov/coverage.json 2>/tmp/cov/cov.err'
        )
    else:
        replay_script = (
            f'mkdir -p /tmp/cov; {coverage_seed_stage}LLVM_PROFILE_FILE=/tmp/cov/coverage.profraw '
            f'{binary_path} -runs=0 /tmp/corpus && '
            f'llvm-profdata merge -o /tmp/cov/merged.profdata /tmp/cov/*.profraw && '
            f'llvm-cov export -format=text {binary_path} -instr-profile=/tmp/cov/merged.profdata '
            f'> /tmp/cov/coverage.json 2>/tmp/cov/cov.err; cat /tmp/cov/coverage.json'
        )
    cmd = ["sh", "-lc", replay_script]
    result = _container_run(
        image_tag=image_tag,
        work_dir=cov_work,
        runner=runner,
        timeout_seconds=timeout_seconds,
        command=cmd,
        phase="coverage",
        copy_in=copy_in if copy_in else None,
        copy_out=("/tmp/cov/coverage.json", cov_work / "coverage.json"),
    )
    copy_in_ok = bool(getattr(result, "copy_in_ok", True))
    copy_out_ok = bool(getattr(result, "copy_out_ok", True))
    cov_path = cov_work / "coverage.json"
    # Parse the executed-file count from the HGB_INPUTS_REPLAYED marker the eta
    # replay loop writes to stderr.  Fall back to the copy_in count for the
    # legacy -runs=0 replay path.
    inputs_replayed = len(copy_in)
    marker_log = (result.stderr or "") + "\n" + (result.stdout or "")
    m = re.search(r"HGB_INPUTS_REPLAYED=(\d+)", marker_log)
    if m:
        inputs_replayed = int(m.group(1))
    # A successful coverage phase requires a real coverage.json copied from
    # the container OR nonempty stdout plus a parseable report (zeta plan §2).
    # For strict eta, the copied coverage.json is mandatory: the stdout-only
    # report_exists fallback is removed (eta plan §6).
    if require_coverage_report:
        report_exists = cov_path.is_file()
    else:
        report_exists = cov_path.is_file() or bool((result.stdout or "").strip())
    return {
        "exit_code": result.exit_code,
        "raw_text": result.stdout,
        "log": str(cov_work / "coverage.log"),
        "coverage_report_path": str(cov_path) if cov_path.is_file() else "",
        "copy_in_ok": copy_in_ok,
        "copy_out_ok": copy_out_ok,
        "report_exists": report_exists,
        "inputs_replayed": inputs_replayed,
    }


# -- G2Fuzz native target-pair builder ------------------------------------

G2FUZZ_BUILD_MODE = "fuzzbench_native_afl_cmps"


def g2fuzz_target_pair_build_commands(
    *,
    artifact_dir: Path,
    target_package: Path,
    workspace: Path,
    program_id: str,
) -> dict:
    """Return the two (afl/cmp) FuzzBench build commands for a G2Fuzz pair.

    Both variants share the same ``argv`` (the native FuzzBench ``build.sh``)
    and the same AFL++ compiler/toolchain env.  They differ ONLY in
    ``AFL_LLVM_CMPLOG`` (0 for ``.afl``, 1 for CmpLog ``.cmp``) and the
    ``HGB_G2FUZZ_OUTPUT`` path.  CmpLog is used exclusively for the ``.cmp``
    build; the ``.afl`` build never sets ``AFL_LLVM_CMPLOG=1``.
    """

    artifact = Path(artifact_dir)
    bench_root = Path(target_package)
    out_root = Path(workspace)
    build_sh = bench_root / "fuzzbench_benchmark" / "build.sh"
    cc = artifact / "afl-clang-fast"
    cxx = artifact / "afl-clang-fast++"
    src = bench_root / "source_input"
    common_env = {
        "CC": str(cc),
        "CXX": str(cxx),
        "FUZZING_ENGINE": "afl",
        "SANITIZER": "address",
        "ARCHITECTURE": "x86_64",
        "SRC": str(src),
        "WORK": str(out_root / "target" / "build_work"),
        "LIB_FUZZING_ENGINE": "",
    }
    afl_env = dict(common_env)
    afl_env["AFL_LLVM_CMPLOG"] = "0"
    afl_env["HGB_G2FUZZ_OUTPUT"] = str(out_root / "target" / "target.afl")
    cmp_env = dict(common_env)
    cmp_env["AFL_LLVM_CMPLOG"] = "1"
    cmp_env["HGB_G2FUZZ_OUTPUT"] = str(out_root / "target" / "target.cmp")
    argv = ["bash", str(build_sh)]
    return {
        "program_id": program_id,
        "build_mode": G2FUZZ_BUILD_MODE,
        "afl": {"env": afl_env, "argv": argv},
        "cmp": {"env": cmp_env, "argv": argv},
        "expected_difference": "AFL_LLVM_CMPLOG and output path only",
    }


def verify_g2fuzz_target_pair(afl_binary: Path, cmp_binary: Path) -> dict:
    """Verify a built G2Fuzz target pair: both binaries exist and are executable.

    A missing ``.cmp`` binary fails verification.  This is used by the pipeline
    and the offline tests; it never soft-skips a missing pair.
    """

    import os as _os

    def _stat(p: Path) -> dict:
        return {
            "path": str(p),
            "exists": p.is_file(),
            "executable": _os.access(p, _os.X_OK) if p.exists() else False,
            "size": p.stat().st_size if p.exists() else 0,
        }

    afl = _stat(Path(afl_binary))
    cmp = _stat(Path(cmp_binary))
    ok = bool(afl["exists"] and afl["executable"] and afl["size"] > 0 and cmp["exists"] and cmp["executable"] and cmp["size"] > 0)
    return {"afl": afl, "cmp": cmp, "ok": ok, "build_mode": G2FUZZ_BUILD_MODE}


# -- G2Fuzz triple (.afl/.cmp/.cov) Docker builder -------------------------

G2FUZZ_AFL_ENGINE = "afl"
G2FUZZ_COVERAGE_ENGINE = "coverage"
G2FUZZ_COVERAGE_FLAGS = "-fprofile-instr-generate -fcoverage-mapping"
G2FUZZ_TRIPLE_VARIANTS = ("afl", "cmp", "cov")


def _g2fuzz_variant_build_args(*, variant: str, sanitizer: str) -> list[str]:
    """Return the FuzzBench ``docker build`` arg list for a G2Fuzz variant.

    - ``afl``: AFL++ default instrumentation (``FUZZING_ENGINE=afl``).
    - ``cmp``: AFL++ CmpLog instrumentation (``FUZZING_ENGINE=afl`` plus
      ``AFL_LLVM_CMPLOG=1`` so ``afl-clang-fast`` instruments comparison
      logging).
    - ``cov``: coverage instrumentation (``FUZZING_ENGINE=coverage`` so the
      FuzzBench compile script uses clang with
      ``-fprofile-instr-generate -fcoverage-mapping``).
    """

    if variant == "cov":
        return [
            "--build-arg", f"FUZZING_ENGINE={G2FUZZ_COVERAGE_ENGINE}",
            "--build-arg", f"SANITIZER={sanitizer}",
            "--build-arg", "ARCHITECTURE=x86_64",
        ]
    # Both afl and cmp use the AFL engine; cmp additionally passes
    # AFL_LLVM_CMPLOG=1 as a build-arg so it is present in the build env.
    args = [
        "--build-arg", f"FUZZING_ENGINE={G2FUZZ_AFL_ENGINE}",
        "--build-arg", f"SANITIZER={sanitizer}",
        "--build-arg", "ARCHITECTURE=x86_64",
    ]
    if variant == "cmp":
        args.extend(["--build-arg", "AFL_LLVM_CMPLOG=1"])
    return args


def _g2fuzz_variant_env(variant: str) -> dict[str, str]:
    """Return the environment variable overrides that distinguish each variant.

    These are recorded in the build commands dict for auditability and used by
    the pipeline to verify CmpLog and coverage instrumentation are present.
    """

    if variant == "afl":
        return {"AFL_LLVM_CMPLOG": "0"}
    if variant == "cmp":
        return {"AFL_LLVM_CMPLOG": "1"}
    if variant == "cov":
        return {
            "CC": "clang",
            "CXX": "clang++",
            "CFLAGS": G2FUZZ_COVERAGE_FLAGS,
            "CXXFLAGS": G2FUZZ_COVERAGE_FLAGS,
        }
    return {}


def g2fuzz_target_triple_build_commands(
    *,
    benchmark_dir: Path,
    image_tag_base: str,
    fuzz_target: str,
    program_id: str,
    sanitizer: str = "address",
) -> dict:
    """Return the three (afl/cmp/cov) Docker build commands for a G2Fuzz triple.

    Each variant builds from the exact FuzzBench benchmark Dockerfile (not a
    direct-host ``build.sh`` invocation).  The three variants differ only in
    build args and environment: ``.afl`` uses default AFL++ instrumentation,
    ``.cmp`` adds ``AFL_LLVM_CMPLOG=1``, and ``.cov`` uses the coverage engine
    with ``-fprofile-instr-generate -fcoverage-mapping``.
    """

    dockerfile = Path(benchmark_dir) / "Dockerfile"
    commands: dict[str, Any] = {}
    for variant in G2FUZZ_TRIPLE_VARIANTS:
        tag = f"{image_tag_base}-{variant}"
        build_cmd = [
            "docker", "build",
            *_g2fuzz_variant_build_args(variant=variant, sanitizer=sanitizer),
            "--file", str(dockerfile),
            "--tag", tag,
            str(benchmark_dir),
        ]
        commands[variant] = {
            "build_command": build_cmd,
            "image_tag": tag,
            "build_args": _g2fuzz_variant_build_args(variant=variant, sanitizer=sanitizer),
            "env": _g2fuzz_variant_env(variant),
            "fuzz_target": fuzz_target,
            "variant": variant,
            "dockerfile": str(dockerfile),
        }
    return {
        "program_id": program_id,
        "build_mode": "fuzzbench_docker_triple",
        "sanitizer": sanitizer,
        **commands,
    }


def build_g2fuzz_target_variant(
    *,
    benchmark_dir: Path,
    image_tag: str,
    fuzz_target: str,
    variant: str,
    work_dir: Path,
    runner: Runner = _run,
    timeout_seconds: int = 3600,
    sanitizer: str = "address",
) -> dict:
    """Build one G2Fuzz target variant from the FuzzBench benchmark Dockerfile.

    Runs ``docker build`` on the exact benchmark Dockerfile with the variant's
    build args, then extracts ``/out/<fuzz_target>`` from the built image via a
    throwaway container.  Returns a record with the image tag/digest, binary
    path, sha256, and build exit code.  This never accepts a prebuilt binary:
    the variant is always built from the benchmark Dockerfile so the
    reproduction is traceable to the exact FuzzBench environment.
    """

    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / "out").mkdir(parents=True, exist_ok=True)
    dockerfile = Path(benchmark_dir) / "Dockerfile"
    build_command = [
        "docker", "build",
        *_g2fuzz_variant_build_args(variant=variant, sanitizer=sanitizer),
        "--file", str(dockerfile),
        "--tag", image_tag,
        str(benchmark_dir),
    ]
    build_result = _run_phase(runner, build_command, timeout_seconds, f"build g2fuzz {variant} target")
    _write_log(work_dir / f"build.{variant}.log", build_result)
    image_digest = ""
    binary_path = ""
    binary_sha256 = ""
    extracted = False
    if build_result.exit_code == 0:
        inspect = _run_phase(runner, ["docker", "image", "inspect", "-f", "{{.Id}}", image_tag], 60, f"inspect {variant} image")
        image_digest = inspect.stdout.strip()
        container_name = f"hgb-g2fuzz-{variant}-{uuid.uuid4().hex[:12]}"
        create = _run_phase(runner, ["docker", "create", "--name", container_name, image_tag, "true"], 60, f"create {variant}")
        if create.exit_code == 0:
            host_binary = work_dir / "out" / f"target.{variant}"
            cp = _run_phase(
                runner,
                ["docker", "cp", f"{container_name}:/out/{fuzz_target}", str(host_binary)],
                120,
                f"copy {variant} binary",
            )
            if cp.exit_code == 0 and host_binary.is_file():
                extracted = True
                binary_path = str(host_binary)
                binary_sha256 = _sha256_file(host_binary)
            _run_phase(runner, ["docker", "rm", "-f", container_name], 60, f"cleanup {variant}")
        else:
            _run_phase(runner, ["docker", "rm", "-f", container_name], 60, f"cleanup {variant}")
    return {
        "variant": variant,
        "sanitizer": sanitizer,
        "image_tag": image_tag,
        "image_digest": image_digest,
        "build_exit_code": build_result.exit_code,
        "binary_path": binary_path,
        "binary_sha256": binary_sha256,
        "binary_extracted": extracted,
        "log": str(work_dir / f"build.{variant}.log"),
        "build_command": build_result.command,
        "env": _g2fuzz_variant_env(variant),
    }


def build_g2fuzz_target_triple(
    *,
    benchmark_dir: Path,
    image_tag_base: str,
    fuzz_target: str,
    work_dir: Path,
    runner: Runner = _run,
    timeout_seconds: int = 3600,
    sanitizer: str = "address",
) -> dict:
    """Build all three G2Fuzz target variants (.afl, .cmp, .cov) via Docker.

    Returns a dict keyed by variant with build records.  Each variant is built
    from the exact FuzzBench benchmark Dockerfile with variant-specific build
    args.  The ``.afl`` variant uses default AFL++ instrumentation, ``.cmp``
    adds ``AFL_LLVM_CMPLOG=1`` for CmpLog, and ``.cov`` uses the coverage
    engine with ``-fprofile-instr-generate -fcoverage-mapping``.
    """

    results: dict[str, Any] = {}
    for variant in G2FUZZ_TRIPLE_VARIANTS:
        tag = f"{image_tag_base}-{variant}"
        results[variant] = build_g2fuzz_target_variant(
            benchmark_dir=benchmark_dir,
            image_tag=tag,
            fuzz_target=fuzz_target,
            variant=variant,
            work_dir=work_dir,
            runner=runner,
            timeout_seconds=timeout_seconds,
            sanitizer=sanitizer,
        )
    return results


def verify_g2fuzz_target_triple(afl_binary: Path, cmp_binary: Path, cov_binary: Path) -> dict:
    """Verify a built G2Fuzz target triple: all three binaries exist and are executable.

    A missing ``.cov`` or ``.cmp`` binary fails verification.  This is used by
    the gamma pipeline and the offline tests; it never soft-skips a missing
    triple member.
    """

    import os as _os

    def _stat(p: Path) -> dict:
        return {
            "path": str(p),
            "exists": p.is_file(),
            "executable": _os.access(p, _os.X_OK) if p.exists() else False,
            "size": p.stat().st_size if p.exists() else 0,
        }

    afl = _stat(Path(afl_binary))
    cmp = _stat(Path(cmp_binary))
    cov = _stat(Path(cov_binary))
    ok = bool(
        afl["exists"] and afl["executable"] and afl["size"] > 0
        and cmp["exists"] and cmp["executable"] and cmp["size"] > 0
        and cov["exists"] and cov["executable"] and cov["size"] > 0
    )
    return {"afl": afl, "cmp": cmp, "cov": cov, "ok": ok, "build_mode": "fuzzbench_docker_triple"}


# -- ELFuzz native+coverage SUT builder ------------------------------------

ELFUZZ_NATIVE_ENGINE = "libfuzzer"
ELFUZZ_COVERAGE_ENGINE = "coverage"


def _elfuzz_build_args(*, engine: str, sanitizer: str) -> list[str]:
    """Return the FuzzBench ``docker build`` arg list for an ELFuzz SUT variant.

    The FuzzBench base-builder ``compile`` script reads ``FUZZING_ENGINE`` and
    ``SANITIZER`` build args and invokes the benchmark ``build.sh`` with the
    matching ``CC``/``CXX``/``FUZZER_LIB``/``SRC``/``WORK``/``OUT`` environment,
    producing ``/out/<fuzz_target>``.  The native variant uses the libFuzzer
    engine (one-input execution via ``@@``); the coverage variant uses the
    FuzzBench coverage engine, which instruments with
    ``-fprofile-instr-generate -fcoverage-mapping`` and a replay main.
    """

    return [
        "--build-arg", f"FUZZING_ENGINE={engine}",
        "--build-arg", f"SANITIZER={sanitizer}",
        "--build-arg", "ARCHITECTURE=x86_64",
    ]


def build_elfuzz_sut(
    *,
    benchmark_dir: Path,
    image_tag: str,
    fuzz_target: str,
    work_dir: Path,
    runner: Runner = _run,
    timeout_seconds: int = 3600,
    engine: str = ELFUZZ_NATIVE_ENGINE,
    sanitizer: str = "address",
) -> dict:
    """Build one ELFuzz SUT variant (native or coverage) from the FuzzBench benchmark.

    Runs ``docker build`` on the exact FuzzBench benchmark Dockerfile with the
    engine/sanitizer build args, then extracts ``/out/<fuzz_target>`` from the
    built image into ``work_dir/out/<fuzz_target>``.  Returns a record with the
    image tag/digest, binary path, and build exit code.  This never accepts a
    prebuilt binary: the SUT is always built from the benchmark Dockerfile so
    the reproduction is traceable to the exact FuzzBench environment.
    """

    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    (work_dir / "out").mkdir(parents=True, exist_ok=True)
    dockerfile = Path(benchmark_dir) / "Dockerfile"
    build_command = [
        "docker", "build",
        *_elfuzz_build_args(engine=engine, sanitizer=sanitizer),
        "--file", str(dockerfile),
        "--tag", image_tag,
        str(benchmark_dir),
    ]
    build_result = _run_phase(runner, build_command, timeout_seconds, f"build elfuzz {engine} sut")
    _write_log(work_dir / "build.log", build_result)
    image_digest = ""
    binary_path = ""
    binary_sha256 = ""
    extracted = False
    if build_result.exit_code == 0:
        inspect = _run_phase(runner, ["docker", "image", "inspect", "-f", "{{.Id}}", image_tag], 60, f"inspect {engine} image")
        image_digest = inspect.stdout.strip()
        # Extract /out/<fuzz_target> from the image via a throwaway container.
        container_name = f"hgb-elfuzz-{engine}-{uuid.uuid4().hex[:12]}"
        create = _run_phase(runner, ["docker", "create", "--name", container_name, image_tag, "true"], 60, f"create {engine}")
        copy_out = CommandResult(list(create.command), create.exit_code, create.stdout, create.stderr)
        if create.exit_code == 0:
            host_binary = work_dir / "out" / Path(fuzz_target).name
            cp = _run_phase(
                runner,
                ["docker", "cp", f"{container_name}:/out/{fuzz_target}", str(host_binary)],
                120,
                f"copy {engine} binary",
            )
            copy_out = cp
            if cp.exit_code == 0 and host_binary.is_file():
                extracted = True
                binary_path = str(host_binary)
                binary_sha256 = _sha256_file(host_binary)
            _run_phase(runner, ["docker", "rm", "-f", container_name], 60, f"cleanup {engine}")
        else:
            _run_phase(runner, ["docker", "rm", "-f", container_name], 60, f"cleanup {engine}")
    return {
        "engine": engine,
        "sanitizer": sanitizer,
        "image_tag": image_tag,
        "image_digest": image_digest,
        "build_exit_code": build_result.exit_code,
        "binary_path": binary_path,
        "binary_sha256": binary_sha256,
        "binary_extracted": extracted,
        "log": str(work_dir / "build.log"),
        "build_command": build_result.command,
    }


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Deterministic FuzzBench builder helper")
    parser.add_argument("--image-tag", action="store_true")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--target", default="")
    parser.add_argument("--candidate-id", default="")
    parser.add_argument("--generator", default="ckgfuzzer")
    args = parser.parse_args()
    if args.image_tag:
        print(deterministic_image_tag(args.run_id, args.target, args.candidate_id, generator=args.generator))
        return 0
    parser.print_help()
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
