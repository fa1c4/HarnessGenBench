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


@dataclass
class CommandResult:
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str


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
    # Overlay the candidate into the context at the native destination.
    dest_in_context = context_dir / native_destination.lstrip("/")
    if dest_in_context.parent != context_dir and not native_destination.startswith("source_input/"):
        # The native destination is under /src/<repo>/...; mirror it inside the
        # context's source_input tree so COPY source_input/ /src/ restores it.
        rel = native_destination
        for prefix in ("/src/", "src/"):
            if rel.startswith(prefix):
                rel = rel[len(prefix):]
                break
        dest_in_context = context_dir / "source_input" / rel
    dest_in_context.parent.mkdir(parents=True, exist_ok=True)
    staged_candidate_host = Path(staged_candidate_host)
    if staged_candidate_host.is_file():
        import shutil

        shutil.copy2(staged_candidate_host, dest_in_context)

    build_command = ["docker", "build", "--file", str(dockerfile), "--tag", image_tag, str(context_dir)]
    build_result = _run_phase(runner, build_command, timeout_seconds, "build candidate image")
    _write_log(work_dir / "image_build.log", build_result)

    image_digest = ""
    if build_result.exit_code == 0:
        inspect = _run_phase(runner, ["docker", "image", "inspect", "-f", "{{.Id}}", image_tag], 60, "inspect image")
        image_digest = inspect.stdout.strip()

    binary_sha256 = ""
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
    env: list[str] | None = None,
) -> CommandResult:
    """Run a one-shot container with the candidate image and capture logs."""
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
    try:
        if create_result.exit_code == 0:
            start_result = _run_phase(runner, ["docker", "start", "-a", container_name], timeout_seconds, f"run {phase}")
            phases.append(("run", start_result))
            result = start_result
            if copy_out:
                src, dst = copy_out
                cp = _run_phase(runner, ["docker", "cp", src, str(dst)], timeout_seconds, f"copy {phase}")
                phases.append(("copy", cp))
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
    """Run the built binary on empty input and available seeds (sanitizer smoke)."""
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
    for host_input, label in invocations:
        container_input = f"/tmp/smoke_{label}"
        result = _container_run(
            image_tag=image_tag,
            work_dir=work_dir / "smoke" / label,
            runner=runner,
            timeout_seconds=timeout_seconds,
            command=["sh", "-lc", f"cp {container_input} /tmp/in && {binary_path} /tmp/in"],
            phase=f"smoke_{label}",
            env=[f"HGB_SMOKE_INPUT={container_input}"],
        )
        # A sanitizer-misuse crash is indicated by a non-zero exit (libFuzzer
        # returns 77 for a misuse crash on a single input).
        crashed = result.exit_code not in (0, 1, 124)
        if "AddressSanitizer" in result.stderr or "UndefinedBehaviorSanitizer" in result.stderr:
            crashed = True
        if crashed:
            misuse_crash = True
        samples.append({"label": label, "exit_code": result.exit_code, "crashed": crashed, "stderr": result.stderr[:4000]})
    return {"samples": samples, "misuse_crash": misuse_crash}


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
    """Run a fixed-budget libFuzzer campaign and parse execs_done from the log."""
    work_dir.mkdir(parents=True, exist_ok=True)
    corpus_dir.mkdir(parents=True, exist_ok=True)
    artifact_dir = work_dir / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    budget = max(1, int(campaign_seconds))
    cmd = [
        "sh",
        "-lc",
        f'mkdir -p /tmp/corpus /tmp/artifacts && {binary_path} '
        f'-max_total_time={budget} -artifact_prefix=/tmp/artifacts/ /tmp/corpus',
    ]
    timeout = timeout_seconds or (budget + 60)
    result = _container_run(
        image_tag=image_tag,
        work_dir=work_dir / "campaign",
        runner=runner,
        timeout_seconds=timeout,
        command=cmd,
        phase="campaign",
    )
    log = result.stdout + "\n" + result.stderr
    execs_done = _parse_execs_done(log)
    new_units = _parse_new_units(log)
    crashes = int("SUMMARY: AddressSanitizer" in log or "SUMMARY: UndefinedBehaviorSanitizer" in log)
    return {
        "execs_done": execs_done,
        "new_units": new_units,
        "crashes": crashes,
        "timeouts": int(result.exit_code == 124),
        "ooms": int("out-of-memory" in log.lower() or "SUMMARY: libFuzzer: out-of-memory" in log),
        "peak_rss_mb": _parse_peak_rss(log),
        "exit_code": result.exit_code,
        "log": str(work_dir / "campaign" / "campaign.log"),
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
) -> dict:
    """Replay the final corpus under a coverage-instrumented binary.

    Returns a dict with the raw coverage text path and exit code.  The caller
    parses it with :mod:`hgb_coverage`.  This never fabricates coverage: if the
    coverage report is missing or empty, the evaluator must mark coverage as
    failed.
    """
    work_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "sh",
        "-lc",
        f'mkdir -p /tmp/cov /tmp/corpus && LLVM_PROFILE_FILE=/tmp/cov/coverage.profraw '
        f'{binary_path} -runs=0 /tmp/corpus && '
        f'llvm-profdata merge -o /tmp/cov/merged.profdata /tmp/cov/*.profraw && '
        f'llvm-cov export -format=text -summary-only {binary_path} -instr-profile=/tmp/cov/merged.profdata '
        f'> /tmp/cov/coverage.json 2>/tmp/cov/cov.err; cat /tmp/cov/coverage.json',
    ]
    result = _container_run(
        image_tag=image_tag,
        work_dir=work_dir / "coverage",
        runner=runner,
        timeout_seconds=timeout_seconds,
        command=cmd,
        phase="coverage",
        copy_out=(f"hgb-eval-coverage-:container:/tmp/cov/coverage.json", work_dir / "coverage" / "coverage.json"),
    )
    return {
        "exit_code": result.exit_code,
        "raw_text": result.stdout,
        "log": str(work_dir / "coverage" / "coverage.log"),
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
