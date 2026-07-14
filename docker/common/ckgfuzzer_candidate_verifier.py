#!/usr/bin/env python3
"""Compile CKGFuzzer candidates with the target's native FuzzBench context.

CKGFuzzer's upstream verifier assumes every project ships a custom
``fuzz_driver/<project>/scripts/check_compilation.sh``.  HarnessGenBench
targets intentionally do not.  This helper instead builds the benchmark's
Dockerfile once, stages each generated driver at the benchmark fuzz-target
path, and runs its native ``build.sh``.  A candidate is verified only when
that command exits successfully *and* produces an executable in ``$OUT``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Sequence

from ckgfuzzer_target_harness import TargetHarnessError, select_native_harness
from ckgfuzzer_verifier_context import VerificationContextError, prepare_verification_context


SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}
COMPILE_MARKER = "HGB_CKG_CANDIDATE_COMPILE"


@dataclass
class CommandResult:
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str


Runner = Callable[[Sequence[str], int], CommandResult]


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
    return CommandResult(
        list(command), completed.returncode, completed.stdout or "", completed.stderr or ""
    )


def _safe_tag(target_root: Path, fuzz_target: str) -> str:
    digest = hashlib.sha256(f"{target_root.resolve()}:{fuzz_target}".encode()).hexdigest()[:16]
    return f"hgb-ckgfuzzer-verify:{digest}"


def _candidate_files(candidates_dir: Path) -> list[Path]:
    if not candidates_dir.is_dir():
        return []
    return [
        path
        for path in sorted(candidates_dir.iterdir())
        if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES
    ]


def _write_log(path: Path, result: CommandResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "$ " + " ".join(result.command) + "\n\n[stdout]\n" + result.stdout
        + "\n[stderr]\n" + result.stderr,
        encoding="utf-8",
    )


def _write_phase_log(path: Path, results: Sequence[tuple[str, CommandResult]]) -> None:
    """Write every container lifecycle phase to one candidate log."""

    path.parent.mkdir(parents=True, exist_ok=True)
    chunks = []
    for phase, result in results:
        chunks.append(
            f"## {phase}\n$ " + " ".join(result.command) + "\n\n[stdout]\n" + result.stdout
            + "\n[stderr]\n" + result.stderr
        )
    path.write_text("\n\n".join(chunks), encoding="utf-8")


def _run_phase(runner: Runner, command: Sequence[str], timeout_seconds: int, phase: str) -> CommandResult:
    """Run a Docker lifecycle phase without preventing cleanup."""
    try:
        return runner(command, timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(list(command), 124, "", f"{phase} timed out: {exc}")
    except OSError as exc:
        return CommandResult(list(command), 127, "", f"could not {phase}: {exc}")


def _summary_path(work_dir: Path) -> Path:
    return work_dir / "results.json"


def _write_summary(work_dir: Path, payload: dict) -> None:
    work_dir.mkdir(parents=True, exist_ok=True)
    _summary_path(work_dir).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def verify_candidates(
    *,
    target_root: Path,
    candidates_dir: Path,
    work_dir: Path,
    fuzz_target: str,
    timeout_seconds: int = 1800,
    runner: Runner = _run,
) -> dict:
    """Verify every saved candidate and return a machine-readable summary.

    A non-zero result from a candidate build is a quality result, not an
    infrastructure failure.  Docker/image/context failures leave
    ``verification_ran`` false so callers never report them as zero verified
    candidates.
    """

    benchmark_dir = target_root / "fuzzbench_benchmark"
    dockerfile = benchmark_dir / "Dockerfile"
    candidates = _candidate_files(candidates_dir)
    payload: dict = {
        "schema_version": 1,
        "target_root": str(target_root),
        "benchmark_dir": str(benchmark_dir),
        "candidates_dir": str(candidates_dir),
        "fuzz_target": fuzz_target,
        "verification_ran": False,
        "infrastructure_error": "",
        "records": [],
        "verified_candidates": [],
    }
    if not dockerfile.is_file():
        payload["infrastructure_error"] = f"missing FuzzBench Dockerfile: {dockerfile}"
        _write_summary(work_dir, payload)
        return payload
    if not candidates:
        payload["infrastructure_error"] = "no candidate source files were supplied"
        _write_summary(work_dir, payload)
        return payload

    try:
        verification_context = prepare_verification_context(target_root, work_dir)
    except VerificationContextError as exc:
        payload["verification_context"] = {
            "mode": "verification_context_unreproducible",
            "error": str(exc),
        }
        payload["infrastructure_error"] = f"verification_context_unreproducible: {exc}"
        _write_summary(work_dir, payload)
        return payload
    payload["verification_context"] = verification_context

    try:
        native_harness = select_native_harness(target_root, fuzz_target)
    except TargetHarnessError as exc:
        payload["infrastructure_error"] = f"native_harness_unresolved: {exc}"
        _write_summary(work_dir, payload)
        return payload
    payload["native_harness"] = asdict(native_harness)

    image_tag = _safe_tag(target_root, fuzz_target)
    build_command = [
        "docker",
        "build",
        "--file",
        verification_context["dockerfile"],
        "--tag",
        image_tag,
        verification_context["context_dir"],
    ]
    try:
        image_build = runner(build_command, timeout_seconds)
    except (OSError, subprocess.TimeoutExpired) as exc:
        payload["infrastructure_error"] = f"could not build FuzzBench verifier image: {exc}"
        _write_summary(work_dir, payload)
        return payload
    _write_log(work_dir / "image_build.log", image_build)
    payload["image_build"] = asdict(image_build)
    if image_build.exit_code != 0:
        payload["infrastructure_error"] = (
            f"FuzzBench verifier image build exited {image_build.exit_code}; "
            "see image_build.log"
        )
        _write_summary(work_dir, payload)
        return payload

    payload["verification_ran"] = True
    for index, candidate in enumerate(candidates, start=1):
        stage_dir = work_dir / "staged" / f"{index:03d}_{candidate.stem}"
        stage_dir.mkdir(parents=True, exist_ok=True)
        # The generated filename is not necessarily the native build input.
        # Preserve the manifest-selected basename and overlay it at the exact
        # native destination below.
        staged_candidate = stage_dir / Path(native_harness.container_destination).name
        # A portable pragma proves that the native build reached this staged
        # candidate. Without it, a dependency failure can otherwise look like
        # a candidate compilation failure even when no candidate was tested.
        staged_candidate.write_bytes(
            f'#pragma message("{COMPILE_MARKER}")\n'.encode("utf-8")
            + candidate.read_bytes()
        )
        output_dir = work_dir / "out" / f"{index:03d}"
        build_work_dir = work_dir / "work" / f"{index:03d}"
        output_dir.mkdir(parents=True, exist_ok=True)
        build_work_dir.mkdir(parents=True, exist_ok=True)
        shell_command = (
            "set -euo pipefail; "
            ': "${SRC:=/src}"; : "${OUT:=/out}"; : "${WORK:=/work}"; '
            'mkdir -p "$OUT" "$WORK"; '
            'export CFLAGS="${CFLAGS:-} -pthread" CXXFLAGS="${CXXFLAGS:-} -pthread"; '
            'if ! find /usr/local/lib/clang -type f -name "libFuzzingEngine.a" -print -quit | grep -q .; then '
            'fuzzer_runtime="$(find /usr/local/lib/clang -type f -name "libclang_rt.fuzzer-${ARCHITECTURE}.a" -print -quit)"; '
            '[ -n "$fuzzer_runtime" ] && ln -sf "$fuzzer_runtime" "$WORK/libFuzzingEngine.a" && ln -sf "$fuzzer_runtime" /usr/lib/libFuzzingEngine.a && export LIBRARY_PATH="$WORK${LIBRARY_PATH:+:$LIBRARY_PATH}"; fi; '
            'test -x "$SRC/build.sh" || { echo "missing $SRC/build.sh" >&2; exit 125; }; '
            'candidate="/tmp/${HGB_CANDIDATE_FILE}"; '
            'test -f "$candidate" || { echo "missing staged candidate $candidate" >&2; exit 126; }; '
            'native_source="${HGB_CANDIDATE_DEST}"; '
            'case "$native_source" in "$SRC"/*) ;; *) echo "unsafe native candidate destination: $native_source" >&2; exit 126;; esac; '
            'test -f "$native_source" || { echo "selected native candidate destination is absent: $native_source" >&2; exit 126; }; '
            'cp "$candidate" "$native_source"; '
            'set +e; bash "$SRC/build.sh"; build_status=$?; set -e; '
            'if find "$OUT" -type f -perm -111 -print -quit | grep -q .; then exit 0; fi; '
            'if [ -f "$WORK/build.ninja" ] && command -v ninja >/dev/null 2>&1; then '
            'ninja -C "$WORK" "$HGB_FUZZ_TARGET"; '
            'native_binary="$(find "$WORK" -type f -name "$HGB_FUZZ_TARGET" -perm -111 -print -quit)"; '
            '[ -n "$native_binary" ] && cp "$native_binary" "$OUT/$HGB_FUZZ_TARGET"; '
            'fi; '
            'find "$OUT" -type f -perm -111 -print -quit | grep -q . || { [ "$build_status" -ne 0 ] && exit "$build_status"; exit 125; }'
        )
        container_name = f"hgb-ckgverify-{uuid.uuid4().hex}"
        create_command = [
            "docker",
            "create",
            "--name",
            container_name,
            "-e",
            "FUZZING_ENGINE=libfuzzer",
            "-e",
            "FUZZER=libfuzzer",
            "-e",
            "SANITIZER=address",
            "-e",
            "ARCHITECTURE=x86_64",
            "-e",
            "CC=clang",
            "-e",
            "CXX=clang++",
            "-e",
            "LIB_FUZZING_ENGINE=-fsanitize=fuzzer",
            "-e",
            "FUZZER_LIB=-fsanitize=fuzzer",
            "-e",
            f"HGB_CANDIDATE_FILE={staged_candidate.name}",
            "-e",
            f"HGB_FUZZ_TARGET={Path(fuzz_target).stem}",
            "-e",
            f"HGB_CANDIDATE_DEST={native_harness.container_destination}",
            image_tag,
            "bash",
            "-lc",
            shell_command,
        ]
        phases: list[tuple[str, CommandResult]] = []
        create_result = _run_phase(
            runner, create_command, timeout_seconds, "create verifier container"
        )
        phases.append(("create", create_result))
        result = create_result
        container_created = create_result.exit_code == 0
        try:
            if container_created:
                stage_command = [
                    "docker",
                    "cp",
                    str(staged_candidate),
                    f"{container_name}:/tmp/{staged_candidate.name}",
                ]
                stage_result = _run_phase(
                    runner,
                    stage_command,
                    timeout_seconds,
                    "stage candidate in verifier container",
                )
                phases.append(("stage_candidate", stage_result))
                result = stage_result
                if stage_result.exit_code == 0:
                    start_command = ["docker", "start", "-a", container_name]
                    result = _run_phase(
                        runner, start_command, timeout_seconds, "run candidate verifier"
                    )
                    phases.append(("build", result))
                    for label, source, destination in (
                        ("copy_out", f"{container_name}:/out/.", output_dir),
                        ("copy_work", f"{container_name}:/work/.", build_work_dir),
                    ):
                        copy_result = _run_phase(
                            runner,
                            ["docker", "cp", source, str(destination)],
                            timeout_seconds,
                            f"copy {label} from verifier container",
                        )
                        phases.append((label, copy_result))
        finally:
            if container_created:
                cleanup_result = _run_phase(
                    runner,
                    ["docker", "rm", "-f", container_name],
                    timeout_seconds,
                    "remove verifier container",
                )
                phases.append(("cleanup", cleanup_result))
        log_path = work_dir / "logs" / f"{index:03d}_{candidate.name}.log"
        _write_phase_log(log_path, phases)
        combined_output = result.stdout + "\n" + result.stderr
        compile_attempted = COMPILE_MARKER in combined_output
        verified = result.exit_code == 0 and compile_attempted
        record = {
            "candidate": str(candidate),
            "staged_candidate": str(staged_candidate),
            "command": result.command,
            "exit_code": result.exit_code,
            "log": str(log_path),
            "stderr": result.stderr,
            "compile_attempted": compile_attempted,
            "verified": verified,
        }
        payload["records"].append(record)
        if verified:
            payload["verified_candidates"].append(str(candidate))

    payload["verification_ran"] = any(
        bool(record.get("compile_attempted")) for record in payload["records"]
    )
    if not payload["verification_ran"]:
        payload["infrastructure_error"] = (
            "native FuzzBench build failed before compiling any staged candidate; "
            "see per-candidate logs"
        )
    _write_summary(work_dir, payload)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-root", required=True, type=Path)
    parser.add_argument("--candidates", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--fuzz-target", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    args = parser.parse_args()
    result = verify_candidates(
        target_root=args.target_root,
        candidates_dir=args.candidates,
        work_dir=args.work_dir,
        fuzz_target=args.fuzz_target,
        timeout_seconds=max(1, args.timeout_seconds),
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["verification_ran"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
