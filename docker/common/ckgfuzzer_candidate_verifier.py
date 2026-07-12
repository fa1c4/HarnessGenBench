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
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Sequence


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


def _source_name(fuzz_target: str, candidate: Path) -> str:
    target = Path(fuzz_target).name
    if Path(target).suffix.lower() in SOURCE_SUFFIXES:
        target = Path(target).stem
    return target + candidate.suffix.lower()


def _write_log(path: Path, result: CommandResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "$ " + " ".join(result.command) + "\n\n[stdout]\n" + result.stdout
        + "\n[stderr]\n" + result.stderr,
        encoding="utf-8",
    )


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

    image_tag = _safe_tag(target_root, fuzz_target)
    build_command = ["docker", "build", "--tag", image_tag, str(benchmark_dir)]
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
        staged_candidate = stage_dir / _source_name(fuzz_target, candidate)
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
            'test -x "$SRC/build.sh" || { echo "missing $SRC/build.sh" >&2; exit 125; }; '
            'candidate="/hgb-candidate/${HGB_CANDIDATE_FILE}"; '
            'test -f "$candidate" || { echo "missing staged candidate $candidate" >&2; exit 126; }; '
            'mapfile -t native_sources < <(find "$SRC" -mindepth 2 -type f -name "${HGB_CANDIDATE_FILE}" -print | sort); '
            'if [ "${#native_sources[@]}" -eq 1 ]; then cp "$candidate" "${native_sources[0]}"; '
            'elif [ "${#native_sources[@]}" -eq 0 ] && grep -Fq "${HGB_CANDIDATE_FILE}" "$SRC/build.sh"; then cp "$candidate" "$SRC/${HGB_CANDIDATE_FILE}"; '
            'else echo "could not stage candidate into the native FuzzBench build" >&2; exit 126; fi; '
            'set +e; bash "$SRC/build.sh"; build_status=$?; set -e; '
            'if find "$OUT" -type f -perm -111 -print -quit | grep -q .; then exit 0; fi; '
            'if [ -f "$WORK/build.ninja" ] && command -v ninja >/dev/null 2>&1; then '
            'ninja -C "$WORK" "$HGB_FUZZ_TARGET"; '
            'native_binary="$(find "$WORK" -type f -name "$HGB_FUZZ_TARGET" -perm -111 -print -quit)"; '
            '[ -n "$native_binary" ] && cp "$native_binary" "$OUT/$HGB_FUZZ_TARGET"; '
            'fi; '
            'find "$OUT" -type f -perm -111 -print -quit | grep -q . || { [ "$build_status" -ne 0 ] && exit "$build_status"; exit 125; }'
        )
        command = [
            "docker",
            "run",
            "--rm",
            "-e",
            "FUZZING_ENGINE=libfuzzer",
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
            f"HGB_CANDIDATE_FILE={staged_candidate.name}",
            "-e",
            f"HGB_FUZZ_TARGET={Path(fuzz_target).stem}",
            "-v",
            f"{stage_dir}:/hgb-candidate:ro",
            "-v",
            f"{output_dir}:/out",
            "-v",
            f"{build_work_dir}:/work",
            image_tag,
            "bash",
            "-lc",
            shell_command,
        ]
        try:
            result = runner(command, timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            result = CommandResult(list(command), 124, "", f"candidate build timed out: {exc}")
        except OSError as exc:
            payload["verification_ran"] = False
            payload["infrastructure_error"] = f"could not run candidate verifier: {exc}"
            _write_summary(work_dir, payload)
            return payload
        log_path = work_dir / "logs" / f"{index:03d}_{candidate.name}.log"
        _write_log(log_path, result)
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
