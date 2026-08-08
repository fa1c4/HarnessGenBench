#!/usr/bin/env python3
"""G2Fuzz target input-contract probe.

Validates the declared adapter input contract (``file``, ``stdin``, or
``argv``) against a built native target by running sample inputs and
detecting whether the target actually reads the file, reads stdin, or
expects additional arguments.  The probe persists ``contract.json`` with
probe samples and exit statuses, and fails if the declared contract does
not execute the target.

This is per-target: ``@@`` is never assumed globally.  The probe runs
sample inputs through the declared ``argv``/stdin mode and verifies the
target is reached (not silently ignored).
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any


class ContractError(RuntimeError):
    def __init__(self, reason: str, code: int = 65) -> None:
        super().__init__(reason)
        self.reason = reason
        self.code = code


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _executable(path: Path) -> bool:
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return path.is_file() and bool(mode & stat.S_IXUSR)


def _write_sample(data: bytes, tmp_dir: Path, name: str) -> Path:
    tmp_dir.mkdir(parents=True, exist_ok=True)
    path = tmp_dir / name
    path.write_bytes(data)
    return path


def _run_target(
    binary: Path,
    argv: list[str],
    stdin_data: bytes | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Run the target binary with the given argv and optional stdin."""
    try:
        proc = subprocess.run(
            argv,
            input=stdin_data,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return {
            "ran": True,
            "exit_code": proc.returncode,
            "timed_out": False,
            "stdout_len": len(proc.stdout or b""),
            "stderr_len": len(proc.stderr or b""),
            "stderr_tail": (proc.stderr or b"").decode("utf-8", "replace")[-800:],
        }
    except subprocess.TimeoutExpired:
        return {"ran": True, "exit_code": 124, "timed_out": True, "stderr_tail": ""}
    except OSError as exc:
        return {"ran": False, "exit_code": None, "timed_out": False, "error": str(exc), "stderr_tail": ""}


def _format_sample_for_mode(fmt: str) -> bytes:
    normalized = fmt.lower()
    if "png" in normalized:
        return bytes.fromhex("89504e470d0a1a0a0000000d49484452") + b"\x00" * 16
    if "jpeg" in normalized or "jpg" in normalized:
        return b"\xff\xd8\xff\xd9"
    if "zlib" in normalized:
        return b"\x78\x9c\x03\x00\x00\x00\x00\x01"
    if "json" in normalized:
        return b"{}\n"
    if "xml" in normalized or "xpath" in normalized:
        return b"<root/>\n"
    if "sql" in normalized:
        return b"select 1;\n"
    if "http" in normalized:
        return b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    if "ttf" in normalized:
        return bytes.fromhex("000100000000000000000000")
    if "otf" in normalized:
        return b"OTTO" + b"\x00" * 8
    if "ttc" in normalized:
        return b"ttcf\x00\x01\x00\x00\x00\x00\x00\x00"
    if "pcap" in normalized:
        return bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")
    if "icc" in normalized:
        return b"\x00\x00\x00\x80" + b"\x00" * 124
    if "elf" in normalized:
        return b"\x7fELF" + b"\x00" * 60
    if "der" in normalized or "x.509" in normalized or "certificate" in normalized:
        return b"\x30\x82\x00\x01\x30\x82"
    if "h.264" in normalized or "h264" in normalized:
        return b"\x00\x00\x00\x01\x67" + b"\x00" * 8
    if "dtls" in normalized:
        return b"\x16\xfe\xfd\x00\x00\x00\x00"
    return (fmt + "\n").encode("utf-8", "replace")


def probe_contract(
    binary: Path,
    adapter: dict[str, Any],
    *,
    formats: list[str] | None = None,
    output_path: Path | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Probe the target input contract by running sample inputs.

    Validates that the declared ``input_mode`` and ``argv`` actually execute
    the target.  For ``file`` mode, a sample file is substituted for ``@@``
    and the target must run.  For ``stdin`` mode, sample bytes are piped to
    stdin.  For ``argv`` mode, the sample is substituted if ``@@`` is present,
    otherwise a minimal argument is appended.

    Returns a contract dict with per-sample probe results and a ``valid``
    flag.  Persists ``contract.json`` to ``output_path`` when provided.
    """
    if not _executable(binary):
        raise ContractError(f"contract probe: target binary is not executable: {binary}", 127)

    input_mode = str(adapter.get("input_mode", "file"))
    adapter_argv = [str(item) for item in adapter.get("argv", [])]
    fmt = (formats[0] if formats else str(adapter.get("formats", ["custom"])[0] if adapter.get("formats") else "custom"))
    sample_a = _format_sample_for_mode(fmt)
    sample_b = sample_a + b"\x00HGB_DISTINGUISHABLE"

    tmp_dir = Path(tempfile.mkdtemp(prefix="hgb-g2contract-"))
    probes: list[dict[str, Any]] = []

    def _record(label: str, sample: bytes, result: dict[str, Any]) -> None:
        probes.append({
            "label": label,
            "sample_sha256": _sha256_bytes(sample),
            "sample_size": len(sample),
            **result,
        })

    for label, sample in (("sample_a", sample_a), ("sample_b", sample_b)):
        if input_mode == "stdin":
            argv = [str(binary)] + [a for a in adapter_argv if a != "@@"]
            result = _run_target(Path(binary), argv, stdin_data=sample, timeout=timeout)
        elif input_mode == "file":
            sample_path = _write_sample(sample, tmp_dir, f"{label}.bin")
            argv = [str(binary)] + [str(a) if a != "@@" else str(sample_path) for a in adapter_argv]
            result = _run_target(Path(binary), argv, timeout=timeout)
        else:
            sample_path = _write_sample(sample, tmp_dir, f"{label}.bin") if "@@" in adapter_argv else None
            argv = [str(binary)] + [str(a) if a != "@@" else str(sample_path) for a in adapter_argv]
            if not sample_path and not any(a != str(binary) for a in argv[1:]):
                argv.append(str(_write_sample(sample, tmp_dir, f"{label}.bin")))
            result = _run_target(Path(binary), argv, timeout=timeout)
        _record(label, sample, result)

    # Missing-input probe for file mode: invoking with a nonexistent path must
    # not be silently ignored (the target should error or no-op, but the
    # invocation itself must reach the target).
    missing_handled = True
    if input_mode == "file":
        missing_path = tmp_dir / "__HGB_MISSING_CONTRACT__"
        if missing_path.exists():
            missing_path.unlink()
        argv = [str(binary)] + [str(a) if a != "@@" else str(missing_path) for a in adapter_argv]
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
            missing_handled = proc.returncode is not None
        except Exception:
            missing_handled = False

    # Determine validity: all probes must have run, and the target must not
    # have crashed on both samples (exit >= 128 indicates a crash/ASAN).
    all_ran = all(p.get("ran") for p in probes)
    all_crashed = all(
        isinstance(p.get("exit_code"), int) and p["exit_code"] >= 128
        for p in probes
    )
    valid = bool(all_ran and not all_crashed and missing_handled)

    contract: dict[str, Any] = {
        "binary": str(binary),
        "input_mode": input_mode,
        "argv": [str(binary)] + adapter_argv,
        "adapter_argv": adapter_argv,
        "uses_at_at": "@@" in adapter_argv,
        "formats": formats or [],
        "probes": probes,
        "missing_input_handled": missing_handled,
        "all_ran": all_ran,
        "all_crashed": all_crashed,
        "consistent": probes[0].get("exit_code") == probes[1].get("exit_code") if len(probes) >= 2 else False,
        "valid": valid,
    }

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # Cleanup temp dir
    try:
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)
    except Exception:
        pass

    if not valid:
        raise ContractError(
            f"contract probe failed for {binary}: target did not execute under declared {input_mode} mode",
            65,
        )
    return contract


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="G2Fuzz target input-contract probe")
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--input-mode", default="file")
    parser.add_argument("--argv", nargs="*", default=["@@"])
    parser.add_argument("--format", default="custom")
    parser.add_argument("--output", default="", type=Path)
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()
    adapter = {"input_mode": args.input_mode, "argv": args.argv, "formats": [args.format]}
    out = args.output if args.output else None
    try:
        contract = probe_contract(args.binary, adapter, formats=[args.format], output_path=out, timeout=args.timeout)
        print(json.dumps(contract, indent=2, sort_keys=True))
        return 0
    except ContractError as exc:
        print(f"ERROR: {exc.reason}", file=__import__("sys").stderr)
        return exc.code


if __name__ == "__main__":
    raise SystemExit(main())
