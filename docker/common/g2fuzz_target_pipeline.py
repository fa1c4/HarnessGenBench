#!/usr/bin/env python3
"""Target-aware G2Fuzz input-generation pipeline for HarnessGenBench.

The real G2Fuzz artifact creates input generators and seeds, then drives its
modified AFL++ against a native target pair built as ``.afl`` (default AFL++
instrumentation) and ``.cmp`` (CmpLog instrumentation) binaries.  G2Fuzz is an
``input_generator``; it never generates ``LLVMFuzzerTestOneInput`` and is never
ranked with harness generators.

This helper owns the HGB contract around that workflow: adapter validation,
automatic target-pair building from the pinned FuzzBench target, input-contract
validation, ``program_gen.py`` orchestration, generated-input validation,
seed-provenance accounting, modified AFL++ campaign execution, real coverage
collection, and normalized schema-version-2 results.

A successful row is ``evaluated`` only when the target pair was built, at least
one G2-generated input validated against the target, the campaign recorded
``execs_done > 0`` and a nonempty queue, and a real coverage report measured a
non-null covered-line count.  AFL ``paths_total`` is never treated as coverage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


STAGE_NAMES = (
    "target_prepared",
    "target_pair_built",
    "input_generators_created",
    "generated_inputs_validated",
    "campaign",
    "coverage",
)
# Goal-stage aliases (beta plan section 0) mapped onto the canonical internal
# stage names so the result payload carries both the internal ordering and the
# contract names.
GOAL_STAGE_ALIASES = {
    "target_pair_build": "target_pair_built",
    "program_generation": "input_generators_created",
    "generated_input_validation": "generated_inputs_validated",
    "campaign": "campaign",
    "coverage": "coverage",
}
REQUIRED_ADAPTER_KEYS = {
    "target",
    "applicability",
    "method_profile",
    "program_id",
    "formats",
    "input_mode",
    "argv",
    "common_corpus",
    "format_spec",
    "contract_probe",
}
PAPER_METHOD_PROFILE = "paper-faithful"
EXTENSION_METHOD_PROFILE = "extension"
TASK_FAMILY = "input_generator"
BUILD_MODE = "fuzzbench_native_afl_cmps"
# Marker written by hgb_targets.ensure_package_build_script when the FuzzBench
# benchmark dir has no top-level build.sh (the real recipe lives in the
# project source and is copied into $SRC by the benchmark Dockerfile).
SYNTHETIC_BUILD_SH_MARKER = "did not include a top-level build.sh"
# Base compiler flags for the native .afl/.cmp build. SANITIZER=address is
# mirrored here so build scripts that never read $SANITIZER still link the
# ASan runtime (the G2Fuzz image ships libclang-rt-18-dev for this).
NATIVE_BUILD_CFLAGS = "-O1 -fno-omit-frame-pointer -fsanitize=address -pthread -Wno-register -Wno-documentation -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
# afl-cc maps -fsanitize=fuzzer onto the bundled libAFLDriver.a, so FuzzBench
# build.sh scripts that use $LIB_FUZZING_ENGINE/$FUZZER_LIB get the AFL driver.
NATIVE_AFL_DRIVER_FLAG = "-fsanitize=fuzzer"
GAMMA_PROFILE = "reproduction-gamma"
DELTA_PROFILE = "reproduction-delta"
EPSILON_PROFILE = "reproduction-epsilon"
ZETA_PROFILE = "reproduction-zeta"
ETA_PROFILE = "reproduction-eta"
GAMMA_BUILD_MODE = "fuzzbench_docker_triple"
# method_variant values reported in the delta result schema (plan section 7).
PAPER_CORE_VARIANT = "paper-core"
EXTENSION_VARIANT = "extension"


def is_gamma_profile(profile: str) -> bool:
    """Return True for the strict triple-build profiles.

    ``reproduction-eta`` is the canonical strictest profile (plan
    ``g2fuzz_reproduction_eta.md``); ``reproduction-zeta`` is the strict
    profile from the zeta plan (plan ``g2fuzz_reproduction_zeta.md``);
    ``reproduction-epsilon`` is the strict profile from the epsilon plan
    (plan ``ckgfuzzer_reproduction_epsilon.md`` shared foundation);
    ``reproduction-delta`` is its backward-compatible alias (plan
    ``g2fuzz_reproduction_delta.md``); ``reproduction-gamma`` is kept as a
    backward-compatible alias.  All five share the exact FuzzBench Docker
    triple build, contract probe, and real coverage replay code path.
    """

    return profile in (GAMMA_PROFILE, DELTA_PROFILE, EPSILON_PROFILE, ZETA_PROFILE, ETA_PROFILE)


def is_delta_profile(profile: str) -> bool:
    """Return True for the strictest triple-build profiles (delta + epsilon + zeta + eta)."""
    return profile in (DELTA_PROFILE, EPSILON_PROFILE, ZETA_PROFILE, ETA_PROFILE)


def is_zeta_profile(profile: str) -> bool:
    """Return True for the zeta and eta profiles (the strictest).

    Eta is the canonical strictest profile (eta plan); zeta is the strict
    profile from the zeta plan. Both reject a precomputed
    ``G2FUZZ_COVERAGE_REPORT`` in production.
    """
    return profile in (ZETA_PROFILE, ETA_PROFILE)


def is_eta_profile(profile: str) -> bool:
    """Return True for the eta profile (the canonical strictest)."""
    return profile == ETA_PROFILE


def method_variant_for(adapter: dict[str, Any]) -> str:
    """Map an adapter ``method_profile`` to a delta ``method_variant``."""

    return PAPER_CORE_VARIANT if str(adapter.get("method_profile", "")) == PAPER_METHOD_PROFILE else EXTENSION_VARIANT


# Coverage helpers are optional at import time; the offline pytest suite does
# not require LLVM tooling.  They are resolved from the same directory as this
# module when available.
try:  # pragma: no cover - import shim
    import hgb_coverage  # type: ignore
    from hgb_coverage import CoverageError, summarize_coverage_report, write_coverage_outputs
except ImportError:  # pragma: no cover
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import hgb_coverage  # type: ignore
        from hgb_coverage import CoverageError, summarize_coverage_report, write_coverage_outputs
    except ImportError:
        CoverageError = RuntimeError  # type: ignore[misc,assignment]
        summarize_coverage_report = None  # type: ignore[assignment]
        write_coverage_outputs = None  # type: ignore[assignment]

try:  # pragma: no cover - import shim
    import hgb_fuzzbench_builder  # type: ignore
    from hgb_fuzzbench_builder import build_g2fuzz_target_triple, g2fuzz_target_triple_build_commands, verify_g2fuzz_target_triple
except ImportError:  # pragma: no cover
    try:
        import sys as _sys2
        _sys2.path.insert(0, str(Path(__file__).resolve().parent))
        import hgb_fuzzbench_builder  # type: ignore
        from hgb_fuzzbench_builder import build_g2fuzz_target_triple, g2fuzz_target_triple_build_commands, verify_g2fuzz_target_triple
    except ImportError:
        hgb_fuzzbench_builder = None  # type: ignore[assignment]
        build_g2fuzz_target_triple = None  # type: ignore[assignment]
        g2fuzz_target_triple_build_commands = None  # type: ignore[assignment]
        verify_g2fuzz_target_triple = None  # type: ignore[assignment]

try:  # pragma: no cover - import shim
    import g2fuzz_contract  # type: ignore
    from g2fuzz_contract import probe_contract as _probe_contract, ContractError as _ContractError
except ImportError:  # pragma: no cover
    try:
        import sys as _sys3
        _sys3.path.insert(0, str(Path(__file__).resolve().parent))
        import g2fuzz_contract  # type: ignore
        from g2fuzz_contract import probe_contract as _probe_contract, ContractError as _ContractError
    except ImportError:
        g2fuzz_contract = None  # type: ignore[assignment]
        _probe_contract = None  # type: ignore[assignment]
        _ContractError = RuntimeError  # type: ignore[misc,assignment]


class PipelineError(RuntimeError):
    def __init__(self, status: str, reason: str, code: int = 1) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.code = code


def json_dump(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(data, sort_keys=True) + "\n")


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def executable(path: Path) -> bool:
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return path.is_file() and bool(mode & stat.S_IXUSR)


def strip_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    out: list[str] = []
    for ch in line:
        if escaped:
            out.append(ch)
            escaped = False
            continue
        if ch == "\\" and quote:
            out.append(ch)
            escaped = True
            continue
        if ch in {"'", '"'}:
            if quote == ch:
                quote = None
            elif quote is None:
                quote = ch
            out.append(ch)
            continue
        if ch == "#" and quote is None:
            break
        out.append(ch)
    return "".join(out).rstrip()


def parse_scalar(raw: str) -> Any:
    value = raw.strip()
    if not value:
        return ""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value in {"null", "Null", "~"}:
        return None
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        parts: list[str] = []
        current: list[str] = []
        quote: str | None = None
        for ch in inner:
            if ch in {"'", '"'}:
                if quote == ch:
                    quote = None
                elif quote is None:
                    quote = ch
                current.append(ch)
                continue
            if ch == "," and quote is None:
                parts.append("".join(current).strip())
                current = []
                continue
            current.append(ch)
        if current:
            parts.append("".join(current).strip())
        return [parse_scalar(part) for part in parts if part]
    if value.startswith("{") and value.endswith("}"):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return {}
    try:
        return int(value)
    except ValueError:
        return value


def parse_simple_yaml(path: Path) -> dict[str, Any]:
    """Parse the small YAML subset used by HGB metadata files.

    This intentionally avoids a PyYAML runtime dependency in the G2Fuzz image.
    It supports top-level scalars and top-level lists of mappings, including
    inline arrays such as ``formats: [PNG, JPEG]``.
    """

    data: dict[str, Any] = {}
    current_key: str | None = None
    current_item: dict[str, Any] | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent == 0 and not stripped.startswith("- "):
            if ":" not in stripped:
                continue
            key, value = stripped.split(":", 1)
            key = key.strip()
            value = value.strip()
            if value:
                data[key] = parse_scalar(value)
                current_key = None
            else:
                data[key] = []
                current_key = key
            current_item = None
            continue
        if stripped.startswith("- "):
            if not current_key:
                raise PipelineError("adapter_parse_failed", f"list item without parent in {path}", 64)
            current_item = {}
            data.setdefault(current_key, []).append(current_item)
            rest = stripped[2:].strip()
            if rest:
                if ":" not in rest:
                    raise PipelineError("adapter_parse_failed", f"bad list item in {path}: {rest}", 64)
                key, value = rest.split(":", 1)
                current_item[key.strip()] = parse_scalar(value.strip())
            continue
        if current_item is not None and ":" in stripped:
            key, value = stripped.split(":", 1)
            current_item[key.strip()] = parse_scalar(value.strip())
    return data


def repo_root_from(start: Path) -> Path:
    cur = start.resolve()
    if cur.is_file():
        cur = cur.parent
    for candidate in (cur, *cur.parents):
        if (candidate / "metadata").is_dir() and (candidate / "scripts").is_dir():
            return candidate
        if (candidate / ".git").exists():
            return candidate
    return Path.cwd()


def default_metadata_root() -> Path:
    env = os.environ.get("HGB_METADATA_DIR")
    if env:
        return Path(env)
    for candidate in (Path("/opt/hgb/metadata"), repo_root_from(Path.cwd()) / "metadata"):
        if candidate.is_dir():
            return candidate
    return Path("metadata")


def default_artifact_dir() -> Path:
    env = os.environ.get("HGB_G2FUZZ_ARTIFACT_DIR") or os.environ.get("HGB_GENERATOR_ARTIFACT_DIR")
    if env:
        return Path(env)
    if Path("/opt/hgb/artifacts/g2fuzz").exists():
        return Path("/opt/hgb/artifacts/g2fuzz")
    return repo_root_from(Path.cwd()) / "artifacts" / "g2fuzz"


def default_workspace() -> Path:
    return Path(os.environ.get("HGB_WORKSPACE", "/workspace"))


def load_adapters(metadata_root: Path | None = None) -> dict[str, dict[str, Any]]:
    root = metadata_root or default_metadata_root()
    path = root / "g2fuzz_target_adapters.yaml"
    if not path.exists():
        raise PipelineError("adapter_manifest_missing", f"missing G2Fuzz adapter manifest: {path}", 66)
    raw = parse_simple_yaml(path)
    adapters: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    for entry in raw.get("targets", []):
        if not isinstance(entry, dict):
            raise PipelineError("adapter_parse_failed", f"adapter entry is not a mapping: {entry}", 64)
        missing = sorted(REQUIRED_ADAPTER_KEYS - set(entry))
        if missing:
            raise PipelineError(
                "adapter_parse_failed",
                f"{entry.get('target', '<unknown>')}: missing adapter keys: {', '.join(missing)}",
                64,
            )
        target = str(entry["target"])
        if target in seen:
            raise PipelineError("adapter_parse_failed", f"duplicate adapter entry for target: {target}", 64)
        seen.add(target)
        formats = entry.get("formats")
        argv = entry.get("argv")
        if not isinstance(formats, list) or not formats:
            raise PipelineError("adapter_parse_failed", f"{target}: formats must be a non-empty list", 64)
        if not isinstance(argv, list):
            raise PipelineError("adapter_parse_failed", f"{target}: argv must be a list", 64)
        if entry["input_mode"] not in {"file", "stdin", "argv"}:
            raise PipelineError("adapter_parse_failed", f"{target}: unsupported input_mode {entry['input_mode']}", 64)
        if entry["method_profile"] not in {PAPER_METHOD_PROFILE, EXTENSION_METHOD_PROFILE}:
            raise PipelineError("adapter_parse_failed", f"{target}: unsupported method_profile {entry['method_profile']}", 64)
        adapters[target] = entry
    return adapters


def valuable_targets(metadata_root: Path | None = None) -> list[str]:
    root = metadata_root or default_metadata_root()
    data = read_json(root / "fuzzbench_targets.json")
    raw = data.get("target_sets", {}).get("valuable", {})
    targets = raw.get("targets", raw) if isinstance(raw, dict) else raw
    return [str(target) for target in targets or []]


def validate_adapter_coverage(metadata_root: Path | None = None) -> list[str]:
    adapters = load_adapters(metadata_root)
    valuable = valuable_targets(metadata_root)
    missing = [target for target in valuable if target not in adapters]
    extra = [target for target in adapters if target not in valuable]
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing valuable adapters: {', '.join(missing)}")
        if extra:
            details.append(f"adapters outside valuable set: {', '.join(extra)}")
        raise PipelineError("adapter_coverage_failed", "; ".join(details), 64)
    return valuable


def adapter_profile_counts(metadata_root: Path | None = None) -> dict[str, int]:
    adapters = load_adapters(metadata_root)
    counts = {PAPER_METHOD_PROFILE: 0, EXTENSION_METHOD_PROFILE: 0}
    for entry in adapters.values():
        profile = str(entry.get("method_profile", ""))
        if profile in counts:
            counts[profile] += 1
    return counts


def formats_for_profile(adapter: dict[str, Any], profile: str, env: dict[str, str] | None = None) -> list[str]:
    formats = [str(item) for item in adapter.get("formats", [])]
    env = env or os.environ
    if profile == "compat-smoke":
        try:
            max_formats = int(env.get("G2FUZZ_MAX_FORMATS", "1") or "1")
        except ValueError:
            max_formats = 1
        return formats[: max(1, max_formats)]
    return formats


def try_num_for_profile(profile: str, env: dict[str, str] | None = None) -> str:
    env = env or os.environ
    if profile == "compat-smoke":
        return env.get("G2FUZZ_TRY_NUM", "1") or "1"
    # gamma and delta share the real paper budget (default 3).  Delta must not
    # patch G2FUZZ_TRY_NUM down to a smoke value (plan section 1.2/4.2).
    if is_gamma_profile(profile):
        return env.get("G2FUZZ_TRY_NUM", "3") or "3"
    return env.get("G2FUZZ_TRY_NUM", "3") or "3"


def build_command_pair(
    adapter: dict[str, Any],
    artifact_dir: str | Path | None = None,
    target_package: str | Path | None = None,
    workspace: str | Path | None = None,
) -> dict[str, Any]:
    """Return the two (afl/cmp) FuzzBench build commands for the target pair.

    Both variants share the same ``argv`` (the native FuzzBench ``build.sh``)
    and the same compiler/toolchain env; they differ ONLY in
    ``AFL_LLVM_CMPLOG`` (0 for the default-instrumented ``.afl`` binary, 1 for
    the CmpLog ``.cmp`` binary) and the ``HGB_G2FUZZ_OUTPUT`` path.  CmpLog is
    used exclusively for the ``.cmp`` build.
    """

    artifact = Path(artifact_dir) if artifact_dir else Path("/opt/hgb/artifacts/g2fuzz")
    bench_root = Path(target_package) if target_package else Path("/target")
    out_root = Path(workspace) if workspace else Path("/workspace")
    build_sh = bench_root / "fuzzbench_benchmark" / "build.sh"
    cc = artifact / "afl-clang-fast"
    cxx = artifact / "afl-clang-fast++"
    src = bench_root / "source_input"
    common_env = {
        "CC": str(cc),
        "CXX": str(cxx),
        "FUZZING_ENGINE": "afl",
        "FUZZER": "afl",
        "SANITIZER": "address",
        "ARCHITECTURE": "x86_64",
        "SRC": str(src),
        "WORK": str(out_root / "target" / "build_work"),
        "LIB_FUZZING_ENGINE": NATIVE_AFL_DRIVER_FLAG,
        "FUZZER_LIB": NATIVE_AFL_DRIVER_FLAG,
        "CFLAGS": f"{NATIVE_BUILD_CFLAGS} -L{src}",
        "CXXFLAGS": f"{NATIVE_BUILD_CFLAGS} -L{src}",
    }
    afl_env = dict(common_env)
    afl_env["AFL_LLVM_CMPLOG"] = "0"
    afl_env["HGB_G2FUZZ_OUTPUT"] = str(out_root / "target" / "target.afl")
    cmp_env = dict(common_env)
    cmp_env["AFL_LLVM_CMPLOG"] = "1"
    cmp_env["HGB_G2FUZZ_OUTPUT"] = str(out_root / "target" / "target.cmp")
    argv = ["bash", str(build_sh)]
    return {
        "program_id": adapter["program_id"],
        "build_mode": BUILD_MODE,
        "afl": {"env": afl_env, "argv": argv},
        "cmp": {"env": cmp_env, "argv": argv},
        "expected_difference": "AFL_LLVM_CMPLOG and output path only",
    }


def resolved_invocation(
    adapter: dict[str, Any],
    executable_path: str | Path,
    input_token: str = "@@",
) -> dict[str, Any]:
    input_mode = str(adapter.get("input_mode", "file"))
    adapter_argv = [str(item) for item in adapter.get("argv", [])]
    token_count = adapter_argv.count(input_token)
    if input_mode == "file" and token_count != 1:
        raise PipelineError("bad_target_invocation", f"{adapter['target']}: file mode requires exactly one @@ in adapter argv", 64)
    if input_mode == "stdin" and token_count:
        raise PipelineError("bad_target_invocation", f"{adapter['target']}: stdin mode must not contain @@", 64)
    if input_mode == "argv" and token_count > 1:
        raise PipelineError("bad_target_invocation", f"{adapter['target']}: argv mode accepts at most one @@", 64)
    argv = [str(executable_path), *adapter_argv]
    return {
        "target": adapter["target"],
        "program_id": adapter["program_id"],
        "input_mode": input_mode,
        "argv": argv,
        "adapter_argv": adapter_argv,
        "uses_at_at": token_count > 0,
        "env": adapter.get("env", {}) if isinstance(adapter.get("env", {}), dict) else {},
        "timeout_seconds": int(adapter.get("timeout_seconds") or 5),
    }


def argv_for_input(invocation: dict[str, Any], input_path: Path) -> list[str]:
    rendered: list[str] = []
    for item in invocation["argv"]:
        rendered.append(str(input_path) if item == "@@" else str(item))
    return rendered


def stage_record(status: str, reason: str = "none", **extra: Any) -> dict[str, Any]:
    record = {"status": status, "reason": reason}
    record.update(extra)
    return record


def _test_mode_cap() -> int | None:
    """Return a strict test-mode timeout cap, or None when not in test mode.

    G2Fuzz reproduction budgets are large (AFL campaign seconds in the
    thousands). Fake AFL/program_gen scripts used in tests that respect
    ``--time`` would hang for that long. ``G2FUZZ_TEST_MODE_SECONDS`` caps the
    effective subprocess timeout for the campaign/program_gen stages so
    ``pytest -q`` always terminates, without affecting real reproduction
    budgets (it is only set by the test suite, never by the production
    entrypoint).

    When running under pytest (``PYTEST_CURRENT_TEST`` is set) and no explicit
    cap is configured, a small default cap is applied so a fake long-running
    subprocess (e.g. a sleeping fake AFL) is killed within the cap and leaves
    no child process behind (zeta plan §2). Set ``G2FUZZ_TEST_MODE_SECONDS=0``
    to disable the auto-cap.
    """

    raw = os.environ.get("G2FUZZ_TEST_MODE_SECONDS")
    if raw is not None and raw != "":
        try:
            value = int(raw)
        except ValueError:
            return None
        return max(1, value) if value > 0 else None
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return 30
    return None


def _kill_process_group(proc: subprocess.Popen) -> None:
    """Terminate the whole process group of ``proc`` so child processes that
    ignore SIGTERM (e.g. a fake AFL that sleeps) cannot survive a timeout
    (zeta plan §2)."""

    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, OSError):
        pgid = proc.pid
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except (ProcessLookupError, OSError):
            return
        try:
            proc.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            continue


def run_subprocess(cmd: list[str], log_path: Path, timeout: int, env: dict[str, str] | None = None, *, cwd: str | Path | None = None) -> tuple[int, bool]:
    """Run a subprocess in its own process group and kill the whole group on timeout.

    Returns ``(exit_code, timed_out)``. A timeout is always reported as exit
    code 124. Under pytest a small default cap is applied so fake long-running
    subprocesses are killed quickly (zeta plan §2).
    """

    log_path.parent.mkdir(parents=True, exist_ok=True)
    timed_out = False
    cap = _test_mode_cap()
    if cap is not None and (timeout is None or timeout <= 0 or timeout > cap):
        timeout = cap
    effective_timeout = timeout if timeout and timeout > 0 else None
    proc: subprocess.Popen | None = None
    log_file = None
    try:
        log_file = log_path.open("wb")
        proc = subprocess.Popen(
            cmd,
            env=env,
            cwd=cwd,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        code = proc.wait(timeout=effective_timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if proc is not None:
            _kill_process_group(proc)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        code = 124
    except FileNotFoundError:
        code = 127
    finally:
        if log_file is not None:
            try:
                log_file.close()
            except (OSError, ValueError):
                pass
    with log_path.open("a", encoding="utf-8") as log:
        log.write(f"\n[exit={code} timed_out={timed_out}]\n")
    return code, timed_out


def is_generated_input_candidate(path: Path) -> bool:
    """Return True only for real generator-produced input files.

    Excludes Python generator source, JSON/model configs, logs, model files,
    common/bootstrap corpus, and preseed files.  Only data files produced by
    generator execution (e.g. under ``gen_seeds``) are admitted.
    """

    # Real generator-produced inputs may use any data extension (JSON seeds
    # for the JSON target, .txt seeds for text-format targets, etc.). Only
    # exclude generator artifacts: Python sources, logs, and JSON-lines
    # traces. Config-like JSON files are still excluded via ignored_stems.
    ignored_suffixes = {".py", ".log", ".jsonl"}
    ignored_stems = {
        "manifest",
        "metadata",
        "meta",
        "config",
        "model_setting",
        "program_to_format",
        "openai_key",
        "lineage",
        "fuzzer_stats",
        "stats",
        "preseed",
        "seed_corpus",
        "input_corpus",
        "corpus_manifest",
        "readme",
    }
    stem = path.stem.lower()
    if path.suffix.lower() in ignored_suffixes:
        return False
    if stem in ignored_stems or stem.startswith("config"):
        return False
    if stem.startswith("preseed") or stem.endswith("_preseed"):
        return False
    if stem.startswith("hgb_corpus") or stem.startswith("common_"):
        return False
    return path.is_file()


def parse_fuzzer_stats(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data: dict[str, Any] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        try:
            data[key] = int(value)
        except ValueError:
            data[key] = value
    return data


def bootstrap_bytes(fmt: str) -> bytes:
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
    return (fmt + "\n").encode("utf-8", "replace")


def count_files(path: Path, exclude_readme: bool = False) -> int:
    if not path.exists():
        return 0
    total = 0
    for item in path.rglob("*"):
        if not item.is_file():
            continue
        if exclude_readme and item.name == "README.txt":
            continue
        total += 1
    return total


def dir_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    total = 0
    for item in path.rglob("*"):
        try:
            if item.is_file():
                total += item.stat().st_size
        except OSError:
            continue
    return total


def unique_dest(directory: Path, name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    safe = name or "seed"
    candidate = directory / safe
    if not candidate.exists():
        return candidate
    stem = candidate.stem
    suffix = candidate.suffix
    index = 1
    while True:
        alt = directory / f"{stem}_{index}{suffix}"
        if not alt.exists():
            return alt
        index += 1


def _is_crash_exit(exit_code: int | None, stderr: str = "") -> bool:
    if exit_code is None:
        return True
    if isinstance(exit_code, int) and exit_code >= 128:
        return True
    if "AddressSanitizer" in stderr or "UndefinedBehaviorSanitizer" in stderr:
        return True
    return False


class G2FuzzPipeline:
    def __init__(
        self,
        workspace: Path,
        target: str,
        target_package: Path,
        artifact_dir: Path,
        metadata_root: Path,
        profile: str,
        protocol: str,
        dry_run: bool = False,
    ) -> None:
        self.workspace = workspace
        self.target = target
        self.target_package = target_package
        self.artifact_dir = artifact_dir
        self.metadata_root = metadata_root
        self.profile = profile
        self.protocol = protocol
        self.dry_run = dry_run
        self.adapters = load_adapters(metadata_root)
        self.adapter = self.adapters.get(target)
        if not self.adapter:
            raise PipelineError("not_applicable", f"G2Fuzz has no adapter for target {target}", 66)
        if self.adapter.get("applicability") != "applicable":
            raise PipelineError("not_applicable", f"G2Fuzz adapter marks {target} as not applicable", 66)
        self.program_id = str(self.adapter["program_id"])
        self.formats = formats_for_profile(self.adapter, self.profile)
        self.stages: dict[str, dict[str, Any]] = {name: stage_record("pending") for name in STAGE_NAMES}
        self.seed_counts: dict[str, int] = {
            "common_initial": 0,
            "bootstrap": 0,
            "g2_generated": 0,
            "afl_initial": 0,
            "afl_queue": 0,
        }
        self.seed_bytes: dict[str, int] = {
            "common_initial": 0,
            "bootstrap": 0,
            "g2_generated": 0,
            "afl_initial": 0,
            "afl_queue": 0,
        }
        self.metrics: dict[str, Any] = {}
        self.generated_generator_count = 0
        self.generated_input_count = 0
        self.valid_generated_input_count = 0
        self.exit_code = 0
        self.reason = "none"
        self.status = "created"
        self.start_time = time.time()
        self.target_afl = self.workspace / "target" / "target.afl"
        self.target_cmp = self.workspace / "target" / "target.cmp"
        self.target_cov = self.workspace / "target" / "target.cov"
        self.target_pair_dir = self.workspace / "target_pair"
        self.runner = None  # Docker runner; defaults to hgb_fuzzbench_builder._run when needed
        self.contract_result: dict[str, Any] = {}
        self.triple_build_results: dict[str, Any] = {}
        self.triple_provenance: dict[str, Any] = {}
        self.consumption_smoke: dict[str, Any] = {}
        self.invocation: dict[str, Any] | None = None
        self.input_contract: dict[str, Any] = {}
        self.build_source = "none"
        self.coverage_summary: dict[str, Any] = {}

    def ensure_layout(self) -> None:
        for rel in (
            "target",
            "target/build_afl",
            "target/build_cmp",
            "target_pair",
            "program_gen",
            "generators/source",
            "seeds/common_initial",
            "seeds/bootstrap",
            "seeds/g2_generated",
            "seeds/afl_initial",
            "seeds/afl_queue",
            "seeds/merged_initial",
            "validation",
            "campaign/output",
            "campaign/stats",
            "coverage",
            "config",
            "logs",
        ):
            (self.workspace / rel).mkdir(parents=True, exist_ok=True)

    def write_runtime_mapping(self) -> None:
        # program_to_format.json is generated from the adapter manifest so the
        # G2Fuzz program maps to this target's formats/spec; no stale default.
        mapping = {self.program_id: self.formats}
        json_dump(self.workspace / "config" / "program_to_format.json", mapping)
        json_dump(
            self.workspace / "config" / "model_setting.json",
            {"model": [os.environ.get("G2FUZZ_MODEL") or os.environ.get("OPENAI_MODEL") or os.environ.get("MODEL") or "gpt-4o-mini"]},
        )
        json_dump(self.workspace / "config" / "adapter.json", self.adapter)
        json_dump(self.workspace / "config" / "build_commands.json", build_command_pair(self.adapter, self.artifact_dir, self.target_package, self.workspace))

    def target_manifest(self) -> dict[str, Any]:
        manifest = Path(os.environ.get("HGB_TARGET_MANIFEST", self.target_package / "target_manifest.json"))
        return read_json(manifest)

    def preflight(self) -> None:
        self.ensure_layout()
        validate_adapter_coverage(self.metadata_root)
        self.write_runtime_mapping()
        spec_rel = Path(str(self.adapter["format_spec"]))
        spec_candidates = [
            repo_root_from(self.metadata_root) / spec_rel,
            Path("/opt/hgb") / spec_rel,
            Path.cwd() / spec_rel,
        ]
        if not any(path.exists() for path in spec_candidates):
            raise PipelineError("adapter_spec_missing", f"missing G2Fuzz format spec note: {spec_rel}", 66)
        required = (
            self.target_package / "target_manifest.json",
            self.target_package / "fuzzbench_benchmark" / "benchmark.yaml",
        )
        missing = [str(path) for path in required if not path.exists()]
        if missing:
            raise PipelineError("target_package_missing", f"target package is missing required files: {', '.join(missing)}", 66)
        self.stages["target_prepared"] = stage_record("complete", formats=self.formats, method_profile=self.adapter["method_profile"])

    # -- target pair discovery / build -------------------------------------

    def candidate_pair_dirs(self) -> list[Path]:
        raw = [
            os.environ.get("G2FUZZ_TARGET_DIR"),
            os.environ.get("HGB_G2FUZZ_TARGET_PAIR_DIR"),
            "/g2fuzz-target-pair",
            str(self.workspace / "targets" / self.program_id),
            str(self.workspace / "target_pair"),
            str(self.workspace / "target"),
        ]
        seen: set[Path] = set()
        dirs: list[Path] = []
        for item in raw:
            if not item:
                continue
            path = Path(item)
            if path in seen:
                continue
            seen.add(path)
            dirs.append(path)
        return dirs

    def locate_pair(self) -> tuple[Path, Path, Path] | None:
        names = (
            (f"{self.program_id}.afl", f"{self.program_id}.cmp"),
            ("target.afl", "target.cmp"),
        )
        for directory in self.candidate_pair_dirs():
            for afl_name, cmp_name in names:
                afl = directory / afl_name
                cmp = directory / cmp_name
                if afl.exists() or cmp.exists():
                    if not (afl.exists() and cmp.exists()):
                        raise PipelineError(
                            "infra_missing",
                            f"G2Fuzz target pair is incomplete: missing {'target.cmp' if afl.exists() else 'target.afl'} in {directory}",
                            127,
                        )
                    if executable(afl) and executable(cmp):
                        return directory, afl, cmp
                    raise PipelineError("infra_missing", f"G2Fuzz target pair exists but is not executable: {afl}, {cmp}", 127)
        return None

    def copy_pair(self, src_afl: Path, src_cmp: Path) -> None:
        self.target_afl.parent.mkdir(parents=True, exist_ok=True)
        if src_afl.resolve() != self.target_afl.resolve():
            shutil.copy2(src_afl, self.target_afl)
        if src_cmp.resolve() != self.target_cmp.resolve():
            shutil.copy2(src_cmp, self.target_cmp)
        if not executable(self.target_afl) or not executable(self.target_cmp):
            raise PipelineError("infra_missing", "copied G2Fuzz target pair is not executable", 127)

    def resolve_toolchain(self) -> tuple[Path, Path]:
        cc = self.artifact_dir / "afl-clang-fast"
        cxx = self.artifact_dir / "afl-clang-fast++"
        if not (executable(cc) and executable(cxx)):
            raise PipelineError(
                "infra_missing",
                "G2Fuzz AFL++ toolchain (afl-clang-fast/afl-clang-fast++) not found at "
                f"{self.artifact_dir}; cannot auto-build the .afl/.cmp target pair",
                127,
            )
        return cc, cxx

    def _is_synthetic_build_sh(self, path: Path) -> bool:
        if not path.is_file():
            return False
        try:
            return SYNTHETIC_BUILD_SH_MARKER in path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False

    def install_fuzzing_engine_library(self, src: Path, engine: str = "afl") -> None:
        """Make -lFuzzingEngine resolvable to the right driver.

        afl-cc maps ``-fsanitize=fuzzer`` onto the bundled libAFLDriver.a, but
        several build recipes hardcode ``-lFuzzingEngine`` (libpng) or use
        meson's ``dependency('FuzzingEngine')`` (systemd), which searches the
        standard library directories. Install the driver as libFuzzingEngine.a
        in /usr/local/lib (the container runs as root) so both styles link.
        For coverage builds use the real libFuzzer driver instead, since the
        replay executes the binary libFuzzer-style.
        """
        if engine == "coverage":
            driver = next(
                (
                    p
                    for p in (
                        Path("/usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.fuzzer-x86_64.a"),
                        Path("/usr/lib/clang/18/lib/linux/libclang_rt.fuzzer-x86_64.a"),
                    )
                    if p.is_file()
                ),
                None,
            )
        else:
            driver = self.artifact_dir / "libAFLDriver.a"
        if driver is None or not driver.is_file():
            return
        for lib_dir in (Path("/usr/local/lib"), Path("/usr/lib"), src):
            target = lib_dir / "libFuzzingEngine.a"
            if target.is_file() and target.samefile(driver):
                continue
            try:
                lib_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(driver, target)
            except OSError:
                pass

    def _derive_build_sh_from_dockerfile(self, dest: Path, dockerfile: Path) -> bool:
        """Materialize $SRC/build.sh the way the benchmark Dockerfile does.

        Many FuzzBench benchmarks keep their recipe inside the project source
        and ``cp`` it into $SRC during the image build (libpng, systemd). This
        replays ``cp ... $SRC`` and follow-up ``sed -i ... $SRC/build.sh``
        commands against the prepared source root.
        """
        if not dockerfile.is_file():
            return False
        src_input = self.target_package / "source_input"
        text = dockerfile.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith(("RUN", "run")):
                continue
            stripped = stripped[3:].strip()
            if "cp " in stripped and ("$SRC" in stripped or "/src" in stripped):
                parts = [p for p in stripped.split() if p not in ("cp", "&&", ";")]
                candidate_sources = [p for p in parts if p.endswith((".sh", "build.sh", ".bash"))]
                target = next((p for p in parts if p in ("$SRC", "$SRC/", "/src", "/src/", "$SRC/build.sh", "/src/build.sh")), None)
                if target is None:
                    continue
                for source in candidate_sources:
                    source = source.replace("$SRC/", "").replace("/src/", "")
                    source_path = src_input / source if source else None
                    if source_path and source_path.is_file():
                        shutil.copy2(source_path, dest / "build.sh")
                        for sed_line in text.splitlines():
                            sed_stripped = sed_line.strip()
                            if "sed -i" in sed_stripped and "$SRC/build.sh" in sed_stripped:
                                import re as _re
                                match = _re.search(r"sed -i (['\"])(.+?)\1", sed_stripped)
                                if match:
                                    subprocess.run(
                                        ["sed", "-i", "-e", match.group(2), str(dest / "build.sh")],
                                        check=False,
                                    )
                        (dest / "build.sh").chmod(0o755)
                        return True
        return False

    def _find_project_build_script(self) -> Path | None:
        src_input = self.target_package / "source_input"
        if not src_input.is_dir():
            return None
        candidates: list[Path] = []
        for pattern in ("**/oss-fuzz/build.sh", "**/contrib/oss-fuzz/build.sh", "**/tools/oss-fuzz.sh", "**/fuzz/build.sh"):
            candidates.extend(p for p in src_input.glob(pattern) if p.is_file())
        candidates.sort(key=lambda p: (p.as_posix().count("/"), p.as_posix()))
        return candidates[0] if candidates else None

    def _recreate_archives(self, dest: Path) -> None:
        build_sh = dest / "build.sh"
        if not build_sh.is_file():
            return
        text = build_sh.read_text(encoding="utf-8", errors="replace")
        import re as _re
        for name in sorted(set(_re.findall(r"[A-Za-z0-9][A-Za-z0-9._+-]*\.(?:tar\.xz|tar\.gz|tgz|zip)", text))):
            archive = dest / name
            if archive.exists():
                continue
            if name.endswith(".tar.xz"):
                stem = name[: -len(".tar.xz")]
            elif name.endswith(".tar.gz"):
                stem = name[: -len(".tar.gz")]
            elif name.endswith(".tgz"):
                stem = name[: -len(".tgz")]
            else:
                stem = name[: -len(".zip")]
            source_dir = dest / stem
            if not source_dir.is_dir():
                continue
            if name.endswith(".zip"):
                subprocess.run(["zip", "-qr", str(archive), stem], cwd=str(dest), check=False)
            elif name.endswith(".tar.xz"):
                subprocess.run(["tar", "-C", str(dest), "-cJf", str(archive), stem], check=False)
            else:
                subprocess.run(["tar", "-C", str(dest), "-czf", str(archive), stem], check=False)

    def _patch_native_build_script(self, dest: Path) -> None:
        build_sh = dest / "build.sh"
        if not build_sh.is_file():
            return
        fuzz_target = self.target_manifest().get("fuzz_target", self.target)
        # Reuse the shared FuzzBench build-context patches (curl single-target
        # build + dependency URL fixes, ftfuzzer iconv conftest, php options,
        # mruby/zip corpus guards, ...). The helper expects a context dir with
        # source_input/<project> and build.sh at the root; the prepared $SRC
        # layout matches except for the source_input/ prefix, so point it there
        # via a temporary symlink.
        try:
            from hgb_fuzzbench_builder import _patch_single_target_build_context

            link = dest / "source_input"
            if not link.exists():
                link.symlink_to(dest, target_is_directory=True)
            try:
                _patch_single_target_build_context(dest, fuzz_target)
            finally:
                if link.is_symlink():
                    link.unlink()
        except Exception:
            pass
        text = build_sh.read_text(encoding="utf-8", errors="replace")
        if fuzz_target.startswith("curl_fuzzer"):
            # The shared patch makes ossfuzz.sh best-effort and rewrites
            # Makefile.am SOURCES for sealed Docker evaluator candidate builds;
            # the native build must surface ossfuzz.sh failures and keep the
            # original COMMON_SOURCES (curl_fuzzer.cc + tlv/callback helpers).
            text = text.replace("./ossfuzz.sh || true", "./ossfuzz.sh")
            makefile = dest / "curl_fuzzer" / "Makefile.am"
            if makefile.is_file():
                make_text = makefile.read_text(encoding="utf-8", errors="replace")
                make_text = make_text.replace(
                    f"{fuzz_target}_SOURCES = curl_fuzzer.cc",
                    f"{fuzz_target}_SOURCES = $(COMMON_SOURCES)",
                )
                makefile.write_text(make_text, encoding="utf-8")
        if fuzz_target == "hb-shape-fuzzer":
            # The benchmark Dockerfile expects Ubuntu 20.04 python3.8; the
            # G2Fuzz image ships python3 (3.12) with ninja + meson 0.56
            # preinstalled, so the runtime pip install is a fast no-op that
            # must not fail the build when PyPI is unreachable.
            text = text.replace(
                "python3.8 -m pip install ninja meson==0.56.0",
                "python3 -m pip install ninja meson==0.56.0 || true",
            )
        if fuzz_target.startswith("php-fuzz"):
            # php's configure hardcodes FUZZING_CC="$CXX -stdlib=libc++".
            # The coverage build links the libstdc++-ABI libFuzzer driver, so
            # strip -stdlib=libc++ from the generated Makefile after configure
            # to keep the C++ ABI consistent (the AFL build tolerates it
            # because the AFL driver is C-only).
            text = text.replace(
                "make -j$(nproc)",
                "sed -i 's/-stdlib=libc++//g' Makefile\nmake -j$(nproc)",
            )
        build_sh.write_text(text, encoding="utf-8")
        if self.target == "mbedtls_fuzz_dtlsclient":
            # mbedtls forces -Werror and -Wdocumentation; clang 18 turns the
            # empty-\retval documentation notes in psa/crypto.h into errors
            # that older FuzzBench clang versions never reported.
            root_cmake = dest / "mbedtls" / "CMakeLists.txt"
            lib_cmake = dest / "mbedtls" / "library" / "CMakeLists.txt"
            for path, replacements in (
                (root_cmake, ((' -Werror")', '")'),)),
                (lib_cmake, (("-Wdocumentation", "-Wno-documentation"),)),
            ):
                if path.is_file():
                    cmake_text = path.read_text(encoding="utf-8", errors="replace")
                    for old, new in replacements:
                        cmake_text = cmake_text.replace(old, new)
                    path.write_text(cmake_text, encoding="utf-8")

    def prepare_source_root(self, variant: str = "afl") -> Path:
        """Prepare a writable $SRC emulating the FuzzBench builder environment.

        The FuzzBench builder image has $SRC holding the benchmark files
        (build.sh, fuzz-target sources, seeds) plus every project checkout
        produced by the Dockerfile RUN commands. Direct build.sh execution
        against the read-only /target package breaks whenever the Dockerfile
        copies the recipe into $SRC, extracts archives, or relies on a
        writable tree. This stage reproduces that layout under
        workspace/target/src_<variant>; each build variant gets a fresh copy
        because FuzzBench build scripts assume a clean tree (some fail on
        ``mkdir build`` when the afl variant already created it).
        """
        dest = self.workspace / "target" / f"src_{variant}"
        marker = dest / ".hgb_prepared"
        if marker.is_file():
            return dest
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True)
        src_input = self.target_package / "source_input"
        if src_input.is_dir():
            # rsync preserves symlinks without following them; shutil.copytree
            # follows symlinked directories while scanning and can loop forever
            # on trees like systemd's recursive testdata links.
            proc = subprocess.run(
                ["rsync", "-a", "--delete", str(src_input) + "/", str(dest) + "/"],
                check=False,
            )
            if proc.returncode != 0 or not any(dest.iterdir()):
                shutil.copytree(src_input, dest, dirs_exist_ok=True)
        # The beta-plan physical split moves the fuzz-target sources (the
        # "reference harnesses") out of source_input into reference_harnesses/.
        # G2Fuzz is a paper-native input generator that must build the original
        # FuzzBench target unchanged, so restore them at their native paths:
        # reference_harnesses/<project>/ mirrors the project tree relative to
        # source_input/<project>/ and selected/source_input/ holds the selected
        # target at its native source_input path.
        ref_root = self.target_package / "reference_harnesses"
        if ref_root.is_dir():
            for item in ref_root.iterdir():
                if item.name == "selected":
                    sel = item / "source_input"
                    if sel.is_dir():
                        shutil.copytree(sel, dest, dirs_exist_ok=True)
                elif item.is_dir():
                    shutil.copytree(item, dest / item.name, dirs_exist_ok=True)
        bench = self.target_package / "fuzzbench_benchmark"
        if bench.is_dir():
            for item in bench.iterdir():
                if item.name == "build.sh" and self._is_synthetic_build_sh(item):
                    continue
                if item.is_dir():
                    shutil.copytree(item, dest / item.name, dirs_exist_ok=True)
                else:
                    shutil.copy2(item, dest / item.name)
        dockerfile = bench / "Dockerfile"
        if not (dest / "build.sh").is_file():
            derived = self._derive_build_sh_from_dockerfile(dest, dockerfile)
            if not derived:
                project_build = self._find_project_build_script()
                if project_build is not None:
                    shutil.copy2(project_build, dest / "build.sh")
                    (dest / "build.sh").chmod(0o755)
        if not (dest / "build.sh").is_file():
            raise PipelineError("infra_missing", "G2Fuzz target build.sh not found for auto-build", 127)
        (dest / "build.sh").chmod(0o755)
        self._recreate_archives(dest)
        self._patch_native_build_script(dest)
        self._prepare_target_seed_artifacts(dest)
        # Some build scripts use the literal /src FuzzBench path (curl).
        # Repoint a /src symlink at this variant's prepared root (the
        # container runs as root).
        src_link = Path("/src")
        try:
            if src_link.is_symlink() or not src_link.exists():
                if src_link.is_symlink():
                    src_link.unlink()
                src_link.symlink_to(dest, target_is_directory=True)
        except OSError:
            pass
        driver = self.artifact_dir / "libAFLDriver.a"
        if driver.is_file():
            shutil.copy2(driver, dest / "libFuzzingEngine.a")
        marker.write_text("ok\n", encoding="utf-8")
        return dest

    def _prepare_target_seed_artifacts(self, dest: Path) -> None:
        """Replay Dockerfile RUN steps that build seed corpora/aux files.

        Several FuzzBench Dockerfiles produce files the build.sh expects at
        build time (seed corpus zips, /opt/seeds). These steps don't exist in
        the prepared source tree, so replay them here.
        """
        fuzz_target = self.target_manifest().get("fuzz_target", self.target)
        bench = self.target_package / "fuzzbench_benchmark"
        if fuzz_target == "libjpeg_turbo_fuzzer":
            corpora = dest / "seed-corpora"
            if corpora.is_dir():
                subprocess.run(
                    ["zip", "-rq", str(dest / "decompress_fuzzer_seed_corpus.zip"), ".", "-i", "afl-testcases/jpeg*", "bugs/decompress*"],
                    cwd=str(corpora), check=False,
                )
                subprocess.run(
                    ["zip", "-rq", str(dest / "compress_fuzzer_seed_corpus.zip"), ".", "-i", "afl-testcases/bmp", "afl-testcases/gif*", "bugs/compress*"],
                    cwd=str(corpora), check=False,
                )
        if fuzz_target == "ossfuzz" and self.target == "sqlite3_ossfuzz":
            sqlite_dir = dest / "sqlite3"
            if sqlite_dir.is_dir():
                subprocess.run(
                    ["bash", "-c", "find sqlite3 -name '*.test' -type f -print | xargs -r zip -q ossfuzz_seed_corpus.zip"],
                    cwd=str(dest), check=False,
                )
        seeds = bench / "seeds"
        if seeds.is_dir():
            opt_seeds = Path("/opt/seeds")
            if not opt_seeds.exists():
                try:
                    shutil.copytree(seeds, opt_seeds, dirs_exist_ok=True)
                except OSError:
                    pass

    def resolve_build_workdir(self, src: Path) -> Path:
        """Return the build.sh working directory per the benchmark Dockerfile.

        FuzzBench runs build.sh with CWD = the Dockerfile's final WORKDIR
        (e.g. ``WORKDIR libpng``); the prepared $SRC must mirror that.
        """
        dockerfile = self.target_package / "fuzzbench_benchmark" / "Dockerfile"
        if dockerfile.is_file():
            for line in dockerfile.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if stripped.startswith("WORKDIR"):
                    rel = stripped[len("WORKDIR"):].strip()
                    for prefix in ("$SRC/", "/src/"):
                        if rel.startswith(prefix):
                            rel = rel[len(prefix):]
                            break
                    if rel in ("", "$SRC", "/src"):
                        return src
                    candidate = (src / rel)
                    if candidate.is_dir():
                        return candidate
        return src

    def resolve_build_sh(self, src: Path | None = None) -> Path:
        prepared = (src or self.prepare_source_root()) / "build.sh"
        if prepared.is_file():
            return prepared
        bench_dir_env = os.environ.get("HGB_FUZZBENCH_BENCHMARK_DIR")
        if bench_dir_env:
            candidate = Path(bench_dir_env) / "build.sh"
            if candidate.is_file() and not self._is_synthetic_build_sh(candidate):
                return candidate
        manifest = self.target_manifest()
        bench_dir = manifest.get("benchmark_dir", "")
        if bench_dir:
            candidate = Path(bench_dir) / "build.sh"
            if candidate.is_file() and not self._is_synthetic_build_sh(candidate):
                return candidate
        pkg_build = self.target_package / "fuzzbench_benchmark" / "build.sh"
        if pkg_build.is_file() and not self._is_synthetic_build_sh(pkg_build):
            return pkg_build
        raise PipelineError("infra_missing", "G2Fuzz target build.sh not found for auto-build", 127)

    def resolve_source_dir(self, variant: str = "afl") -> Path:
        return self.prepare_source_root(variant)

    def _build_sh_command(self, build_sh: Path) -> list[str]:
        """Return the build.sh argv, preserving its shebang flags.

        FuzzBench executes build.sh directly, so ``#!/bin/bash -ex`` flags
        (errexit/xtrace) take effect.  Invoking it via ``bash build.sh`` drops
        them, letting failed compile/link steps pass silently and produce
        exit-0 builds without the fuzz target.
        """
        if build_sh.is_file() and executable(build_sh):
            try:
                with build_sh.open("rb") as handle:
                    first = handle.readline(256)
                if first.startswith(b"#!"):
                    return [str(build_sh)]
            except OSError:
                pass
        return ["bash", str(build_sh)]

    def auto_build_pair(self) -> tuple[dict[str, Any], dict[str, Any]]:
        cc, cxx = self.resolve_toolchain()
        fuzz_target = self.target_manifest().get("fuzz_target", self.target)
        self.install_fuzzing_engine_library(self.workspace / "target" / "src_afl")
        commands = build_command_pair(self.adapter, self.artifact_dir, self.target_package, self.workspace)
        results: dict[str, Any] = {}
        for label, variant in (("afl", commands["afl"]), ("cmp", commands["cmp"])):
            src = self.resolve_source_dir(label)
            build_sh = self.resolve_build_sh(src)
            build_cwd = self.resolve_build_workdir(src)
            out_dir = self.workspace / "target" / f"build_{label}"
            work_dir = self.workspace / "target" / f"work_{label}"
            out_dir.mkdir(parents=True, exist_ok=True)
            work_dir.mkdir(parents=True, exist_ok=True)
            env = os.environ.copy()
            env.update(variant["env"])
            env["OUT"] = str(out_dir)
            env["SRC"] = str(src)
            env["WORK"] = str(work_dir)
            env["CFLAGS"] = f"{NATIVE_BUILD_CFLAGS} -L{src}"
            env["CXXFLAGS"] = f"{NATIVE_BUILD_CFLAGS} -L{src}"
            env["LIB_FUZZING_ENGINE"] = NATIVE_AFL_DRIVER_FLAG
            env["FUZZER_LIB"] = NATIVE_AFL_DRIVER_FLAG
            env["FUZZER"] = "afl"
            library_path = env.get("LIBRARY_PATH", "")
            env["LIBRARY_PATH"] = f"{src}:/usr/local/lib" + (f":{library_path}" if library_path else "")
            log_path = self.workspace / "logs" / f"build_{label}.log"
            cmd = self._build_sh_command(build_sh)
            try:
                with log_path.open("wb") as log:
                    proc = subprocess.run(
                        cmd,
                        env=env,
                        cwd=str(build_cwd) if build_cwd.is_dir() else str(src),
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        timeout=int(os.environ.get("G2FUZZ_BUILD_TIMEOUT_SECONDS", "3600") or "3600"),
                        check=False,
                    )
                code = proc.returncode
            except subprocess.TimeoutExpired:
                code = 124
            except OSError as exc:
                raise PipelineError("infra_failure", f"G2Fuzz {label} build invocation failed: {exc}", 127)
            produced = out_dir / fuzz_target
            results[label] = {
                "command": cmd,
                "env": {k: variant["env"][k] for k in ("AFL_LLVM_CMPLOG", "HGB_G2FUZZ_OUTPUT")},
                "exit_code": code,
                "out_dir": str(out_dir),
                "produced": str(produced),
                "produced_exists": produced.is_file(),
                "log": str(log_path),
            }
            if code != 0 or not produced.is_file():
                raise PipelineError(
                    "infra_failure",
                    f"G2Fuzz {label} target build failed (exit {code}); no {fuzz_target} produced at {produced}",
                    127,
                )
            dest = self.target_afl if label == "afl" else self.target_cmp
            shutil.copy2(produced, dest)
            if not executable(dest):
                raise PipelineError("infra_failure", f"G2Fuzz {label} built binary is not executable: {dest}", 127)
            # FuzzBench ships the whole $OUT layout at runtime; some binaries
            # carry RUNPATH=$ORIGIN/src/shared (systemd). Keep that layout
            # next to the copied binary.
            shared_out = out_dir / "src" / "shared"
            if shared_out.is_dir():
                shutil.copytree(shared_out, self.workspace / "target" / "src" / "shared", dirs_exist_ok=True)
        return results, commands

    def write_invocation(self) -> None:
        self.invocation = resolved_invocation(self.adapter, self.target_afl)
        json_dump(self.workspace / "target" / "invocation.json", self.invocation)
        command = " ".join(self.invocation["argv"])
        (self.workspace / "target" / "command.txt").write_text(command + "\n", encoding="utf-8")

    def _invoke(self, binary: Path, sample: bytes, timeout: int | None = None) -> dict[str, Any]:
        assert self.invocation is not None
        input_mode = self.invocation["input_mode"]
        adapter_argv = list(self.invocation["adapter_argv"])
        timeout = timeout or int(self.invocation.get("timeout_seconds", 5))
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(sample)
            sample_path = Path(tmp.name)
        try:
            if input_mode == "stdin":
                cmd = [str(binary)] + [a for a in adapter_argv if a != "@@"]
                proc = subprocess.run(cmd, input=sample, capture_output=True, timeout=timeout, check=False)
            else:
                cmd = [str(binary)] + [str(a) if a != "@@" else str(sample_path) for a in adapter_argv]
                proc = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
            return {
                "ran": True,
                "exit_code": proc.returncode,
                "timed_out": False,
                "stderr": (proc.stderr or b"").decode("utf-8", "replace")[-1000:],
            }
        except subprocess.TimeoutExpired:
            return {"ran": True, "exit_code": 124, "timed_out": True, "stderr": ""}
        except OSError as exc:
            return {"ran": False, "exit_code": None, "timed_out": False, "error": str(exc)}
        finally:
            try:
                sample_path.unlink()
            except OSError:
                pass

    def validate_input_contract(self) -> dict[str, Any]:
        """Validate the adapter input contract against both pair binaries.

        Ensures a provided sample runs, a missing sample is not silently
        ignored for file mode, and both binaries behave consistently.  This is
        per-target: ``@@`` is never assumed globally.
        """

        if not self.invocation:
            return {"valid": False, "reason": "no invocation"}
        sample_a = bootstrap_bytes(self.formats[0] if self.formats else "custom")
        sample_b = sample_a + b"\x00HGB_DISTINGUISHABLE"
        per_binary: dict[str, Any] = {}
        for label, binary in (("afl", self.target_afl), ("cmp", self.target_cmp)):
            res_a = self._invoke(binary, sample_a)
            res_b = self._invoke(binary, sample_b)
            per_binary[label] = {"sample_a": res_a, "sample_b": res_b}
        # Missing-input check for file mode: invoking with a nonexistent path
        # must not be silently ignored (the target should error or no-op, but
        # the invocation itself must reach the target).
        missing_ok = True
        if self.invocation["input_mode"] == "file":
            missing_path = self.workspace / "seeds" / "__HGB_MISSING_CONTRACT__"
            missing_path.parent.mkdir(parents=True, exist_ok=True)
            if missing_path.exists():
                missing_path.unlink()
            cmd = [str(self.target_afl)] + [str(a) if a != "@@" else str(missing_path) for a in self.invocation["adapter_argv"]]
            try:
                proc = subprocess.run(cmd, capture_output=True, timeout=int(self.invocation.get("timeout_seconds", 5)), check=False)
                missing_ok = proc.returncode is not None
            except Exception:
                missing_ok = False
        contract = {
            "input_mode": self.invocation["input_mode"],
            "argv": list(self.invocation["argv"]),
            "uses_at_at": self.invocation["uses_at_at"],
            "per_binary": per_binary,
            "missing_input_handled": missing_ok,
            "consistent": per_binary["afl"]["sample_a"].get("exit_code") == per_binary["cmp"]["sample_a"].get("exit_code"),
            "valid": bool(
                per_binary["afl"]["sample_a"].get("ran")
                and per_binary["cmp"]["sample_a"].get("ran")
                and missing_ok
            ),
        }
        json_dump(self.workspace / "target" / "input_contract.json", contract)
        self.input_contract = contract
        return contract

    def _smoke_seed_bytes(self) -> bytes:
        """Prefer a real corpus file for the pair smoke.

        The crude bootstrap seed (the format name as bytes) crashes some
        targets on garbage input (e.g. libxslt xpath SEGVs on ``XPath\n``),
        while FuzzBench smokes builds against real corpus entries. Fall back
        through the built seed-corpus zips, the package seed dirs, and finally
        the bootstrap bytes.
        """
        import zipfile as _zipfile
        for archive in sorted(self.workspace.glob("target/build_afl/*_seed_corpus.zip")):
            try:
                with _zipfile.ZipFile(archive) as zf:
                    names = sorted(n for n in zf.namelist() if not n.endswith("/"))
                    for name in names:
                        data = zf.read(name)
                        if data:
                            return data
            except Exception:  # noqa: BLE001
                pass
        for seeds_dir in (self.target_package / "seeds", self.target_package / "fuzzbench_benchmark" / "seeds"):
            if seeds_dir.is_dir():
                for path in sorted(p for p in seeds_dir.rglob("*") if p.is_file() and p.stat().st_size < 1_048_576):
                    try:
                        data = path.read_bytes()
                    except OSError:
                        continue
                    if data:
                        return data
        # Fall back to real corpus-like files in the materialized sources
        # (tests/corpus/seed trees) so targets that crash on garbage inputs
        # (e.g. libxslt xpath SEGVs on raw format-name bytes) smoke against a
        # plausible input.
        src_input = self.target_package / "source_input"
        if src_input.is_dir():
            candidates = sorted(
                p
                for p in src_input.rglob("*")
                if p.is_file()
                and p.stat().st_size < 1_048_576
                and any(part in ("tests", "test", "corpus", "corpora", "seed", "seeds", "testdata") for part in p.parts)
            )
            for suffix in (".xml", ".html", ".txt", ".json", ""):
                for path in candidates:
                    if suffix and not path.name.endswith(suffix):
                        continue
                    try:
                        data = path.read_bytes()
                    except OSError:
                        continue
                    if data:
                        return data
        return bootstrap_bytes(self.formats[0] if self.formats else "custom")

    def _install_harness_context_files(self) -> None:
        """Install context files some harnesses load relative to the binary.

        libxslt's xpath fuzzer reads a fixed ``xpath.xml`` document from the
        binary's directory (the fuzzed input is the XPath expression itself);
        without it the harness crashes on any probe input.
        """
        if self.target == "libxslt_xpath":
            candidates = (
                self.target_package / "source_input" / "libxslt" / "tests" / "fuzz" / "xpath.xml",
                self.target_package / "generator_input" / "source_input" / "libxslt" / "tests" / "fuzz" / "xpath.xml",
            )
            for candidate in candidates:
                if candidate.is_file():
                    shutil.copy2(candidate, self.workspace / "target" / "xpath.xml")
                    break

    def smoke_pair(self) -> dict[str, Any]:
        smoke_dir = self.workspace / "seeds" / "bootstrap"
        smoke_dir.mkdir(parents=True, exist_ok=True)
        smoke_input = smoke_dir / f"{self.program_id}_bootstrap_seed"
        if not smoke_input.exists():
            smoke_input.write_bytes(self._smoke_seed_bytes())
        empty_input = smoke_dir / f"{self.program_id}_empty_seed"
        if not empty_input.exists():
            empty_input.write_bytes(b"")
        results: dict[str, Any] = {}
        for label, binary in (("afl", self.target_afl), ("cmp", self.target_cmp)):
            inv = dict(self.invocation) if self.invocation else {}
            inv["argv"] = [str(binary), *(self.invocation or {}).get("adapter_argv", [])]
            per: dict[str, Any] = {}
            for name, sample in (("empty", empty_input), ("seed", smoke_input)):
                cmd = argv_for_input(inv, sample)
                try:
                    proc = subprocess.run(
                        cmd,
                        input=sample.read_bytes() if inv.get("input_mode") == "stdin" else None,
                        text=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                        timeout=int(inv.get("timeout_seconds", 5)),
                        check=False,
                    )
                    per[name] = {
                        "exit_code": proc.returncode,
                        "stderr_tail": (proc.stderr or b"").decode("utf-8", "replace")[-500:],
                    }
                except Exception as exc:  # noqa: BLE001
                    per[name] = {"exit_code": None, "error": str(exc)}
            results[label] = per
        return results

    def build_target_pair(self) -> None:
        if is_gamma_profile(self.profile):
            self.build_target_triple_gamma()
            return
        located = self.locate_pair()
        build_results: dict[str, Any]
        commands = build_command_pair(self.adapter, self.artifact_dir, self.target_package, self.workspace)
        if located:
            source_dir, src_afl, src_cmp = located
            self.copy_pair(src_afl, src_cmp)
            self.build_source = "prebuilt_override"
            build_results = {
                "afl": {"prebuilt": str(src_afl)},
                "cmp": {"prebuilt": str(src_cmp)},
                "source_dir": str(source_dir),
            }
        else:
            build_results, commands = self.auto_build_pair()
            self.build_source = "auto_built"
            source_dir = self.workspace / "target"
        self._install_harness_context_files()
        self.write_invocation()
        contract = self.validate_input_contract()
        smoke = self.smoke_pair()
        # Smoke failure (process cannot run, or crashes on empty/seed) fails
        # the stage as infra_failure, never a soft skip.
        for label in ("afl", "cmp"):
            for name in ("empty", "seed"):
                res = smoke.get(label, {}).get(name, {})
                if not res.get("ran", True) and res.get("error"):
                    raise PipelineError("infra_failure", f"G2Fuzz pair smoke could not run {label}/{name}: {res.get('error')}", 127)
                if _is_crash_exit(res.get("exit_code"), res.get("stderr_tail", "")):
                    raise PipelineError(
                        "infra_failure",
                        f"G2Fuzz pair smoke crashed for {label}/{name} (exit {res.get('exit_code')})",
                        127,
                    )
        hashes = {"afl": sha256_file(self.target_afl), "cmp": sha256_file(self.target_cmp)}
        record = {
            "afl_binary": str(self.target_afl),
            "cmp_binary": str(self.target_cmp),
            "afl_sha256": hashes["afl"],
            "cmp_sha256": hashes["cmp"],
            "build_mode": BUILD_MODE,
            "build_source": self.build_source,
            "build_commands": commands,
            "build_results": build_results,
            "input_contract": contract,
            "smoke": smoke,
            "source_dir": str(source_dir),
            "status": "completed",
        }
        json_dump(self.workspace / "target" / "build.json", record)
        stage_extra = {k: v for k, v in record.items() if k != "status"}
        self.stages["target_pair_built"] = stage_record("complete", "none", **stage_extra)

    # -- gamma: exact FuzzBench Docker triple build ------------------------

    def _resolve_runner(self):
        if self.runner is not None:
            return self.runner
        if hgb_fuzzbench_builder is not None:
            return hgb_fuzzbench_builder._run
        raise PipelineError("infra_missing", "hgb_fuzzbench_builder is not available for Docker triple build", 127)

    def _resolve_benchmark_dir(self) -> Path:
        bench_dir_env = os.environ.get("HGB_FUZZBENCH_BENCHMARK_DIR")
        if bench_dir_env and Path(bench_dir_env).is_dir():
            return Path(bench_dir_env)
        manifest = self.target_manifest()
        bench_dir = manifest.get("benchmark_dir", "")
        if bench_dir and Path(bench_dir).is_dir():
            return Path(bench_dir)
        pkg_bench = self.target_package / "fuzzbench_benchmark"
        if pkg_bench.is_dir():
            return pkg_bench
        raise PipelineError("infra_missing", "G2Fuzz gamma: FuzzBench benchmark directory not found for Docker triple build", 127)

    def build_target_triple_gamma(self) -> None:
        """Build .afl/.cmp/.cov from the exact FuzzBench Docker environment.

        Refuses prebuilt ``G2FUZZ_TARGET_DIR`` and direct-host ``build.sh`` in
        the strict triple-build profiles (reproduction-delta and
        reproduction-gamma).  Uses ``docker build`` on the benchmark Dockerfile
        with variant-specific build args (CmpLog for .cmp, coverage for .cov).
        Runs the contract probe after the triple is built.  Delta additionally
        writes ``target/triple_provenance.json``, containerized execution
        wrappers, and a consumption smoke (plan sections 2/3).
        """

        label = self.profile if is_delta_profile(self.profile) else "reproduction-gamma"
        # Refuse prebuilt override in the strict triple-build profiles.
        if os.environ.get("G2FUZZ_TARGET_DIR"):
            raise PipelineError(
                "infra_missing",
                f"G2Fuzz {label} refuses prebuilt G2FUZZ_TARGET_DIR; "
                "the .afl/.cmp/.cov triple must be built from the FuzzBench Docker environment",
                127,
            )
        if build_g2fuzz_target_triple is None or g2fuzz_target_triple_build_commands is None:
            raise PipelineError("infra_missing", f"G2Fuzz {label}: hgb_fuzzbench_builder triple functions are not available", 127)

        benchmark_dir = self._resolve_benchmark_dir()
        dockerfile = benchmark_dir / "Dockerfile"
        if not dockerfile.is_file():
            raise PipelineError("infra_missing", f"G2Fuzz {label}: benchmark Dockerfile not found: {dockerfile}", 127)

        fuzz_target = self.target_manifest().get("fuzz_target", self.target)
        runner = self._resolve_runner()
        # Deterministic image tag base.
        import hashlib as _hl
        tag_digest = _hl.sha256(f"{self.program_id}|{self.target}".encode()).hexdigest()[:8]
        image_tag_base = f"hgb-g2fuzz-{tag_digest}"

        self.target_pair_dir.mkdir(parents=True, exist_ok=True)
        triple_work = self.target_pair_dir

        # Record the build commands for auditability.
        commands = g2fuzz_target_triple_build_commands(
            benchmark_dir=benchmark_dir,
            image_tag_base=image_tag_base,
            fuzz_target=fuzz_target,
            program_id=self.program_id,
        )
        json_dump(triple_work / "build_commands.json", commands)

        # Build all three variants.
        results = build_g2fuzz_target_triple(
            benchmark_dir=benchmark_dir,
            image_tag_base=image_tag_base,
            fuzz_target=fuzz_target,
            work_dir=triple_work,
            runner=runner,
            timeout_seconds=int(os.environ.get("G2FUZZ_BUILD_TIMEOUT_SECONDS", "3600") or "3600"),
        )
        self.triple_build_results = results

        # Verify and copy binaries to canonical paths.
        for variant, dest_name in (("afl", "target.afl"), ("cmp", "target.cmp"), ("cov", "target.cov")):
            rec = results.get(variant, {})
            binary_path = rec.get("binary_path", "")
            if not binary_path or not Path(binary_path).is_file():
                raise PipelineError(
                    "infra_failure",
                    f"G2Fuzz {label}: {variant} build failed (exit {rec.get('build_exit_code', '?')}); "
                    f"no {fuzz_target} produced",
                    127,
                )
            dest = self.workspace / "target" / dest_name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(binary_path, dest)
            if not executable(dest):
                raise PipelineError("infra_failure", f"G2Fuzz {label}: {variant} built binary is not executable: {dest}", 127)
            # Also place in target_pair/ directory.
            pair_dest = self.target_pair_dir / dest_name
            shutil.copy2(binary_path, pair_dest)

        # Verify all three.
        verify = verify_g2fuzz_target_triple(self.target_afl, self.target_cmp, self.target_cov)
        if not verify["ok"]:
            raise PipelineError("infra_failure", f"G2Fuzz {label}: target triple verification failed: {verify}", 127)

        self.build_source = "fuzzbench_docker_triple"
        self.write_invocation()

        # Delta: write triple provenance and containerized execution wrappers
        # (plan section 2.4/2.5).
        if is_delta_profile(self.profile):
            self.write_triple_provenance(results, commands)
            self.write_execution_wrappers(results)

        # Run contract probe (gamma/delta).
        self.run_contract_probe()

        # Delta: run a consumption smoke against the declared adapter contract
        # (plan section 3) and persist target_contract/consumption_smoke.json.
        if is_delta_profile(self.profile):
            self.run_consumption_smoke()
            # Delta/epsilon: write the per-target build artifacts (image tags,
            # binary paths, build logs), the runtime environment record, and a
            # preliminary instrumentation check (plan G2-2/G2-3). The cov part
            # of the instrumentation check is finalized after coverage replay.
            self.write_build_artifacts(results, commands)
            self.write_runtime_environment(results)
            self.write_instrumentation_check()

        # Smoke pair on .afl and .cmp.
        smoke = self.smoke_pair()
        for label_ in ("afl", "cmp"):
            for name in ("empty", "seed"):
                res = smoke.get(label_, {}).get(name, {})
                if not res.get("ran", True) and res.get("error"):
                    raise PipelineError("infra_failure", f"G2Fuzz pair smoke could not run {label_}/{name}: {res.get('error')}", 127)
                if _is_crash_exit(res.get("exit_code"), res.get("stderr_tail", "")):
                    raise PipelineError(
                        "infra_failure",
                        f"G2Fuzz pair smoke crashed for {label_}/{name} (exit {res.get('exit_code')})",
                        127,
                    )

        hashes = {
            "afl": sha256_file(self.target_afl),
            "cmp": sha256_file(self.target_cmp),
            "cov": sha256_file(self.target_cov),
        }
        record = {
            "afl_binary": str(self.target_afl),
            "cmp_binary": str(self.target_cmp),
            "cov_binary": str(self.target_cov),
            "afl_sha256": hashes["afl"],
            "cmp_sha256": hashes["cmp"],
            "cov_sha256": hashes["cov"],
            "build_mode": GAMMA_BUILD_MODE,
            "build_source": self.build_source,
            "build_commands": commands,
            "build_results": results,
            "input_contract": self.contract_result,
            "smoke": smoke,
            "source_dir": str(self.target_pair_dir),
            "status": "completed",
        }
        json_dump(self.workspace / "target" / "build.json", record)
        json_dump(self.target_pair_dir / "build.json", record)
        # Build logs are already in target_pair/ (triple_work == target_pair_dir).
        stage_extra = {k: v for k, v in record.items() if k != "status"}
        self.stages["target_pair_built"] = stage_record("complete", "none", **stage_extra)

    def run_contract_probe(self) -> dict[str, Any]:
        """Run the per-target input-contract probe against .afl and .cmp.

        Persists ``contract.json`` in the target_pair directory and fails if the
        declared adapter contract does not execute the target.
        """

        if _probe_contract is None:
            raise PipelineError("infra_missing", "G2Fuzz gamma: g2fuzz_contract module is not available", 127)
        contract_path = self.target_pair_dir / "contract.json"
        try:
            self.contract_result = _probe_contract(
                self.target_afl,
                self.adapter,
                formats=self.formats,
                output_path=contract_path,
                timeout=int(os.environ.get("G2FUZZ_CONTRACT_TIMEOUT_SECONDS", "10") or "10"),
            )
        except _ContractError as exc:
            self.contract_result = {"valid": False, "reason": exc.reason}
            json_dump(contract_path, self.contract_result)
            raise PipelineError("infra_failure", f"G2Fuzz gamma: contract probe failed: {exc.reason}", 127)
        return self.contract_result

    # -- delta: triple provenance / wrappers / consumption smoke ------------

    def write_triple_provenance(self, results: dict[str, Any], commands: dict[str, Any]) -> None:
        """Write ``target/triple_provenance.json`` (plan section 2.5).

        Records that all three variants were built from the exact FuzzBench
        Docker environment, with per-variant image tag, image digest, binary
        sha256, and a verified flag set only when the binary exists and is
        executable.
        """

        variants: dict[str, Any] = {}
        for variant, dest_name in (("afl", "target.afl"), ("cmp", "target.cmp"), ("cov", "target.cov")):
            rec = results.get(variant, {}) if isinstance(results, dict) else {}
            cmd = commands.get(variant, {}) if isinstance(commands, dict) else {}
            binary = self.workspace / "target" / dest_name
            verified = binary.is_file() and executable(binary)
            variants[variant] = {
                "image_tag": str(cmd.get("image_tag", rec.get("image_tag", ""))),
                "image_digest": str(rec.get("image_digest", "")),
                "binary_sha256": sha256_file(binary) if verified else "",
                "verified": verified,
            }
        provenance = {
            "uses_fuzzbench_docker_environment": True,
            "variants": variants,
        }
        json_dump(self.workspace / "target" / "triple_provenance.json", provenance)
        json_dump(self.target_pair_dir / "triple_provenance.json", provenance)
        self.triple_provenance = provenance

    def write_execution_wrappers(self, results: dict[str, Any]) -> None:
        """Write containerized execution wrappers for each variant (plan 2.4).

        ``run_afl.sh``/``run_cmp.sh``/``run_cov.sh`` run the target inside the
        corresponding built image with mounted input/corpus paths.  The campaign
        may use exported binaries directly only when runtime verification passes;
        otherwise it must use these wrappers.
        """

        target_dir = self.workspace / "target"
        for variant, dest_name in (("afl", "target.afl"), ("cmp", "target.cmp"), ("cov", "target.cov")):
            rec = results.get(variant, {}) if isinstance(results, dict) else {}
            image_tag = str(rec.get("image_tag", ""))
            wrapper = target_dir / f"run_{variant}.sh"
            argv_tail = " ".join(str(a) for a in self.adapter.get("argv", ["@@"]))
            input_mode = str(self.adapter.get("input_mode", "file"))
            if input_mode == "stdin":
                # Wrapper reads input from the first positional arg and pipes it.
                script = (
                    "#!/usr/bin/env bash\n"
                    f"# Containerized execution wrapper for the {variant} target variant.\n"
                    f"set -euo pipefail\n"
                    f'IMAGE="${{HGB_G2FUZZ_{variant.upper()}_IMAGE:-{image_tag}}}"\n'
                    f'INPUT="${{1:-}}"\n'
                    f'docker run --rm -i "$IMAGE" /out/{self.target_manifest().get("fuzz_target", self.target)} {argv_tail} < "$INPUT"\n'
                )
            else:
                script = (
                    "#!/usr/bin/env bash\n"
                    f"# Containerized execution wrapper for the {variant} target variant.\n"
                    f"set -euo pipefail\n"
                    f'IMAGE="${{HGB_G2FUZZ_{variant.upper()}_IMAGE:-{image_tag}}}"\n'
                    f'INPUT="${{1:-}}"\n'
                    f'docker run --rm -v "$INPUT:/tmp/hgb_input:ro" "$IMAGE" /out/{self.target_manifest().get("fuzz_target", self.target)} {argv_tail.replace("@@", "/tmp/hgb_input")}\n'
                )
            wrapper.write_text(script, encoding="utf-8")
            wrapper.chmod(0o755)

    def run_consumption_smoke(self) -> dict[str, Any]:
        """Run a consumption smoke against the declared adapter (plan section 3).

        Verifies the target actually consumes inputs under its adapter contract:
        a valid sample must execute successfully or with an accepted libFuzzer
        no-crash code, and for file mode replacing ``@@`` with a sample path
        must pass.  Persists ``target_contract/consumption_smoke.json`` and
        fails the target contract when ``consumed_input`` is False.
        """

        assert self.invocation is not None
        contract_dir = self.workspace / "target_contract"
        contract_dir.mkdir(parents=True, exist_ok=True)
        fmt = self.formats[0] if self.formats else "custom"
        sample = bootstrap_bytes(fmt)
        sample_path = contract_dir / "valid_sample.bin"
        sample_path.write_bytes(sample)
        input_mode = self.invocation["input_mode"]
        adapter_argv = list(self.invocation["adapter_argv"])
        timeout = int(self.invocation.get("timeout_seconds", 5))
        if input_mode == "stdin":
            cmd = [str(self.target_afl)] + [a for a in adapter_argv if a != "@@"]
            proc = subprocess.run(cmd, input=sample, capture_output=True, timeout=timeout, check=False)
        else:
            cmd = [str(self.target_afl)] + [str(a) if a != "@@" else str(sample_path) for a in adapter_argv]
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
        accepted = proc.returncode in (0, 1, 77) or proc.returncode is None
        crash = _is_crash_exit(proc.returncode, (proc.stderr or b"").decode("utf-8", "replace"))
        consumed = bool(proc.returncode is not None) and not crash
        result = {
            "command": cmd,
            "exit_code": proc.returncode,
            "accepted_no_crash_code": accepted,
            "stderr_excerpt": (proc.stderr or b"").decode("utf-8", "replace")[-800:],
            "input_mode": input_mode,
            "valid_sample": str(sample_path),
            "consumed_input": consumed,
        }
        self.consumption_smoke = result
        json_dump(contract_dir / "consumption_smoke.json", result)
        if not consumed:
            raise PipelineError(
                "infra_failure",
                f"G2Fuzz delta: target contract failed; {self.target} did not consume input under {input_mode} mode (exit {proc.returncode})",
                127,
            )
        return result

    def write_build_artifacts(self, results: dict[str, Any], commands: dict[str, Any]) -> None:
        """Write the per-target build-artifact text files (plan G2-2).

        Records one file per field so the triple build provenance is
        machine-readable without parsing ``build.json``:
        ``target_pair/<variant>_image_tag.txt``,
        ``target_pair/<variant>_binary_path.txt``, and
        ``target_pair/build_<variant>.log`` (alongside the canonical
        ``build.<variant>.log`` produced by the builder).
        """

        pair = self.target_pair_dir
        pair.mkdir(parents=True, exist_ok=True)
        for variant, dest_name in (("afl", "target.afl"), ("cmp", "target.cmp"), ("cov", "target.cov")):
            rec = results.get(variant, {}) if isinstance(results, dict) else {}
            cmd = commands.get(variant, {}) if isinstance(commands, dict) else {}
            (pair / f"{variant}_image_tag.txt").write_text(
                str(cmd.get("image_tag", rec.get("image_tag", ""))) + "\n", encoding="utf-8"
            )
            (pair / f"{variant}_binary_path.txt").write_text(
                str(rec.get("binary_path", "")) + "\n", encoding="utf-8"
            )
            log_src = Path(rec.get("log", pair / f"build.{variant}.log"))
            if log_src.is_file():
                shutil.copy2(log_src, pair / f"build_{variant}.log")

    def write_runtime_environment(self, results: dict[str, Any]) -> dict[str, Any]:
        """Record the runtime execution strategy (plan G2-3).

        Extracted FuzzBench binaries are not executed inside the G2Fuzz
        container unless runtime dependencies are proven available.  This
        records the chosen strategy (``extracted_out_closure`` when the
        exported ``/out`` runtime closure is used with ``ldd`` verification,
        or ``containerized_wrapper`` when the execution wrappers run the
        target inside the built image) and the per-variant image tags so the
        reproduction is traceable.
        """

        pair = self.target_pair_dir
        pair.mkdir(parents=True, exist_ok=True)
        strategy = os.environ.get("G2FUZZ_RUNTIME_STRATEGY", "extracted_out_closure")
        variants: dict[str, Any] = {}
        for variant, dest_name in (("afl", "target.afl"), ("cmp", "target.cmp"), ("cov", "target.cov")):
            rec = results.get(variant, {}) if isinstance(results, dict) else {}
            binary = self.workspace / "target" / dest_name
            ldd_ok = True
            ldd_output = ""
            if binary.is_file() and strategy == "extracted_out_closure":
                try:
                    proc = subprocess.run(
                        ["ldd", str(binary)],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    ldd_output = proc.stdout
                    ldd_ok = "not found" not in (proc.stdout + proc.stderr).lower() and proc.returncode == 0
                except (OSError, subprocess.TimeoutExpired):
                    ldd_ok = False
                    ldd_output = ""
            variants[variant] = {
                "image_tag": str(rec.get("image_tag", "")),
                "binary_path": str(binary),
                "ldd_verified": ldd_ok,
                "ldd_output": ldd_output[-2000:],
            }
        env_record = {
            "strategy": strategy,
            "ld_library_path": os.environ.get("LD_LIBRARY_PATH", ""),
            "uses_fuzzbench_docker_environment": True,
            "variants": variants,
        }
        json_dump(pair / "runtime_environment.json", env_record)
        json_dump(self.workspace / "target" / "runtime_environment.json", env_record)
        return env_record

    def write_instrumentation_check(self, *, cov_check: dict[str, Any] | None = None) -> dict[str, Any]:
        """Write ``instrumentation_check.json`` (plan G2-2).

        Proves the AFL/default binary executes a seed (consumption smoke),
        the CmpLog binary exists and AFL++ accepts it with ``-c`` (campaign
        ran with ``-c <target.cmp>`` and ``execs_done > 0``), and the coverage
        binary produces ``.profraw`` plus non-empty ``llvm-cov export`` JSON
        when replaying at least one seed (coverage replay).  The cov checks
        are merged in by ``collect_coverage`` after the replay succeeds.
        """

        pair = self.target_pair_dir
        pair.mkdir(parents=True, exist_ok=True)
        path = pair / "instrumentation_check.json"
        existing = read_json(path) if path.is_file() else {}
        afl_seed_executed = bool(self.consumption_smoke.get("consumed_input"))
        cmplog_binary_present = self.target_cmp.is_file() and executable(self.target_cmp)
        cmplog_accepted_by_afl = bool(
            int(self.metrics.get("execs_done") or 0) > 0
            and self.target_cmp.is_file()
        )
        check = {
            "afl_seed_executed": afl_seed_executed,
            "cmplog_binary_present": cmplog_binary_present,
            "cmplog_accepted_by_afl": cmplog_accepted_by_afl,
            "cov_binary_present": self.target_cov.is_file() and executable(self.target_cov),
            "cov_produces_profraw": existing.get("cov_produces_profraw", False),
            "cov_export_nonempty": existing.get("cov_export_nonempty", False),
            "cov_inputs_replayed": existing.get("cov_inputs_replayed", 0),
            "all_passed": bool(
                afl_seed_executed
                and cmplog_binary_present
                and cmplog_accepted_by_afl
                and existing.get("cov_produces_profraw", False)
                and existing.get("cov_export_nonempty", False)
            ),
        }
        if cov_check is not None:
            check["cov_produces_profraw"] = bool(cov_check.get("produces_profraw", False))
            check["cov_export_nonempty"] = bool(cov_check.get("export_nonempty", False))
            check["cov_inputs_replayed"] = int(cov_check.get("inputs_replayed", 0) or 0)
            check["all_passed"] = bool(
                check["afl_seed_executed"]
                and check["cmplog_binary_present"]
                and check["cmplog_accepted_by_afl"]
                and check["cov_produces_profraw"]
                and check["cov_export_nonempty"]
            )
        json_dump(path, check)
        json_dump(self.workspace / "target" / "instrumentation_check.json", check)
        return check

    # -- seed corpus / generation ------------------------------------------

    def copy_common_corpus(self) -> None:
        if not bool(self.adapter.get("common_corpus")):
            return
        out_dir = self.workspace / "seeds" / "common_initial"
        roots = (
            self.target_package / "corpus",
            self.target_package / "seeds",
            self.target_package / "seed_corpus",
            self.target_package / "fuzzbench_benchmark" / "seeds",
        )
        copied = 0
        limit = int(os.environ.get("G2FUZZ_MAX_PRESEEDED_CORPUS_FILES", "32") or "32")
        for root in roots:
            if not root.exists():
                continue
            for path in sorted(p for p in root.rglob("*") if p.is_file()):
                if copied >= limit:
                    return
                if path.stat().st_size > 1024 * 1024:
                    continue
                dest = out_dir / f"common_{copied:04d}_{path.name}"
                shutil.copy2(path, dest)
                copied += 1

    def write_bootstrap_seed(self) -> None:
        out = self.workspace / "seeds" / "bootstrap" / f"{self.program_id}_bootstrap_seed"
        if not out.exists():
            out.write_bytes(bootstrap_bytes(self.formats[0] if self.formats else "custom"))

    def program_gen_command(self, output_dir: Path) -> tuple[list[str], Path]:
        program_gen = Path(os.environ.get("G2FUZZ_PROGRAM_GEN", "")) if os.environ.get("G2FUZZ_PROGRAM_GEN") else self.artifact_dir / "program_gen.py"
        if not program_gen.exists():
            raise PipelineError("infra_missing", f"missing G2Fuzz program_gen.py: {program_gen}", 127)
        if program_gen.suffix == ".py":
            python = os.environ.get("HGB_PYTHON") or sys.executable
            cmd = [python, str(program_gen), "--output", str(output_dir), "--program", self.program_id]
        else:
            cmd = [str(program_gen), "--output", str(output_dir), "--program", self.program_id]
        return cmd, program_gen

    def run_program_gen(self) -> None:
        self.copy_common_corpus()
        self.write_bootstrap_seed()
        output_dir = self.workspace / "g2fuzz_upstream_output"
        runtime = Path(os.environ.get("G2FUZZ_RUNTIME_DIR", tempfile.mkdtemp(prefix="hgb-g2fuzz-")))
        runtime.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.workspace / "config" / "program_to_format.json", runtime / "program_to_format.json")
        shutil.copy2(self.workspace / "config" / "model_setting.json", runtime / "model_setting.json")
        cmd, program_gen = self.program_gen_command(output_dir)
        key = os.environ.get("OPENAI_API_KEY") or os.environ.get("API_KEY")
        if not key and not os.environ.get("G2FUZZ_PROGRAM_GEN"):
            raise PipelineError("missing_api_key", "OPENAI_API_KEY is not set", 2)
        key_file = runtime / "openai_key.txt"
        key_file.write_text((key or "hgb-offline-placeholder") + "\n", encoding="utf-8")
        key_file.chmod(0o600)
        (self.workspace / "generators" / "command.txt").write_text(" ".join(cmd) + "\n", encoding="utf-8")
        env = os.environ.copy()
        env["G2FUZZ_TRY_NUM"] = try_num_for_profile(self.profile, env)
        if self.profile == "compat-smoke":
            env["G2FUZZ_MAX_FORMATS"] = str(len(self.formats))
        timeout = int(env.get("G2FUZZ_PER_FORMAT_TIMEOUT_SECONDS") or env.get("HGB_GENERATION_TIMEOUT_SECONDS") or "10800")
        code, _timed_out = run_subprocess(cmd, self.workspace / "logs" / "program_gen.log", timeout, env=env, cwd=runtime)
        try:
            key_file.unlink()
        except OSError:
            pass
        if code == 124:
            self.collect_program_gen_outputs(output_dir)
            raise PipelineError("failed", "program_gen timed out; partial inputs are not evaluated", 124)
        if code != 0:
            self.collect_program_gen_outputs(output_dir)
            raise PipelineError("failed", f"program_gen exited {code}", code)
        self.collect_program_gen_outputs(output_dir)
        if self.generated_input_count <= 0:
            raise PipelineError("failed", "G2Fuzz program_gen completed without generated input files", 65)
        # Delta invariant (plan section 4.4): zero Python generators is a
        # generation failure, not a soft skip.
        if is_delta_profile(self.profile) and self.generated_generator_count <= 0:
            raise PipelineError("failed", "G2Fuzz program_gen completed without generated Python generators", 65)
        self.stages["input_generators_created"] = stage_record(
            "complete",
            "none",
            program_gen=str(program_gen),
            generator_count=self.generated_generator_count,
            generated_input_count=self.generated_input_count,
        )

    def collect_program_gen_outputs(self, output_dir: Path) -> None:
        source_dir = self.workspace / "generators" / "source"
        seed_dir = self.workspace / "seeds" / "g2_generated"
        generator_roots = [output_dir / "default" / "generators", output_dir / "generators"]
        seed_roots = [output_dir / "default" / "gen_seeds", output_dir / "gen_seeds"]
        copied_generators = 0
        for root in generator_roots:
            if not root.exists():
                continue
            for path in sorted(p for p in root.rglob("*") if p.is_file() and p.suffix == ".py"):
                dest = unique_dest(source_dir, path.name)
                shutil.copy2(path, dest)
                copied_generators += 1
        copied_seeds = 0
        for root in seed_roots:
            if not root.exists():
                continue
            for path in sorted(p for p in root.rglob("*") if p.is_file()):
                if not is_generated_input_candidate(path):
                    continue
                dest = unique_dest(seed_dir, path.name)
                shutil.copy2(path, dest)
                copied_seeds += 1
        self.generated_generator_count = copied_generators
        self.generated_input_count = copied_seeds
        # Record g2_programs ancillary logs (plan section 4.3): llm_trace.jsonl,
        # dependency_install.log, and program_gen.log when produced upstream.
        g2_programs_logs = self.workspace / "g2_programs"
        g2_programs_logs.mkdir(parents=True, exist_ok=True)
        for log_name in ("llm_trace.jsonl", "dependency_install.log", "program_gen.log"):
            for root in (output_dir, output_dir / "default"):
                candidate = root / log_name
                if candidate.is_file():
                    shutil.copy2(candidate, unique_dest(g2_programs_logs, log_name))
                    break
        json_dump(
            self.workspace / "generators" / "source" / "manifest.json",
            {
                "program_id": self.program_id,
                "formats": self.formats,
                "generator_count": copied_generators,
                "generated_input_count": copied_seeds,
                "upstream_output_dir": str(output_dir),
                "generator_sha256": [sha256_file(p) for p in sorted(source_dir.glob("*.py"))] if source_dir.exists() else [],
            },
        )

    def validate_generated_inputs(self) -> None:
        generated = sorted((self.workspace / "seeds" / "g2_generated").rglob("*"))
        files = [path for path in generated if path.is_file() and is_generated_input_candidate(path)]
        non_empty = [path for path in files if path.stat().st_size > 0]
        max_inputs = int(os.environ.get("G2FUZZ_VALIDATE_MAX_INPUTS", "32") or "32")
        results: list[dict[str, Any]] = []
        valid_count = 0
        invalid_count = 0
        for path in non_empty[: max(1, max_inputs)]:
            assert self.invocation is not None
            res = self._invoke(self.target_afl, path.read_bytes())
            crash = _is_crash_exit(res.get("exit_code"), res.get("stderr", ""))
            ok = bool(res.get("ran") and res.get("exit_code") in (0, 1) and not res.get("timed_out") and not crash)
            if ok:
                valid_count += 1
            else:
                invalid_count += 1
            results.append({"path": str(path), "exit_code": res.get("exit_code"), "timeout": bool(res.get("timed_out")), "crash": crash, "valid": ok})
        validation = {
            "file_count": len(files),
            "non_empty_count": len(non_empty),
            "validated_count": len(results),
            "valid_count": valid_count,
            "invalid_count": invalid_count,
            "per_input": results,
        }
        json_dump(self.workspace / "seeds" / "validation.json", validation)
        self.valid_generated_input_count = valid_count
        if valid_count == 0:
            raise PipelineError("quality_failure", "G2Fuzz generated input validation: all generated inputs failed target execution", 65)
        self.stages["generated_inputs_validated"] = stage_record("complete", "none", **validation)

    def write_seed_provenance(self) -> None:
        provenance = self.workspace / "seeds" / "provenance.jsonl"
        if provenance.exists():
            provenance.unlink()
        seen: dict[str, str] = {}
        source_classes = ("common_initial", "bootstrap", "g2_generated", "afl_queue")
        if is_gamma_profile(self.profile):
            source_classes = ("common_initial", "bootstrap", "g2_generated", "merged_initial", "afl_queue")
        for source_class in source_classes:
            base = self.workspace / "seeds" / source_class
            count = 0
            if base.exists():
                for path in sorted(p for p in base.rglob("*") if p.is_file()):
                    digest = sha256_file(path)
                    deduplicated = digest in seen
                    if not deduplicated:
                        seen[digest] = str(path)
                    record = {
                        "sha256": digest,
                        "size": path.stat().st_size,
                        "source_class": source_class,
                        "original_path": str(path),
                        "deduplicated": deduplicated,
                        "admitted_to_initial_afl_input": source_class in {"common_initial", "bootstrap", "g2_generated", "merged_initial"} and not deduplicated,
                    }
                    if source_class == "g2_generated":
                        record["generator_manifest"] = str(self.workspace / "generators" / "source" / "manifest.json")
                    append_jsonl(provenance, record)
                    count += 1
            self.seed_counts[source_class] = count
            self.seed_bytes[source_class] = dir_bytes(base)

    def assemble_initial_corpus(self) -> Path:
        dir_name = "merged_initial" if is_gamma_profile(self.profile) else "afl_initial"
        initial = self.workspace / "seeds" / dir_name
        if initial.exists():
            shutil.rmtree(initial)
        initial.mkdir(parents=True)
        index = 0
        seen: set[str] = set()
        for source_class in ("common_initial", "bootstrap", "g2_generated"):
            base = self.workspace / "seeds" / source_class
            if not base.exists():
                continue
            for path in sorted(p for p in base.rglob("*") if p.is_file()):
                if source_class == "g2_generated" and not is_generated_input_candidate(path):
                    continue
                digest = sha256_file(path)
                if digest in seen:
                    continue
                seen.add(digest)
                shutil.copy2(path, initial / f"{index:06d}_{source_class}_{path.name}")
                index += 1
        if index == 0:
            fallback = initial / "empty"
            fallback.write_bytes(b"\n")
        self.seed_counts[dir_name] = count_files(initial)
        self.seed_bytes[dir_name] = dir_bytes(initial)
        # Also track under afl_initial for backward-compatible provenance keys.
        if dir_name != "afl_initial":
            self.seed_counts["afl_initial"] = count_files(initial)
            self.seed_bytes["afl_initial"] = dir_bytes(initial)
        return initial

    # -- campaign ----------------------------------------------------------

    def afl_fuzz_path(self) -> Path:
        path = Path(os.environ.get("G2FUZZ_AFL_FUZZ", "")) if os.environ.get("G2FUZZ_AFL_FUZZ") else self.artifact_dir / "afl-fuzz"
        if not executable(path):
            raise PipelineError("infra_missing", f"missing executable G2Fuzz modified afl-fuzz: {path}", 127)
        return path

    def run_campaign(self) -> None:
        assert self.invocation is not None
        initial = self.assemble_initial_corpus()
        afl_fuzz = self.afl_fuzz_path()
        # Delta invariant (plan section 5): the AFL command must use G2Fuzz's
        # modified afl-fuzz with a CmpLog target (-c) and the G2Fuzz repo (-k).
        # A missing -c CmpLog argument must fail.
        if not self.target_cmp.is_file():
            raise PipelineError("infra_missing", "G2Fuzz campaign requires a CmpLog target.cmp binary", 127)
        out = self.workspace / "campaign" / "output"
        cmd = [
            str(afl_fuzz),
            "-i",
            str(initial),
            "-o",
            str(out),
            "-c",
            str(self.target_cmp),
            "-m",
            os.environ.get("G2FUZZ_MEMORY_MB", "none"),
            "-k",
            str(self.artifact_dir),
            "--",
            str(self.target_afl),
            *self.invocation["adapter_argv"],
        ]
        # Guard: the constructed command must contain the CmpLog -c argument.
        if "-c" not in cmd or str(self.target_cmp) not in cmd:
            raise PipelineError("infra_missing", "G2Fuzz campaign command is missing the -c CmpLog argument", 127)
        (self.workspace / "campaign" / "command.txt").write_text(" ".join(cmd) + "\n", encoding="utf-8")
        env = os.environ.copy()
        env.update(
            {
                "AFL_NO_UI": "1",
                "AFL_SKIP_CPUFREQ": "1",
                "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
            }
        )
        timeout = int(os.environ.get("G2FUZZ_AFL_TIMEOUT_SECONDS", "3600") or "3600")
        code, timed_out = run_subprocess(cmd, self.workspace / "logs" / "afl.log", timeout, env=env)
        queue_dir = out / "default" / "queue"
        crashes_dir = out / "default" / "crashes"
        hangs_dir = out / "default" / "hangs"
        afl_queue = self.workspace / "seeds" / "afl_queue"
        if queue_dir.exists():
            for path in sorted(p for p in queue_dir.rglob("*") if p.is_file()):
                shutil.copy2(path, unique_dest(afl_queue, path.name))
        stats = parse_fuzzer_stats(out / "default" / "fuzzer_stats")
        queue_count = count_files(queue_dir, exclude_readme=False)
        crash_count = count_files(crashes_dir, exclude_readme=True)
        hang_count = count_files(hangs_dir, exclude_readme=True)
        execs_done = int(stats.get("execs_done") or 0)
        metrics = {
            "afl_exit_code": code,
            "campaign_timeout_configured": timed_out or code == 124,
            "deadline_reached": timed_out and code == 124,
            "queue_count": queue_count,
            "crash_count": crash_count,
            "hang_count": hang_count,
            "execs_done": execs_done,
            "fuzzer_stats": stats,
            "fuzzer_stats_exists": (out / "default" / "fuzzer_stats").is_file(),
            "instrumentation_handshake_failure": "no instrumentation" in (self.workspace / "logs" / "afl.log").read_text(encoding="utf-8", errors="replace").lower() if (self.workspace / "logs" / "afl.log").exists() else False,
        }
        self.metrics.update(metrics)
        self.seed_counts["afl_queue"] = count_files(afl_queue)
        self.seed_bytes["afl_queue"] = dir_bytes(afl_queue)
        json_dump(self.workspace / "campaign" / "metrics.json", metrics)
        if code not in {0, 124}:
            raise PipelineError("failed", f"afl-fuzz exited {code}", code)
        # Campaign success requires real progress: fuzzer_stats, execs_done>0,
        # a nonempty queue, and no instrumentation handshake failure.
        if not metrics["fuzzer_stats_exists"]:
            self.stages["campaign"] = stage_record("failed", "G2Fuzz campaign produced no fuzzer_stats", **metrics)
            raise PipelineError("failed", "G2Fuzz campaign produced no fuzzer_stats", 65)
        if metrics["instrumentation_handshake_failure"]:
            self.stages["campaign"] = stage_record("failed", "G2Fuzz AFL++ instrumentation handshake failure", **metrics)
            raise PipelineError("failed", "G2Fuzz AFL++ instrumentation handshake failure", 65)
        if execs_done <= 0:
            self.stages["campaign"] = stage_record("failed", "G2Fuzz campaign produced zero target executions", **metrics)
            raise PipelineError("failed", "G2Fuzz campaign produced zero target executions", 65)
        if queue_count <= 0:
            self.stages["campaign"] = stage_record("failed", "G2Fuzz campaign produced an empty queue", **metrics)
            raise PipelineError("failed", "G2Fuzz campaign produced an empty queue", 65)
        self.stages["campaign"] = stage_record("complete", "none", **metrics)

    # -- coverage ----------------------------------------------------------

    def build_coverage_target(self) -> Path | None:
        """Best-effort build of a coverage-instrumented native target.

        Uses the same FuzzBench build.sh with ``clang``/``clang++`` and
        ``-fprofile-instr-generate -fcoverage-mapping``.  Returns the binary
        path on success, ``None`` when the build environment is unavailable.
        """

        clang = shutil.which("clang") or shutil.which("clang-18") or shutil.which("clang-17")
        clangxx = shutil.which("clang++") or shutil.which("clang++-18") or shutil.which("clang++-17")
        if not clang or not clangxx:
            return None
        try:
            src = self.resolve_source_dir("cov")
            build_sh = self.resolve_build_sh(src)
        except PipelineError:
            return None
        fuzz_target = self.target_manifest().get("fuzz_target", self.target)
        build_cwd = self.resolve_build_workdir(src)
        self.install_fuzzing_engine_library(src, engine="coverage")
        out_dir = self.workspace / "target" / "build_cov"
        work_dir = self.workspace / "target" / "work_cov"
        out_dir.mkdir(parents=True, exist_ok=True)
        work_dir.mkdir(parents=True, exist_ok=True)
        cov_flags = "-fprofile-instr-generate -fcoverage-mapping -pthread -Wno-register -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
        env = os.environ.copy()
        env.update(
            {
                "CC": clang,
                "CXX": clangxx,
                "FUZZING_ENGINE": "coverage",
                "SANITIZER": "address",
                "ARCHITECTURE": "x86_64",
                "SRC": str(src),
                "OUT": str(out_dir),
                "WORK": str(work_dir),
                "CFLAGS": f"{cov_flags} -L{src}",
                "CXXFLAGS": f"{cov_flags} -L{src}",
                "LIB_FUZZING_ENGINE": "-fsanitize=fuzzer",
                "FUZZER_LIB": "-fsanitize=fuzzer",
                "FUZZER": "libfuzzer",
            }
        )
        log_path = self.workspace / "logs" / "build_cov.log"
        try:
            with log_path.open("wb") as log:
                proc = subprocess.run(self._build_sh_command(build_sh), env=env, cwd=str(build_cwd), stdout=log, stderr=subprocess.STDOUT, timeout=int(os.environ.get("G2FUZZ_BUILD_TIMEOUT_SECONDS", "3600") or "3600"), check=False)
            if proc.returncode != 0:
                return None
        except Exception:
            return None
        produced = out_dir / fuzz_target
        if not produced.is_file() or not executable(produced):
            return None
        shutil.copy2(produced, self.target_cov)
        shared_out = out_dir / "src" / "shared"
        if shared_out.is_dir():
            shutil.copytree(shared_out, self.workspace / "target" / "src" / "shared", dirs_exist_ok=True)
        return self.target_cov

    def collect_coverage(self) -> None:
        stats = self.metrics.get("fuzzer_stats", {}) if isinstance(self.metrics.get("fuzzer_stats"), dict) else {}
        execs_done = int(stats.get("execs_done") or self.metrics.get("execs_done") or 0)
        queue_count = int(self.metrics.get("queue_count") or 0)
        report_path: Path | None = None
        raw_text = ""
        inputs_replayed = 0
        # 1. Explicit coverage report hook (test/CI or precomputed report).
        # eta/zeta plan §8: in production (no PYTEST_CURRENT_TEST) eta and zeta
        # must reject a precomputed G2FUZZ_COVERAGE_REPORT; only fixture tests
        # may use it.
        env_report = os.environ.get("G2FUZZ_COVERAGE_REPORT")
        if env_report and Path(env_report).is_file():
            if is_zeta_profile(self.profile) and not os.environ.get("PYTEST_CURRENT_TEST"):
                raise PipelineError(
                    "failed",
                    f"G2Fuzz {self.profile} forbids G2FUZZ_COVERAGE_REPORT in production; "
                    "coverage must come from a real coverage replay",
                    65,
                )
            report_path = Path(env_report)
        # Count replayable inputs (from afl_queue and g2_generated) for gamma.
        if is_gamma_profile(self.profile):
            for source_class in ("afl_queue", "g2_generated"):
                base = self.workspace / "seeds" / source_class
                if base.exists():
                    seen_replay: set[str] = set()
                    for path in sorted(p for p in base.rglob("*") if p.is_file()):
                        digest = sha256_file(path)
                        if digest not in seen_replay:
                            seen_replay.add(digest)
                            inputs_replayed += 1
        # 2. Build a coverage-instrumented target and replay the corpus.
        if report_path is None and summarize_coverage_report is not None:
            if is_gamma_profile(self.profile):
                cov_target = self.target_cov if self.target_cov.exists() else None
            else:
                cov_target = self.target_cov if self.target_cov.exists() else self.build_coverage_target()
            if cov_target and queue_count > 0:
                # Replay the AFL queue plus the G2-generated corpus (plan 9).
                corpus = self.workspace / "coverage" / "corpus"
                if corpus.exists():
                    shutil.rmtree(corpus)
                corpus.mkdir(parents=True, exist_ok=True)
                seen: set[str] = set()
                for source_class in ("afl_queue", "g2_generated"):
                    base = self.workspace / "seeds" / source_class
                    if not base.exists():
                        continue
                    for path in sorted(p for p in base.rglob("*") if p.is_file()):
                        digest = sha256_file(path)
                        if digest in seen:
                            continue
                        seen.add(digest)
                        shutil.copy2(path, unique_dest(corpus, path.name))
                        inputs_replayed += 1
                try:
                    import hgb_input_campaign  # type: ignore

                    replay = hgb_input_campaign.run_coverage_replay(
                        target_binary=cov_target,
                        corpus_dir=corpus,
                        work_dir=self.workspace / "coverage",
                        timeout_seconds=int(os.environ.get("G2FUZZ_COVERAGE_TIMEOUT_SECONDS", "600") or "600"),
                    )
                    if replay.get("report_path") and Path(replay["report_path"]).is_file():
                        report_path = Path(replay["report_path"])
                        raw_text = replay.get("raw_text", "")
                except Exception:
                    report_path = None
        coverage: dict[str, Any] = {
            "coverage_mode": "g2fuzz_campaign",
            "edge_coverage": {"status": "unavailable", "reason": "not_collected"},
            "line_coverage": None,
            "function_coverage": None,
            "regions": None,
            "execs_done": execs_done,
            "queue_count": queue_count,
            "inputs_replayed": inputs_replayed,
            "report_path": str(report_path) if report_path else None,
            "report_exists": bool(report_path and report_path.is_file()),
            "has_executions": execs_done > 0,
        }
        if report_path and report_path.is_file() and summarize_coverage_report is not None:
            try:
                parsed = summarize_coverage_report(report_path)
                coverage["line_coverage"] = parsed.get("line_coverage")
                coverage["function_coverage"] = parsed.get("function_coverage")
                coverage["regions"] = parsed.get("regions")
                coverage["coverage_mode"] = parsed.get("source", "g2fuzz_campaign")
            except CoverageError:
                coverage["report_parse_error"] = True
        if write_coverage_outputs is not None and coverage.get("line_coverage") is not None:
            try:
                write_coverage_outputs(self.workspace / "coverage", coverage, raw_text)
            except Exception:
                pass
        # Write gamma coverage outputs.
        if is_gamma_profile(self.profile):
            json_dump(self.workspace / "coverage" / "coverage.json", coverage)
            replay_log = self.workspace / "coverage" / "replay.log"
            if not replay_log.exists():
                replay_log.write_text(raw_text or "", encoding="utf-8")
        json_dump(self.workspace / "coverage" / "summary.json", coverage)
        self.coverage_summary = coverage
        # Coverage cannot complete from AFL path count alone: a real report
        # with a non-null covered-line count is required.
        if coverage.get("line_coverage") is None or coverage["line_coverage"].get("covered") is None:
            self.stages["coverage"] = stage_record("failed", "G2Fuzz coverage requires a real coverage report; AFL path count is not coverage", **coverage)
            raise PipelineError("failed", "G2Fuzz coverage requires a real coverage report; AFL path count is not coverage", 65)
        if is_gamma_profile(self.profile) and inputs_replayed <= 0:
            self.stages["coverage"] = stage_record("failed", "G2Fuzz gamma coverage requires inputs_replayed > 0", **coverage)
            raise PipelineError("failed", "G2Fuzz gamma coverage requires inputs_replayed > 0", 65)
        # Delta/epsilon: finalize the instrumentation check with the coverage
        # replay proof (plan G2-2). The .cov binary must produce a .profraw
        # and a non-empty llvm-cov export JSON when replaying >= 1 seed.
        if is_delta_profile(self.profile):
            cov_check = {
                "produces_profraw": bool(coverage.get("report_exists")),
                "export_nonempty": bool(
                    isinstance(coverage.get("line_coverage"), dict)
                    and coverage["line_coverage"].get("covered") is not None
                ),
                "inputs_replayed": int(inputs_replayed or 0),
            }
            self.write_instrumentation_check(cov_check=cov_check)
        self.stages["coverage"] = stage_record("complete", "none", **coverage)

    # -- result ------------------------------------------------------------

    def _evaluated_ok(self) -> bool:
        if self.stages["target_pair_built"].get("status") != "complete":
            return False
        if self.valid_generated_input_count <= 0:
            return False
        if int(self.metrics.get("execs_done") or 0) <= 0:
            return False
        if int(self.metrics.get("queue_count") or 0) <= 0:
            return False
        line_cov = self.coverage_summary.get("line_coverage")
        if not isinstance(line_cov, dict) or line_cov.get("covered") is None:
            return False
        if is_gamma_profile(self.profile):
            if not self.target_cov.exists():
                return False
            if not self.contract_result.get("valid"):
                return False
            if int(self.coverage_summary.get("inputs_replayed") or 0) <= 0:
                return False
        # Delta invariants (plan section 7): the target triple must be verified,
        # at least one generator must be produced, at least one G2-generated
        # payload must exist, and the covered-line count must be strictly > 0.
        if is_delta_profile(self.profile):
            if self.generated_generator_count <= 0:
                return False
            if self.generated_input_count <= 0:
                return False
            variants = self.triple_provenance.get("variants", {}) if isinstance(self.triple_provenance, dict) else {}
            if not all(
                bool(variants.get(v, {}).get("verified"))
                for v in ("afl", "cmp", "cov")
            ):
                return False
            if not self.triple_provenance.get("uses_fuzzbench_docker_environment"):
                return False
            if not self.consumption_smoke.get("consumed_input", True):
                return False
            if isinstance(line_cov.get("covered"), int) and int(line_cov["covered"]) <= 0:
                return False
            # G2-2/G2-7: the instrumentation check must prove all three
            # variants (afl seed exec, cmplog accepted by afl -c, cov replay).
            instr_path = self.target_pair_dir / "instrumentation_check.json"
            instr = read_json(instr_path) if instr_path.is_file() else {}
            if not instr.get("all_passed"):
                return False
            # G2-3: a runtime environment record must exist.
            if not (self.target_pair_dir / "runtime_environment.json").is_file():
                return False
        return True

    def result_payload(self, status: str, reason: str, exit_code: int) -> dict[str, Any]:
        manifest = self.target_manifest()
        stats = self.metrics.get("fuzzer_stats", {}) if isinstance(self.metrics.get("fuzzer_stats"), dict) else {}
        execs_done = int(stats.get("execs_done") or self.metrics.get("execs_done") or 0)
        # Build a stages view that includes the goal-stage aliases.
        stages_view: dict[str, Any] = dict(self.stages)
        for alias, canonical in GOAL_STAGE_ALIASES.items():
            if canonical in self.stages and alias not in stages_view:
                stages_view[alias] = self.stages[canonical]
        seed_provenance = {
            "common_initial": self.seed_counts.get("common_initial", 0),
            "bootstrap": self.seed_counts.get("bootstrap", 0),
            "g2_generated": self.seed_counts.get("g2_generated", 0),
            "afl_initial": self.seed_counts.get("afl_initial", 0),
            "afl_queue": self.seed_counts.get("afl_queue", 0),
        }
        seed_provenance_bytes = {
            "common_initial": self.seed_bytes.get("common_initial", 0),
            "bootstrap": self.seed_bytes.get("bootstrap", 0),
            "g2_generated": self.seed_bytes.get("g2_generated", 0),
            "afl_initial": self.seed_bytes.get("afl_initial", 0),
            "afl_queue": self.seed_bytes.get("afl_queue", 0),
        }
        target_pair_build = {
            "status": "completed" if self.stages.get("target_pair_built", {}).get("status") == "complete" else self.stages.get("target_pair_built", {}).get("status", "pending"),
            "afl_binary": str(self.target_afl) if self.target_afl.exists() else "",
            "cmp_binary": str(self.target_cmp) if self.target_cmp.exists() else "",
            "cov_binary": str(self.target_cov) if self.target_cov.exists() else "",
            "afl_sha256": sha256_file(self.target_afl) if self.target_afl.exists() else "",
            "cmp_sha256": sha256_file(self.target_cmp) if self.target_cmp.exists() else "",
            "cov_sha256": sha256_file(self.target_cov) if self.target_cov.exists() else "",
            "build_mode": GAMMA_BUILD_MODE if is_gamma_profile(self.profile) else BUILD_MODE,
            "build_source": self.build_source,
        }
        # Gamma target_pair nested object (plan section 11).
        target_pair_gamma = {
            "afl": {"path": str(self.target_afl), "sha256": sha256_file(self.target_afl) if self.target_afl.exists() else ""},
            "cmp": {"path": str(self.target_cmp), "sha256": sha256_file(self.target_cmp) if self.target_cmp.exists() else ""},
            "cov": {"path": str(self.target_cov), "sha256": sha256_file(self.target_cov) if self.target_cov.exists() else ""},
        }
        # Gamma g2fuzz nested object (plan section 11).
        line_cov = self.coverage_summary.get("line_coverage") or {}
        region_cov = self.coverage_summary.get("regions") or {}
        func_cov = self.coverage_summary.get("function_coverage") or {}
        line_pct = float(line_cov.get("percent", 0.0)) if isinstance(line_cov, dict) else 0.0
        region_pct = float(region_cov.get("percent", 0.0)) if isinstance(region_cov, dict) else 0.0
        func_pct = float(func_cov.get("percent", 0.0)) if isinstance(func_cov, dict) else 0.0
        g2fuzz_gamma = {
            "program_id": self.program_id,
            "formats": self.formats,
            "afl_binary": str(self.target_afl),
            "cmplog_enabled": True,
            "generated_generators": self.generated_generator_count,
            "g2_generated_seeds": self.generated_input_count,
            "valid_g2_generated_seeds": self.valid_generated_input_count,
            "common_initial_seeds": self.seed_counts.get("common_initial", 0),
            "bootstrap_seeds": self.seed_counts.get("bootstrap", 0),
        }
        # Gamma coverage nested object (plan section 11).
        coverage_gamma = {
            "line_coverage": line_pct,
            "region_coverage": region_pct,
            "function_coverage": func_pct,
            "inputs_replayed": int(self.coverage_summary.get("inputs_replayed") or 0),
        }
        campaign_gamma = {
            "execs_done": execs_done,
            "queued_paths": int(self.metrics.get("queue_count") or 0),
            "crashes": int(self.metrics.get("crash_count") or 0),
            "hangs": int(self.metrics.get("hang_count") or 0),
        }
        protocol = self.protocol
        if is_gamma_profile(self.profile):
            protocol = "paper-native" if self.adapter["method_profile"] == PAPER_METHOD_PROFILE else "extension"
        # Delta nested schema (plan section 7).  method_variant distinguishes
        # paper-core (paper-faithful adapters) from extension adapters so the
        # matrix collector can aggregate the two subsets separately.
        method_variant = method_variant_for(self.adapter)
        variants_provenance = self.triple_provenance.get("variants", {}) if isinstance(self.triple_provenance, dict) else {}
        target_triple = {
            "uses_fuzzbench_docker_environment": bool(self.triple_provenance.get("uses_fuzzbench_docker_environment")) if isinstance(self.triple_provenance, dict) else False,
            "variants": {
                v: {
                    "image_tag": str(variants_provenance.get(v, {}).get("image_tag", "")),
                    "image_digest": str(variants_provenance.get(v, {}).get("image_digest", "")),
                    "binary_sha256": str(variants_provenance.get(v, {}).get("binary_sha256", "")),
                    "verified": bool(variants_provenance.get(v, {}).get("verified")),
                }
                for v in ("afl", "cmp", "cov")
            },
        }
        program_generation = {
            "generator_count": self.generated_generator_count,
            "g2_generated_count": self.generated_input_count,
            "valid_g2_generated_count": self.valid_generated_input_count,
        }
        seed_provenance_delta = {
            "common_initial": self.seed_counts.get("common_initial", 0),
            "bootstrap": self.seed_counts.get("bootstrap", 0),
            "g2_generated_count": self.seed_counts.get("g2_generated", 0),
            "g2_generated": self.seed_counts.get("g2_generated", 0),
            "afl_queue": self.seed_counts.get("afl_queue", 0),
            "excluded_artifacts": ["*.py", "*.json", "logs"],
        }
        build_record = {
            "uses_fuzzbench_docker_environment": bool(target_triple["uses_fuzzbench_docker_environment"]),
            "build_source": self.build_source,
            "build_mode": GAMMA_BUILD_MODE if is_gamma_profile(self.profile) else BUILD_MODE,
        }
        artifacts = {
            "generators_dir": str(self.workspace / "generators" / "source"),
            "g2_generated_seeds_dir": str(self.workspace / "seeds" / "g2_generated"),
            "afl_queue_dir": str(self.workspace / "seeds" / "afl_queue"),
            "coverage_dir": str(self.workspace / "coverage"),
            "generator_count": self.generated_generator_count,
            "g2_generated_count": self.generated_input_count,
        }
        reproducibility = {
            "target_triple_verified": all(target_triple["variants"][v]["verified"] for v in ("afl", "cmp", "cov")),
            "consumed_input": bool(self.consumption_smoke.get("consumed_input", True)) if self.consumption_smoke else True,
            "contract_valid": bool(self.contract_result.get("valid")) if self.contract_result else False,
        }
        error_record = {"reason": reason, "exit_code": exit_code} if status not in ("evaluated", "dry_run_ok") else None
        return {
            "schema_version": 2,
            "baseline": "g2fuzz",
            "generator": "g2fuzz",
            "fuzzer": "g2fuzz",
            "task_family": TASK_FAMILY,
            "capability": TASK_FAMILY,
            "applicability": "applicable",
            "target": self.target,
            "project": manifest.get("project", os.environ.get("HGB_TARGET_PROJECT", "")),
            "fuzz_target": manifest.get("fuzz_target", os.environ.get("HGB_TARGET_FUZZ_TARGET", "")),
            "program_id": self.program_id,
            "formats": self.formats,
            "profile": self.profile,
            "protocol": protocol,
            "method_profile": self.adapter["method_profile"],
            "method_variant": method_variant,
            # G2-6: applicability_group separates paper-core (paper-faithful)
            # from extension targets so matrix aggregation never mixes the two
            # without a label.
            "applicability_group": PAPER_CORE_VARIANT if method_variant == PAPER_CORE_VARIANT else EXTENSION_VARIANT,
            "model": os.environ.get("G2FUZZ_MODEL") or os.environ.get("OPENAI_MODEL") or os.environ.get("MODEL") or "",
            "api_key_present": bool(os.environ.get("OPENAI_API_KEY") or os.environ.get("API_KEY")),
            "paper_core": self.adapter["method_profile"] == PAPER_METHOD_PROFILE,
            "excluded_from_aggregate": self.profile == "compat-smoke",
            "exclude_from_aggregate": self.profile == "compat-smoke",
            "excluded_from_paper_aggregate": self.adapter["method_profile"] != PAPER_METHOD_PROFILE,
            "status": status,
            "reason": reason,
            "exit_code": exit_code,
            "run_type": "generate-target",
            "generated_harness_count": 0,
            "generated_input_count": self.generated_input_count,
            "generator_count": self.generated_generator_count,
            "seed_counts": self.seed_counts,
            "queue_count": int(self.metrics.get("queue_count") or 0),
            "crash_count": int(self.metrics.get("crash_count") or 0),
            "hang_count": int(self.metrics.get("hang_count") or 0),
            # Global invariant 5 fields.
            "build": build_record,
            "artifacts": artifacts,
            "reproducibility": reproducibility,
            "error": error_record,
            # Nested beta schema (plan section 11).
            "target_pair_build": target_pair_build,
            "input_generation": {
                "program_count": self.generated_generator_count,
                "g2_generated_count": self.generated_input_count,
                "valid_g2_generated_count": self.valid_generated_input_count,
            },
            "seed_provenance": seed_provenance,
            "seed_provenance_bytes": seed_provenance_bytes,
            "campaign": {
                "execs_done": execs_done,
                "queue_count": int(self.metrics.get("queue_count") or 0),
                "crashes": int(self.metrics.get("crash_count") or 0),
                "hangs": int(self.metrics.get("hang_count") or 0),
            },
            "coverage": self.coverage_summary,
            "stages": stages_view,
            "workspace": str(self.workspace),
            "target_manifest": str(Path(os.environ.get("HGB_TARGET_MANIFEST", self.target_package / "target_manifest.json"))),
            "command_file": str(self.workspace / "campaign" / "command.txt"),
            "log_file": str(self.workspace / "logs" / "program_gen.log"),
            "duration_seconds": round(time.time() - self.start_time, 3),
            # Gamma nested schema (plan section 11).
            "g2fuzz": g2fuzz_gamma,
            "target_pair": target_pair_gamma,
            "campaign_gamma": campaign_gamma,
            "coverage_gamma": coverage_gamma,
            # Delta nested schema (plan section 7).
            "target_triple": target_triple,
            "program_generation": program_generation,
            "seed_provenance_delta": seed_provenance_delta,
            # Epsilon G2-2/G2-3: instrumentation check and runtime environment
            # proof, read back from the persisted records so the matrix
            # collector can verify them per evaluated row.
            "instrumentation_check": read_json(self.target_pair_dir / "instrumentation_check.json")
            if (self.target_pair_dir / "instrumentation_check.json").is_file() else {},
            "runtime_environment": read_json(self.target_pair_dir / "runtime_environment.json")
            if (self.target_pair_dir / "runtime_environment.json").is_file() else {},
        }

    def write_outputs(self, status: str, reason: str, exit_code: int) -> None:
        self.write_seed_provenance()
        payload = self.result_payload(status, reason, exit_code)
        json_dump(self.workspace / "result.json", payload)
        json_dump(self.workspace / "metadata.json", payload)
        self.write_summary(payload)

    def write_summary(self, payload: dict[str, Any]) -> None:
        lines = [
            "# HarnessGenBench G2Fuzz Summary",
            "",
            f"- Run directory: `{self.workspace}`",
            "- Task family: `input_generator`",
            f"- Target: `{self.target}`",
            f"- Program: `{self.program_id}`",
            f"- Profile: `{self.profile}`",
            f"- Method profile: `{self.adapter['method_profile']}`",
            f"- Status: `{payload['status']}`",
            f"- Generated inputs: `{payload['generated_input_count']}`",
            f"- Valid generated inputs: `{self.valid_generated_input_count}`",
            f"- Generators: `{payload['generator_count']}`",
            f"- Queue/crash/hang counts: queue={payload['queue_count']}, crashes={payload['crash_count']}, hangs={payload['hang_count']}",
            f"- Target pair build: `{payload['target_pair_build']['status']}` (source: `{self.build_source}`)",
            f"- Top failure reason: {payload['reason']}",
            "",
            "## Stages",
            "",
        ]
        for name in STAGE_NAMES:
            stage = self.stages.get(name, {})
            lines.append(f"- `{name}`: `{stage.get('status', 'pending')}`")
        lines.extend(["", "## Logs", ""])
        for path in sorted((self.workspace / "logs").glob("*")):
            if path.is_file():
                lines.append(f"- `{path.relative_to(self.workspace)}`")
        (self.workspace / "HGB_SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def full(self) -> int:
        try:
            self.preflight()
            if self.dry_run:
                self.write_outputs("dry_run_ok", "dry run prepared G2Fuzz adapter and runtime mapping", 0)
                return 0
            self.build_target_pair()
            self.run_program_gen()
            self.validate_generated_inputs()
            self.write_seed_provenance()
            self.run_campaign()
            self.write_seed_provenance()
            self.collect_coverage()
            if self._evaluated_ok():
                self.write_outputs("evaluated", "none", 0)
            else:
                self.write_outputs("quality_failure", "G2Fuzz completed stages but evaluated invariants were not met", 65)
            return 0
        except PipelineError as exc:
            self.reason = exc.reason
            self.status = exc.status
            failed_stage = next((name for name in STAGE_NAMES if self.stages.get(name, {}).get("status") == "pending"), STAGE_NAMES[-1])
            if self.stages.get(failed_stage, {}).get("status") == "pending":
                self.stages[failed_stage] = stage_record(exc.status, exc.reason)
            self.write_outputs(exc.status, exc.reason, exc.code)
            return exc.code


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workspace", default=str(default_workspace()))
    parser.add_argument("--target", default=os.environ.get("HGB_TARGET", ""))
    parser.add_argument("--target-package", default=os.environ.get("HGB_TARGET_PACKAGE", "/target"))
    parser.add_argument("--artifact-dir", default=str(default_artifact_dir()))
    parser.add_argument("--metadata-root", default=str(default_metadata_root()))
    parser.add_argument("--profile", default=os.environ.get("HGB_BASELINE_PROFILE", "alpha"))
    parser.add_argument("--protocol", default=os.environ.get("HGB_BASELINE_PROTOCOL", "paper-native"))
    parser.add_argument("--dry-run", action="store_true", default=os.environ.get("HGB_DRY_RUN", "0") == "1")


def make_pipeline(args: argparse.Namespace) -> G2FuzzPipeline:
    target = args.target or os.environ.get("HGB_TARGET")
    if not target:
        raise PipelineError("missing_target", "--target or HGB_TARGET is required", 64)
    return G2FuzzPipeline(
        workspace=Path(args.workspace),
        target=target,
        target_package=Path(args.target_package),
        artifact_dir=Path(args.artifact_dir),
        metadata_root=Path(args.metadata_root),
        profile=args.profile,
        protocol=args.protocol,
        dry_run=bool(args.dry_run),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("full", "preflight", "build-target-pair", "generate-inputs", "run-campaign", "evaluate"):
        p = sub.add_parser(name)
        add_common_args(p)
    validate_parser = sub.add_parser("validate-adapters")
    validate_parser.add_argument("--metadata-root", default=str(default_metadata_root()))
    dump_parser = sub.add_parser("dump-adapter")
    dump_parser.add_argument("target")
    dump_parser.add_argument("--metadata-root", default=str(default_metadata_root()))
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-adapters":
            validate_adapter_coverage(Path(args.metadata_root))
            return 0
        if args.command == "dump-adapter":
            adapter = load_adapters(Path(args.metadata_root))[args.target]
            print(json.dumps(adapter, indent=2, sort_keys=True))
            return 0
        pipeline = make_pipeline(args)
        if args.command == "full":
            return pipeline.full()
        pipeline.preflight()
        if args.command == "preflight":
            pipeline.write_outputs("dry_run_ok", "preflight completed", 0)
            return 0
        pipeline.build_target_pair()
        if args.command == "build-target-pair":
            pipeline.write_outputs("target_pair_built", "target pair built", 0)
            return 0
        pipeline.run_program_gen()
        if args.command == "generate-inputs":
            pipeline.write_outputs("input_generators_created", "input generators created", 0)
            return 0
        pipeline.validate_generated_inputs()
        pipeline.run_campaign()
        if args.command == "run-campaign":
            pipeline.write_outputs("campaign_completed", "campaign completed", 0)
            return 0
        pipeline.collect_coverage()
        pipeline.write_outputs("evaluated", "none", 0)
        return 0
    except PipelineError as exc:
        print(f"ERROR: {exc.reason}", file=sys.stderr)
        return exc.code
    except KeyError as exc:
        print(f"ERROR: unknown adapter: {exc}", file=sys.stderr)
        return 66


if __name__ == "__main__":
    raise SystemExit(main())
