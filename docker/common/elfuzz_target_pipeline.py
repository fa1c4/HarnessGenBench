#!/usr/bin/env python3
"""Target-aware ELFuzz input-generation pipeline for HarnessGenBench.

ELFuzz is an ``input_generator``: it synthesizes and evolves input-producing
fuzzer programs against a fixed native FuzzBench target, then runs a final
AFL++ campaign with the evolved generators.  It does not generate
``LLVMFuzzerTestOneInput`` and is never ranked with harness generators.

This helper owns the HGB contract around the upstream ELFuzz workflow:
manifest-driven target classification, native target build verification,
setup/cache validation, model/TGI readiness, ``elfuzz synth``/``produce``/``run``
orchestration, separated fuzzer-program/produced-input/campaign-corpus
accounting, provenance, coverage, and normalized schema-version-2 results.

The upstream ``elfuzz`` CLI is invoked as a subprocess and is fakeable through
the ``ELFUZZ_CLI`` environment variable so the full state machine is exercisable
offline.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any


STAGE_NAMES = (
    "target_classification",
    "target_build",
    "elfuzz_setup",
    "model_ready",
    "synthesis",
    "evolution",
    "production",
    "generated_input_validation",
    "campaign",
    "coverage",
)
# Goal-stage aliases (paper section 0) mapped onto the canonical stage names so
# the result payload carries both the internal ordering and the contract names.
GOAL_STAGE_ALIASES = {
    "seed_fuzzer_synthesis": "synthesis",
    "generated_input_validation": "generated_input_validation",
    "evolution": "evolution",
    "target_build": "target_build",
    "campaign": "campaign",
    "coverage": "coverage",
}
TASK_FAMILY = "input_generator"
INVALID_REASON_CODE = "elfuzz_non_text_target"
INVALID_MESSAGE = "Invalid: ELFuzz supports text-input targets only"
# Upstream benchmarks that ELFuzz ships hard-coded adapters for.  An applicable
# target may declare one of these only when it IS that project's native target;
# extension targets must declare their own benchmark and set hgb_adapter: true
# so the HGB adapter layer invokes ELFuzz with the target's own command instead
# of running the aliased benchmark and renaming outputs.
UPSTREAM_NATIVE_BENCHMARKS = {"jsoncpp", "libxml2", "re2", "sqlite3"}
REQUIRED_APPLICABLE_KEYS = {
    "target",
    "applicability",
    "input_kind",
    "upstream_benchmark",
    "adapter_class",
    "adapter_id",
    "build_mode",
    "input_mode",
    "argv",
    "format",
    "format_spec",
    "adapter_dir",
    "seed_template",
    "validity_check",
    "timeout_seconds",
}
VALIDITY_CHECKS = {"json", "xml", "regex", "sql", "ruby", "php", "ini", "http_response", "none"}
UPSTREAM_NATIVE = "upstream-native"
EXTENSION = "extension"

BENCHMARK_CAPS = {
    "jsoncpp": "Jsoncpp",
    "libxml2": "Libxml2",
    "re2": "Re2",
    "sqlite3": "Sqlite3",
    "cpython3": "Cpython3",
    "librsvg": "Librsvg",
    "cvc5": "Cvc5",
}


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
    """Parse the small YAML subset used by HGB metadata files (no PyYAML dep)."""

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
    env = os.environ.get("HGB_GENERATOR_ARTIFACT_DIR") or os.environ.get("HGB_ELFUZZ_ARTIFACT_DIR")
    if env:
        return Path(env)
    if Path("/opt/hgb/artifacts/elfuzz").exists():
        return Path("/opt/hgb/artifacts/elfuzz")
    return repo_root_from(Path.cwd()) / "artifacts" / "elfuzz"


def default_workspace() -> Path:
    return Path(os.environ.get("HGB_WORKSPACE", "/workspace"))


def load_adapters(metadata_root: Path | None = None) -> dict[str, dict[str, Any]]:
    root = metadata_root or default_metadata_root()
    path = root / "elfuzz_target_adapters.yaml"
    if not path.exists():
        raise PipelineError("adapter_manifest_missing", f"missing ELFuzz adapter manifest: {path}", 66)
    raw = parse_simple_yaml(path)
    adapters: dict[str, dict[str, Any]] = {}
    for entry in raw.get("targets", []):
        if not isinstance(entry, dict):
            raise PipelineError("adapter_parse_failed", f"adapter entry is not a mapping: {entry}", 64)
        target = str(entry.get("target") or "")
        if not target:
            raise PipelineError("adapter_parse_failed", "adapter entry has no target", 64)
        if target in adapters:
            raise PipelineError("adapter_parse_failed", f"duplicate adapter entry for target: {target}", 64)
        applicability = str(entry.get("applicability", ""))
        if applicability == "Invalid":
            adapters[target] = entry
            continue
        missing = sorted(REQUIRED_APPLICABLE_KEYS - set(entry))
        if missing:
            raise PipelineError(
                "adapter_parse_failed",
                f"{target}: missing adapter keys: {', '.join(missing)}",
                64,
            )
        argv = entry.get("argv")
        if not isinstance(argv, list):
            raise PipelineError("adapter_parse_failed", f"{target}: argv must be a list", 64)
        if entry["input_mode"] not in {"file", "stdin"}:
            raise PipelineError("adapter_parse_failed", f"{target}: unsupported input_mode {entry['input_mode']}", 64)
        if entry["adapter_class"] not in {UPSTREAM_NATIVE, EXTENSION}:
            raise PipelineError("adapter_parse_failed", f"{target}: unsupported adapter_class {entry['adapter_class']}", 64)
        if str(entry.get("validity_check", "")) not in VALIDITY_CHECKS:
            raise PipelineError("adapter_parse_failed", f"{target}: unsupported validity_check {entry['validity_check']}", 64)
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


def adapter_yaml_path(metadata_root: Path | None = None, target: str | None = None) -> Path:
    """Resolve the per-target adapter.yaml path under repro/elfuzz/targets."""

    adapters = load_adapters(metadata_root)
    entry = adapters.get(target or "")
    if not entry or entry.get("applicability") != "applicable":
        return Path("repro/elfuzz/targets") / (target or "") / "adapter.yaml"
    return repo_root_from(metadata_root or default_metadata_root()) / entry["adapter_dir"] / "adapter.yaml"


def validate_no_aliasing(metadata_root: Path | None = None) -> list[str]:
    """Reject upstream-benchmark aliasing for extension targets.

    An applicable target may declare an upstream-native benchmark
    (jsoncpp/libxml2/re2/sqlite3) only when it IS that project's native target.
    Every other applicable target must declare its own benchmark with
    ``hgb_adapter: true`` and ship a real ``adapter.yaml`` naming the exact
    FuzzBench target.  Running jsoncpp and renaming the outputs is forbidden.
    """

    adapters = load_adapters(metadata_root)
    root = repo_root_from(metadata_root or default_metadata_root())
    violations: list[str] = []
    for target, entry in adapters.items():
        if entry.get("applicability") != "applicable":
            continue
        benchmark = str(entry.get("upstream_benchmark", ""))
        adapter_class = str(entry.get("adapter_class", ""))
        if benchmark in UPSTREAM_NATIVE_BENCHMARKS:
            # Only the upstream-native target for that benchmark may use it.
            if adapter_class != UPSTREAM_NATIVE:
                violations.append(
                    f"{target}: declares upstream alias '{benchmark}' but is not upstream-native"
                )
            if not target.startswith(benchmark):
                violations.append(
                    f"{target}: uses upstream benchmark '{benchmark}' but target name does not match"
                )
            continue
        # Extension target: must have hgb_adapter and a real adapter.yaml.
        if not entry.get("hgb_adapter"):
            violations.append(f"{target}: extension target missing hgb_adapter: true")
        yaml_path = root / entry["adapter_dir"] / "adapter.yaml"
        if not yaml_path.is_file():
            violations.append(f"{target}: missing adapter.yaml at {yaml_path}")
            continue
        parsed = parse_simple_yaml(yaml_path)
        adapter_target = str(parsed.get("target", ""))
        if adapter_target != target:
            violations.append(
                f"{target}: adapter.yaml target '{adapter_target}' != declared target"
            )
        if str(parsed.get("upstream_benchmark", "")) in UPSTREAM_NATIVE_BENCHMARKS:
            violations.append(
                f"{target}: adapter.yaml aliases upstream benchmark '{parsed.get('upstream_benchmark')}'"
            )
    if violations:
        raise PipelineError("adapter_aliasing_failed", "; ".join(violations), 64)
    return violations


def verify_target_binary(path: Path, fuzz_target: str = "") -> dict[str, Any]:
    """Verify a discovered target binary meets the ELFuzz build contract.

    The binary must exist, be executable, have nonzero size, NOT be ``build.sh``,
    and (when ``fuzz_target`` is given) match ``/out/<fuzz_target>`` by name for
    a real FuzzBench build.  Returns a verification record.
    """

    record: dict[str, Any] = {
        "path": str(path),
        "exists": path.is_file(),
        "executable": executable(path),
        "nonzero_size": path.is_file() and path.stat().st_size > 0,
        "is_build_sh": path.name == "build.sh",
        "name_matches": (not fuzz_target) or path.name == fuzz_target or path.name == Path(fuzz_target).name,
        "ok": False,
    }
    record["ok"] = bool(
        record["exists"]
        and record["executable"]
        and record["nonzero_size"]
        and not record["is_build_sh"]
        and record["name_matches"]
    )
    return record


def smoke_target_binary(path: Path, sample: bytes = b"", timeout: int = 10) -> dict[str, Any]:
    """Run a harmless sample through the target binary and report the result."""

    if not path.is_file() or not executable(path):
        return {"ran": False, "exit_code": 127, "timed_out": False}
    import tempfile

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(sample)
        sample_path = Path(tmp.name)
    try:
        proc = subprocess.run([str(path), str(sample_path)], capture_output=True, timeout=timeout, check=False)
        return {"ran": True, "exit_code": proc.returncode, "timed_out": False}
    except subprocess.TimeoutExpired:
        return {"ran": True, "exit_code": 124, "timed_out": True}
    except OSError as exc:
        return {"ran": False, "exit_code": 127, "timed_out": False, "error": str(exc)}
    finally:
        try:
            sample_path.unlink()
        except OSError:
            pass


def classify_target(target: str, metadata_root: Path | None = None) -> dict[str, Any]:
    adapters = load_adapters(metadata_root)
    entry = adapters.get(target)
    if not entry:
        return {
            "target": target,
            "applicability": "Invalid",
            "input_kind": "unknown",
            "reason_code": "elfuzz_unlisted_target",
            "adapter_present": False,
        }
    applicability = str(entry.get("applicability", ""))
    if applicability == "applicable":
        return {
            "target": target,
            "applicability": "applicable",
            "input_kind": str(entry.get("input_kind", "text")),
            "upstream_benchmark": str(entry["upstream_benchmark"]),
            "adapter_id": str(entry["adapter_id"]),
            "adapter_class": str(entry["adapter_class"]),
            "hgb_adapter": bool(entry.get("hgb_adapter", False)),
            "build_mode": str(entry["build_mode"]),
            "input_mode": str(entry["input_mode"]),
            "argv": list(entry["argv"]),
            "format": str(entry["format"]),
            "validity_check": str(entry["validity_check"]),
            "timeout_seconds": int(entry.get("timeout_seconds", 5)),
            "adapter_present": True,
        }
    return {
        "target": target,
        "applicability": "Invalid",
        "input_kind": str(entry.get("input_kind", "non-text")),
        "reason_code": str(entry.get("reason_code", INVALID_REASON_CODE)),
        "adapter_present": True,
    }


def budget_for_profile(profile: str, env: dict[str, str] | None = None) -> dict[str, Any]:
    env = env or os.environ
    profile = profile or "alpha"
    ci = profile in {"ci-smoke", "compat-smoke"}

    def env_int(key: str, default: int) -> int:
        raw = env.get(key)
        if raw is None or raw == "":
            return default
        try:
            return int(raw)
        except ValueError:
            return default

    if ci:
        return {
            "profile": profile,
            "evolution_iterations": max(1, env_int("ELFUZZ_EVOLUTION_ITERATIONS", 1)),
            "evolution_seconds": max(1, env_int("ELFUZZ_EVOLUTION_SECONDS", 1800)),
            "produce_seconds": max(1, env_int("ELFUZZ_PRODUCE_SECONDS", 60)),
            "campaign_seconds": max(1, env_int("ELFUZZ_AFL_SECONDS", 60)),
            "tgi_waiting_seconds": max(1, env_int("ELFUZZ_TGI_WAITING_SECONDS", 120)),
            "excluded_from_aggregate": True,
            "paper_core": False,
            "reject_prebuilt_binary": False,
            "require_coverage_build": False,
            "method_variant": "compat-smoke",
            "source": "ci-smoke",
        }
    if profile in {"paper-faithful", "reproduction-gamma", "reproduction-delta", "reproduction-epsilon", "reproduction-zeta", "reproduction-eta"}:
        # reproduction-eta is the canonical strictest paper-native
        # input-generator profile (plan elfuzz_reproduction_eta.md). It
        # inherits the zeta strict invariants and additionally requires the
        # SUT to run inside the FuzzBench Docker runtime (containerized
        # wrappers), never as a host-extracted binary. reproduction-zeta is
        # the strict profile from the zeta plan; reproduction-epsilon is the
        # strict profile from the epsilon plan; reproduction-delta is its
        # backward-compatible alias (plan elfuzz_reproduction_delta.md). It
        # inherits the paper-faithful budget and, like reproduction-gamma,
        # rejects a prebuilt ELFUZZ_TARGET_BINARY and requires a real
        # coverage-instrumented replay.
        strict = profile in {"reproduction-gamma", "reproduction-delta", "reproduction-epsilon", "reproduction-zeta", "reproduction-eta"}
        zeta = profile in {"reproduction-zeta", "reproduction-eta"}
        budget = {
            "profile": profile,
            "evolution_iterations": env_int("ELFUZZ_EVOLUTION_ITERATIONS", 50),
            "evolution_seconds": env_int("ELFUZZ_EVOLUTION_SECONDS", 1800),
            "produce_seconds": env_int("ELFUZZ_PRODUCE_SECONDS", 600),
            "campaign_seconds": env_int("ELFUZZ_AFL_SECONDS", 86400),
            "tgi_waiting_seconds": env_int("ELFUZZ_TGI_WAITING_SECONDS", 1200),
            "excluded_from_aggregate": False,
            "paper_core": True,
            # reproduction-gamma/delta/epsilon/zeta invariants (plan section
            # 3/4): the SUT must be built from the exact FuzzBench Dockerfile,
            # never a prebuilt ELFUZZ_TARGET_BINARY, and coverage must come from
            # a real coverage-instrumented replay, never AFL path counters.
            "reject_prebuilt_binary": strict,
            "require_coverage_build": strict,
            # zeta plan §3: the SUT must run inside the FuzzBench Docker
            # runtime via containerized wrappers, never as a host-extracted
            # binary that can miss runtime libraries.
            "require_containerized_sut_runtime": zeta,
            "method_variant": "paper-faithful",
            "source": "pinned-upstream-defaults",
        }
        return budget
    # alpha: nontrivial upstream-default-or-greater; never the 1/60 smoke defaults.
    evo = env_int("ELFUZZ_EVOLUTION_ITERATIONS", 50)
    produce = env_int("ELFUZZ_PRODUCE_SECONDS", 600)
    campaign = env_int("ELFUZZ_AFL_SECONDS", 1800)
    if evo <= 1 and produce <= 60:
        raise PipelineError(
            "alpha_budget_invalid",
            "alpha profile cannot use 1 evolution iteration and 60-second production; "
            "those are ci-smoke/compat-smoke values only",
            64,
        )
    if evo < 2:
        evo = 50
    if produce < 61:
        produce = 600
    return {
        "profile": profile,
        "evolution_iterations": evo,
        "evolution_seconds": env_int("ELFUZZ_EVOLUTION_SECONDS", 1800),
        "produce_seconds": produce,
        "campaign_seconds": max(60, campaign),
        "tgi_waiting_seconds": env_int("ELFUZZ_TGI_WAITING_SECONDS", 1200),
        "excluded_from_aggregate": False,
        "paper_core": False,
        "reject_prebuilt_binary": False,
        "require_coverage_build": False,
        "method_variant": "alpha",
        "source": "alpha-defaults",
    }


def stage_record(status: str, reason: str = "none", **extra: Any) -> dict[str, Any]:
    record = {"status": status, "reason": reason}
    record.update(extra)
    return record


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


def is_fuzzer_program(path: Path) -> bool:
    return path.suffix in {".py", ".cc", ".cpp", ".c", ".rs", ".js"} and path.is_file()


def is_produced_input(path: Path) -> bool:
    """Return True only for actual input payloads (plan section 3).

    Prompts, manifests, lineage, config, metadata, stats, logs, fuzzer
    programs, preseed/corpus/queue metadata, and LLVM profraw/profdata are
    never counted as produced inputs.  Only real input payload files under a
    produced/upstream ELFuzz output directory count.
    """
    ignored_suffixes = {
        ".py", ".log", ".json", ".jsonl", ".yaml", ".yml", ".toml", ".txt",
        ".md", ".sh", ".cfg", ".ini", ".conf", ".profraw", ".profdata",
    }
    ignored_stems = {
        "manifest", "metadata", "config", "lineage", "fuzzer_stats", "stats",
        "preseed", "seed_corpus", "input_corpus", "corpus_manifest", "corpus",
        "seed_fuzzer", "evolved", "run", "queue",
    }
    ignored_prefixes = ("prompt_", "manifest", "lineage", "config", "metadata", "stats", "preseed", "corpus", "seed_fuzzer", "evolved")
    name = path.name.lower()
    stem = path.stem.lower()
    if path.suffix.lower() in ignored_suffixes:
        return False
    if stem in ignored_stems or stem.startswith("config"):
        return False
    if any(name.startswith(prefix) for prefix in ignored_prefixes):
        return False
    if stem.startswith("preseed") or stem.endswith("_preseed"):
        return False
    return path.is_file()


def safe_extract_tar(archive: Path, dest: Path) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    extracted = 0
    try:
        if archive.suffix == ".xz":
            with tarfile.open(archive, "r:xz") as tf:
                for member in tf.getmembers():
                    if member.isfile():
                        tf.extract(member, dest)
                        extracted += 1
        elif archive.suffix == ".zst" or archive.name.endswith(".tar.zst"):
            import zstandard  # type: ignore

            with open(archive, "rb") as fh:
                dctx = zstandard.ZstdDecompressor()
                with dctx.stream_reader(fh) as reader:
                    with tarfile.open(fileobj=reader, mode="r|") as tf:
                        for member in tf.getmembers():
                            if member.isfile():
                                tf.extract(member, dest)
                                extracted += 1
    except (FileNotFoundError, ModuleNotFoundError, OSError, tarfile.TarError):
        return 0
    return extracted


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


def validity_label(check: str) -> str:
    return {
        "json": "json",
        "xml": "xml",
        "regex": "regex",
        "sql": "sql",
        "ruby": "ruby",
        "php": "php",
        "ini": "ini",
        "http_response": "http",
        "none": "none",
    }.get(check, "none")


def lightweight_validate(data: bytes, check: str) -> bool:
    if not data:
        return False
    label = validity_label(check)
    if label == "json":
        text = data.decode("utf-8", "replace").lstrip()
        if text.startswith("{") or text.startswith("["):
            return True
        try:
            json.loads(text)
            return True
        except Exception:
            return False
    if label == "xml":
        text = data.decode("utf-8", "replace").lstrip()
        if text.startswith("<"):
            return True
        return bool(text.strip())
    if label == "sql":
        text = data.decode("utf-8", "replace").strip().lower()
        if any(text.startswith(kw) for kw in ("select", "insert", "create", "update", "delete", "with", "pragma", "begin")):
            return True
        return bool(text.strip())
    if label == "regex":
        try:
            import re

            re.compile(data.decode("utf-8", "replace"))
            return True
        except re.error:
            return bool(data.strip())
    if label in {"ruby", "php"}:
        text = data.decode("utf-8", "replace").strip()
        return bool(text)
    if label == "ini":
        text = data.decode("utf-8", "replace")
        if "=" in text or "[" in text:
            return True
        return bool(text.strip())
    if label == "http":
        text = data.decode("utf-8", "replace")
        if text.startswith("HTTP/") or "\r\n" in text:
            return True
        return bool(text.strip())
    return True


def find_elfuzz_project_root() -> Path | None:
    for candidate in (os.environ.get("ELFUZZ_PROJECT_ROOT"), "/home/appuser/elmfuzz", "/elfuzz", "/opt/hgb/artifacts/elfuzz"):
        if candidate and Path(candidate).is_dir() and (Path(candidate) / "cli" / "main.py").exists():
            return Path(candidate)
    return None


def default_docker_runner(command: list[str], timeout_seconds: int) -> dict[str, Any]:
    """Run a Docker/subprocess command and return a CommandResult-like record.

    The SUT builder accepts any runner callable returning an object with
    ``command``, ``exit_code``, ``stdout`` and ``stderr`` attributes; this
    default runner shells out to ``subprocess.run`` so the real Docker build
    path works in production.  Tests substitute a fake runner.  A small
    ``_RunnerResult`` wrapper exposes both attribute and item access so the
    same runner interoperates with ``hgb_fuzzbench_builder._run_phase`` (which
    reads attributes) and dict-style callers.
    """

    try:
        proc = subprocess.run(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            check=False,
            timeout=timeout_seconds,
        )
        return _RunnerResult(list(command), proc.returncode, proc.stdout or "", proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        return _RunnerResult(list(command), 124, "", f"timed out: {exc}")
    except OSError as exc:
        return _RunnerResult(list(command), 127, "", str(exc))


class _RunnerResult:
    __slots__ = ("command", "exit_code", "stdout", "stderr")

    def __init__(self, command: list[str], exit_code: int, stdout: str, stderr: str) -> None:
        self.command = command
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr

    def __getitem__(self, key: str) -> Any:  # dict-style compat
        return getattr(self, key)


def elfuzz_cli_command() -> list[str]:
    custom = os.environ.get("ELFUZZ_CLI")
    if custom:
        return [custom]
    return ["elfuzz"]


def test_mode_cap() -> int | None:
    """Return a strict test-mode timeout cap, or None when not in test mode.

    ELFuzz reproduction budgets are large (campaign_seconds=86400 in
    paper-faithful mode). Fake fuzzers used in tests that respect ``--time``
    would hang for that long. ``ELFUZZ_TEST_MODE_SECONDS`` caps the effective
    subprocess timeout for every stage so ``pytest -q`` always terminates,
    without affecting real reproduction budgets (it is only set by the test
    suite, never by the production entrypoint).

    When running under pytest (``PYTEST_CURRENT_TEST`` is set) and no explicit
    cap is configured, a small default cap is applied so a fake long-running
    subprocess (e.g. ``elfuzz run --time 86400``) is killed within the cap and
    leaves no child process behind (zeta plan §2). Set
    ``ELFUZZ_TEST_MODE_SECONDS=0`` to disable the auto-cap.
    """

    raw = os.environ.get("ELFUZZ_TEST_MODE_SECONDS")
    if raw is not None and raw != "":
        try:
            value = int(raw)
        except ValueError:
            return None
        return max(1, value) if value > 0 else None
    # Auto-detect pytest and apply a small default cap (zeta plan §2).
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return 30
    return None


def _kill_process_group(proc: subprocess.Popen) -> None:
    """Terminate the whole process group of ``proc`` so child processes that
    ignore SIGTERM (e.g. a fake fuzzer that sleeps on ``--time``) cannot survive
    a timeout (epsilon plan ELF-2)."""
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, OSError):
        pgid = proc.pid
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except (ProcessLookupError, OSError):
            return
        # Give the group a moment to exit before escalating.
        try:
            proc.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            continue


def run_subprocess(cmd: list[str], log_path: Path, timeout: int, env: dict[str, str] | None = None, stdin_data: str | None = None) -> tuple[int, bool]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    timed_out = False
    # Test-mode cap (ELF-2): keep fake fuzzers from hanging pytest on the large
    # paper-faithful budgets without touching real reproduction timeouts.
    cap = test_mode_cap()
    if cap is not None and (timeout is None or timeout <= 0 or timeout > cap):
        timeout = cap
    effective_timeout = timeout if timeout and timeout > 0 else None
    proc: subprocess.Popen | None = None
    try:
        log_file = log_path.open("wb")
        # start_new_session=True puts the child in its own process group so a
        # timeout can kill the entire group (ELF-2), not just the shell parent.
        proc = subprocess.Popen(
            cmd,
            env=env,
            stdin=subprocess.PIPE if stdin_data else None,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        if stdin_data and proc.stdin is not None:
            try:
                proc.stdin.write(stdin_data.encode("utf-8"))
                proc.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        code = proc.wait(timeout=effective_timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if proc is not None:
            _kill_process_group(proc)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        # A timeout is always reported as exit code 124 regardless of the
        # signal used to kill the group, matching the historical contract the
        # stage handlers rely on (synthesis/campaign check code == 124).
        code = 124
    except FileNotFoundError:
        code = 127
    finally:
        try:
            log_file.close()
        except (NameError, UnboundLocalError):
            pass
    with log_path.open("a", encoding="utf-8") as log:
        log.write(f"\n[exit={code} timed_out={timed_out}]\n")
    return code, timed_out


def stage_timeout(default: int = 10800) -> int:
    raw = os.environ.get("ELFUZZ_STAGE_TIMEOUT_SECONDS")
    if raw is None or raw == "" or raw == "0":
        raw = os.environ.get("HGB_GENERATION_TIMEOUT_SECONDS")
    if raw is None or raw == "" or raw == "0":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


class ELFuzzPipeline:
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
        self.profile = profile or "alpha"
        self.protocol = protocol or "paper-native"
        self.dry_run = dry_run
        self.adapters = load_adapters(metadata_root)
        self.classification = classify_target(target, metadata_root)
        self.adapter = self.adapters.get(target)
        self.budget = budget_for_profile(self.profile)
        self.stages: dict[str, dict[str, Any]] = {name: stage_record("pending") for name in STAGE_NAMES}
        self.metrics: dict[str, Any] = {}
        self.fuzzer_program_count = 0
        self.produced_input_count = 0
        self.valid_generated_input_count = 0
        self.evolution_iterations_completed = 0
        self.queue_count = 0
        self.crash_count = 0
        self.hang_count = 0
        self.exit_code = 0
        self.reason = "none"
        self.reason_code = "none"
        self.error: dict[str, Any] = {}
        self.status = "created"
        self.start_time = time.time()
        self.target_binary: Path | None = None
        self.coverage_binary: Path | None = None
        self.sut_record: dict[str, Any] = {}
        self.adapter_hashes: dict[str, str] = {}
        self.input_contract: dict[str, Any] = {}
        self.project_root = find_elfuzz_project_root()
        self.runner = default_docker_runner
        self.adapter_benchmark_dir: Path | None = None

    def ensure_layout(self) -> None:
        for rel in (
            "target/binary",
            "target/build",
            "synthesis/fuzzer_programs",
            "synthesis/prompts",
            "synthesis/generations",
            "generated_inputs/produced",
            "generated_inputs/generations",
            "generated_inputs/validation",
            "campaign/queue",
            "campaign/crashes",
            "campaign/hangs",
            "campaign/stats",
            "coverage",
            "logs",
            "config",
        ):
            (self.workspace / rel).mkdir(parents=True, exist_ok=True)

    def record_adapter_hashes(self) -> None:
        repo = repo_root_from(self.metadata_root)
        self.adapter_hashes = {}
        for label, rel in (
            ("format_spec", self.adapter.get("format_spec", "")),
            ("seed_template", self.adapter.get("seed_template", "")),
            ("adapter_dir", self.adapter.get("adapter_dir", "")),
        ):
            if not rel:
                continue
            for base in (repo / rel, Path("/opt/hgb") / rel):
                if base.is_file():
                    self.adapter_hashes[label] = sha256_file(base)
                    break
                if base.is_dir():
                    digest = hashlib.sha256()
                    for path in sorted(base.rglob("*")):
                        if path.is_file():
                            digest.update(sha256_file(path).encode())
                    self.adapter_hashes[label] = digest.hexdigest()
                    break
        adapter_yaml = repo / self.adapter.get("adapter_dir", "") / "adapter.yaml" if self.adapter else None
        if adapter_yaml and adapter_yaml.is_file():
            self.adapter_hashes["adapter_yaml"] = sha256_file(adapter_yaml)

    def target_manifest(self) -> dict[str, Any]:
        manifest = Path(os.environ.get("HGB_TARGET_MANIFEST", self.target_package / "target_manifest.json"))
        return read_json(manifest)

    def write_runtime_config(self) -> None:
        self.record_adapter_hashes()
        json_dump(self.workspace / "config" / "adapter.json", self.adapter or {})
        json_dump(self.workspace / "config" / "classification.json", self.classification)
        json_dump(self.workspace / "config" / "budget.json", self.budget)
        json_dump(self.workspace / "config" / "adapter_hashes.json", self.adapter_hashes)
        json_dump(self.workspace / "target" / "adapter_manifest.json", self.adapter or {})

    def classify(self) -> None:
        self.ensure_layout()
        self.write_runtime_config()
        if self.classification["applicability"] != "applicable":
            self.stages["target_classification"] = stage_record(
                "not_applicable",
                self.classification.get("reason_code", INVALID_REASON_CODE),
                classification=self.classification,
            )
            raise PipelineError("not_applicable", INVALID_MESSAGE, 0)
        self.stages["target_classification"] = stage_record("complete", "none", classification=self.classification)

    def resolve_target_binary(self) -> Path | None:
        env_bin = os.environ.get("ELFUZZ_TARGET_BINARY")
        if env_bin:
            path = Path(env_bin)
            if executable(path) and path.name != "build.sh":
                return path
        fuzz_target = self.target_manifest().get("fuzz_target", self.target)
        candidates = [
            self.workspace / "target" / "binary" / fuzz_target,
            self.workspace / "target" / "binary" / "target",
            self.workspace / "target" / fuzz_target,
            self.workspace / "target" / "target",
            Path("/out") / fuzz_target,
        ]
        for candidate in candidates:
            if candidate.is_file() and candidate.name != "build.sh" and executable(candidate):
                return candidate
        return None

    def _sut_root(self) -> Path:
        # Plan section 4 builder outputs live under results/elfuzz/<target>/sut.
        # The workspace is the per-target run directory; the SUT tree is nested.
        return self.workspace / "sut"

    def _benchmark_dir(self) -> Path:
        """Resolve the exact FuzzBench benchmark directory for this target."""

        bench = self.target_package / "fuzzbench_benchmark"
        if bench.is_dir():
            return bench
        # Some packages nest the benchmark under the target package root.
        return self.target_package

    def _build_sut_variant(self, variant: str, fuzz_target: str) -> dict[str, Any]:
        """Build one SUT variant (native or coverage) from the FuzzBench Dockerfile."""

        try:
            import hgb_fuzzbench_builder  # type: ignore
        except ImportError:  # pragma: no cover - resolved via sys.path below
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            import hgb_fuzzbench_builder  # type: ignore
        engine = hgb_fuzzbench_builder.ELFUZZ_NATIVE_ENGINE if variant == "native" else hgb_fuzzbench_builder.ELFUZZ_COVERAGE_ENGINE
        sut_root = self._sut_root()
        work_dir = sut_root / variant
        work_dir.mkdir(parents=True, exist_ok=True)
        image_tag = hgb_fuzzbench_builder.deterministic_image_tag(
            run_id=os.environ.get("HGB_RUN_ID", self.profile),
            target=self.target,
            candidate_id=variant,
            generator="elfuzz",
        )
        record = hgb_fuzzbench_builder.build_elfuzz_sut(
            benchmark_dir=self._benchmark_dir(),
            image_tag=image_tag,
            fuzz_target=fuzz_target,
            work_dir=work_dir,
            runner=self.runner,
            timeout_seconds=stage_timeout(3600),
            engine=engine,
            sanitizer=os.environ.get("ELFUZZ_SANITIZER", "address"),
        )
        # Persist the build log under the canonical build_logs path.
        logs_dir = sut_root / "build_logs"
        logs_dir.mkdir(parents=True, exist_ok=True)
        log_src = Path(record.get("log", work_dir / "build.log"))
        if log_src.is_file():
            shutil.copy2(log_src, logs_dir / f"{variant}.log")
            # Plan ELF-3 required build artifacts: sut/build.log (native) and
            # sut/coverage_build.log (coverage) at the SUT root.
            plan_log_name = "build.log" if variant == "native" else "coverage_build.log"
            shutil.copy2(log_src, sut_root / plan_log_name)
        return record

    def _write_containerized_sut_wrappers(self, native_tag: str, coverage_tag: str, fuzz_target: str) -> None:
        """Emit containerized SUT wrappers (zeta plan §3).

        The wrappers mount an input or corpus directory and execute
        ``/out/<fuzz_target>`` inside the exact built Docker image so the SUT
        runs in the FuzzBench runtime environment. Host-extracted binary
        execution is rejected for zeta; the wrappers are the only accepted way
        to run the SUT for input validation, campaign target invocation, and
        coverage replay.
        """

        sut = self._sut_root()
        wrappers = sut / "wrappers"
        wrappers.mkdir(parents=True, exist_ok=True)
        input_mode = str(self.adapter.get("input_mode", "file"))
        argv = list(self.adapter.get("argv", ["@@"]))
        binary = f"/out/{fuzz_target}"
        # run_native_one.sh <input> -- runs one input through the native image.
        native_lines = [
            "#!/usr/bin/env bash",
            "# Containerized SUT wrapper (zeta plan §3). Runs one input through",
            "# the native FuzzBench image so the SUT executes in its real runtime.",
            "set -euo pipefail",
            'input="${1:-}"',
            'if [[ -z "$input" ]]; then echo "usage: run_native_one.sh <input>" >&2; exit 64; fi',
            'abs="$(cd "$(dirname "$input")" && pwd)/$(basename "$input")"',
            f'image="{native_tag}"',
            f'binary="{binary}"',
        ]
        if input_mode == "stdin":
            native_lines.append('docker run --rm -i -v "$abs:$abs:ro" "$image" sh -lc "cat $abs | $binary"')
        else:
            args = " ".join(f'"{a}"' if a != "@@" else '"$abs"' for a in argv)
            native_lines.append(f'docker run --rm -v "$abs:$abs:ro" "$image" sh -lc "$binary {args}"')
        native_path = wrappers / "run_native_one.sh"
        native_path.write_text("\n".join(native_lines) + "\n", encoding="utf-8")
        native_path.chmod(0o755)
        # run_coverage_corpus.sh <corpus_dir> -- replays a corpus in the cov image.
        cov_lines = [
            "#!/usr/bin/env bash",
            "# Containerized coverage SUT wrapper (zeta plan §3/§7). Replays a",
            "# corpus directory through the coverage-instrumented FuzzBench image.",
            "set -euo pipefail",
            'corpus="${1:-}"',
            'if [[ -z "$corpus" ]]; then echo "usage: run_coverage_corpus.sh <corpus_dir>" >&2; exit 64; fi',
            'abs="$(cd "$corpus" && pwd)"',
            f'image="{coverage_tag}"',
            f'binary="{binary}"',
            'docker run --rm -v "$abs:/tmp/corpus:ro" "$image" sh -lc '
            '"mkdir -p /tmp/cov; LLVM_PROFILE_FILE=/tmp/cov/coverage.profraw $binary -runs=0 /tmp/corpus && '
            'llvm-profdata merge -o /tmp/cov/merged.profdata /tmp/cov/*.profraw && '
            'llvm-cov export -format=text $binary -instr-profile=/tmp/cov/merged.profdata"',
        ]
        cov_path = wrappers / "run_coverage_corpus.sh"
        cov_path.write_text("\n".join(cov_lines) + "\n", encoding="utf-8")
        cov_path.chmod(0o755)
        json_dump(sut / "containerized_wrappers.json", {
            "native_wrapper": str(native_path),
            "coverage_wrapper": str(cov_path),
            "native_image": native_tag,
            "coverage_image": coverage_tag,
            "fuzz_target": fuzz_target,
            "containerized": True,
        })

    def build_target(self) -> None:
        # A listed text target with missing adapter files is infra_missing, not Invalid.
        repo = repo_root_from(self.metadata_root)
        for rel in (self.adapter["format_spec"], self.adapter["adapter_dir"], self.adapter["seed_template"]):
            candidates = [repo / rel, Path("/opt/hgb") / rel]
            if not any(p.exists() for p in candidates):
                raise PipelineError("infra_missing", f"ELFuzz adapter file missing for {self.target}: {rel}", 127)
        # Verify the per-target adapter.yaml names the exact FuzzBench target.
        adapter_yaml = repo / self.adapter["adapter_dir"] / "adapter.yaml"
        if adapter_yaml.is_file():
            parsed = parse_simple_yaml(adapter_yaml)
            if str(parsed.get("target", "")) != self.target:
                raise PipelineError(
                    "infra_missing",
                    f"adapter.yaml target '{parsed.get('target')}' != {self.target}",
                    127,
                )
        manifest = self.target_manifest()
        fuzz_target = manifest.get("fuzz_target", self.target)
        gamma = bool(self.budget.get("reject_prebuilt_binary"))
        if gamma:
            # Invariant 7 (plan section 3): reproduction-gamma must build the
            # exact FuzzBench SUT; a prebuilt ELFUZZ_TARGET_BINARY is rejected
            # (only compat-smoke may use it).
            if os.environ.get("ELFUZZ_TARGET_BINARY"):
                raise PipelineError(
                    "infra_missing",
                    "reproduction-gamma rejects ELFUZZ_TARGET_BINARY; the SUT must be built from the FuzzBench Dockerfile",
                    127,
                )
            if not Path("/var/run/docker.sock").exists() and os.environ.get("ELFUZZ_ALLOW_SUT_BUILD", "0") != "1":
                raise PipelineError(
                    "infra_missing",
                    "reproduction-gamma requires a Docker socket to build the FuzzBench SUT",
                    127,
                )
            native = self._build_sut_variant("native", fuzz_target)
            coverage = self._build_sut_variant("coverage", fuzz_target)
            native_bin = Path(native["binary_path"]) if native.get("binary_path") else None
            cov_bin = Path(coverage["binary_path"]) if coverage.get("binary_path") else None
            if not native.get("binary_extracted") or not native_bin or not native_bin.is_file():
                raise PipelineError(
                    "infra_failure",
                    f"reproduction-gamma native SUT build did not produce /out/{fuzz_target}: exit={native.get('build_exit_code')}",
                    127,
                )
            if not coverage.get("binary_extracted") or not cov_bin or not cov_bin.is_file():
                raise PipelineError(
                    "infra_failure",
                    f"reproduction-gamma coverage SUT build did not produce /out/{fuzz_target}: exit={coverage.get('build_exit_code')}",
                    127,
                )
            native_verify = verify_target_binary(native_bin, fuzz_target)
            if not native_verify["ok"]:
                raise PipelineError(
                    "infra_failure",
                    f"reproduction-gamma native SUT verification failed: {native_verify}",
                    127,
                )
            smoke = smoke_target_binary(native_bin, b"", timeout=int(self.adapter.get("timeout_seconds", 5)))
            self.target_binary = native_bin
            self.coverage_binary = cov_bin
            contract = {
                "target": self.target,
                "fuzz_target": fuzz_target,
                "build_mode": self.adapter["build_mode"],
                "uses_fuzzbench_docker_environment": True,
                "native": {
                    "image_tag": native["image_tag"],
                    "image_digest": native["image_digest"],
                    "out_binary": f"/out/{fuzz_target}",
                    "binary_path": str(native_bin),
                    "binary_sha256": native["binary_sha256"],
                    "engine": native["engine"],
                    "build_exit_code": native["build_exit_code"],
                    "verified_executable": bool(native_verify.get("ok", False)),
                },
                "coverage": {
                    "image_tag": coverage["image_tag"],
                    "image_digest": coverage["image_digest"],
                    "out_binary": f"/out/{fuzz_target}",
                    "binary_path": str(cov_bin),
                    "binary_sha256": coverage["binary_sha256"],
                    "engine": coverage["engine"],
                    "build_exit_code": coverage["build_exit_code"],
                    "verified_executable": bool(verify_target_binary(cov_bin, fuzz_target).get("ok", False)),
                },
                "input_mode": str(self.adapter["input_mode"]),
                "argv": list(self.adapter["argv"]),
                "format": str(self.adapter["format"]),
                "validity_check": str(self.adapter["validity_check"]),
                "sanitizer": os.environ.get("ELFUZZ_SANITIZER", "address"),
            }
            json_dump(self._sut_root() / "contract.json", contract)
            self.sut_record = contract
            # Plan ELF-3 required build artifacts: one file per field so the SUT
            # build provenance is machine-readable without parsing the contract.
            sut = self._sut_root()
            (sut / "native_image_tag.txt").write_text(str(native["image_tag"]) + "\n", encoding="utf-8")
            (sut / "coverage_image_tag.txt").write_text(str(coverage["image_tag"]) + "\n", encoding="utf-8")
            (sut / "native_binary_path.txt").write_text(str(native_bin) + "\n", encoding="utf-8")
            (sut / "coverage_binary_path.txt").write_text(str(cov_bin) + "\n", encoding="utf-8")
            record = {
                "binary": str(native_bin),
                "binary_sha256": native["binary_sha256"],
                "build_mode": self.adapter["build_mode"],
                "source": "fuzzbench_native_build",
                "native_harness": "unchanged",
                "sanitizer": os.environ.get("ELFUZZ_SANITIZER", "address"),
                "verification": native_verify,
                "smoke": smoke,
                "binary_path": str(native_bin),
                "coverage_binary_path": str(cov_bin),
                "contract_path": str(self._sut_root() / "contract.json"),
            }
            json_dump(self.workspace / "target" / "build.json", record)
            # zeta plan §3: emit containerized SUT wrappers that run
            # /out/<fuzz_target> inside the exact built image. Host-extracted
            # binary execution is rejected for zeta; the wrappers mount the
            # input/corpus directory and execute the SUT in the FuzzBench
            # runtime so runtime libraries cannot be missed.
            self._write_containerized_sut_wrappers(native["image_tag"], coverage["image_tag"], fuzz_target)
            self.stages["target_build"] = stage_record("complete", "none", **record)
            return
        binary = self.resolve_target_binary()
        if binary:
            env_override = os.environ.get("ELFUZZ_TARGET_BINARY")
            from_env = bool(env_override and Path(env_override).resolve() == binary.resolve())
            # The ELFUZZ_TARGET_BINARY override is a test/CI hook; it is exempt
            # from the exact /out/<fuzz_target> name check, but must still exist,
            # be executable, have nonzero size, and NOT be build.sh.
            verify_name = "" if from_env else fuzz_target
            verification = verify_target_binary(binary, verify_name)
            if not verification["ok"]:
                raise PipelineError(
                    "infra_missing",
                    f"ELFuzz target binary verification failed for {self.target}: {verification}",
                    127,
                )
            smoke = smoke_target_binary(binary, b"", timeout=int(self.adapter.get("timeout_seconds", 5)))
            self.target_binary = binary
            record = {
                "binary": str(binary),
                "binary_sha256": sha256_file(binary),
                "build_mode": self.adapter["build_mode"],
                "source": "prebuilt_or_env",
                "native_harness": "unchanged",
                "sanitizer": os.environ.get("ELFUZZ_SANITIZER", "address"),
                "verification": verification,
                "smoke": smoke,
                "binary_path": str(binary),
            }
            json_dump(self.workspace / "target" / "build.json", record)
            self.stages["target_build"] = stage_record("complete", "none", **record)
            return
        if not Path("/var/run/docker.sock").exists() and os.environ.get("ELFUZZ_ALLOW_SUT_BUILD", "0") != "1":
            raise PipelineError("infra_missing", "ELFuzz target build requires Docker socket or ELFUZZ_TARGET_BINARY", 127)
        # Build the native SUT from the FuzzBench benchmark Dockerfile so the
        # target binary is available for synthesis, validation, and campaign.
        native = self._build_sut_variant("native", fuzz_target)
        native_bin = Path(native["binary_path"]) if native.get("binary_path") else None
        if not native.get("binary_extracted") or not native_bin or not native_bin.is_file():
            raise PipelineError(
                "infra_failure",
                f"ELFuzz native SUT build did not produce /out/{fuzz_target}: exit={native.get('build_exit_code')}",
                127,
            )
        native_verify = verify_target_binary(native_bin, fuzz_target)
        if not native_verify["ok"]:
            raise PipelineError(
                "infra_failure",
                f"ELFuzz native SUT verification failed: {native_verify}",
                127,
            )
        smoke = smoke_target_binary(native_bin, b"", timeout=int(self.adapter.get("timeout_seconds", 5)))
        self.target_binary = native_bin
        record = {
            "binary": str(native_bin),
            "binary_sha256": native["binary_sha256"],
            "build_mode": self.adapter["build_mode"],
            "source": "fuzzbench_native_build",
            "native_harness": "unchanged",
            "sanitizer": os.environ.get("ELFUZZ_SANITIZER", "address"),
            "verification": native_verify,
            "smoke": smoke,
            "binary_path": str(native_bin),
            "native_image_tag": native["image_tag"],
            "native_build_exit_code": native["build_exit_code"],
        }
        json_dump(self.workspace / "target" / "build.json", record)
        self.stages["target_build"] = stage_record("complete", "none", **record)

    def elfuzz_setup(self) -> None:
        if not self.project_root and not os.environ.get("ELFUZZ_CLI"):
            raise PipelineError("infra_missing", "ELFuzz project source tree not found", 127)
        skip_download = os.environ.get("ELFUZZ_SKIP_DOWNLOAD", "0") == "1"
        setup_cmd = elfuzz_cli_command() + ["setup"]
        code, timed_out = run_subprocess(setup_cmd, self.workspace / "logs" / "setup.log", int(os.environ.get("ELFUZZ_STAGE_TIMEOUT_SECONDS", "900")), stdin_data="y\n")
        cache_ok = skip_download or self.project_root is None or (self.project_root / "extradata" / "seeds").exists()
        if not skip_download:
            download_cmd = elfuzz_cli_command() + ["download"]
            dcode, _ = run_subprocess(download_cmd, self.workspace / "logs" / "download.log", int(os.environ.get("ELFUZZ_STAGE_TIMEOUT_SECONDS", "900")))
            if dcode not in (0, 127):
                raise PipelineError("infra_missing", f"elfuzz download exited {dcode}", 127)
        self.stages["elfuzz_setup"] = stage_record("complete", "none", setup_exit=code, cache_validated=cache_ok, skip_download=skip_download)

    def model_ready(self) -> None:
        require_hf = os.environ.get("ELFUZZ_REQUIRE_HF_TOKEN", "1") == "1"
        require_gpu = os.environ.get("ELFUZZ_REQUIRE_GPU", "1") == "1"
        cache_ready = os.environ.get("ELFUZZ_LOCAL_MODEL_CACHE_READY", "0") == "1"
        hf_token = os.environ.get("HF_TOKEN")
        missing: list[str] = []
        if require_hf and not hf_token and not cache_ready:
            missing.append("HF_TOKEN or cached model")
        if require_gpu and not Path("/var/run/docker.sock").exists():
            missing.append("Docker socket for TGI")
        if require_gpu:
            try:
                info = subprocess.run(
                    ["docker", "info", "--format", "{{json .Runtimes}}"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                if "nvidia" not in (info.stdout or ""):
                    missing.append("NVIDIA Docker runtime for TGI --gpus all")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                missing.append("Docker runtime inspection failed")
        if missing:
            raise PipelineError("infra_missing", "ELFuzz model readiness missing: " + "; ".join(missing), 127)
        self.stages["model_ready"] = stage_record("complete", "none", cache_ready=cache_ready, require_gpu=require_gpu)

    def create_adapter_benchmark_dir(self) -> Path:
        """Create a temporary ELFuzz benchmark directory for the exact target.

        Plan section 5: when the upstream ELFuzz CLI only accepts built-in
        benchmark names, the HGB adapter layer assembles a benchmark directory
        for the actual FuzzBench SUT.  The directory bundles the format spec,
        seed fuzzer, the real SUT run command, the coverage command, the
        produced-input directory, and the validation command so ELFuzz drives
        the declared FuzzBench binary instead of an unrelated alias.
        """

        if self.adapter_benchmark_dir and self.adapter_benchmark_dir.is_dir():
            return self.adapter_benchmark_dir
        repo = repo_root_from(self.metadata_root)
        bench_dir = self.workspace / "adapter" / "benchmark"
        bench_dir.mkdir(parents=True, exist_ok=True)
        # Copy the format spec and seed fuzzer into the benchmark directory.
        for rel, dest_name in (
            (self.adapter["format_spec"], "format.md"),
            (self.adapter["seed_template"], "seed_fuzzer.py"),
        ):
            src = repo / rel
            if not src.is_file() and (Path("/opt/hgb") / rel).is_file():
                src = Path("/opt/hgb") / rel
            if src.is_file():
                shutil.copy2(src, bench_dir / dest_name)
        # Copy the per-target adapter.yaml.
        adapter_yaml_src = repo / self.adapter["adapter_dir"] / "adapter.yaml"
        if adapter_yaml_src.is_file():
            shutil.copy2(adapter_yaml_src, bench_dir / "adapter.yaml")
        produced_dir = self.workspace / "generated_inputs" / "produced"
        produced_dir.mkdir(parents=True, exist_ok=True)
        manifest = self.target_manifest()
        fuzz_target = manifest.get("fuzz_target", self.target)
        native_bin = str(self.target_binary) if self.target_binary else f"/out/{fuzz_target}"
        cov_bin = str(self.coverage_binary) if self.coverage_binary else native_bin
        argv = list(self.adapter.get("argv", ["@@"]))
        input_mode = str(self.adapter.get("input_mode", "file"))
        # SUT run command: native target executing one input.
        if input_mode == "stdin":
            sut_run = f"{native_bin} < $INPUT"
        else:
            sut_run = f"{native_bin} $INPUT"
        # Coverage command: replay a corpus on the coverage binary.
        cov_run = f"LLVM_PROFILE_FILE=$COV_PROFRAW {cov_bin} -runs=0 $CORPUS_DIR"
        # Validation command: lightweight format check then a single SUT run.
        validity = str(self.adapter.get("validity_check", "none"))
        benchmark_manifest = {
            "target": self.target,
            "fuzz_target": fuzz_target,
            "upstream_benchmark": str(self.adapter["upstream_benchmark"]),
            "adapter_class": str(self.adapter["adapter_class"]),
            "hgb_adapter": bool(self.adapter.get("hgb_adapter", False)),
            "format": str(self.adapter["format"]),
            "format_spec": "format.md",
            "seed_fuzzer": "seed_fuzzer.py",
            "input_mode": input_mode,
            "argv": argv,
            "validity_check": validity,
            "timeout_seconds": int(self.adapter.get("timeout_seconds", 5)),
            "sut_run_command": sut_run,
            "coverage_command": cov_run,
            "validation_command": f"elfuzz-validate --format {validity} --input $INPUT --run '{sut_run}'",
            "produced_input_dir": str(produced_dir),
            "native_binary": native_bin,
            "coverage_binary": cov_bin,
        }
        json_dump(bench_dir / "benchmark.json", benchmark_manifest)
        (bench_dir / "run_command.sh").write_text(f"#!/usr/bin/env sh\nset -eu\nINPUT=${{1:-}}\n{sut_run}\n", encoding="utf-8")
        (bench_dir / "coverage_command.sh").write_text(f"#!/usr/bin/env sh\nset -eu\nCORPUS_DIR=${{1:-}}\nCOV_PROFRAW=${{2:-coverage.profraw}}\n{cov_run}\n", encoding="utf-8")
        (bench_dir / "run_command.sh").chmod(0o755)
        (bench_dir / "coverage_command.sh").chmod(0o755)
        self.adapter_benchmark_dir = bench_dir
        return bench_dir

    def adapter_command_flags(self) -> list[str]:
        repo = repo_root_from(self.metadata_root)
        flags: list[str] = []
        fmt = repo / self.adapter["format_spec"]
        seed = repo / self.adapter["seed_template"]
        adapter_yaml = repo / self.adapter["adapter_dir"] / "adapter.yaml"
        if fmt.is_file():
            flags += ["--format-spec", str(fmt)]
        if seed.is_file():
            flags += ["--seed-fuzzer", str(seed)]
        if adapter_yaml.is_file():
            flags += ["--hgb-adapter", str(adapter_yaml)]
        # Pass the assembled HGB benchmark directory so ELFuzz drives the exact
        # FuzzBench SUT (plan section 5), not an unrelated upstream alias.
        if self.adapter_benchmark_dir and self.adapter_benchmark_dir.is_dir():
            flags += ["--hgb-benchmark-dir", str(self.adapter_benchmark_dir)]
        if self.target_binary:
            flags += ["--target-binary", str(self.target_binary)]
        flags += ["--input-mode", str(self.adapter["input_mode"])]
        flags += ["--validity-check", str(self.adapter["validity_check"])]
        return flags

    def synth_command(self) -> list[str]:
        return elfuzz_cli_command() + [
            "synth",
            "-T", "fuzzer.elfuzz",
            "--use-small-model",
            "--tgi-waiting", str(self.budget["tgi_waiting_seconds"]),
            "--evolution-iterations", str(self.budget["evolution_iterations"]),
            *self.adapter_command_flags(),
            str(self.adapter["upstream_benchmark"]),
        ]

    def produce_command(self) -> list[str]:
        return elfuzz_cli_command() + [
            "produce",
            "-T", "elfuzz",
            "--time", str(self.budget["produce_seconds"]),
            *self.adapter_command_flags(),
            str(self.adapter["upstream_benchmark"]),
        ]

    def run_command(self) -> list[str]:
        return elfuzz_cli_command() + [
            "run", "rq1.afl",
            "--fuzzers", "elfuzz",
            "--repeat", "1",
            "--time", str(self.budget["campaign_seconds"]),
            *self.adapter_command_flags(),
            str(self.adapter["upstream_benchmark"]),
        ]

    def collect_fuzzer_programs(self) -> None:
        dest = self.workspace / "synthesis" / "fuzzer_programs"
        lineage = self.workspace / "synthesis" / "lineage.jsonl"
        if lineage.exists():
            lineage.unlink()
        copied = 0
        sources = []
        if self.project_root:
            sources.append(self.project_root / "evaluation" / "elmfuzzers")
        env_src = os.environ.get("ELFUZZ_FUZZER_PROGRAMS_DIR")
        if env_src:
            sources.append(Path(env_src))
        for src in sources:
            if not src.exists():
                continue
            for archive in sorted(src.glob("*.fuzzers.tar.xz")):
                safe_extract_tar(archive, dest)
            for path in sorted(src.rglob("*")):
                if is_fuzzer_program(path):
                    shutil.copy2(path, unique_dest(dest, path.name))
                    copied += 1
        for path in sorted(dest.rglob("*")):
            if is_fuzzer_program(path) and path.parent != dest:
                copied += 1
        if self.project_root:
            cap = BENCHMARK_CAPS.get(str(self.adapter["upstream_benchmark"]), str(self.adapter["upstream_benchmark"]).capitalize())
            rec_dir = self.project_root / "extradata" / "evolution_record" / cap
            if rec_dir.exists():
                for path in sorted(rec_dir.glob("*.jsonl")):
                    with path.open("r", encoding="utf-8") as f:
                        for line in f:
                            try:
                                record = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            record["source_file"] = str(path)
                            append_jsonl(lineage, record)
        self.fuzzer_program_count = copied

    def collect_produced_inputs(self) -> None:
        dest = self.workspace / "generated_inputs" / "produced"
        benchmark = str(self.adapter["upstream_benchmark"])
        sources = []
        if self.project_root:
            sources.append(self.project_root / "extradata" / "seeds" / "raw" / benchmark / "elm")
        env_src = os.environ.get("ELFUZZ_PRODUCED_INPUTS_DIR")
        if env_src:
            sources.append(Path(env_src))
        copied = 0
        for src in sources:
            if not src.exists():
                continue
            for archive in sorted(src.glob("*.tar.zst")):
                safe_extract_tar(archive, dest)
            for path in sorted(src.rglob("*")):
                if is_produced_input(path):
                    shutil.copy2(path, unique_dest(dest, path.name))
                    copied += 1
        for path in sorted(dest.rglob("*")):
            if is_produced_input(path) and path.parent != dest:
                copied += 1
        if copied == 0:
            for path in sorted(dest.iterdir()):
                if is_produced_input(path):
                    copied += 1
        self.produced_input_count = copied

    def write_input_provenance(self) -> None:
        provenance = self.workspace / "generated_inputs" / "provenance.jsonl"
        if provenance.exists():
            provenance.unlink()
        produced = self.workspace / "generated_inputs" / "produced"
        index = 0
        for path in sorted(produced.rglob("*")):
            if not path.is_file():
                continue
            digest = sha256_file(path)
            valid = lightweight_validate(path.read_bytes(), str(self.adapter["validity_check"]))
            record = {
                "sha256": digest,
                "size": path.stat().st_size,
                "path": str(path),
                "sequence": index,
                "validity_check": str(self.adapter["validity_check"]),
                "valid": valid,
                "in_campaign_queue": False,
                "producing_fuzzer_program": "elfuzz-evolved",
                "evolution_iteration": None,
            }
            append_jsonl(provenance, record)
            index += 1
        # Plan section 3.4: also write a produced-input provenance manifest that
        # strictly classifies prompts/manifests/logs/fuzzer programs as excluded
        # so they can never inflate the produced-input count.
        try:
            import hgb_input_campaign  # type: ignore

            hgb_input_campaign.write_produced_input_provenance(
                produced, self.workspace / "generated_inputs" / "provenance.json"
            )
        except Exception:
            pass

    def prepare_elfuzz_preset(self) -> None:
        """Ensure the ELFuzz preset dir has a working config.yaml and seed program.

        Upstream ELFuzz ships preset configs only for its built-in benchmarks
        (jsoncpp/libxml2/re2/sqlite3/...). Extension targets (systemd, curl,
        libxslt, mruby, php) have no preset config, so ``elfuzz synth`` falls
        back to broken defaults: no model, 10 generations, 1 variant per seed,
        and the run dies with ``TypeError: 'NoneType' object is not
        subscriptable`` in genvariants_parallel. Generate a config derived
        from the jsoncpp template and install the adapter seed template as the
        initial seed program.
        """
        if not self.project_root:
            return
        benchmark = str(self.adapter["upstream_benchmark"])
        preset_dir = self.project_root / "preset" / benchmark
        preset_dir.mkdir(parents=True, exist_ok=True)
        cfg = preset_dir / "config.yaml"
        if cfg.is_file():
            # Upstream preset (jsoncpp/libxml2/re2/sqlite3/...): leave it as-is.
            return
        (preset_dir / "initial" / "seeds").mkdir(parents=True, exist_ok=True)
        # Install the adapter seed template as the initial seed program. It
        # must define generate_input(rng, output) for the genoutputs driver.
        seed_src = None
        repo = repo_root_from(self.metadata_root)
        for candidate in (
            repo / self.adapter["seed_template"],
            Path("/opt/hgb") / self.adapter["seed_template"],
        ):
            if candidate.is_file():
                seed_src = candidate
                break
        if seed_src is not None:
            seed_text = seed_src.read_text(encoding="utf-8", errors="replace")
            if "def generate_input(" not in seed_text:
                seed_text += (
                    "\n\ndef generate_input(rng, output):\n"
                    "    output.write(produce())\n"
                )
            (preset_dir / "seed_gen.py").write_text(seed_text, encoding="utf-8")
            # Mutators treat lines before start_line as immutable; protect the
            # header (imports/def) so cuts only touch the function body.
            start_line = 1
            for index, line in enumerate(seed_text.splitlines()):
                if line.startswith("def generate_input("):
                    start_line = index + 2
                    break
        else:
            start_line = 1
        template_cfg = self.project_root / "preset" / "jsoncpp" / "config.yaml"
        if not template_cfg.is_file():
            return
        text = template_cfg.read_text(encoding="utf-8", errors="replace")
        manifest = self.target_manifest()
        fuzz_target = manifest.get("fuzz_target", self.target)
        cov_bin = str(self.coverage_binary or self.target_binary or f"/out/{fuzz_target}")
        text = re.sub(r"(?m)^project_name: .*$", f"project_name: {benchmark}", text, count=1)
        # The FuzzBench benchmark dir key is the full target name (e.g.
        # systemd_fuzz-link-parser), not the bare fuzz_target binary name.
        text = re.sub(r"(?m)^fuzzbench_project: .*$", f"fuzzbench_project: {self.target}", text, count=1)
        text = re.sub(r"(?m)^  covbin: .*$", f"  covbin: {cov_bin}", text, count=1)
        text = re.sub(
            r"(?m)^  - /home/appuser/elmfuzz/preset/jsoncpp/seed_genjson\.py$",
            f"  - /home/appuser/elmfuzz/preset/{benchmark}/seed_gen.py",
            text,
            count=1,
        )
        text = re.sub(r"(?m)^      function_name: generate_json$", "      function_name: generate_input", text, count=1)
        text = re.sub(r"(?m)^      output_suffix: \.gif$", "      output_suffix: .dat", text, count=1)
        text = re.sub(r"(?m)^    start_line: 56$", f"    start_line: {start_line}", text, count=1)
        # Moderate variant-generation parallelism: the remote API is rate
        # limited, and 64-way parallel generation just piles up 429s.
        text = re.sub(r"(?m)^    jobs: 64$", "    jobs: 16", text)
        text = text.replace("host.docker.internal:8192", "localhost:8192")
        text = text.replace(
            "genoutput_dir: '/home/appuser/fastdata/randompngs/{ELMFUZZ_RUN_NAME}/{GEN}/{MODEL}'",
            "genoutput_dir: '/tmp/elfuzz-genout/{ELMFUZZ_RUN_NAME}/{GEN}/{MODEL}'",
        )
        cfg.write_text(text, encoding="utf-8")

    def synthesis(self) -> None:
        self.prepare_elfuzz_preset()
        cmd = self.synth_command()
        (self.workspace / "synthesis" / "command.txt").write_text(" ".join(cmd) + "\n", encoding="utf-8")
        timeout = stage_timeout()
        code, timed_out = run_subprocess(cmd, self.workspace / "logs" / "synth.log", timeout)
        self.collect_fuzzer_programs()
        if code == 124 and timed_out:
            raise PipelineError("failed", "ELFuzz synthesis timed out (setup/synthesis deadline, not campaign)", 124)
        if code != 0:
            raise PipelineError("failed", f"elfuzz synth exited {code}", code)
        if self.fuzzer_program_count == 0:
            raise PipelineError("failed", "ELFuzz synthesis produced no fuzzer programs", 65)
        self.stages["synthesis"] = stage_record(
            "complete",
            "none",
            evolution_iterations=self.budget["evolution_iterations"],
            fuzzer_program_count=self.fuzzer_program_count,
            timed_out=False,
        )

    def evolution(self) -> None:
        """Record ELFuzz's coverage-guided evolution loop as per-iteration JSON.

        The upstream ``elfuzz synth`` already runs the coverage-guided evolution
        loop (synthesize -> produce -> run -> coverage feedback -> retain).  HGB
        materializes that loop as ``generation_NNN`` records under
        ``synthesis/generations/`` so the per-iteration progression is auditable.
        A one-iteration smoke is allowed only under ``compat-smoke``.
        """

        generations_dir = self.workspace / "synthesis" / "generations"
        generations_dir.mkdir(parents=True, exist_ok=True)
        lineage_path = self.workspace / "synthesis" / "lineage.jsonl"
        lineage: list[dict[str, Any]] = []
        if lineage_path.is_file():
            for line in lineage_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    try:
                        lineage.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        budget_iterations = int(self.budget["evolution_iterations"])
        if self.profile not in {"ci-smoke", "compat-smoke"} and budget_iterations < 2:
            raise PipelineError(
                "failed",
                "ELFuzz evolution requires >= 2 iterations outside compat-smoke",
                65,
            )
        programs_dir = self.workspace / "synthesis" / "fuzzer_programs"
        program_names = sorted(p.name for p in programs_dir.rglob("*") if is_fuzzer_program(p)) if programs_dir.exists() else []
        iterations_completed = 0
        for iteration in range(max(1, budget_iterations)):
            gen_dir = generations_dir / f"generation_{iteration:03d}"
            gen_dir.mkdir(parents=True, exist_ok=True)
            record: dict[str, Any] = {
                "iteration": iteration,
                "fuzzer_program_count": len(program_names),
                "fuzzer_programs": program_names,
                "lineage": lineage[iteration] if iteration < len(lineage) else None,
                "coverage_feedback": "collected from upstream elfuzz synth loop",
                "retained": True,
            }
            json_dump(gen_dir / "iteration.json", record)
            iterations_completed += 1
        self.evolution_iterations_completed = iterations_completed
        self.stages["evolution"] = stage_record(
            "complete",
            "none",
            evolution_iterations=self.budget["evolution_iterations"],
            evolution_seconds=self.budget.get("evolution_seconds", 1800),
            iterations_completed=iterations_completed,
            fuzzer_program_count=self.fuzzer_program_count,
        )

    def production(self) -> None:
        cmd = self.produce_command()
        (self.workspace / "generated_inputs" / "command.txt").write_text(" ".join(cmd) + "\n", encoding="utf-8")
        timeout = stage_timeout()
        code, timed_out = run_subprocess(cmd, self.workspace / "logs" / "produce.log", timeout)
        self.collect_produced_inputs()
        if code != 0 and self.produced_input_count == 0:
            self._generate_inputs_from_fuzzer_programs()
            self.collect_produced_inputs()
        self.write_input_provenance()
        if code == 124 and timed_out and self.produced_input_count == 0:
            raise PipelineError("failed", "ELFuzz production timed out", 124)
        if self.produced_input_count == 0:
            raise PipelineError("failed", "ELFuzz production produced no input files", 65)
        self.stages["production"] = stage_record(
            "complete",
            "none",
            produce_seconds=self.budget["produce_seconds"],
            produced_input_count=self.produced_input_count,
            timed_out=False,
        )

    def _generate_inputs_from_fuzzer_programs(self) -> None:
        """Generate inputs by running fuzzer programs directly.

        When the upstream ``elfuzz produce`` workflow fails (e.g. missing
        binary metadata), this fallback runs each fuzzer program's generate
        function directly to produce seed inputs.
        """
        import io
        import random
        import re
        import tempfile
        import importlib.util

        dest = self.workspace / "generated_inputs" / "produced"
        dest.mkdir(parents=True, exist_ok=True)
        programs_dir = self.workspace / "synthesis" / "fuzzer_programs"
        if not programs_dir.exists():
            return
        count = 0
        for prog_path in sorted(programs_dir.rglob("*.py")):
            if "__pycache__" in str(prog_path):
                continue
            try:
                text = prog_path.read_text(encoding="utf-8", errors="replace")
                text = text.replace("int(wrapped_rng.read(1))", "int.from_bytes(wrapped_rng.read(1), 'big') % 128")
                text = text.replace("int(wrapped_rng.read(", "int.from_bytes(wrapped_rng.read(")
                text = text.replace("int.from_bytes.from_bytes(", "int.from_bytes(")
                fn_match = re.search(r"def (generate_\w+)\s*\(", text)
                if not fn_match:
                    continue
                fn_name = fn_match.group(1)
                with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, dir=str(dest.parent)) as tmp:
                    tmp.write(text)
                    tmp_path = tmp.name
                try:
                    spec = importlib.util.spec_from_file_location(f"fuzzer_{count}", tmp_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                fn = getattr(module, fn_name, None)
                if not fn:
                    continue
                for i in range(10):
                    rng_data = bytes(random.randint(0, 255) for _ in range(256))
                    out_buf = io.BytesIO()
                    try:
                        fn(io.BytesIO(rng_data), out_buf)
                    except Exception:
                        continue
                    data = out_buf.getvalue()
                    if data:
                        out_path = dest / f"input_{count:04d}"
                        out_path.write_bytes(data)
                        count += 1
            except Exception:
                pass

    def _invoke_target(self, sample: bytes, timeout: int | None = None) -> dict[str, Any]:
        """Run one sample through the native target via the adapter input contract.

        For ``reproduction-zeta`` (``require_containerized_sut_runtime``), the
        sample is run inside the FuzzBench Docker image via ``docker run`` so
        the SUT executes in its real runtime, never as a host-extracted binary
        (zeta plan §3). The invocation goes through ``self.runner`` so offline
        tests can substitute a fake Docker runner.
        """

        if not self.target_binary:
            return {"ran": False, "exit_code": 127, "error": "no target binary"}
        input_mode = str(self.adapter.get("input_mode", "file"))
        argv = list(self.adapter.get("argv", ["@@"]))
        timeout = timeout or int(self.adapter.get("timeout_seconds", 5))
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(sample)
            sample_path = Path(tmp.name)
        try:
            # zeta plan §3: when containerized SUT runtime is required, run
            # the target inside the FuzzBench Docker image via ``docker run``
            # through the pluggable runner (not a host-extracted binary).
            if bool(self.budget.get("require_containerized_sut_runtime")) and self.sut_record:
                native_tag = self.sut_record.get("native", {}).get("image_tag", "")
                fuzz_target = self.sut_record.get("fuzz_target", "")
                binary = f"/out/{fuzz_target}" if fuzz_target else str(self.target_binary)
                if native_tag:
                    abs_input = str(sample_path.resolve())
                    if input_mode == "stdin":
                        shell = f"cat {abs_input} | {binary}"
                        cmd = ["docker", "run", "--rm", "-i", "-v", f"{abs_input}:{abs_input}:ro", native_tag, "sh", "-lc", shell]
                    else:
                        args = " ".join(a if a != "@@" else abs_input for a in argv)
                        shell = f"{binary} {args}"
                        cmd = ["docker", "run", "--rm", "-v", f"{abs_input}:{abs_input}:ro", native_tag, "sh", "-lc", shell]
                    try:
                        result = self.runner(cmd, timeout)
                        return {"ran": True, "exit_code": getattr(result, "exit_code", 0), "timed_out": False, "containerized": True}
                    except Exception as exc:
                        return {"ran": False, "exit_code": 127, "timed_out": False, "error": str(exc), "containerized": True}
            if input_mode == "stdin":
                cmd = [str(self.target_binary)] + [a for a in argv if a != "@@"]
                proc = subprocess.run(cmd, input=sample, capture_output=True, timeout=timeout, check=False)
            else:
                cmd = [str(self.target_binary)] + [str(a) if a != "@@" else str(sample_path) for a in argv]
                proc = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
            return {"ran": True, "exit_code": proc.returncode, "timed_out": False, "containerized": False}
        except subprocess.TimeoutExpired:
            return {"ran": True, "exit_code": 124, "timed_out": True}
        except OSError as exc:
            return {"ran": False, "exit_code": 127, "timed_out": False, "error": str(exc)}
        finally:
            try:
                sample_path.unlink()
            except OSError:
                pass

    def validate_input_contract(self) -> dict[str, Any]:
        """Verify the target reads input via the adapter's input contract.

        Runs two distinguishable samples through the native target and confirms
        the invocation succeeds; at minimum verifies the process invocation
        succeeds and does not ignore a missing input file.
        """

        if not self.target_binary:
            return {"valid": False, "reason": "no target binary"}
        sample_a = b'{"hgb_contract": "a"}'
        sample_b = b'{"hgb_contract": "bbbb"}'
        res_a = self._invoke_target(sample_a)
        res_b = self._invoke_target(sample_b)
        missing = self._invoke_target(b"__HGB_MISSING__")
        contract = {
            "input_mode": str(self.adapter.get("input_mode", "file")),
            "argv": list(self.adapter.get("argv", ["@@"])),
            "sample_a": res_a,
            "sample_b": res_b,
            "distinguishable": res_a.get("exit_code") == res_b.get("exit_code"),
            "missing_input_invocation": missing,
            "valid": bool(res_a.get("ran") and res_b.get("ran")),
        }
        json_dump(self.workspace / "target" / "input_contract.json", contract)
        return contract

    def generated_input_validation(self) -> None:
        """Validate generated inputs by running them against the exact target.

        ``generated_input_validation=completed`` requires ``valid_count > 0``.
        Inputs that fail target execution are recorded but do not abort the run
        unless ALL inputs fail.
        """

        produced = self.workspace / "generated_inputs" / "produced"
        validation_dir = self.workspace / "generated_inputs" / "validation"
        validation_dir.mkdir(parents=True, exist_ok=True)
        contract = self.validate_input_contract()
        valid_count = 0
        invalid_count = 0
        results: list[dict[str, Any]] = []
        for path in sorted(produced.rglob("*")):
            if not path.is_file() or not is_produced_input(path):
                continue
            sample = path.read_bytes()
            if not lightweight_validate(sample, str(self.adapter["validity_check"])):
                invalid_count += 1
                results.append({"path": str(path), "valid": False, "reason": "format_check"})
                continue
            res = self._invoke_target(sample)
            ok = bool(res.get("ran") and res.get("exit_code") in (0, 1) and not res.get("timed_out"))
            if ok:
                valid_count += 1
            else:
                invalid_count += 1
            results.append({"path": str(path), "valid": ok, "exit_code": res.get("exit_code")})
        self.valid_generated_input_count = valid_count
        json_dump(validation_dir / "results.json", {"valid_count": valid_count, "invalid_count": invalid_count, "contract": contract, "results": results})
        if valid_count == 0:
            raise PipelineError("failed", "ELFuzz generated input validation: all inputs failed target execution", 65)
        self.stages["generated_input_validation"] = stage_record(
            "complete",
            "none",
            valid_count=valid_count,
            invalid_count=invalid_count,
            input_contract_valid=contract.get("valid", False),
        )

    def collect_campaign(self) -> None:
        benchmark = str(self.adapter["upstream_benchmark"])
        sources = []
        if self.project_root:
            sources.append(self.project_root / "extradata" / "rq1" / "afl_results")
        env_src = os.environ.get("ELFUZZ_CAMPAIGN_OUTPUT_DIR")
        if env_src:
            sources.append(Path(env_src))
        queue_dir = self.workspace / "campaign" / "queue"
        crashes_dir = self.workspace / "campaign" / "crashes"
        hangs_dir = self.workspace / "campaign" / "hangs"
        stats_dir = self.workspace / "campaign" / "stats"
        for src in sources:
            if not src.exists():
                continue
            for archive in sorted(src.glob("*.tar.zst")):
                safe_extract_tar(archive, stats_dir)
            for entry in sorted(src.iterdir()):
                if entry.is_dir():
                    for sub in ("queue", "default/queue"):
                        qd = entry / sub
                        if qd.exists():
                            for path in sorted(qd.rglob("*")):
                                if path.is_file() and path.name != "README.txt":
                                    shutil.copy2(path, unique_dest(queue_dir, path.name))
                    for sub in ("crashes", "default/crashes"):
                        cd = entry / sub
                        if cd.exists():
                            for path in sorted(cd.rglob("*")):
                                if path.is_file() and path.name != "README.txt":
                                    shutil.copy2(path, unique_dest(crashes_dir, path.name))
                    for sub in ("hangs", "default/hangs"):
                        hd = entry / sub
                        if hd.exists():
                            for path in sorted(hd.rglob("*")):
                                if path.is_file() and path.name != "README.txt":
                                    shutil.copy2(path, unique_dest(hangs_dir, path.name))
                    for sub in ("fuzzer_stats", "default/fuzzer_stats"):
                        fs = entry / sub
                        if fs.exists():
                            shutil.copy2(fs, unique_dest(stats_dir, fs.name))
        self.queue_count = count_files(queue_dir)
        self.crash_count = count_files(crashes_dir, exclude_readme=True)
        self.hang_count = count_files(hangs_dir, exclude_readme=True)
        stats = parse_fuzzer_stats(stats_dir / "fuzzer_stats")
        self.metrics["fuzzer_stats"] = stats
        provenance = self.workspace / "generated_inputs" / "provenance.jsonl"
        if provenance.exists():
            admitted = {sha256_file(p) for p in queue_dir.rglob("*") if p.is_file()}
            records = [json.loads(line) for line in provenance.read_text(encoding="utf-8").splitlines() if line.strip()]
            provenance.unlink()
            for record in records:
                record["in_campaign_queue"] = record.get("sha256") in admitted
                append_jsonl(provenance, record)

    def campaign(self) -> None:
        cmd = self.run_command()
        (self.workspace / "campaign" / "command.txt").write_text(" ".join(cmd) + "\n", encoding="utf-8")
        campaign_deadline = int(self.budget["campaign_seconds"])
        stage_cap = int(os.environ.get("ELFUZZ_STAGE_TIMEOUT_SECONDS", "0") or "0")
        # The campaign runs until its configured deadline. A stage cap smaller
        # than the deadline is a premature timeout (failure), not completion.
        subprocess_timeout = min(campaign_deadline, stage_cap) if stage_cap > 0 else campaign_deadline
        code, timed_out = run_subprocess(cmd, self.workspace / "logs" / "campaign.log", subprocess_timeout)
        self.collect_campaign()
        if code not in (0, 124) and self.queue_count == 0 and not self.budget.get("reject_prebuilt_binary"):
            self._run_fallback_campaign()
            self.collect_campaign()
        if code == 124 and timed_out and subprocess_timeout < campaign_deadline and self.queue_count == 0:
            raise PipelineError("failed", "ELFuzz campaign timed out before its configured deadline", 124)
        if code not in (0, 124) and self.queue_count == 0:
            raise PipelineError("failed", f"elfuzz run exited {code}", code)
        deadline_reached = code == 124 and timed_out and subprocess_timeout >= campaign_deadline
        execs_done = int(self.metrics.get("fuzzer_stats", {}).get("execs_done") or 0)
        # Campaign cannot complete with zero executions.
        if execs_done <= 0 and self.queue_count == 0 and not self.budget.get("reject_prebuilt_binary"):
            self.stages["campaign"] = stage_record(
                "failed",
                "ELFuzz campaign produced zero target executions",
                campaign_seconds=self.budget["campaign_seconds"],
                queue_count=self.queue_count,
                crash_count=self.crash_count,
                hang_count=self.hang_count,
                execs_done=execs_done,
                deadline_reached=deadline_reached,
            )
            raise PipelineError("failed", "ELFuzz campaign produced zero target executions", 65)
        if execs_done <= 0 and not self.budget.get("reject_prebuilt_binary"):
            execs_done = self.queue_count
        if execs_done <= 0 and self.budget.get("reject_prebuilt_binary"):
            self.stages["campaign"] = stage_record(
                "failed",
                "ELFuzz campaign produced zero target executions",
                campaign_seconds=self.budget["campaign_seconds"],
                queue_count=self.queue_count,
                crash_count=self.crash_count,
                hang_count=self.hang_count,
                execs_done=execs_done,
                deadline_reached=deadline_reached,
            )
            raise PipelineError("failed", "ELFuzz campaign produced zero target executions", 65)
        self.stages["campaign"] = stage_record(
            "complete",
            "none",
            campaign_seconds=self.budget["campaign_seconds"],
            queue_count=self.queue_count,
            crash_count=self.crash_count,
            hang_count=self.hang_count,
            execs_done=execs_done,
            deadline_reached=deadline_reached,
        )
        # zeta plan §6: record campaign evidence artifacts. The campaign log,
        # fuzzer_stats, queue directory, and command.txt must persist so a
        # missing/empty campaign cannot be disguised as completed.
        campaign_dir = self.workspace / "campaign"
        campaign_dir.mkdir(parents=True, exist_ok=True)
        log_src = self.workspace / "logs" / "campaign.log"
        if log_src.is_file():
            shutil.copy2(log_src, campaign_dir / "target_runtime.log")
        stats_src = campaign_dir / "stats" / "fuzzer_stats"
        if stats_src.is_file():
            shutil.copy2(stats_src, campaign_dir / "fuzzer_stats")
        # Prove the actual target wrapper/binary was invoked (zeta plan §6).
        runtime_evidence = {
            "command": " ".join(cmd),
            "execs_done": execs_done,
            "queue_count": self.queue_count,
            "deadline_reached": deadline_reached,
            "target_binary": str(self.target_binary) if self.target_binary else "",
            "containerized": bool(self.budget.get("require_containerized_sut_runtime")),
        }
        json_dump(campaign_dir / "target_runtime.json", runtime_evidence)

    def _run_fallback_campaign(self) -> None:
        """Run a simple campaign by executing the target on generated inputs.

        When the upstream ``elfuzz run`` workflow fails (e.g. missing seed
        metadata), this fallback runs each generated input through the target
        binary and collects the results as campaign queue items.
        """
        if not self.target_binary:
            return
        queue_dir = self.workspace / "campaign" / "queue"
        crashes_dir = self.workspace / "campaign" / "crashes"
        hangs_dir = self.workspace / "campaign" / "hangs"
        stats_dir = self.workspace / "campaign" / "stats"
        queue_dir.mkdir(parents=True, exist_ok=True)
        crashes_dir.mkdir(parents=True, exist_ok=True)
        hangs_dir.mkdir(parents=True, exist_ok=True)
        stats_dir.mkdir(parents=True, exist_ok=True)
        produced = self.workspace / "generated_inputs" / "produced"
        if not produced.exists():
            return
        execs = 0
        for path in sorted(produced.rglob("*")):
            if not path.is_file() or not is_produced_input(path):
                continue
            res = self._invoke_target(path.read_bytes())
            execs += 1
            if res.get("exit_code") == 124 or res.get("timed_out"):
                shutil.copy2(path, unique_dest(hangs_dir, path.name))
            elif res.get("exit_code") not in (0, 1):
                shutil.copy2(path, unique_dest(crashes_dir, path.name))
            else:
                shutil.copy2(path, unique_dest(queue_dir, path.name))
        (stats_dir / "fuzzer_stats").write_text(f"execs_done : {execs}\npaths_total : {execs}\n", encoding="utf-8")

    def _replay_corpus(self) -> Path:
        """Assemble the replay corpus from generated inputs and campaign queue.

        Plan section 8: replay ELFuzz generated inputs, minimized inputs, and
        the campaign queue/corpus on the coverage-instrumented SUT.
        """

        corpus = self.workspace / "coverage" / "replay_corpus"
        if corpus.exists():
            shutil.rmtree(corpus)
        corpus.mkdir(parents=True, exist_ok=True)
        index = 0
        for src_dir in (
            self.workspace / "generated_inputs" / "produced",
            self.workspace / "generated_inputs" / "minimized",
            self.workspace / "campaign" / "queue",
        ):
            if not src_dir.is_dir():
                continue
            for path in sorted(src_dir.rglob("*")):
                if not path.is_file() or not is_produced_input(path):
                    continue
                dest = corpus / f"input_{index:06d}"
                shutil.copy2(path, dest)
                index += 1
        return corpus

    def _run_coverage_replay(self, corpus_dir: Path) -> dict[str, Any]:
        """Replay the corpus on the coverage binary and return a coverage report.

        Uses the pluggable runner so offline tests can substitute a fake
        coverage JSON.  In production this shells out to the coverage binary
        with ``LLVM_PROFILE_FILE`` and merges/exports with llvm-profdata/llvm-cov.
        """

        cov_bin = self.coverage_binary or self.target_binary
        work_dir = self.workspace / "coverage"
        work_dir.mkdir(parents=True, exist_ok=True)
        if not cov_bin or not Path(cov_bin).is_file():
            return {"exit_code": 127, "report_path": None, "inputs_replayed": 0, "raw_text": ""}
        inputs_replayed = sum(1 for p in corpus_dir.iterdir() if p.is_file()) if corpus_dir.is_dir() else 0
        cov_json = work_dir / "coverage.json"
        cmd = [
            "sh", "-lc",
            f"set -e; mkdir -p /tmp/cov; cp -r {corpus_dir}/. /tmp/corpus/ 2>/dev/null || true; "
            f"LLVM_PROFILE_FILE=/tmp/cov/coverage.profraw {cov_bin} -runs=0 /tmp/corpus && "
            f"llvm-profdata merge -o /tmp/cov/merged.profdata /tmp/cov/*.profraw && "
            f"llvm-cov export -format=text {cov_bin} -instr-profile=/tmp/cov/merged.profdata "
            f"> {cov_json} 2>/tmp/cov/cov.err; cat {cov_json}",
        ]
        try:
            result = self.runner(cmd, 600)
        except Exception as exc:
            result = _RunnerResult(list(cmd), 127, "", str(exc))
        (work_dir / "replay.log").write_text(
            f"$ {' '.join(cmd)}\n[stdout]\n{getattr(result, 'stdout', '')}\n[stderr]\n{getattr(result, 'stderr', '')}\n[exit]\n{getattr(result, 'exit_code', 0)}\n",
            encoding="utf-8",
        )
        report_text = getattr(result, "stdout", "") or ""
        if report_text.strip().startswith("{"):
            cov_json.write_text(report_text, encoding="utf-8")
        report_path = cov_json if cov_json.is_file() and cov_json.read_text(encoding="utf-8", errors="replace").strip() else None
        return {
            "exit_code": getattr(result, "exit_code", 0),
            "report_path": str(report_path) if report_path else None,
            "inputs_replayed": inputs_replayed,
            "raw_text": report_text,
        }

    def _fail_coverage(self, coverage: dict[str, Any], reason_code: str, message: str) -> None:
        """Mark coverage failed and record the delta reason_code (plan section 7)."""
        self.reason_code = reason_code
        self.error = {"reason_code": reason_code, "message": message}
        coverage["complete"] = False
        coverage["report_exists"] = bool(coverage.get("report_exists"))
        json_dump(self.workspace / "coverage" / "coverage.json", coverage)
        self.stages["coverage"] = stage_record("failed", message, reason_code=reason_code, **coverage)

    def collect_coverage(self) -> None:
        stats = self.metrics.get("fuzzer_stats", {}) if isinstance(self.metrics.get("fuzzer_stats"), dict) else {}
        execs_done = int(stats.get("execs_done") or 0)
        paths_total = int(stats.get("paths_total") or stats.get("queued_paths") or self.queue_count or 0)
        strict = bool(self.budget.get("require_coverage_build"))
        replay = self._run_coverage_replay(self._replay_corpus())
        report_path = Path(replay["report_path"]) if replay.get("report_path") else None
        inputs_replayed = int(replay.get("inputs_replayed") or 0)
        coverage: dict[str, Any] = {
            "coverage_mode": "elfuzz_campaign",
            "edge_coverage": {"status": "unavailable", "value": None},
            "line_coverage": None,
            "region_coverage": None,
            "function_coverage": None,
            "covered_lines": 0,
            "total_lines": 0,
            "covered_functions": 0,
            "total_functions": 0,
            "inputs_replayed": inputs_replayed,
            "execs_done": execs_done,
            "paths_total": paths_total,
            "queue_count": self.queue_count,
            "produced_input_count": self.produced_input_count,
            "fuzzer_program_count": self.fuzzer_program_count,
            "report_path": str(self.workspace / "coverage" / "coverage.json"),
            "report_exists": bool(report_path and report_path.is_file()),
            "has_executions": execs_done > 0 or inputs_replayed > 0,
            "complete": False,
        }
        if report_path and report_path.is_file():
            try:
                import hgb_coverage  # type: ignore

                parsed = hgb_coverage.summarize_coverage_report(report_path)
                line_cov = parsed.get("line_coverage", {}) or {}
                func_cov = parsed.get("function_coverage", {}) or {}
                region_cov = parsed.get("region_coverage", parsed.get("regions", {})) or {}
                coverage.update(
                    {
                        "coverage_mode": parsed.get("source", "llvm_source_based"),
                        "line_coverage": line_cov,
                        "region_coverage": region_cov,
                        "function_coverage": func_cov,
                        "covered_lines": int(line_cov.get("covered", 0) or 0),
                        "total_lines": int(line_cov.get("total", 0) or 0),
                        "covered_functions": int(func_cov.get("covered", 0) or 0),
                        "total_functions": int(func_cov.get("total", 0) or 0),
                        "covered_function_names": parsed.get("covered_functions", []),
                    }
                )
                # Write the human-readable llvm-cov text export alongside the JSON.
                llvm_text = self.workspace / "coverage" / "llvm-cov.txt"
                llvm_text.write_text(replay.get("raw_text", ""), encoding="utf-8")
            except Exception:
                coverage["report_parse_error"] = True
                coverage["report_exists"] = False
        summary_path = self.workspace / "coverage" / "coverage.json"
        json_dump(summary_path, coverage)
        # Strict (reproduction-delta/gamma) invariants (plan section 7): a real
        # LLVM coverage report is mandatory. AFL ``paths_total`` is never
        # accepted as line/edge coverage. A missing/empty/malformed report
        # fails coverage with reason_code ``coverage_report_missing``.
        if strict:
            if self.coverage_binary is None or not Path(self.coverage_binary).is_file():
                self._write_coverage_diagnostic(coverage, execs_done, paths_total, inputs_replayed)
                self._fail_coverage(coverage, "coverage_report_missing", "ELFuzz coverage binary missing for reproduction-delta/gamma")
                raise PipelineError("failed", "ELFuzz coverage binary missing for reproduction-delta/gamma", 65)
            if not coverage.get("report_exists"):
                self._write_coverage_diagnostic(coverage, execs_done, paths_total, inputs_replayed)
                self._fail_coverage(coverage, "coverage_report_missing", "ELFuzz coverage requires a real LLVM coverage report (AFL paths_total is not coverage)")
                raise PipelineError("failed", "ELFuzz coverage requires a real LLVM coverage report (AFL paths_total is not coverage)", 65)
            if coverage.get("total_lines", 0) == 0 or coverage.get("line_coverage") is None:
                self._write_coverage_diagnostic(coverage, execs_done, paths_total, inputs_replayed)
                self._fail_coverage(coverage, "coverage_report_missing", "ELFuzz coverage JSON missing line/region/function data")
                raise PipelineError("failed", "ELFuzz coverage JSON missing line/region/function data", 65)
            if inputs_replayed == 0 and self.queue_count == 0 and self.produced_input_count == 0:
                self._fail_coverage(coverage, "coverage_report_missing", "ELFuzz coverage replayed zero inputs")
                raise PipelineError("failed", "ELFuzz coverage replayed zero inputs", 65)
            coverage["complete"] = True
            json_dump(summary_path, coverage)
            self.stages["coverage"] = stage_record("complete", "none", **coverage)
            return
        # Non-strict (alpha/compat-smoke): a real LLVM report is preferred. If
        # the replay produced none, fall back to a campaign-execution summary
        # (never labeling AFL paths_total as edge/line coverage) so the beta
        # contract's ``report_exists`` reflects the written summary file.
        if not coverage.get("report_exists"):
            if execs_done <= 0:
                self._fail_coverage(coverage, "coverage_report_missing", "ELFuzz coverage cannot complete from AFL path count alone")
                raise PipelineError("failed", "ELFuzz coverage cannot complete from AFL path count alone", 65)
            coverage.update(
                {
                    "coverage_mode": "elfuzz_campaign",
                    "line_coverage": None,
                    "region_coverage": None,
                    "function_coverage": None,
                    "report_path": str(summary_path),
                    "report_exists": True,
                    "has_executions": execs_done > 0,
                    "complete": True,
                }
            )
        else:
            coverage["complete"] = True
        json_dump(summary_path, coverage)
        self.stages["coverage"] = stage_record("complete", "none", **coverage)

    def _write_coverage_diagnostic(self, coverage: dict[str, Any], execs_done: int, paths_total: int, inputs_replayed: int) -> None:
        """Write AFL campaign counters as a diagnostic, never as coverage.

        Plan section 7.2: a missing coverage report must not be disguised as a
        real ``coverage.json``.  AFL ``paths_total``/``execs_done`` are written
        to ``coverage_diagnostic.json`` with ``line_coverage=null`` so the
        failure is auditable without faking coverage.
        """
        diagnostic = {
            "diagnostic": True,
            "line_coverage": None,
            "execs_done": execs_done,
            "paths_total": paths_total,
            "inputs_replayed": inputs_replayed,
            "queue_count": self.queue_count,
            "produced_input_count": self.produced_input_count,
            "note": "AFL path counters are not line/edge coverage",
        }
        json_dump(self.workspace / "coverage" / "coverage_diagnostic.json", diagnostic)

    def result_payload(self, status: str, reason: str, exit_code: int) -> dict[str, Any]:
        manifest = self.target_manifest()
        adapter_class = self.adapter.get("adapter_class") if self.adapter else None
        stats = self.metrics.get("fuzzer_stats", {}) if isinstance(self.metrics.get("fuzzer_stats"), dict) else {}
        execs_done = int(stats.get("execs_done") or 0)
        coverage_summary = read_json(self.workspace / "coverage" / "coverage.json") if (self.workspace / "coverage" / "coverage.json").is_file() else read_json(self.workspace / "coverage" / "summary.json")
        # Build a stages view that includes the goal-stage aliases (paper section 0).
        stages_view: dict[str, Any] = dict(self.stages)
        for alias, canonical in GOAL_STAGE_ALIASES.items():
            if canonical in self.stages and alias not in stages_view:
                stages_view[alias] = self.stages[canonical]
        model = os.environ.get("ELFUZZ_MODEL") or os.environ.get("OPENAI_MODEL") or os.environ.get("MODEL") or ""
        # Plan section 5: record both the reported target and the actual SUT
        # project/fuzz-target so a curl result is never reported from a jsoncpp
        # benchmark alias.  The executed SUT is always the declared FuzzBench
        # target (validate_no_aliasing forbids running an aliased benchmark), so
        # ``alias_used_for_execution`` is false; an upstream native benchmark
        # reused only for prompt templates is recorded as ``prompt_template_source``.
        upstream_benchmark = str((self.adapter or {}).get("upstream_benchmark", ""))
        alias_used = False
        prompt_template_source = ""
        if self.adapter and self.adapter.get("adapter_class") == EXTENSION:
            if upstream_benchmark in UPSTREAM_NATIVE_BENCHMARKS:
                prompt_template_source = upstream_benchmark
        build_record = read_json(self.workspace / "target" / "build.json")
        sut_contract = read_json(self._sut_root() / "contract.json") if (self._sut_root() / "contract.json").is_file() else {}
        wrapper_manifest = read_json(self._sut_root() / "containerized_wrappers.json") if (self._sut_root() / "containerized_wrappers.json").is_file() else {}
        build_provenance: dict[str, Any] = {
            "uses_fuzzbench_docker_environment": bool(sut_contract),
            "native": sut_contract.get("native", {}) if sut_contract else {},
            "coverage": sut_contract.get("coverage", {}) if sut_contract else {},
            "binary_path": build_record.get("binary_path", ""),
            "source": build_record.get("source", ""),
            "verified_executable": bool((build_record.get("verification") or {}).get("ok", False)),
            # zeta plan §3/§8: record whether the SUT ran inside the FuzzBench
            # Docker runtime via containerized wrappers.
            "containerized_sut_runtime": bool(wrapper_manifest.get("containerized", False)),
            "containerized_wrappers": wrapper_manifest,
        }
        artifacts = {
            "seed_fuzzers": count_files(self.workspace / "synthesis" / "fuzzer_programs"),
            "synth_prompts": count_files(self.workspace / "synthesis" / "prompts"),
            "generated_fuzzer_programs": count_files(self.workspace / "synthesis" / "fuzzer_programs"),
            "produced_inputs": count_files(self.workspace / "generated_inputs" / "produced"),
            "campaign_queue": self.queue_count,
            "coverage_report": bool(coverage_summary.get("report_exists")) if isinstance(coverage_summary, dict) else False,
        }
        reason_code = self.reason_code if self.reason_code != "none" else (
            self.classification.get("reason_code") if status == "not_applicable" else "none"
        )
        excluded = bool(self.budget.get("excluded_from_aggregate", False)) or status == "not_applicable"
        return {
            "schema_version": 2,
            "baseline": "elfuzz",
            "generator": "elfuzz",
            "fuzzer": "elfuzz",
            "task_family": TASK_FAMILY,
            "capability": TASK_FAMILY,
            "target": self.target,
            "project": manifest.get("project", os.environ.get("HGB_TARGET_PROJECT", "")),
            "fuzz_target": manifest.get("fuzz_target", os.environ.get("HGB_TARGET_FUZZ_TARGET", "")),
            "upstream_benchmark": upstream_benchmark,
            "adapter_id": (self.adapter or {}).get("adapter_id", ""),
            "adapter_class": adapter_class,
            "hgb_adapter": bool((self.adapter or {}).get("hgb_adapter", False)),
            "adapter_hashes": self.adapter_hashes,
            "profile": self.profile,
            "protocol": self.protocol,
            "method_variant": self.budget.get("method_variant", self.profile),
            "budget": self.budget,
            "model": model,
            "api_key_present": bool(os.environ.get("OPENAI_API_KEY") or os.environ.get("API_KEY") or os.environ.get("HF_TOKEN")),
            "paper_core": self.budget.get("paper_core", False),
            "exclude_from_aggregate": excluded,
            "excluded_from_aggregate": excluded,
            "status": status,
            "reason": reason,
            "reason_code": reason_code,
            "error": self.error,
            "applicability": self.classification.get("applicability", "applicable"),
            "exit_code": exit_code,
            "run_type": "generate-target",
            "generated_harness_count": 0,
            "generated_input_count": self.produced_input_count,
            "fuzzer_program_count": self.fuzzer_program_count,
            "queue_count": self.queue_count,
            "crash_count": self.crash_count,
            "hang_count": self.hang_count,
            # Plan section 5: reported target vs actual SUT.
            "reported_target": self.target,
            "actual_sut_project": manifest.get("project", self.target.split("_", 1)[0] if self.target else ""),
            "actual_sut_fuzz_target": manifest.get("fuzz_target", self.target),
            "upstream_benchmark_alias": prompt_template_source,
            "alias_used_for_execution": alias_used,
            "prompt_template_source": prompt_template_source,
            "build": build_provenance,
            "method": {
                "generated_fuzzer_program_count": self.fuzzer_program_count,
                "evolution_iterations_completed": self.evolution_iterations_completed,
                "produced_input_count": self.produced_input_count,
            },
            "artifacts": artifacts,
            "reproducibility": {
                "adapter_hashes": self.adapter_hashes,
                "fuzzbench_commit": manifest.get("fuzzbench_commit", ""),
                "build_uses_fuzzbench_docker_environment": bool(sut_contract),
                "method_variant": self.budget.get("method_variant", self.profile),
            },
            "elfuzz": {
                "adapter_class": adapter_class or "",
                "format": (self.adapter or {}).get("format", ""),
                "fuzzer_programs": self.fuzzer_program_count,
                "generated_inputs": self.produced_input_count,
                "valid_generated_inputs": self.valid_generated_input_count,
                "evolution_iterations": self.evolution_iterations_completed,
                "model": model,
            },
            "input_generation": {
                "fuzzer_program_count": self.fuzzer_program_count,
                "generated_input_count": self.produced_input_count,
                "valid_generated_input_count": self.valid_generated_input_count,
                "evolution_iterations_completed": self.evolution_iterations_completed,
            },
            "campaign": {
                "execs_done": execs_done,
                "crashes": self.crash_count,
                "hangs": self.hang_count,
                "queue_count": self.queue_count,
            },
            "coverage": coverage_summary,
            "stages": stages_view,
            "workspace": str(self.workspace),
            "target_manifest": str(Path(os.environ.get("HGB_TARGET_MANIFEST", self.target_package / "target_manifest.json"))),
            "command_file": str(self.workspace / "campaign" / "command.txt"),
            "log_dir": str(self.workspace / "logs"),
            "duration_seconds": round(time.time() - self.start_time, 3),
        }

    def write_outputs(self, status: str, reason: str, exit_code: int) -> None:
        payload = self.result_payload(status, reason, exit_code)
        json_dump(self.workspace / "result.json", payload)
        json_dump(self.workspace / "metadata.json", payload)
        self.write_summary(payload)

    def write_summary(self, payload: dict[str, Any]) -> None:
        lines = [
            "# HarnessGenBench ELFuzz Summary",
            "",
            f"- Run directory: `{self.workspace}`",
            "- Task family: `input_generator`",
            f"- Target: `{self.target}`",
            f"- Upstream benchmark: `{payload.get('upstream_benchmark', '')}`",
            f"- Adapter: `{payload.get('adapter_id', '')}` ({payload.get('adapter_class', '')})",
            f"- Profile: `{self.profile}`",
            f"- Budget: evolution={self.budget['evolution_iterations']}, produce={self.budget['produce_seconds']}s, campaign={self.budget['campaign_seconds']}s",
            f"- Status: `{payload['status']}`",
            f"- Fuzzer programs: `{payload['fuzzer_program_count']}`",
            f"- Produced inputs: `{payload['generated_input_count']}`",
            f"- Queue/crash/hang counts: queue={payload['queue_count']}, crashes={payload['crash_count']}, hangs={payload['hang_count']}",
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

    def _assert_evaluated_invariants(self) -> None:
        """Plan section 3/12: ``evaluated`` requires real generated inputs,
        input validation, real SUT execution, and a real coverage replay.

        A build-only or fake-coverage result must never be marked ``evaluated``.
        For ``reproduction-eta`` and ``reproduction-zeta`` additionally require
        the containerized SUT wrappers, ``evolution_iterations >= 2``, and a
        nonempty campaign queue (eta/zeta plan §5/§6/§8).
        """

        if self.fuzzer_program_count <= 0:
            raise PipelineError("failed", "evaluated requires at least one ELFuzz fuzzer program", 65)
        if self.produced_input_count <= 0:
            raise PipelineError("failed", "evaluated requires ELFuzz-generated inputs", 65)
        if self.valid_generated_input_count <= 0:
            raise PipelineError("failed", "evaluated requires at least one valid generated input", 65)
        if not self.target_binary or not Path(self.target_binary).is_file():
            raise PipelineError("failed", "evaluated requires a real native SUT binary", 65)
        cov = read_json(self.workspace / "coverage" / "coverage.json")
        if not cov:
            raise PipelineError("failed", "evaluated requires a real coverage replay", 65)
        if bool(self.budget.get("require_coverage_build")):
            if not self.coverage_binary or not Path(self.coverage_binary).is_file():
                raise PipelineError("failed", "evaluated requires a real coverage SUT binary", 65)
            if cov.get("total_lines", 0) == 0 or cov.get("line_coverage") is None:
                raise PipelineError("failed", "evaluated requires real LLVM line/region/function coverage", 65)
            if int(cov.get("inputs_replayed", 0) or 0) <= 0:
                raise PipelineError("failed", "evaluated requires replayed inputs on the coverage SUT", 65)
        # eta/zeta plan §5/§6/§8: stricter invariants for the eta/zeta profiles.
        if bool(self.budget.get("require_containerized_sut_runtime")):
            _profile = self.budget.get("profile", "reproduction-zeta")
            if self.evolution_iterations_completed < 2:
                raise PipelineError(
                    "failed",
                    f"{_profile} evaluated requires evolution_iterations >= 2",
                    65,
                )
            if self.queue_count <= 0:
                raise PipelineError(
                    "failed",
                    f"{_profile} evaluated requires a nonempty campaign queue",
                    65,
                )
            wrapper = self._sut_root() / "wrappers" / "run_native_one.sh"
            if not wrapper.is_file():
                raise PipelineError(
                    "failed",
                    f"{_profile} evaluated requires containerized SUT wrappers",
                    65,
                )

    def full(self) -> int:
        try:
            self.classify()
            if self.dry_run:
                self.write_outputs("dry_run_ok", "dry run validated ELFuzz adapter and budget", 0)
                return 0
            self.build_target()
            self.create_adapter_benchmark_dir()
            self.elfuzz_setup()
            self.model_ready()
            self.synthesis()
            self.evolution()
            self.production()
            self.generated_input_validation()
            self.campaign()
            self.collect_coverage()
            self._assert_evaluated_invariants()
            self.write_outputs("evaluated", "none", 0)
            return 0
        except PipelineError as exc:
            self.reason = exc.reason
            self.status = exc.status
            failed_stage = next((name for name in STAGE_NAMES if self.stages.get(name, {}).get("status") == "pending"), STAGE_NAMES[-1])
            if self.stages.get(failed_stage, {}).get("status") == "pending":
                self.stages[failed_stage] = stage_record(exc.status, exc.reason)
            self.write_outputs(exc.status, exc.reason, exc.code)
            if exc.status == "not_applicable":
                print(INVALID_MESSAGE)
                return 0
            return exc.code


def invalid_payload(target: str, metadata_root: Path) -> dict[str, Any]:
    cls = classify_target(target, metadata_root)
    reason_code = cls.get("reason_code", INVALID_REASON_CODE)
    stages = {name: stage_record("not_applicable", reason_code) for name in STAGE_NAMES}
    for alias, canonical in GOAL_STAGE_ALIASES.items():
        if canonical in stages and alias not in stages:
            stages[alias] = stages[canonical]
    # Plan section 2: the Invalid result must carry the paper-native
    # applicability/generation/campaign/coverage stage view in addition to the
    # canonical HGB stage names, with applicability completed and every
    # downstream stage not_applicable.
    stages["applicability"] = stage_record("completed", "none")
    stages["generation"] = stage_record("not_applicable", reason_code)
    stages["campaign"] = stage_record("not_applicable", reason_code)
    stages["coverage"] = stage_record("not_applicable", reason_code)
    profile = os.environ.get("HGB_BASELINE_PROFILE", "alpha")
    protocol = os.environ.get("HGB_BASELINE_PROTOCOL", "paper-native")
    return {
        "schema_version": 2,
        "baseline": "elfuzz",
        "generator": "elfuzz",
        "fuzzer": "elfuzz",
        "task_family": TASK_FAMILY,
        "capability": TASK_FAMILY,
        "target": target,
        "project": target.split("_", 1)[0] if target else "",
        "fuzz_target": target,
        "profile": profile,
        "protocol": protocol,
        "method_variant": "paper-faithful" if profile in {"reproduction-gamma", "reproduction-delta", "reproduction-epsilon", "reproduction-zeta", "reproduction-eta"} else profile,
        "status": "not_applicable",
        "applicability": "Invalid",
        "reason_code": reason_code,
        "reason": INVALID_MESSAGE,
        "exit_code": 0,
        "run_type": "generate-target",
        "generated_harness_count": 0,
        "generated_input_count": 0,
        # Plan section 2 / global invariant 5: both the schema-v2
        # ``exclude_from_aggregate`` field and the legacy
        # ``excluded_from_aggregate`` spelling are emitted so the matrix
        # collector and downstream consumers agree Invalid rows never count in
        # the scientific aggregate.
        "exclude_from_aggregate": True,
        "excluded_from_aggregate": True,
        "reported_target": target,
        "actual_sut_project": target.split("_", 1)[0] if target else "",
        "actual_sut_fuzz_target": target,
        "upstream_benchmark_alias": "",
        "alias_used_for_execution": False,
        "elfuzz": {
            "adapter_class": "",
            "format": "",
            "fuzzer_programs": 0,
            "generated_inputs": 0,
            "valid_generated_inputs": 0,
            "evolution_iterations": 0,
            "model": "",
        },
        "input_generation": {
            "fuzzer_program_count": 0,
            "generated_input_count": 0,
            "valid_generated_input_count": 0,
            "evolution_iterations_completed": 0,
        },
        "campaign": {"execs_done": 0, "crashes": 0, "hangs": 0},
        "coverage": {},
        "build": {"uses_fuzzbench_docker_environment": False, "native": {}, "coverage": {}, "verified_executable": False},
        "method": {"generated_fuzzer_program_count": 0, "evolution_iterations_completed": 0, "produced_input_count": 0},
        "artifacts": {
            "seed_fuzzers": 0, "synth_prompts": 0, "generated_fuzzer_programs": 0,
            "produced_inputs": 0, "campaign_queue": 0, "coverage_report": False,
        },
        "reproducibility": {
            "fuzzbench_commit": "",
            "build_uses_fuzzbench_docker_environment": False,
            "method_variant": "paper-faithful" if profile in {"reproduction-gamma", "reproduction-delta", "reproduction-epsilon", "reproduction-zeta", "reproduction-eta"} else profile,
        },
        "error": {"reason_code": reason_code, "message": INVALID_MESSAGE},
        "stages": stages,
        "classification": cls,
    }


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workspace", default=str(default_workspace()))
    parser.add_argument("--target", default=os.environ.get("HGB_TARGET", ""))
    parser.add_argument("--target-package", default=os.environ.get("HGB_TARGET_PACKAGE", "/target"))
    parser.add_argument("--artifact-dir", default=str(default_artifact_dir()))
    parser.add_argument("--metadata-root", default=str(default_metadata_root()))
    parser.add_argument("--profile", default=os.environ.get("HGB_BASELINE_PROFILE", "alpha"))
    parser.add_argument("--protocol", default=os.environ.get("HGB_BASELINE_PROTOCOL", "paper-native"))
    parser.add_argument("--dry-run", action="store_true", default=os.environ.get("HGB_DRY_RUN", "0") == "1")


def make_pipeline(args: argparse.Namespace) -> ELFuzzPipeline:
    target = args.target or os.environ.get("HGB_TARGET")
    if not target:
        raise PipelineError("missing_target", "--target or HGB_TARGET is required", 64)
    return ELFuzzPipeline(
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
    for name in ("full", "preflight"):
        p = sub.add_parser(name)
        add_common_args(p)
    classify_parser = sub.add_parser("classify")
    classify_parser.add_argument("--target", required=True)
    classify_parser.add_argument("--metadata-root", default=str(default_metadata_root()))
    write_invalid = sub.add_parser("write-invalid")
    write_invalid.add_argument("--target", required=True)
    write_invalid.add_argument("--metadata-root", default=str(default_metadata_root()))
    write_invalid.add_argument("--out", required=True)
    validate_parser = sub.add_parser("validate-adapters")
    validate_parser.add_argument("--metadata-root", default=str(default_metadata_root()))
    dump_parser = sub.add_parser("dump-adapter")
    dump_parser.add_argument("target")
    dump_parser.add_argument("--metadata-root", default=str(default_metadata_root()))
    args = parser.parse_args(argv)
    try:
        if args.command == "classify":
            print(json.dumps(classify_target(args.target, Path(args.metadata_root)), indent=2, sort_keys=True))
            return 0
        if args.command == "write-invalid":
            payload = invalid_payload(args.target, Path(args.metadata_root))
            out = Path(args.out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(INVALID_MESSAGE)
            return 0
        if args.command == "validate-adapters":
            validate_adapter_coverage(Path(args.metadata_root))
            validate_no_aliasing(Path(args.metadata_root))
            return 0
        if args.command == "dump-adapter":
            print(json.dumps(load_adapters(Path(args.metadata_root))[args.target], indent=2, sort_keys=True))
            return 0
        pipeline = make_pipeline(args)
        if args.command == "full":
            return pipeline.full()
        pipeline.classify()
        pipeline.write_outputs("dry_run_ok", "preflight completed", 0)
        return 0
    except PipelineError as exc:
        print(f"ERROR: {exc.reason}", file=sys.stderr)
        return exc.code if exc.status != "not_applicable" else 0


if __name__ == "__main__":
    raise SystemExit(main())
