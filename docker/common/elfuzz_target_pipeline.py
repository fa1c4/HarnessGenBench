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
import shutil
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
    "production",
    "campaign",
    "coverage",
)
TASK_FAMILY = "input_generator"
INVALID_REASON_CODE = "elfuzz_non_text_target"
INVALID_MESSAGE = "Invalid: ELFuzz supports text-input targets only"
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
            "produce_seconds": max(1, env_int("ELFUZZ_PRODUCE_SECONDS", 60)),
            "campaign_seconds": max(1, env_int("ELFUZZ_AFL_SECONDS", 60)),
            "tgi_waiting_seconds": max(1, env_int("ELFUZZ_TGI_WAITING_SECONDS", 120)),
            "excluded_from_aggregate": True,
            "paper_core": False,
            "source": "ci-smoke",
        }
    if profile == "paper-faithful":
        return {
            "profile": profile,
            "evolution_iterations": env_int("ELFUZZ_EVOLUTION_ITERATIONS", 50),
            "produce_seconds": env_int("ELFUZZ_PRODUCE_SECONDS", 600),
            "campaign_seconds": env_int("ELFUZZ_AFL_SECONDS", 86400),
            "tgi_waiting_seconds": env_int("ELFUZZ_TGI_WAITING_SECONDS", 1200),
            "excluded_from_aggregate": False,
            "paper_core": True,
            "source": "pinned-upstream-defaults",
        }
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
        "produce_seconds": produce,
        "campaign_seconds": max(60, campaign),
        "tgi_waiting_seconds": env_int("ELFUZZ_TGI_WAITING_SECONDS", 1200),
        "excluded_from_aggregate": False,
        "paper_core": False,
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
    ignored_suffixes = {".py", ".log", ".json", ".jsonl", ".txt", ".toml", ".md"}
    ignored_stems = {"manifest", "metadata", "config", "lineage", "fuzzer_stats", "stats"}
    stem = path.stem.lower()
    if path.suffix.lower() in ignored_suffixes:
        return False
    if stem in ignored_stems or stem.startswith("config"):
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
        try:
            json.loads(data.decode("utf-8", "replace"))
            return True
        except Exception:
            return False
    if label == "xml":
        text = data.decode("utf-8", "replace").lstrip()
        return text.startswith("<")
    if label == "sql":
        text = data.decode("utf-8", "replace").strip().lower()
        return any(text.startswith(kw) for kw in ("select", "insert", "create", "update", "delete", "with", "pragma", "begin"))
    if label == "regex":
        try:
            import re

            re.compile(data.decode("utf-8", "replace"))
            return True
        except re.error:
            return False
    if label in {"ruby", "php"}:
        text = data.decode("utf-8", "replace").strip()
        return bool(text)
    if label == "ini":
        text = data.decode("utf-8", "replace")
        return "=" in text or "[" in text
    if label == "http":
        text = data.decode("utf-8", "replace")
        return text.startswith("HTTP/") or "\r\n" in text
    return True


def find_elfuzz_project_root() -> Path | None:
    for candidate in (os.environ.get("ELFUZZ_PROJECT_ROOT"), "/home/appuser/elmfuzz", "/elfuzz", "/opt/hgb/artifacts/elfuzz"):
        if candidate and Path(candidate).is_dir() and (Path(candidate) / "cli" / "main.py").exists():
            return Path(candidate)
    return None


def elfuzz_cli_command() -> list[str]:
    custom = os.environ.get("ELFUZZ_CLI")
    if custom:
        return [custom]
    return ["elfuzz"]


def run_subprocess(cmd: list[str], log_path: Path, timeout: int, env: dict[str, str] | None = None) -> tuple[int, bool]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    timed_out = False
    effective_timeout = timeout if timeout and timeout > 0 else None
    try:
        with log_path.open("wb") as log:
            proc = subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=effective_timeout, check=False)
        code = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        code = 124
    except FileNotFoundError:
        code = 127
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
        self.queue_count = 0
        self.crash_count = 0
        self.hang_count = 0
        self.exit_code = 0
        self.reason = "none"
        self.status = "created"
        self.start_time = time.time()
        self.target_binary: Path | None = None
        self.project_root = find_elfuzz_project_root()

    def ensure_layout(self) -> None:
        for rel in (
            "target/binary",
            "target/build",
            "synthesis/fuzzer_programs",
            "synthesis/prompts",
            "generated_inputs/produced",
            "campaign/queue",
            "campaign/crashes",
            "campaign/hangs",
            "campaign/stats",
            "coverage",
            "logs",
            "config",
        ):
            (self.workspace / rel).mkdir(parents=True, exist_ok=True)

    def target_manifest(self) -> dict[str, Any]:
        manifest = Path(os.environ.get("HGB_TARGET_MANIFEST", self.target_package / "target_manifest.json"))
        return read_json(manifest)

    def write_runtime_config(self) -> None:
        json_dump(self.workspace / "config" / "adapter.json", self.adapter or {})
        json_dump(self.workspace / "config" / "classification.json", self.classification)
        json_dump(self.workspace / "config" / "budget.json", self.budget)
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
            if executable(path):
                return path
        candidates = [
            self.workspace / "target" / "binary" / "target",
            self.workspace / "target" / "target",
            self.target_package / "fuzzbench_benchmark" / "build.sh",
        ]
        for candidate in candidates:
            if executable(candidate):
                return candidate
        return None

    def build_target(self) -> None:
        # A listed text target with missing adapter files is infra_missing, not Invalid.
        repo = repo_root_from(self.metadata_root)
        for rel in (self.adapter["format_spec"], self.adapter["adapter_dir"], self.adapter["seed_template"]):
            candidates = [repo / rel, Path("/opt/hgb") / rel]
            if not any(p.exists() for p in candidates):
                raise PipelineError("infra_missing", f"ELFuzz adapter file missing for {self.target}: {rel}", 127)
        binary = self.resolve_target_binary()
        if binary:
            self.target_binary = binary
            record = {
                "binary": str(binary),
                "binary_hash": sha256_file(binary),
                "build_mode": self.adapter["build_mode"],
                "source": "prebuilt_or_env",
                "native_harness": "unchanged",
            }
            json_dump(self.workspace / "target" / "build.json", record)
            self.stages["target_build"] = stage_record("complete", "none", **record)
            return
        if not Path("/var/run/docker.sock").exists():
            raise PipelineError("infra_missing", "ELFuzz target build requires Docker socket or ELFUZZ_TARGET_BINARY", 127)
        if not shutil.which(elfuzz_cli_command()[0]) and not Path(elfuzz_cli_command()[0]).exists():
            raise PipelineError("infra_missing", "elfuzz CLI not found for target build", 127)
        record = {
            "build_mode": self.adapter["build_mode"],
            "native_harness": "unchanged",
            "binary": None,
            "note": "target build delegated to upstream elfuzz sibling-container workflow",
        }
        json_dump(self.workspace / "target" / "build.json", record)
        self.stages["target_build"] = stage_record("complete", "none", **record)

    def elfuzz_setup(self) -> None:
        if not self.project_root and not os.environ.get("ELFUZZ_CLI"):
            raise PipelineError("infra_missing", "ELFuzz project source tree not found", 127)
        skip_download = os.environ.get("ELFUZZ_SKIP_DOWNLOAD", "0") == "1"
        setup_cmd = elfuzz_cli_command() + ["setup"]
        code, timed_out = run_subprocess(setup_cmd, self.workspace / "logs" / "setup.log", int(os.environ.get("ELFUZZ_STAGE_TIMEOUT_SECONDS", "900")))
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

    def synth_command(self) -> list[str]:
        return elfuzz_cli_command() + [
            "synth",
            "-T", "fuzzer.elfuzz",
            "--use-small-model",
            "--tgi-waiting", str(self.budget["tgi_waiting_seconds"]),
            "--evolution-iterations", str(self.budget["evolution_iterations"]),
            str(self.adapter["upstream_benchmark"]),
        ]

    def produce_command(self) -> list[str]:
        return elfuzz_cli_command() + [
            "produce",
            "-T", "elfuzz",
            "--time", str(self.budget["produce_seconds"]),
            str(self.adapter["upstream_benchmark"]),
        ]

    def run_command(self) -> list[str]:
        return elfuzz_cli_command() + [
            "run", "rq1.afl",
            "--fuzzers", "elfuzz",
            "--repeat", "1",
            "--time", str(self.budget["campaign_seconds"]),
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

    def synthesis(self) -> None:
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

    def production(self) -> None:
        cmd = self.produce_command()
        (self.workspace / "generated_inputs" / "command.txt").write_text(" ".join(cmd) + "\n", encoding="utf-8")
        timeout = stage_timeout()
        code, timed_out = run_subprocess(cmd, self.workspace / "logs" / "produce.log", timeout)
        self.collect_produced_inputs()
        self.write_input_provenance()
        if code == 124 and timed_out:
            raise PipelineError("failed", "ELFuzz production timed out", 124)
        if code != 0:
            raise PipelineError("failed", f"elfuzz produce exited {code}", code)
        if self.produced_input_count == 0:
            raise PipelineError("failed", "ELFuzz production produced no input files", 65)
        self.stages["production"] = stage_record(
            "complete",
            "none",
            produce_seconds=self.budget["produce_seconds"],
            produced_input_count=self.produced_input_count,
            timed_out=False,
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
        if code == 124 and timed_out and subprocess_timeout < campaign_deadline:
            raise PipelineError("failed", "ELFuzz campaign timed out before its configured deadline", 124)
        if code not in (0, 124):
            raise PipelineError("failed", f"elfuzz run exited {code}", code)
        deadline_reached = code == 124 and timed_out and subprocess_timeout >= campaign_deadline
        self.stages["campaign"] = stage_record(
            "complete",
            "none",
            campaign_seconds=self.budget["campaign_seconds"],
            queue_count=self.queue_count,
            crash_count=self.crash_count,
            hang_count=self.hang_count,
            execs_done=int(self.metrics.get("fuzzer_stats", {}).get("execs_done") or 0),
            deadline_reached=deadline_reached,
        )

    def collect_coverage(self) -> None:
        stats = self.metrics.get("fuzzer_stats", {}) if isinstance(self.metrics.get("fuzzer_stats"), dict) else {}
        execs_done = int(stats.get("execs_done") or 0)
        paths_total = int(stats.get("paths_total") or stats.get("queued_paths") or self.queue_count or 0)
        coverage = {
            "coverage_mode": "elfuzz_afl_fuzzer_stats",
            "edge_coverage": paths_total,
            "line_coverage": None,
            "execs_done": execs_done,
            "queue_count": self.queue_count,
            "produced_input_count": self.produced_input_count,
            "fuzzer_program_count": self.fuzzer_program_count,
            "non_empty": paths_total > 0 or self.queue_count > 0 or execs_done > 0,
        }
        json_dump(self.workspace / "coverage" / "summary.json", coverage)
        if not coverage["non_empty"]:
            raise PipelineError("failed", "coverage artifacts are empty; campaign produced no measurable coverage", 65)
        self.stages["coverage"] = stage_record("complete", "none", **coverage)

    def result_payload(self, status: str, reason: str, exit_code: int) -> dict[str, Any]:
        manifest = self.target_manifest()
        adapter_class = self.adapter.get("adapter_class") if self.adapter else None
        return {
            "schema_version": 2,
            "generator": "elfuzz",
            "fuzzer": "elfuzz",
            "task_family": TASK_FAMILY,
            "capability": TASK_FAMILY,
            "target": self.target,
            "project": manifest.get("project", os.environ.get("HGB_TARGET_PROJECT", "")),
            "fuzz_target": manifest.get("fuzz_target", os.environ.get("HGB_TARGET_FUZZ_TARGET", "")),
            "upstream_benchmark": (self.adapter or {}).get("upstream_benchmark", ""),
            "adapter_id": (self.adapter or {}).get("adapter_id", ""),
            "adapter_class": adapter_class,
            "profile": self.profile,
            "protocol": self.protocol,
            "budget": self.budget,
            "model": os.environ.get("ELFUZZ_MODEL") or os.environ.get("OPENAI_MODEL") or os.environ.get("MODEL") or "",
            "api_key_present": bool(os.environ.get("OPENAI_API_KEY") or os.environ.get("API_KEY") or os.environ.get("HF_TOKEN")),
            "paper_core": self.budget.get("paper_core", False),
            "excluded_from_aggregate": self.budget.get("excluded_from_aggregate", False),
            "status": status,
            "reason": reason,
            "reason_code": (self.classification.get("reason_code") if status == "not_applicable" else "none"),
            "applicability": self.classification.get("applicability", "applicable"),
            "exit_code": exit_code,
            "run_type": "generate-target",
            "generated_harness_count": 0,
            "generated_input_count": self.produced_input_count,
            "fuzzer_program_count": self.fuzzer_program_count,
            "queue_count": self.queue_count,
            "crash_count": self.crash_count,
            "hang_count": self.hang_count,
            "stages": self.stages,
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

    def full(self) -> int:
        try:
            self.classify()
            if self.dry_run:
                self.write_outputs("dry_run_ok", "dry run validated ELFuzz adapter and budget", 0)
                return 0
            self.build_target()
            self.elfuzz_setup()
            self.model_ready()
            self.synthesis()
            self.production()
            self.campaign()
            self.collect_coverage()
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
    manifest = {}
    return {
        "schema_version": 2,
        "generator": "elfuzz",
        "fuzzer": "elfuzz",
        "task_family": TASK_FAMILY,
        "capability": TASK_FAMILY,
        "target": target,
        "project": target.split("_", 1)[0] if target else "",
        "fuzz_target": target,
        "profile": os.environ.get("HGB_BASELINE_PROFILE", "alpha"),
        "protocol": os.environ.get("HGB_BASELINE_PROTOCOL", "paper-native"),
        "status": "not_applicable",
        "applicability": "Invalid",
        "reason_code": cls.get("reason_code", INVALID_REASON_CODE),
        "reason": INVALID_MESSAGE,
        "exit_code": 0,
        "run_type": "generate-target",
        "generated_harness_count": 0,
        "generated_input_count": 0,
        "stages": {name: stage_record("not_applicable", cls.get("reason_code", INVALID_REASON_CODE)) for name in STAGE_NAMES},
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
