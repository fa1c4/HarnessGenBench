#!/usr/bin/env python3
"""Target-aware G2Fuzz input-generation pipeline for HarnessGenBench.

The real G2Fuzz artifact creates input generators and seeds, then drives its
modified AFL++ against an existing native target.  This helper owns the HGB
contract around that workflow: adapter validation, target-pair discovery,
invocation rendering, provenance accounting, campaign execution, and normalized
result metadata.
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
}
PAPER_METHOD_PROFILE = "paper-faithful"
EXTENSION_METHOD_PROFILE = "extension"
TASK_FAMILY = "input_generator"


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
    except FileNotFoundError:
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
    return env.get("G2FUZZ_TRY_NUM", "3") or "3"


def build_command_pair(adapter: dict[str, Any]) -> dict[str, Any]:
    common = [
        "bash",
        "/target/fuzzbench_benchmark/build.sh",
    ]
    afl_env = {
        "FUZZING_ENGINE": "afl",
        "AFL_LLVM_CMPLOG": "0",
        "HGB_G2FUZZ_OUTPUT": "/workspace/target/target.afl",
    }
    cmp_env = {
        "FUZZING_ENGINE": "afl",
        "AFL_LLVM_CMPLOG": "1",
        "HGB_G2FUZZ_OUTPUT": "/workspace/target/target.cmp",
    }
    return {
        "program_id": adapter["program_id"],
        "afl": {"env": afl_env, "argv": common},
        "cmp": {"env": cmp_env, "argv": common},
        "expected_difference": "AFL_LLVM_CMPLOG and output path only",
    }


def resolved_invocation(
    adapter: dict[str, Any],
    executable: str | Path,
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
    argv = [str(executable), *adapter_argv]
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
            "afl_queue": 0,
        }
        self.metrics: dict[str, Any] = {}
        self.generated_generator_count = 0
        self.generated_input_count = 0
        self.exit_code = 0
        self.reason = "none"
        self.status = "created"
        self.start_time = time.time()
        self.target_afl = self.workspace / "target" / "target.afl"
        self.target_cmp = self.workspace / "target" / "target.cmp"
        self.invocation: dict[str, Any] | None = None

    def ensure_layout(self) -> None:
        for rel in (
            "target",
            "generators/source",
            "seeds/common_initial",
            "seeds/bootstrap",
            "seeds/g2_generated",
            "seeds/afl_queue",
            "campaign/output",
            "campaign/stats",
            "coverage",
            "config",
            "logs",
        ):
            (self.workspace / rel).mkdir(parents=True, exist_ok=True)

    def write_runtime_mapping(self) -> None:
        mapping = {self.program_id: self.formats}
        json_dump(self.workspace / "config" / "program_to_format.json", mapping)
        json_dump(
            self.workspace / "config" / "model_setting.json",
            {"model": [os.environ.get("G2FUZZ_MODEL") or os.environ.get("OPENAI_MODEL") or os.environ.get("MODEL") or "gpt-4o-mini"]},
        )
        json_dump(self.workspace / "config" / "adapter.json", self.adapter)
        json_dump(self.workspace / "config" / "build_commands.json", build_command_pair(self.adapter))

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
            self.target_package / "fuzzbench_benchmark" / "build.sh",
        )
        missing = [str(path) for path in required if not path.exists()]
        if missing:
            raise PipelineError("target_package_missing", f"target package is missing required files: {', '.join(missing)}", 66)
        self.stages["target_prepared"] = stage_record("complete", formats=self.formats, method_profile=self.adapter["method_profile"])

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

    def write_invocation(self) -> None:
        self.invocation = resolved_invocation(self.adapter, self.target_afl)
        json_dump(self.workspace / "target" / "invocation.json", self.invocation)
        command = " ".join(self.invocation["argv"])
        (self.workspace / "target" / "command.txt").write_text(command + "\n", encoding="utf-8")

    def smoke_pair(self) -> dict[str, Any]:
        assert self.invocation is not None
        smoke_dir = self.workspace / "seeds" / "bootstrap"
        smoke_dir.mkdir(parents=True, exist_ok=True)
        smoke_input = smoke_dir / f"{self.program_id}_bootstrap_seed"
        if not smoke_input.exists():
            smoke_input.write_bytes(bootstrap_bytes(self.formats[0] if self.formats else "custom"))
        results: dict[str, Any] = {}
        for label, binary in (("afl", self.target_afl), ("cmp", self.target_cmp)):
            inv = dict(self.invocation)
            inv["argv"] = [str(binary), *self.invocation["adapter_argv"]]
            cmd = argv_for_input(inv, smoke_input)
            try:
                proc = subprocess.run(
                    cmd,
                    input=smoke_input.read_bytes() if inv["input_mode"] == "stdin" else None,
                    text=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    timeout=int(inv.get("timeout_seconds", 5)),
                    check=False,
                )
                results[label] = {"exit_code": proc.returncode, "stderr_tail": proc.stderr.decode("utf-8", "replace")[-500:]}
            except Exception as exc:  # noqa: BLE001 - smoke failures are recorded, not fatal.
                results[label] = {"exit_code": None, "error": str(exc)}
        return results

    def build_target_pair(self) -> None:
        located = self.locate_pair()
        if not located:
            searched = [str(path) for path in self.candidate_pair_dirs()]
            (self.workspace / "target" / "TARGET_BUILD_MISSING.md").write_text(
                "# G2Fuzz Target Pair Missing\n\n"
                "G2Fuzz requires a native target pair built for its modified AFL++.\n\n"
                f"- Program: `{self.program_id}`\n"
                f"- Required binaries: `{self.program_id}.afl` and `{self.program_id}.cmp` or `target.afl` and `target.cmp`\n"
                f"- Searched: `{', '.join(searched)}`\n",
                encoding="utf-8",
            )
            raise PipelineError("infra_missing", "G2Fuzz target .afl/.cmp pair is missing", 127)
        source_dir, src_afl, src_cmp = located
        self.copy_pair(src_afl, src_cmp)
        self.write_invocation()
        smoke = self.smoke_pair()
        hashes = {"afl": sha256_file(self.target_afl), "cmp": sha256_file(self.target_cmp)}
        json_dump(
            self.workspace / "target" / "build.json",
            {
                "source_dir": str(source_dir),
                "source_afl": str(src_afl),
                "source_cmp": str(src_cmp),
                "binary_hashes": hashes,
                "smoke": smoke,
                "build_commands": build_command_pair(self.adapter),
            },
        )
        self.stages["target_pair_built"] = stage_record("complete", source_dir=str(source_dir), binary_hashes=hashes, smoke=smoke)

    def copy_common_corpus(self) -> None:
        if not bool(self.adapter.get("common_corpus")):
            return
        out_dir = self.workspace / "seeds" / "common_initial"
        roots = (
            self.target_package / "corpus",
            self.target_package / "seeds",
            self.target_package / "seed_corpus",
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
        try:
            with (self.workspace / "logs" / "program_gen.log").open("wb") as log:
                proc = subprocess.run(cmd, cwd=runtime, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=timeout, check=False)
            code = proc.returncode
        except subprocess.TimeoutExpired:
            code = 124
        finally:
            try:
                key_file.unlink()
            except OSError:
                pass
        if code == 124:
            self.collect_program_gen_outputs(output_dir)
            raise PipelineError("generation_timeout", "program_gen timed out; partial inputs are not evaluated", 124)
        if code != 0:
            self.collect_program_gen_outputs(output_dir)
            raise PipelineError("failed", f"program_gen exited {code}", code)
        self.collect_program_gen_outputs(output_dir)
        if self.generated_input_count <= 0:
            raise PipelineError("validation_failed", "G2Fuzz program_gen completed without generated input files", 65)
        self.stages["input_generators_created"] = stage_record(
            "complete",
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
        json_dump(
            self.workspace / "generators" / "source" / "manifest.json",
            {
                "program_id": self.program_id,
                "formats": self.formats,
                "generator_count": copied_generators,
                "generated_input_count": copied_seeds,
                "upstream_output_dir": str(output_dir),
            },
        )

    def validate_generated_inputs(self) -> None:
        generated = sorted((self.workspace / "seeds" / "g2_generated").rglob("*"))
        files = [path for path in generated if path.is_file()]
        non_empty = [path for path in files if path.stat().st_size > 0]
        unique_hashes = {sha256_file(path) for path in non_empty}
        validation = {
            "file_count": len(files),
            "non_empty_count": len(non_empty),
            "unique_count": len(unique_hashes),
            "size_distribution": sorted(path.stat().st_size for path in non_empty),
        }
        if len(non_empty) == 0 or len(unique_hashes) == 0:
            json_dump(self.workspace / "seeds" / "validation.json", validation)
            raise PipelineError("validation_failed", "G2Fuzz generated inputs are empty or duplicate-only", 65)
        assert self.invocation is not None
        sample_results = []
        for path in non_empty[: min(8, len(non_empty))]:
            inv = dict(self.invocation)
            cmd = argv_for_input(inv, path)
            try:
                proc = subprocess.run(
                    cmd,
                    input=path.read_bytes() if inv["input_mode"] == "stdin" else None,
                    text=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    timeout=int(inv.get("timeout_seconds", 5)),
                    check=False,
                )
                sample_results.append({"path": str(path), "exit_code": proc.returncode})
            except Exception as exc:  # noqa: BLE001
                sample_results.append({"path": str(path), "error": str(exc)})
        validation["target_sample_results"] = sample_results
        json_dump(self.workspace / "seeds" / "validation.json", validation)
        self.stages["generated_inputs_validated"] = stage_record("complete", **validation)

    def write_seed_provenance(self) -> None:
        provenance = self.workspace / "seeds" / "provenance.jsonl"
        if provenance.exists():
            provenance.unlink()
        seen: dict[str, str] = {}
        for source_class in ("common_initial", "bootstrap", "g2_generated", "afl_queue"):
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
                        "admitted_to_initial_afl_input": source_class in {"common_initial", "bootstrap", "g2_generated"} and not deduplicated,
                    }
                    if source_class == "g2_generated":
                        record["generator_manifest"] = str(self.workspace / "generators" / "source" / "manifest.json")
                    append_jsonl(provenance, record)
                    count += 1
            self.seed_counts[source_class] = count

    def assemble_initial_corpus(self) -> Path:
        initial = self.workspace / "campaign" / "initial_corpus"
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
                digest = sha256_file(path)
                if digest in seen:
                    continue
                seen.add(digest)
                shutil.copy2(path, initial / f"{index:06d}_{source_class}_{path.name}")
                index += 1
        if index == 0:
            fallback = initial / "empty"
            fallback.write_bytes(b"\n")
        return initial

    def afl_fuzz_path(self) -> Path:
        path = Path(os.environ.get("G2FUZZ_AFL_FUZZ", "")) if os.environ.get("G2FUZZ_AFL_FUZZ") else self.artifact_dir / "afl-fuzz"
        if not executable(path):
            raise PipelineError("infra_missing", f"missing executable G2Fuzz modified afl-fuzz: {path}", 127)
        return path

    def run_campaign(self) -> None:
        assert self.invocation is not None
        initial = self.assemble_initial_corpus()
        afl_fuzz = self.afl_fuzz_path()
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
            os.environ.get("G2FUZZ_MEMORY_MB", "1024"),
            "-k",
            str(self.artifact_dir),
            "--",
            str(self.target_afl),
            *self.invocation["adapter_argv"],
        ]
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
        timed_out = False
        try:
            with (self.workspace / "logs" / "afl.log").open("wb") as log:
                proc = subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=timeout, check=False)
            code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            code = 124
        queue_dir = out / "default" / "queue"
        crashes_dir = out / "default" / "crashes"
        hangs_dir = out / "default" / "hangs"
        afl_queue = self.workspace / "seeds" / "afl_queue"
        if queue_dir.exists():
            for path in sorted(p for p in queue_dir.rglob("*") if p.is_file()):
                shutil.copy2(path, unique_dest(afl_queue, path.name))
        metrics = {
            "afl_exit_code": code,
            "campaign_timeout_configured": timed_out or code == 124,
            "queue_count": count_files(queue_dir, exclude_readme=False),
            "crash_count": count_files(crashes_dir, exclude_readme=True),
            "hang_count": count_files(hangs_dir, exclude_readme=True),
            "fuzzer_stats": parse_fuzzer_stats(out / "default" / "fuzzer_stats"),
        }
        self.metrics.update(metrics)
        if code not in {0, 124}:
            json_dump(self.workspace / "campaign" / "metrics.json", metrics)
            raise PipelineError("failed", f"afl-fuzz exited {code}", code)
        json_dump(self.workspace / "campaign" / "metrics.json", metrics)
        self.stages["campaign"] = stage_record("complete", **metrics)

    def collect_coverage(self) -> None:
        stats = self.metrics.get("fuzzer_stats", {}) if isinstance(self.metrics.get("fuzzer_stats"), dict) else {}
        queue_count = int(self.metrics.get("queue_count") or 0)
        paths_total = int(stats.get("paths_total") or stats.get("queued_paths") or queue_count or 0)
        execs_done = int(stats.get("execs_done") or 0)
        coverage = {
            "coverage_mode": "afl_fuzzer_stats",
            "edge_coverage": paths_total,
            "line_coverage": None,
            "execs_done": execs_done,
            "queue_count": queue_count,
            "common_initial_count": self.seed_counts.get("common_initial", 0),
            "bootstrap_count": self.seed_counts.get("bootstrap", 0),
            "g2_generated_count": self.seed_counts.get("g2_generated", 0),
        }
        json_dump(self.workspace / "coverage" / "summary.json", coverage)
        self.stages["coverage"] = stage_record("complete", **coverage)

    def result_payload(self, status: str, reason: str, exit_code: int) -> dict[str, Any]:
        manifest = self.target_manifest()
        return {
            "schema_version": 2,
            "generator": "g2fuzz",
            "fuzzer": "g2fuzz",
            "task_family": TASK_FAMILY,
            "capability": TASK_FAMILY,
            "target": self.target,
            "project": manifest.get("project", os.environ.get("HGB_TARGET_PROJECT", "")),
            "fuzz_target": manifest.get("fuzz_target", os.environ.get("HGB_TARGET_FUZZ_TARGET", "")),
            "program_id": self.program_id,
            "formats": self.formats,
            "profile": self.profile,
            "protocol": self.protocol,
            "method_profile": self.adapter["method_profile"],
            "model": os.environ.get("G2FUZZ_MODEL") or os.environ.get("OPENAI_MODEL") or os.environ.get("MODEL") or "",
            "api_key_present": bool(os.environ.get("OPENAI_API_KEY") or os.environ.get("API_KEY")),
            "paper_core": self.adapter["method_profile"] == PAPER_METHOD_PROFILE,
            "excluded_from_aggregate": self.profile == "compat-smoke",
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
            "stages": self.stages,
            "workspace": str(self.workspace),
            "target_manifest": str(Path(os.environ.get("HGB_TARGET_MANIFEST", self.target_package / "target_manifest.json"))),
            "command_file": str(self.workspace / "campaign" / "command.txt"),
            "log_file": str(self.workspace / "logs" / "program_gen.log"),
            "duration_seconds": round(time.time() - self.start_time, 3),
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
            f"- Generators: `{payload['generator_count']}`",
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
            self.write_outputs("evaluated", "none", 0)
            return 0
        except PipelineError as exc:
            self.reason = exc.reason
            self.status = exc.status
            failed_stage = next((name for name in STAGE_NAMES if self.stages.get(name, {}).get("status") == "pending"), STAGE_NAMES[-1])
            if self.stages.get(failed_stage, {}).get("status") == "pending":
                self.stages[failed_stage] = stage_record(exc.status, exc.reason)
            self.write_outputs(exc.status, exc.reason, exc.code)
            return exc.code


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



def is_generated_input_candidate(path: Path) -> bool:
    ignored_suffixes = {".py", ".log"}
    ignored_names = {"manifest", "metadata", "config", "model_setting", "program_to_format"}
    stem = path.stem.lower()
    if path.suffix.lower() in ignored_suffixes:
        return False
    if stem in ignored_names or stem.startswith("config"):
        return False
    return True

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
