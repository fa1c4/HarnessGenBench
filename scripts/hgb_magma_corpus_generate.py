#!/usr/bin/env python3
"""Generate MAGMA seed corpora with the ELFuzz and G2Fuzz baselines.

This is the MAGMA-phase corpus generator driver.  It does not run evaluation
campaigns; it invokes the corpus-generator baselines inside their pinned
containers, collects the seeds they produce, and writes a per-target manifest.

Design notes
------------

* MAGMA adapters live in parallel manifests:
  ``metadata/elfuzz_target_adapters_magma.yaml`` and
  ``metadata/g2fuzz_target_adapters_magma.yaml``.  The committed FuzzBench
  adapter files and their validation are untouched.
* ELFuzz runs its corpus-only pipeline mode: it synthesizes/evolves fuzzer
  programs and materializes their generated outputs, but skips the native SUT
  build, validation campaign, and coverage replay (those belong to the
  evaluator, not corpus generation).
* G2Fuzz runs its upstream ``generate-seeds`` entrypoint mode against a
  MAGMA-specific ``program_to_format.json`` overlay.
* A short MAGMA-native libFuzzer campaign can optionally consume the generated
  corpus (``--validate-seconds``) to prove the corpus is usable.

Usage
-----

    export HGB_API_KEY_CONFIG=$HOME/api_keys/HarnessGenBench/set_api_key_magma.sh
    python3 scripts/hgb_magma_corpus_generate.py --generator g2fuzz --targets libpng --validate-seconds 20
    python3 scripts/hgb_magma_corpus_generate.py --generator elfuzz --targets libxml2 --validate-seconds 15
    python3 scripts/hgb_magma_corpus_generate.py --generator all --targets all

Outputs (per generator/target)::

    workspace/magma/corpus/<generator>/<target>/<run-id>/   raw generator run
    workspace/magma/corpus/<generator>/<target>/current     symlink to run
    workspace/magma/corpus/<generator>/<target>/corpus/     canonical seed set
    workspace/magma/corpus/<generator>/<target>/manifest.json
    workspace/magma/corpus/<generator>/summary.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
MAGMA_TARGETS = ROOT / "metadata/magma_targets.yaml"
ELFUZZ_MAGMA_ADAPTERS = ROOT / "metadata/elfuzz_target_adapters_magma.yaml"
G2FUZZ_MAGMA_ADAPTERS = ROOT / "metadata/g2fuzz_target_adapters_magma.yaml"
ELFUZZ_ENTRYPOINT = ROOT / "docker/elfuzz/entrypoint.sh"
COMMON_BIN = ROOT / "docker/common"
CORPUS_ROOT = ROOT / "workspace/magma/corpus"
LLM_LOCKS = ROOT / "workspace/llm-locks"
MAX_SEED_BYTES = 4 * 1024 * 1024
PRINT_LOCK = threading.Lock()


class DriverError(RuntimeError):
    pass


def log(message: str) -> None:
    with PRINT_LOCK:
        print(message, flush=True)


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def load_targets() -> dict[str, dict[str, Any]]:
    data = load_yaml(MAGMA_TARGETS)
    return data.get("targets", {})


def load_adapters(path: Path) -> dict[str, dict[str, Any]]:
    data = load_yaml(path)
    return {str(item["target"]): item for item in data.get("targets", [])}


def resolve_targets(raw: str, targets: dict[str, dict[str, Any]]) -> list[str]:
    if raw.strip() in {"", "all"}:
        return list(targets)
    selected = [item for item in raw.replace(",", " ").split() if item]
    unknown = [item for item in selected if item not in targets]
    if unknown:
        raise DriverError(f"unknown MAGMA target(s): {', '.join(unknown)}")
    return selected


def source_api_config(config_path: Path | None) -> None:
    """Load the shell credential file and merge its exports into os.environ."""

    if config_path is None:
        return
    if not config_path.is_file():
        raise DriverError(f"HGB_API_KEY_CONFIG does not exist: {config_path}")
    script = f"set -a; source {shlex.quote(str(config_path))}; env -0"
    proc = subprocess.run(["bash", "-c", script], capture_output=True, check=False)
    if proc.returncode != 0:
        raise DriverError(
            f"failed to source API key config {config_path}: "
            f"{proc.stderr.decode('utf-8', 'replace').strip()}"
        )
    for entry in proc.stdout.split(b"\0"):
        if b"=" not in entry:
            continue
        key, value = entry.split(b"=", 1)
        os.environ[key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")


def resolve_provider() -> dict[str, str]:
    """Resolve the OpenAI-compatible credential triple (llm_provider.sh rules)."""

    api_key = (
        os.environ.get("HGB_LLM_API_KEY")
        or os.environ.get("USTC_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or os.environ.get("API_KEY")
        or ""
    )
    base_url = (
        os.environ.get("HGB_LLM_BASE_URL")
        or os.environ.get("USTC_BASE_URL")
        or os.environ.get("USTC_API_BASE")
        or os.environ.get("OPENAI_BASE_URL")
        or os.environ.get("BASE_URL")
        or ""
    )
    model = (
        os.environ.get("HGB_LLM_MODEL")
        or os.environ.get("OPENAI_MODEL")
        or os.environ.get("MODEL")
        or ""
    )
    provider = (os.environ.get("HGB_LLM_PROVIDER") or "auto").lower()
    if provider == "auto":
        if "api.deepseek.com" in base_url:
            provider = "deepseek"
        elif "api.llm.ustc.edu.cn" in base_url:
            provider = "ustc"
        else:
            provider = "custom"
    if not base_url:
        base_url = {
            "deepseek": "https://api.deepseek.com",
            "ustc": "https://api.llm.ustc.edu.cn",
        }.get(provider, "https://api.openai.com/v1")
    if not model:
        model = {
            "deepseek": "deepseek-v4-pro",
            "ustc": "glm-5.2",
        }.get(provider, "gpt-4o-mini")
    resolved = {
        "API_KEY": api_key,
        "BASE_URL": base_url,
        "MODEL": model,
        "OPENAI_API_KEY": api_key,
        "OPENAI_BASE_URL": base_url,
        "OPENAI_MODEL": model,
        "HGB_LLM_PROVIDER": provider,
        "HGB_LLM_PROVIDER_RESOLVED": provider,
        "HGB_LLM_API_KEY": api_key,
        "HGB_LLM_BASE_URL": base_url,
        "HGB_LLM_MODEL": model,
    }
    for key, value in resolved.items():
        if value:
            os.environ[key] = value
    if not api_key:
        raise DriverError("no LLM API key configured; set HGB_API_KEY_CONFIG or API_KEY")
    return resolved


def docker_image_present(image: str) -> bool:
    return (
        subprocess.run(
            ["docker", "image", "inspect", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


def run_logged(
    command: list[str],
    log_path: Path,
    timeout_seconds: int,
    env: dict[str, str] | None = None,
    container_name: str | None = None,
) -> int:
    """Run a command with stdout/stderr captured in log_path."""

    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as handle:
        proc = subprocess.Popen(
            command,
            stdout=handle,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
        )
        try:
            return proc.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            if container_name:
                subprocess.run(
                    ["docker", "rm", "-f", container_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            proc.kill()
            proc.wait(timeout=60)
            return 124


def chown_tree(path: Path, image: str) -> None:
    """The generator entrypoints use exec, so their EXIT chown trap never runs."""

    if not path.exists():
        return
    try:
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--pull=never",
                "--entrypoint",
                "/bin/chown",
                "-v",
                f"{path}:/workspace",
                image,
                "-R",
                f"{os.getuid()}:{os.getgid()}",
                "/workspace",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        log(f"warning: chown of {path} timed out; continuing (files remain readable)")


def remove_tree(path: Path, image: str) -> None:
    if not path.exists():
        return
    try:
        shutil.rmtree(path)
        return
    except PermissionError:
        pass
    try:
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--pull=never",
                "--entrypoint",
                "/bin/rm",
                "-v",
                f"{path.parent}:/cleanup",
                image,
                "-rf",
                f"/cleanup/{path.name}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        log(f"warning: cleanup of {path} timed out")


def prepare_target_package(target: str, spec: dict[str, Any]) -> Path:
    """Create the minimal target package the ELFuzz corpus-only entrypoint needs."""

    package = CORPUS_ROOT / "_packages" / f"magma_{target}"
    benchmark = package / "fuzzbench_benchmark"
    benchmark.mkdir(parents=True, exist_ok=True)
    manifest = {
        "target": f"magma_{target}",
        "project": str(spec.get("project", target)),
        "fuzz_target": str(spec.get("program", "")),
        "source": "magma",
        "corpus_generation_package": True,
        "note": "placeholder benchmark used only by the corpus-generation path",
    }
    (package / "target_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (benchmark / "benchmark.yaml").write_text(
        f"project: {manifest['project']}\nfuzz_target: {manifest['fuzz_target']}\n",
        encoding="utf-8",
    )
    (benchmark / "build.sh").write_text(
        "#!/bin/bash\n# Corpus-generation placeholder: no SUT is built on this path.\nexit 0\n",
        encoding="utf-8",
    )
    return package


def format_slug(formats: list[str]) -> list[str]:
    return [str(item) for item in formats if str(item).strip()]


def g2fuzz_program_map(
    adapter: dict[str, Any],
    formats_override: str,
    all_formats: bool,
) -> dict[str, list[str]]:
    formats = format_slug(adapter.get("formats", []))
    if formats_override:
        formats = [item.strip() for item in formats_override.split(",") if item.strip()]
    elif not all_formats:
        formats = formats[:1]
    if not formats:
        raise DriverError(f"no G2Fuzz format configured for {adapter.get('target')}")
    return {str(adapter["program_id"]): formats}


def dedupe_corpus(source: Path, destination: Path, max_files: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Copy the unique input payloads from source to destination.

    Returns a summary and a per-file provenance list.  Identical payloads are
    collapsed so a generator that emits the same seed many times does not
    inflate the corpus count.
    """

    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    seen: dict[str, str] = {}
    provenance: list[dict[str, Any]] = []
    total_bytes = 0
    if source.is_dir():
        candidates = sorted(path for path in source.rglob("*") if path.is_file())
    else:
        candidates = []
    for path in candidates:
        if len(seen) >= max_files:
            break
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size <= 0 or size > MAX_SEED_BYTES:
            continue
        digest = sha256_file(path)
        if digest in seen:
            continue
        suffix = path.suffix if 0 < len(path.suffix) <= 12 else ""
        stored = f"seed_{len(seen):04d}{suffix}"
        shutil.copy2(path, destination / stored)
        seen[digest] = stored
        total_bytes += size
        provenance.append(
            {
                "sha256": digest,
                "size": size,
                "source": str(path),
                "stored": stored,
            }
        )
    summary = {
        "source_files": len([p for p in candidates if p.is_file()]),
        "unique_files": len(seen),
        "bytes": total_bytes,
    }
    return summary, provenance


def first_failed_stage(result: dict[str, Any]) -> str:
    stages = result.get("stages", {}) if isinstance(result.get("stages"), dict) else {}
    for name, record in stages.items():
        if isinstance(record, dict) and record.get("status") == "failed":
            return name
    return ""


def read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def run_seed_replay(target: str, corpus: Path, log_dir: Path) -> dict[str, Any]:
    """Replay the corpus with libFuzzer ``-runs=0`` inside the MAGMA image.

    This is the reliable consumption check: fork-mode fuzzing can spend the
    whole short smoke window in startup on a loaded host, while ``-runs=0``
    reports exactly how many seed files libFuzzer admitted.
    """

    spec = load_targets().get(target, {})
    program = str(spec.get("program", ""))
    if not program:
        return {"replay_exit": 127, "replay_accepted": 0, "error": "unknown MAGMA program"}
    image = f"hgb-magma-{target}-libfuzzer_asan:latest"
    if not docker_image_present(image):
        return {"replay_exit": 127, "replay_accepted": 0, "error": f"missing image {image}"}
    log_path = log_dir / "seed_replay.log"
    log_dir.mkdir(parents=True, exist_ok=True)
    script = (
        "set -u; cd /tmp; "
        "ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:abort_on_error=0 "
        f"timeout 180 /magma_out/{program} -runs=0 -timeout=25 -len_control=0 /corpus; "
        "echo replay_exit=$?"
    )
    command = [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--entrypoint",
        "/bin/bash",
        "-v",
        f"{corpus}:/corpus:ro",
        image,
        "-lc",
        script,
    ]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=300, check=False)
        exit_code = proc.returncode
        text = (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        exit_code = 124
        text = "seed replay timed out\n"
    log_path.write_text(text, encoding="utf-8")
    accepted = 0
    seed_files = 0
    for line in text.splitlines():
        if "seed corpus: files:" in line:
            try:
                seed_files = int(line.split("files:", 1)[1].split()[0])
            except (IndexError, ValueError):
                pass
        if "corp: " in line:
            try:
                accepted = max(accepted, int(line.split("corp: ", 1)[1].split("/")[0]))
            except (IndexError, ValueError):
                pass
    return {
        "replay_exit": exit_code,
        "replay_seed_files": seed_files,
        "replay_accepted": accepted,
        "replay_log": str(log_path),
    }


def run_native_campaign(
    target: str,
    corpus: Path,
    out_dir: Path,
    seconds: int,
    log_dir: Path,
) -> dict[str, Any]:
    command = [
        sys.executable,
        str(ROOT / "scripts/hgb_magma_eval.py"),
        "--target",
        target,
        "--fuzzer",
        "libfuzzer_asan",
        "campaign",
        "--seeds",
        str(corpus),
        "--seconds",
        str(seconds),
        "--out",
        str(out_dir),
    ]
    replay = run_seed_replay(target, corpus, log_dir)
    env = dict(os.environ)
    env.setdefault("DOCKER_BUILDKIT", "0")
    code = run_logged(command, log_dir / "validation_campaign.log", timeout_seconds=seconds + 300, env=env)
    campaign_log = out_dir / "campaign.log"
    log_text = campaign_log.read_text(encoding="utf-8", errors="replace") if campaign_log.is_file() else ""
    accepted = 0
    for line in log_text.splitlines():
        seed_match = re.search(r"(\d+) seed inputs", line)
        if seed_match:
            accepted = max(accepted, int(seed_match.group(1)))
        if "corp: " in line:
            try:
                accepted = max(accepted, int(line.split("corp: ", 1)[1].split()[0]))
            except (IndexError, ValueError):
                continue
    final_corpus = out_dir / "final_corpus"
    accepted = max(accepted, int(replay.get("replay_accepted", 0) or 0))
    return {
        "campaign_exit": code,
        "seconds": seconds,
        "input_seed_files": len([p for p in corpus.iterdir() if p.is_file()]) if corpus.is_dir() else 0,
        "accepted_corpus_hint": accepted,
        "campaign_corpus_files": len([p for p in final_corpus.rglob("*") if p.is_file()]) if final_corpus.is_dir() else 0,
        "crashes": len([p for p in (out_dir / "crashes").rglob("*") if p.is_file()]) if (out_dir / "crashes").is_dir() else 0,
        "seed_replay": replay,
        "log": str(log_dir / "validation_campaign.log"),
        "campaign_log": str(campaign_log),
    }


# ---------------------------------------------------------------------------
# ELFuzz
# ---------------------------------------------------------------------------


def elfuzz_invalid(
    target: str,
    adapter: dict[str, Any],
    out_root: Path,
    run_id: str,
) -> dict[str, Any]:
    run_dir = out_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    invalid_path = run_dir / "invalid.json"
    command = [
        sys.executable,
        str(COMMON_BIN / "elfuzz_target_pipeline.py"),
        "write-invalid",
        "--target",
        str(adapter["target"]),
        "--metadata-root",
        str(ROOT / "metadata"),
        "--out",
        str(invalid_path),
    ]
    code = subprocess.run(command, capture_output=True, text=True, check=False).returncode
    payload = read_json(invalid_path)
    if code != 0 or not payload:
        return {
            "schema_version": 1,
            "generator": "elfuzz",
            "target": target,
            "magma_target": adapter["target"],
            "status": "failed",
            "applicability": str(adapter.get("applicability")),
            "reason": "could not materialize the committed Invalid classification",
            "reason_code": "invalid_payload_failed",
            "run_id": run_id,
            "run_dir": str(run_dir),
            "generated_at": utc_stamp(),
        }
    manifest = {
        "schema_version": 1,
        "generator": "elfuzz",
        "task_family": "input_generator",
        "target": target,
        "magma_target": adapter["target"],
        "status": "not_applicable",
        "applicability": payload.get("applicability", "Invalid"),
        "reason": payload.get("reason", "Invalid: ELFuzz supports text-input targets only"),
        "reason_code": payload.get("reason_code", "elfuzz_non_text_target"),
        "failure_stage": "target_classification",
        "run_id": run_id,
        "run_dir": str(run_dir),
        "corpus_dir": "",
        "corpus_file_count": 0,
        "corpus_unique_count": 0,
        "corpus_bytes": 0,
        "model": "",
        "command": command,
        "generated_at": utc_stamp(),
        "adapter": adapter,
        "notes": [
            "Contractual N/A: ELFuzz only synthesizes text-input generator programs.",
            "No container, model request, or corpus was produced for this cell.",
        ],
    }
    (out_root / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def run_elfuzz(
    target: str,
    spec: dict[str, Any],
    adapter: dict[str, Any],
    args: argparse.Namespace,
    env: dict[str, str],
    run_id: str,
) -> dict[str, Any]:
    out_root = CORPUS_ROOT / "elfuzz" / target
    out_root.mkdir(parents=True, exist_ok=True)
    if adapter.get("applicability") != "applicable":
        return elfuzz_invalid(target, adapter, out_root, run_id)

    image = "hgb-elfuzz:latest"
    if not docker_image_present(image):
        raise DriverError(f"generator image missing: {image}")

    run_dir = out_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    package = prepare_target_package(target, spec)
    container = f"hgb-magma-corpus-elfuzz-{target}-{run_id.lower()}"
    log_path = run_dir / "host.log"
    elfuzz_env = dict(os.environ)
    elfuzz_env.update(
        {
            "HGB_TARGET": adapter["target"],
            "HGB_TARGET_PACKAGE": "/target",
            "HGB_BASELINE_PROFILE": args.profile,
            "HGB_BASELINE_PROTOCOL": "blind-project",
            "HGB_GENERATION_TIMEOUT_SECONDS": str(args.elfuzz_timeout),
            "HGB_SAVE_MODE": "debug",
            "HGB_HOST_UID": str(os.getuid()),
            "HGB_HOST_GID": str(os.getgid()),
            "HGB_RUN_ID": run_id,
            "HGB_WORKSPACE_HOST": str(run_dir.resolve()),
            "HGB_DOCKER_BUILDKIT": "0",
            "DOCKER_BUILDKIT": "0",
            "ELFUZZ_CORPUS_ONLY": "1",
            "ELFUZZ_SKIP_FUZZBENCH_PREPARE": "1",
            "ELFUZZ_SKIP_COVERAGE": "1",
            "ELFUZZ_KEEP_GENERATED_OUTPUTS": "1",
            "ELFUZZ_EVOLUTION_ITERATIONS": str(args.elfuzz_iterations),
            "ELFUZZ_NUM_VARIANTS": str(args.elfuzz_variants),
            "ELFUZZ_NUM_OUTPUTS_PER_VARIANT": str(args.elfuzz_outputs),
            "ELFUZZ_VARIANT_JOBS": str(args.elfuzz_jobs),
            "ELFUZZ_CORPUS_MAX_OUTPUTS": str(args.elfuzz_max_outputs),
            "ELFUZZ_FALLBACK_INPUTS_PER_PROGRAM": str(args.elfuzz_fallback_inputs),
            "ELFUZZ_TGI_WAITING_SECONDS": str(args.elfuzz_tgi_waiting),
            "HGB_LLM_LOCK_DIR": "/hgb-llm-locks",
            "HGB_LLM_MIN_INTERVAL_SECONDS": str(args.llm_min_interval),
            "HGB_LLM_REQUEST_TIMEOUT_SECONDS": str(args.llm_timeout),
        }
    )
    command = [
        "docker",
        "run",
        "--rm",
        "--init",
        "--pull=never",
        "--name",
        container,
        "--entrypoint",
        "/opt/hgb/entrypoint.sh",
        "-e",
        "API_KEY",
        "-e",
        "BASE_URL",
        "-e",
        "MODEL",
        "-e",
        "OPENAI_API_KEY",
        "-e",
        "OPENAI_BASE_URL",
        "-e",
        "OPENAI_MODEL",
        "-e",
        "HGB_LLM_PROVIDER",
        "-e",
        "HGB_LLM_API_KEY",
        "-e",
        "HGB_LLM_BASE_URL",
        "-e",
        "HGB_LLM_MODEL",
        "-e",
        "HGB_LLM_REQUEST_TIMEOUT_SECONDS",
        "-e",
        "HGB_LLM_LOCK_DIR",
        "-e",
        "HGB_LLM_MIN_INTERVAL_SECONDS",
        "-e",
        "HGB_TARGET",
        "-e",
        "HGB_TARGET_PACKAGE",
        "-e",
        "HGB_BASELINE_PROFILE",
        "-e",
        "HGB_BASELINE_PROTOCOL",
        "-e",
        "HGB_GENERATION_TIMEOUT_SECONDS",
        "-e",
        "HGB_SAVE_MODE",
        "-e",
        "HGB_HOST_UID",
        "-e",
        "HGB_HOST_GID",
        "-e",
        "HGB_RUN_ID",
        "-e",
        "HGB_WORKSPACE_HOST",
        "-e",
        "DOCKER_BUILDKIT",
        "-e",
        "ELFUZZ_CORPUS_ONLY",
        "-e",
        "ELFUZZ_SKIP_FUZZBENCH_PREPARE",
        "-e",
        "ELFUZZ_SKIP_COVERAGE",
        "-e",
        "ELFUZZ_KEEP_GENERATED_OUTPUTS",
        "-e",
        "ELFUZZ_EVOLUTION_ITERATIONS",
        "-e",
        "ELFUZZ_NUM_VARIANTS",
        "-e",
        "ELFUZZ_NUM_OUTPUTS_PER_VARIANT",
        "-e",
        "ELFUZZ_VARIANT_JOBS",
        "-e",
        "ELFUZZ_CORPUS_MAX_OUTPUTS",
        "-e",
        "ELFUZZ_FALLBACK_INPUTS_PER_PROGRAM",
        "-e",
        "ELFUZZ_TGI_WAITING_SECONDS",
        "-v",
        f"{run_dir}:/workspace",
        "-v",
        f"{package}:/target:ro",
        "-v",
        f"{ROOT / 'metadata'}:/opt/hgb/metadata:ro",
        "-v",
        f"{ROOT / 'repro'}:/opt/hgb/repro:ro",
        "-v",
        f"{COMMON_BIN}:/opt/hgb/bin:ro",
        "-v",
        f"{ELFUZZ_ENTRYPOINT}:/opt/hgb/entrypoint.sh:ro",
        "-v",
        f"{LLM_LOCKS}:/hgb-llm-locks",
        image,
        "generate-target",
    ]
    command_path = run_dir / "host_command.txt"
    command_path.write_text(" ".join(shlex.quote(part) for part in command) + "\n", encoding="utf-8")
    if args.dry_run:
        log(f"[dry-run] elfuzz {target}: {' '.join(shlex.quote(part) for part in command)}")
        return {
            "schema_version": 1,
            "generator": "elfuzz",
            "target": target,
            "magma_target": adapter["target"],
            "status": "dry_run",
            "applicability": "applicable",
            "reason": "dry run",
            "run_id": run_id,
            "run_dir": str(run_dir),
            "generated_at": utc_stamp(),
        }

    log(f"elfuzz {target}: synthesizing corpus in {run_dir} (model={env.get('MODEL')})")
    code = run_logged(command, log_path, args.elfuzz_timeout + 300, env=elfuzz_env, container_name=container)
    chown_tree(run_dir, image)
    result = read_json(run_dir / "result.json")
    status = str(result.get("status", "failed"))
    reason = str(result.get("reason", f"container exited {code}"))
    produced = run_dir / "generated_inputs" / "produced"
    corpus_dir = out_root / "corpus"
    summary, provenance = dedupe_corpus(produced, corpus_dir, args.max_corpus_files)
    manifest_status = "corpus_ready" if status == "corpus_ready" and summary["unique_files"] > 0 else "failed"
    if status == "corpus_ready" and summary["unique_files"] == 0:
        reason = "ELFuzz reported corpus_ready but produced no usable input files"
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "generator": "elfuzz",
        "task_family": "input_generator",
        "target": target,
        "magma_target": adapter["target"],
        "status": manifest_status,
        "applicability": "applicable",
        "reason": reason,
        "reason_code": "" if manifest_status == "corpus_ready" else "elfuzz_corpus_generation_failed",
        "failure_stage": "" if manifest_status == "corpus_ready" else (first_failed_stage(result) or "synthesis"),
        "run_id": run_id,
        "run_dir": str(run_dir),
        "corpus_dir": str(corpus_dir),
        "corpus_file_count": summary["unique_files"],
        "corpus_unique_count": summary["unique_files"],
        "corpus_bytes": summary["bytes"],
        "source_file_count": summary["source_files"],
        "model": str(env.get("MODEL", "")),
        "profile": args.profile,
        "command": command,
        "container_exit": code,
        "generated_at": utc_stamp(),
        "elfuzz": result.get("elfuzz", {}),
        "stages": result.get("stages", {}),
        "adapter": adapter,
        "corpus_provenance": provenance[: args.max_corpus_files],
        "notes": [
            "Corpus-only mode: no native SUT build, validation campaign, or coverage replay.",
            "Inputs are outputs generated by ELFuzz's synthesized/evolved variant programs.",
        ],
    }
    if args.validate_seconds > 0 and manifest_status == "corpus_ready":
        validation_dir = out_root / "validation" / run_id
        manifest["validation"] = run_native_campaign(
            target, corpus_dir, validation_dir, args.validate_seconds, validation_dir
        )
    (out_root / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (run_dir / "corpus_manifest.jsonl").write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in provenance),
        encoding="utf-8",
    )
    update_current(out_root, run_dir)
    return manifest


def update_current(out_root: Path, run_dir: Path) -> None:
    current = out_root / "current"
    try:
        if current.is_symlink() or current.is_file():
            current.unlink()
        elif current.is_dir():
            shutil.rmtree(current)
        current.symlink_to(run_dir.name)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# G2Fuzz
# ---------------------------------------------------------------------------


def run_g2fuzz(
    target: str,
    spec: dict[str, Any],
    adapter: dict[str, Any],
    args: argparse.Namespace,
    env: dict[str, str],
    run_id: str,
) -> dict[str, Any]:
    image = "hgb-g2fuzz:latest"
    if not docker_image_present(image):
        raise DriverError(f"generator image missing: {image}")
    out_root = CORPUS_ROOT / "g2fuzz" / target
    out_root.mkdir(parents=True, exist_ok=True)
    run_dir = out_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    program_map = g2fuzz_program_map(adapter, args.g2fuzz_formats, args.g2fuzz_all_formats)
    map_path = run_dir / "program_to_format.json"
    map_path.write_text(json.dumps(program_map, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    container = f"hgb-magma-corpus-g2fuzz-{target}-{run_id.lower()}"
    log_path = run_dir / "host.log"
    g2_env = dict(os.environ)
    g2_env.update(
        {
            "G2FUZZ_PROGRAM": str(adapter["program_id"]),
            "G2FUZZ_MODEL": str(env.get("MODEL", "")),
            "G2FUZZ_TRY_NUM": str(args.g2fuzz_try_num),
            "G2FUZZ_PER_FORMAT_TIMEOUT_SECONDS": str(args.g2fuzz_timeout),
            "G2FUZZ_MAX_PRESEEDED_CORPUS_FILES": "0",
            "G2FUZZ_LLM_REQUEST_TIMEOUT_SECONDS": str(args.llm_timeout),
            "HGB_LLM_REQUEST_TIMEOUT_SECONDS": str(args.llm_timeout),
            "HGB_LLM_LOCK_DIR": "/hgb-llm-locks",
            "HGB_LLM_MIN_INTERVAL_SECONDS": str(args.llm_min_interval),
            "HGB_HOST_UID": str(os.getuid()),
            "HGB_HOST_GID": str(os.getgid()),
        }
    )
    command = [
        "docker",
        "run",
        "--rm",
        "--init",
        "--pull=never",
        "--name",
        container,
        "--entrypoint",
        "/opt/hgb/entrypoint.sh",
        "-e",
        "API_KEY",
        "-e",
        "BASE_URL",
        "-e",
        "MODEL",
        "-e",
        "OPENAI_API_KEY",
        "-e",
        "OPENAI_BASE_URL",
        "-e",
        "OPENAI_MODEL",
        "-e",
        "HGB_LLM_PROVIDER",
        "-e",
        "HGB_LLM_API_KEY",
        "-e",
        "HGB_LLM_BASE_URL",
        "-e",
        "HGB_LLM_MODEL",
        "-e",
        "HGB_LLM_REQUEST_TIMEOUT_SECONDS",
        "-e",
        "HGB_LLM_LOCK_DIR",
        "-e",
        "HGB_LLM_MIN_INTERVAL_SECONDS",
        "-e",
        "HGB_HOST_UID",
        "-e",
        "HGB_HOST_GID",
        "-e",
        "G2FUZZ_PROGRAM",
        "-e",
        "G2FUZZ_MODEL",
        "-e",
        "G2FUZZ_TRY_NUM",
        "-e",
        "G2FUZZ_PER_FORMAT_TIMEOUT_SECONDS",
        "-e",
        "G2FUZZ_MAX_PRESEEDED_CORPUS_FILES",
        "-e",
        "G2FUZZ_LLM_REQUEST_TIMEOUT_SECONDS",
        "-v",
        f"{run_dir}:/workspace",
        "-v",
        f"{map_path}:/opt/hgb/artifacts/g2fuzz/program_to_format.json:ro",
        "-v",
        f"{LLM_LOCKS}:/hgb-llm-locks",
        image,
        "generate-seeds",
    ]
    (run_dir / "host_command.txt").write_text(
        " ".join(shlex.quote(part) for part in command) + "\n", encoding="utf-8"
    )
    if args.dry_run:
        log(f"[dry-run] g2fuzz {target}: {' '.join(shlex.quote(part) for part in command)}")
        return {
            "schema_version": 1,
            "generator": "g2fuzz",
            "target": target,
            "magma_target": adapter["target"],
            "status": "dry_run",
            "applicability": "applicable",
            "reason": "dry run",
            "run_id": run_id,
            "run_dir": str(run_dir),
            "generated_at": utc_stamp(),
        }

    log(
        f"g2fuzz {target}: generating {program_map[adapter['program_id']]} seeds in {run_dir} "
        f"(model={env.get('MODEL')})"
    )
    code = run_logged(command, log_path, args.g2fuzz_timeout + 300, env=g2_env, container_name=container)
    chown_tree(run_dir, image)
    metadata = read_json(run_dir / "metadata.json")
    output_dir = run_dir / f"{adapter['program_id']}_output" / "default"
    seeds_dir = output_dir / "gen_seeds"
    generators_dir = output_dir / "generators"
    corpus_dir = out_root / "corpus"
    summary, provenance = dedupe_corpus(seeds_dir, corpus_dir, args.max_corpus_files)
    upstream_status = str(metadata.get("status", ""))
    manifest_status = (
        "corpus_ready"
        if upstream_status in {"completed", "partial_completed"} and summary["unique_files"] > 0
        else "failed"
    )
    reason = str(metadata.get("reason", f"container exited {code}"))
    if manifest_status == "failed" and not reason:
        reason = f"G2Fuzz container exited {code}"
    generators_out = out_root / "generators"
    if generators_out.exists():
        shutil.rmtree(generators_out)
    if generators_dir.is_dir():
        shutil.copytree(generators_dir, generators_out)
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "generator": "g2fuzz",
        "task_family": "input_generator",
        "target": target,
        "magma_target": adapter["target"],
        "status": manifest_status,
        "applicability": "applicable",
        "reason": reason,
        "reason_code": "" if manifest_status == "corpus_ready" else "g2fuzz_corpus_generation_failed",
        "failure_stage": "" if manifest_status == "corpus_ready" else "program_generation",
        "run_id": run_id,
        "run_dir": str(run_dir),
        "corpus_dir": str(corpus_dir),
        "corpus_file_count": summary["unique_files"],
        "corpus_unique_count": summary["unique_files"],
        "corpus_bytes": summary["bytes"],
        "source_file_count": summary["source_files"],
        "generator_count": len([p for p in generators_out.rglob("*") if p.is_file()]) if generators_out.is_dir() else 0,
        "model": str(env.get("MODEL", "")),
        "method_profile": str(adapter.get("method_profile", "")),
        "formats": program_map[adapter["program_id"]],
        "command": command,
        "container_exit": code,
        "generated_at": utc_stamp(),
        "upstream_status": upstream_status,
        "upstream_metadata": metadata,
        "adapter": adapter,
        "corpus_provenance": provenance[: args.max_corpus_files],
        "notes": [
            "G2Fuzz program_to_format overlay is generated from the parallel MAGMA adapter manifest.",
            "Preseeded MAGMA corpus files are disabled so the corpus contains only G2-generated seeds.",
        ],
    }
    if args.validate_seconds > 0 and manifest_status == "corpus_ready":
        validation_dir = out_root / "validation" / run_id
        manifest["validation"] = run_native_campaign(
            target, corpus_dir, validation_dir, args.validate_seconds, validation_dir
        )
    (out_root / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (run_dir / "corpus_manifest.jsonl").write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in provenance),
        encoding="utf-8",
    )
    update_current(out_root, run_dir)
    return manifest


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def previous_success(out_root: Path) -> str:
    manifest = read_json(out_root / "manifest.json")
    if manifest.get("status") == "corpus_ready" and (out_root / "corpus").is_dir():
        return str(manifest.get("run_id", ""))
    return ""


def write_summary(generator: str, results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for item in results.values():
        status = str(item.get("status", "failed"))
        counts[status] = counts.get(status, 0) + 1
    summary = {
        "schema_version": 1,
        "generator": generator,
        "generated_at": utc_stamp(),
        "targets": {
            target: {
                "status": item.get("status"),
                "reason": item.get("reason"),
                "reason_code": item.get("reason_code", ""),
                "applicability": item.get("applicability"),
                "corpus_dir": item.get("corpus_dir", ""),
                "corpus_file_count": item.get("corpus_file_count", 0),
                "corpus_bytes": item.get("corpus_bytes", 0),
                "run_dir": item.get("run_dir", ""),
                "validation": item.get("validation"),
            }
            for target, item in sorted(results.items())
        },
        "counts": counts,
    }
    path = CORPUS_ROOT / generator / "summary.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--generator", choices=("elfuzz", "g2fuzz", "all"), default="all")
    parser.add_argument(
        "--targets",
        nargs="+",
        default=["all"],
        help="one or more MAGMA target names (default: all)",
    )
    parser.add_argument("--run-id", default="", help="explicit run id (default: UTC timestamp)")
    parser.add_argument("--force", action="store_true", help="rerun even when a successful corpus exists")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--parallel", type=int, default=1, help="concurrent target runs (default 1)")
    parser.add_argument("--max-corpus-files", type=int, default=1024, help="cap unique seed files per target")
    parser.add_argument("--validate-seconds", type=int, default=0,
                        help="run a MAGMA-native libFuzzer campaign of this length against each corpus")
    parser.add_argument("--profile", default="compat-smoke", help="ELFuzz profile (corpus-only ignores campaign budget)")
    parser.add_argument("--elfuzz-iterations", type=int, default=1)
    parser.add_argument("--elfuzz-variants", type=int, default=4)
    parser.add_argument("--elfuzz-outputs", type=int, default=10,
                        help="outputs generated per variant program during synthesis")
    parser.add_argument("--elfuzz-jobs", type=int, default=8)
    parser.add_argument("--elfuzz-max-outputs", type=int, default=256,
                        help="cap retained outputs per generation before do_gen cleanup")
    parser.add_argument("--elfuzz-fallback-inputs", type=int, default=20)
    parser.add_argument("--elfuzz-tgi-waiting", type=int, default=5)
    parser.add_argument("--elfuzz-timeout", type=int, default=3600)
    parser.add_argument("--g2fuzz-formats", default="", help="override formats, comma separated")
    parser.add_argument("--g2fuzz-all-formats", action="store_true",
                        help="use every format in the adapter (default: first format only)")
    parser.add_argument("--g2fuzz-try-num", type=int, default=1)
    parser.add_argument("--g2fuzz-timeout", type=int, default=1800)
    parser.add_argument("--llm-timeout", type=int, default=900)
    parser.add_argument("--llm-min-interval", type=float, default=2.0)
    parser.add_argument("--api-key-config", default=os.environ.get("HGB_API_KEY_CONFIG", ""))
    args = parser.parse_args(argv)

    if args.parallel < 1:
        parser.error("--parallel must be >= 1")
    if args.validate_seconds < 0:
        parser.error("--validate-seconds must be >= 0")
    try:
        config_path = Path(os.path.expanduser(args.api_key_config)) if args.api_key_config else None
        source_api_config(config_path)
        env = resolve_provider()
        if not docker_image_present("hgb-magma-libpng-libfuzzer_asan:latest"):
            raise DriverError("MAGMA native images are missing (hgb-magma-*-libfuzzer_asan:latest)")
        if args.validate_seconds > 0 and not (ROOT / "scripts/hgb_magma_eval.py").is_file():
            raise DriverError("scripts/hgb_magma_eval.py is required for --validate-seconds")
        targets_all = load_targets()
        selected = resolve_targets(" ".join(args.targets), targets_all)
        elfuzz_adapters = load_adapters(ELFUZZ_MAGMA_ADAPTERS)
        g2fuzz_adapters = load_adapters(G2FUZZ_MAGMA_ADAPTERS)
        for label, adapters in (("elfuzz", elfuzz_adapters), ("g2fuzz", g2fuzz_adapters)):
            for target in selected:
                adapter = adapters.get(f"magma_{target}")
                if not adapter:
                    raise DriverError(f"no {label} MAGMA adapter for target {target}")
                spec_path = str(adapter.get("format_spec", ""))
                if spec_path and not (ROOT / spec_path).is_file():
                    raise DriverError(f"{label}/{target}: missing format spec {spec_path}")
        LLM_LOCKS.mkdir(parents=True, exist_ok=True)
        CORPUS_ROOT.mkdir(parents=True, exist_ok=True)
        run_id = args.run_id or utc_stamp()

        jobs: list[tuple[str, str]] = []
        generators = ["elfuzz", "g2fuzz"] if args.generator == "all" else [args.generator]
        for generator in generators:
            adapters = elfuzz_adapters if generator == "elfuzz" else g2fuzz_adapters
            for target in selected:
                if f"magma_{target}" not in adapters:
                    raise DriverError(f"no {generator} MAGMA adapter for target {target}")
                if not args.force and not args.dry_run:
                    existing = previous_success(CORPUS_ROOT / generator / target)
                    if existing:
                        log(f"skip {generator}/{target}: existing corpus_ready run {existing}")
                        continue
                jobs.append((generator, target))

        results: dict[str, dict[str, Any]] = {}

        def result_key(generator: str, target: str) -> str:
            return f"{generator}/{target}"

        def work(generator: str, target: str) -> dict[str, Any]:
            target_run_id = run_id if args.run_id or len(jobs) == 1 else f"{run_id}-{target}"
            if generator == "elfuzz":
                return run_elfuzz(
                    target,
                    targets_all[target],
                    elfuzz_adapters[f"magma_{target}"],
                    args,
                    env,
                    target_run_id,
                )
            return run_g2fuzz(
                target,
                targets_all[target],
                g2fuzz_adapters[f"magma_{target}"],
                args,
                env,
                target_run_id,
            )

        if args.parallel == 1:
            for generator, target in jobs:
                key = result_key(generator, target)
                try:
                    results[key] = work(generator, target)
                except Exception as exc:  # noqa: BLE001 - report per-target failure
                    results[key] = {
                        "schema_version": 1,
                        "generator": generator,
                        "target": target,
                        "status": "failed",
                        "reason": f"driver error: {exc}",
                        "reason_code": "driver_error",
                        "generated_at": utc_stamp(),
                    }
        else:
            with ThreadPoolExecutor(max_workers=args.parallel) as pool:
                futures = {pool.submit(work, g, t): (g, t) for g, t in jobs}
                for future in as_completed(futures):
                    generator, target = futures[future]
                    key = result_key(generator, target)
                    try:
                        results[key] = future.result()
                    except Exception as exc:  # noqa: BLE001
                        results[key] = {
                            "schema_version": 1,
                            "generator": generator,
                            "target": target,
                            "status": "failed",
                            "reason": f"driver error: {exc}",
                            "reason_code": "driver_error",
                            "generated_at": utc_stamp(),
                        }

        # Load every persisted manifest so a per-target rerun never shrinks the
        # generator-wide summary (e.g. rerunning libtiff must keep libpng).
        for generator in generators:
            out_root = CORPUS_ROOT / generator
            if not out_root.is_dir():
                continue
            for target_dir in sorted(out_root.iterdir()):
                manifest_path = target_dir / "manifest.json"
                if not target_dir.is_dir() or not manifest_path.is_file():
                    continue
                key = result_key(generator, target_dir.name)
                if key not in results:
                    results[key] = read_json(manifest_path)

        failures = [
            (key, item.get("reason", ""))
            for key, item in results.items()
            if item.get("status") in {"failed", "infra_missing"}
        ]
        for generator in generators:
            filtered = {
                key.split("/", 1)[1]: item
                for key, item in results.items()
                if key.startswith(generator + "/")
            }
            summary = write_summary(generator, filtered)
            log(f"{generator}: {json.dumps(summary['counts'], sort_keys=True)}")
        if args.generator == "all":
            combined = {
                "schema_version": 1,
                "generated_at": utc_stamp(),
                "generators": {
                    generator: read_json(CORPUS_ROOT / generator / "summary.json")
                    for generator in generators
                },
            }
            (CORPUS_ROOT / "summary.json").write_text(
                json.dumps(combined, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
        if failures:
            for target, reason in failures:
                log(f"FAILED {target}: {reason}")
            return 1
        return 0
    except DriverError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
