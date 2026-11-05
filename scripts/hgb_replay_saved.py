#!/usr/bin/env python3
"""Phase B: fuzz a verified Phase A artifact without invoking an LLM generator."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker/common"))

HARNESS_BASELINES = {"ckgfuzzer", "promefuzz", "oss-fuzz-gen"}
BASELINES = HARNESS_BASELINES | {"g2fuzz", "elfuzz"}


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    """Publish a result only after its contents are durable on the host."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                     prefix=f".{path.name}.", delete=False) as handle:
        temporary = Path(handle.name)
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def workspace_path(raw: str) -> Path:
    path = Path(raw)
    if not path.is_absolute():
        path = ROOT / path
    path = path.resolve(strict=True)
    if not path.is_relative_to(ROOT / "workspace"):
        raise ValueError(f"source run is outside workspace: {path}")
    return path


def host_command(source: Path) -> dict[str, str]:
    path = source / "host_command.txt"
    if not path.is_file():
        raise ValueError(f"missing Phase A host command: {path}")
    fields = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value
    return fields


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def selected_harness(source: Path) -> Path:
    result = read_json(source / "evaluation/result.json")
    if result.get("status") != "evaluated":
        raise ValueError(f"Phase A harness evaluation is not evaluated: {source}")
    raw = str((result.get("selected_candidate") or {}).get("candidate_path") or "")
    if not raw:
        raise ValueError(f"Phase A has no selected harness: {source}")
    if raw.startswith("/workspace/"):
        candidate = source / raw.removeprefix("/workspace/")
    else:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = ROOT / candidate
    candidate = candidate.resolve(strict=True)
    if not candidate.is_relative_to(source):
        raise ValueError(f"selected harness is outside its Phase A run: {candidate}")
    if not candidate.is_file() or candidate.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
        raise ValueError(f"selected harness is not a C/C++ source file: {candidate}")
    return candidate


def phase_a_source(baseline: str, raw: str) -> tuple[Path, Path]:
    selected_run = workspace_path(raw)
    selected_meta = read_json(selected_run / "metadata.json")
    if selected_meta.get("status") != "evaluated":
        raise ValueError(f"Phase A run is not evaluated: {selected_run}")
    source = selected_run
    if selected_meta.get("source_run"):
        source = workspace_path(str(selected_meta["source_run"]))
    return selected_run, source


def source_target(selected: Path, source: Path) -> str:
    """Older reevaluation wrappers have no target in their metadata."""
    selected_target = read_json(selected / "metadata.json").get("target")
    source_target_name = read_json(source / "metadata.json").get("target")
    return str(selected_target or source_target_name or selected.parent.name)


def docker_image_exists(tag: str) -> bool:
    return bool(tag) and subprocess.run(
        ["docker", "image", "inspect", tag],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    ).returncode == 0


def docker_limits(cpu: int, memory_gib: int) -> list[str]:
    return ["--cpus", "1", "--cpuset-cpus", str(cpu),
            "--memory", f"{memory_gib}g", "--memory-swap", f"{memory_gib}g"]


def eval_all_docker_options() -> list[str]:
    """Identify containers so an interrupted coordinator can stop its own run."""
    run_id = os.environ.get("HGB_EVAL_ALL_RUN_ID", "")
    if not run_id:
        return []
    if not re.fullmatch(r"[A-Za-z0-9_-]+", run_id):
        raise ValueError("HGB_EVAL_ALL_RUN_ID contains unsupported characters")
    return ["--label", f"hgb.eval_all_run={run_id}",
            "-e", f"HGB_EVAL_ALL_RUN_ID={run_id}"]


def run_harness(baseline: str, selected: Path, source: Path, run: Path, package: Path,
                image: str, budget: int, cpu: int, memory_gib: int,
                recover_existing: bool = False,
                canonical_build: bool = False,
                stage: str = "all") -> int:
    import hgb_fuzzbench_builder as builder

    candidate = selected_harness(selected)
    staged = run / "generated_harnesses" / candidate.name
    staged.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(candidate, staged)
    source_result = read_json(selected / "evaluation/result.json")
    intended = (source_result.get("selected_candidate") or {}).get("api_reachability", {}).get("intended_apis") or []
    intended = [item for item in intended if isinstance(item, str)]
    provenance = {"phase": "B", "source_run": str(source), "selected_phase_a_run": str(selected),
                  "selected_harness": str(candidate),
                  "selected_harness_sha256": sha256(staged), "campaign_seconds": budget}
    (run / "replay_provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    source_meta = read_json(selected / "metadata.json")
    generation_meta = read_json(source / "metadata.json")
    if not source_meta.get("target"):
        source_meta["target"] = generation_meta.get("target") or selected.parent.name
    profile = str(source_meta.get("profile") or "alpha")
    protocol = str(source_meta.get("protocol") or "blind-project")
    manifest = read_json(package / "generator_input/target_manifest.json")
    saved_candidate = source_result.get("selected_candidate") or {}
    coverage_image = builder.deterministic_image_tag(
        selected.name, str(manifest.get("fuzz_target") or ""),
        str(saved_candidate.get("candidate_id") or "cand_001") + "-cov", generator=baseline,
    )
    cmd = [
        "docker", "run", "--rm", "--pull=never", "--init", *docker_limits(cpu, memory_gib),
        *eval_all_docker_options(),
        "-v", f"{run}:/workspace",
        "-v", f"{run}:{run}",
        "-v", f"{selected}:/phase-a:ro",
        "-v", f"{package / 'generator_input'}:/target:ro",
        "-v", f"{package / 'evaluator_only'}:/evaluator:ro",
        "-v", f"{ROOT / 'docker/common'}:/opt/hgb/bin:ro",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-e", f"HGB_RUN_ID={run.name}", "-e", f"HGB_TARGET={manifest.get('target', '')}",
        "-e", f"HGB_WORKSPACE_HOST={run}", "-e", f"HGB_TARGET_PACKAGE_HOST={package}",
        "-e", "HGB_DOCKER_CPUS=1", "-e", f"HGB_DOCKER_CPUSET={cpu}",
        "-e", f"HGB_DOCKER_MEMORY={memory_gib}g",
        "-e", "HGB_CAMPAIGN_TMPFS_SIZE", "-e", "HGB_CAMPAIGN_CHECKPOINT_SECONDS",
        "-e", "HGB_PHASE_B_REPLAY=1",
        "--entrypoint", "/opt/hgb/venv/bin/python", image,
        "/opt/hgb/bin/hgb_harness_evaluator.py",
        "--generator", baseline, "--target-root", "/target", "--evaluator-root", "/evaluator",
        "--candidate", f"/workspace/generated_harnesses/{candidate.name}",
        "--keep-going-campaign",
        "--work-dir", "/workspace/evaluation",
        "--project", str(manifest.get("project") or ""),
        "--fuzz-target", str(manifest.get("fuzz_target") or ""),
        "--profile", profile, "--protocol", protocol,
        "--campaign-seconds", str(budget), "--build-timeout-seconds", "7200",
        "--strict", "--build-coverage-image", "--stop-on-first-success",
        "--intended-apis", ",".join(intended),
    ]
    if not canonical_build:
        cmd.extend(["--phase-a-result", "/phase-a/evaluation/result.json"])
    # Keep executable file:line identities for a common source-set audit.
    # LCOV also avoids excessive JSON export memory on large targets such as PHP.
    cmd.extend(["--coverage-format", "lcov"])
    if not canonical_build and docker_image_exists(coverage_image):
        cmd.extend(["--prebuilt-coverage-image", coverage_image])
    if recover_existing:
        cmd.append("--reuse-saved-campaign")
    if stage != "all":
        cmd.extend(["--stage", stage])
    if baseline == "ckgfuzzer" and profile in {"reproduction-eta", "reproduction-zeta"}:
        cmd.append("--run-native-control")
    env = os.environ.copy()
    env.update({"HGB_DOCKER_CPUS": "1", "HGB_DOCKER_CPUSET": str(cpu),
                "HGB_DOCKER_MEMORY": f"{memory_gib}g", "HGB_PHASE_B_REPLAY": "1"})
    if stage == "runner":
        (run / "evaluation/runner_result.json").unlink(missing_ok=True)
    log_name = "evaluator.recovery.log" if recover_existing else "evaluator.log"
    with (run / log_name).open("w", encoding="utf-8") as log:
        code = subprocess.run(cmd, cwd=run, env=env, stdout=log,
                              stderr=subprocess.STDOUT, check=False).returncode
    result_name = "runner_result.json" if stage == "runner" else "result.json"
    result = read_json(run / "evaluation" / result_name)
    meta = dict(source_meta)
    meta.update({"run_type": "phase_b_saved_harness", "source_run": str(source),
                 "selected_phase_a_run": str(selected),
                 "status": result.get("status") or "infra_failure",
                 "reason": result.get("reason") or (f"evaluator exited {code}" if code else ""),
                 "campaign": result.get("campaign") or {},
                 "coverage": result.get("coverage") or {},
                 "profile": profile, "protocol": protocol})
    for name in ("metadata.json", "result.json"):
        write_json_atomic(run / name, meta)
    expected_status = "corpus_ready" if stage == "runner" else "evaluated"
    return code if code else (0 if result.get("status") == expected_status else 1)


def run_g2(source: Path, run: Path, package: Path, image: str,
           target: str, budget: int, cpu: int, memory_gib: int,
           measure: bool = True) -> int:
    if not (source / "target/target.afl").is_file() or not (source / "target/target.cmp").is_file():
        raise ValueError("Phase A G2Fuzz target pair is missing")
    if not (source / "seeds/g2_generated").is_dir():
        raise ValueError("Phase A G2Fuzz generated inputs are missing")
    meta = read_json(source / "metadata.json")
    tmpfs_size = os.environ.get("HGB_CAMPAIGN_TMPFS_SIZE", "4g")
    if not re.fullmatch(r"[1-9][0-9]*[kKmMgG]", tmpfs_size):
        raise ValueError("HGB_CAMPAIGN_TMPFS_SIZE must be a positive Docker size")
    cmd = [
        "docker", "run", "--rm", "--pull=never", "--init", *docker_limits(cpu, memory_gib),
        *eval_all_docker_options(),
        "--tmpfs", f"/tmp:size={tmpfs_size}",
        "-v", f"{run}:/workspace", "-v", f"{source}:/source:ro",
        "-v", f"{package}:/target:ro",
        "-v", f"{ROOT / 'docker/common'}:/opt/hgb/bin:ro",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-e", f"G2FUZZ_AFL_TIMEOUT_SECONDS={budget}", "-e", "AFL_NO_AFFINITY=1",
        "-e", "HGB_PHASE_B_REPLAY=1",
        "-e", "HGB_CAMPAIGN_TMP_ROOT=/tmp", "-e", "HGB_CAMPAIGN_CHECKPOINT_SECONDS",
        "-e", "OMP_NUM_THREADS=1", "-e", f"HGB_DOCKER_MEMORY={memory_gib}g",
        "--entrypoint", "/opt/hgb/venv/bin/python", image,
        "/opt/hgb/bin/g2fuzz_target_pipeline.py", "replay",
        "--workspace", "/workspace", "--target", target,
        "--target-package", "/target", "--artifact-dir", "/opt/hgb/artifacts/g2fuzz",
        "--metadata-root", "/opt/hgb/metadata",
        "--profile", str(meta.get("profile") or "alpha"),
        "--protocol", str(meta.get("protocol") or "paper-native"),
        "--source-run", "/source",
    ]
    if target == "mruby_mruby_fuzzer_8c8bbd":
        cmd[cmd.index("--entrypoint"):cmd.index("--entrypoint")] = [
            "-e", "G2FUZZ_REPLAY_FILTER_SEEDS=1",
            "-e", "G2FUZZ_REPLAY_SEED_TIMEOUT_SECONDS=1.2",
            "-e", "G2FUZZ_AFL_EXEC_TIMEOUT_MS=1000",
        ]
    if not measure:
        cmd.append("--runner-only")
    with (run / "replay.log").open("w", encoding="utf-8") as log:
        code = subprocess.run(cmd, cwd=run, stdout=log,
                              stderr=subprocess.STDOUT, check=False).returncode
    if measure:
        return finish_g2_coverage(run, package, target, cpu, memory_gib, code, budget)
    return code if code else (0 if read_json(run / "result.json").get("status") == "corpus_ready" else 1)


def verify_g2_saved_corpus(run: Path, target: str, budget: int,
                           result: dict[str, Any], code: int) -> Path:
    """Require a full saved AFL campaign before a measurer can publish coverage."""
    provenance = read_json(run / "phase_b_source.json")
    if (provenance.get("baseline") != "g2fuzz" or provenance.get("target") != target
            or not provenance.get("selected_phase_a_run")):
        raise ValueError("G2Fuzz saved campaign provenance is missing or mismatched")
    campaign = result.get("campaign") or {}
    stages = result.get("stages") or {}
    if code and (stages.get("coverage") or {}).get("status") != "failed":
        raise ValueError(f"G2Fuzz runner exited {code} before saving a valid campaign")
    for stage in ("target_pair_build", "generated_input_validation", "campaign"):
        if (stages.get(stage) or {}).get("status") != "complete":
            raise ValueError(f"G2Fuzz saved {stage} stage is incomplete")
    if any(isinstance(stage, dict) and stage.get("status") == "failed"
           for name, stage in stages.items() if name != "coverage"):
        raise ValueError("G2Fuzz saved run has a failed non-coverage stage")
    if int(campaign.get("execs_done") or 0) <= 0 or int(campaign.get("queue_count") or 0) <= 0:
        raise ValueError("G2Fuzz saved campaign has no target executions or AFL queue")
    elapsed = campaign.get("campaign_wall_seconds")
    if elapsed is None:
        stats = (stages.get("campaign") or {}).get("fuzzer_stats") or {}
        try:
            elapsed = int(stats["last_update"]) - int(stats["start_time"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("G2Fuzz saved campaign has no duration proof") from exc
    elapsed = float(elapsed)
    minimum = max(0, budget - min(60, max(2, round(budget * 0.01))))
    if not math.isfinite(elapsed) or elapsed < minimum:
        raise ValueError(f"G2Fuzz saved campaign ran {elapsed:g}s, below {minimum}s minimum")
    if result.get("status") == "corpus_ready":
        metrics = read_json(run / "campaign/metrics.json")
        if (metrics.get("duration_mode") != "afl-native-V"
                or metrics.get("deadline_reached") is not True):
            raise ValueError("G2Fuzz runner has no AFL native duration completion proof")
        if int(campaign.get("persisted_corpus_file_count") or 0) <= 0:
            raise ValueError("G2Fuzz runner did not record a saved corpus")
    corpus = run / "coverage/corpus"
    if not corpus.is_dir() or not any(path.is_file() for path in corpus.iterdir()):
        raise ValueError("G2Fuzz saved coverage corpus is empty")
    return corpus


def finish_g2_coverage(run: Path, package: Path, target: str,
                       cpu: int, memory_gib: int, code: int, budget: int) -> int:
    """Use the saved G2Fuzz corpus with the shared host-built coverage oracle."""
    import hgb_coverage
    import hgb_fuzzbench_builder as builder

    result = read_json(run / "result.json")
    stages = result.get("stages") or {}
    try:
        corpus = verify_g2_saved_corpus(run, target, budget, result, code)
    except (OSError, TypeError, ValueError) as exc:
        reason = f"G2Fuzz measurer rejected saved campaign: {exc}"
        result.update({"status": "quality_failure", "reason": reason, "exit_code": 1})
        stages["coverage"] = {"status": "failed", "reason": reason}
        result["stages"] = stages
        for name in ("result.json", "metadata.json"):
            write_json_atomic(run / name, result)
        return 1
    host_coverage = run / "host_coverage"
    host_coverage.mkdir(exist_ok=True)
    manifest = read_json(package / "target_manifest.json")
    fuzz_target = str(manifest.get("fuzz_target") or target)
    tag = builder.deterministic_image_tag(run.name, fuzz_target, "coverage", generator="g2fuzz")
    os.environ.update({"HGB_DOCKER_CPUS": "1", "HGB_DOCKER_CPUSET": str(cpu),
                       "HGB_DOCKER_MEMORY": f"{memory_gib}g"})
    reason = ""
    try:
        oracle = builder.build_elfuzz_sut(
            benchmark_dir=package / "fuzzbench_benchmark", image_tag=tag,
            fuzz_target=fuzz_target, work_dir=host_coverage / "sut",
            engine=builder.ELFUZZ_COVERAGE_ENGINE,
            sanitizer=builder.ELFUZZ_COVERAGE_SANITIZER,
            timeout_seconds=7200)
        (host_coverage / "oracle.json").write_text(json.dumps(oracle, indent=2, sort_keys=True) + "\n")
        if not oracle.get("binary_extracted"):
            raise ValueError("canonical coverage target build failed")
        measurement_dir = Path(tempfile.mkdtemp(prefix="measurement_", dir=host_coverage))
        readable_corpus = measurement_dir / "corpus"
        readable_corpus.mkdir()
        copy_command = [
            "docker", "run", "--rm", "--pull=never", *docker_limits(cpu, memory_gib),
            *eval_all_docker_options(), "-v", f"{corpus}:/hgb_source:ro",
            "-v", f"{readable_corpus}:/hgb_destination", tag, "sh", "-lc",
            f"cp -R /hgb_source/. /hgb_destination/ && chown -R {os.getuid()}:{os.getgid()} /hgb_destination",
        ]
        copied = subprocess.run(copy_command, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, text=True, check=False)
        if copied.returncode:
            raise ValueError(f"canonical corpus copy failed: {copied.stderr[-500:]}")
        replay = builder.run_coverage(
            image_tag=tag, binary_path=f"/out/{fuzz_target}", corpus_dir=readable_corpus,
            work_dir=measurement_dir, timeout_seconds=21600 if fuzz_target == "php-fuzz-parser" else 3600,
            require_coverage_report=True, coverage_format="lcov")
        report = Path(str(replay.get("coverage_report_path") or ""))
        if not replay.get("copy_out_ok") or not report.is_file():
            raise ValueError("canonical coverage replay produced no copied LCOV report")
        coverage = hgb_coverage.summarize_coverage_report(
            report, project=str(manifest.get("project") or target.split("_", 1)[0]))
        coverage.update({"report_path": str(report), "coverage_report_path": str(report),
                         "inputs_replayed": replay.get("inputs_replayed", 0),
                         "coverage_mode": "canonical_fuzzbench_source_coverage"})
        result["coverage"] = coverage
        result["coverage_gamma"] = {
            "line_coverage": (coverage.get("line_coverage") or {}).get("percent", 0),
            "region_coverage": (coverage.get("regions") or {}).get("percent", 0),
            "function_coverage": (coverage.get("function_coverage") or {}).get("percent", 0),
        }
        stages["coverage"] = {"status": "complete", "reason": "none",
                              "report_path": str(report),
                              "inputs_replayed": replay.get("inputs_replayed", 0)}
        result["stages"] = stages
        result["status"] = "evaluated"
        result["reason"] = "none"
        result["error"] = None
        result["exit_code"] = 0
    except (OSError, ValueError, hgb_coverage.CoverageError) as exc:
        reason = f"canonical G2Fuzz coverage failed: {exc}"
        result["status"] = "quality_failure"
        result["reason"] = reason
        result["exit_code"] = 1
    for name in ("result.json", "metadata.json"):
        write_json_atomic(run / name, result)
    return 0 if not reason else 1


def run_elfuzz(source: Path, run: Path, package: Path,
               budget: int, cpu: int, memory_gib: int,
               recover_existing: bool = False,
               canonical_build: bool = False,
               measure: bool = True) -> int:
    import hgb_coverage
    import hgb_fuzzbench_builder as builder

    build = read_json(source / "target/build.json")
    native_image = str(build.get("native_image_tag") or "")
    source_meta = read_json(source / "metadata.json")
    manifest = read_json(package / "target_manifest.json")
    fuzz_target = str(source_meta.get("fuzz_target") or "")
    if not fuzz_target or (not canonical_build and (not native_image or not docker_image_exists(native_image))):
        raise ValueError("Phase A ELFuzz native FuzzBench image is missing")
    if canonical_build:
        native_image = builder.deterministic_image_tag(
            run.name, fuzz_target, "native", generator="elfuzz")
        if not recover_existing:
            native_build = builder.build_elfuzz_sut(
                benchmark_dir=package / "fuzzbench_benchmark",
                image_tag=native_image, fuzz_target=fuzz_target,
                work_dir=run / "sut/native", engine=builder.ELFUZZ_NATIVE_ENGINE,
                sanitizer="address", timeout_seconds=7200)
            if not native_build.get("binary_extracted"):
                raise ValueError("canonical ELFuzz native target build failed")
    produced = source / "generated_inputs/produced"
    if not produced.is_dir():
        raise ValueError("Phase A ELFuzz produced input directory is missing")
    seed_dir = run / "seeds"
    seed_dir.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for index, path in enumerate(sorted(p for p in produced.rglob("*") if p.is_file() and p.stat().st_size)):
        dest = seed_dir / f"input_{index:06d}"
        shutil.copy2(path, dest)
        hashes[dest.name] = sha256(dest)
    if not hashes:
        raise ValueError("Phase A ELFuzz has no nonempty produced inputs")
    (run / "replay_provenance.json").write_text(json.dumps({
        "phase": "B", "source_run": str(source), "mode": "elfuzz_saved_input_libfuzzer",
        "native_image": native_image, "seed_sha256": hashes,
        "campaign_seconds": budget,
    }, indent=2, sort_keys=True) + "\n")
    os.environ.update({"HGB_DOCKER_CPUS": "1", "HGB_DOCKER_CPUSET": str(cpu),
                       "HGB_DOCKER_MEMORY": f"{memory_gib}g",
                       "HGB_WORKSPACE_HOST": str(run)})
    campaign = (builder.load_saved_campaign(run, budget) if recover_existing else
                builder.run_campaign(
                    image_tag=native_image, binary_path=f"/out/{fuzz_target}",
                    corpus_dir=seed_dir, work_dir=run, campaign_seconds=budget,
                    keep_going=True,
                    durable=not measure,
                ))
    coverage: dict[str, Any] = {"line_coverage": {"covered": None}}
    reason = ""
    if not measure and not recover_existing:
        try:
            # The runner publishes corpus_ready only after the final archive,
            # extracted corpus, execution count, and active duration agree.
            campaign = builder.load_saved_campaign(run, budget)
            active = campaign.get("campaign_active_seconds")
            minimum = max(0, budget - min(60, max(2, round(budget * 0.01))))
            if active is None or float(active) < minimum:
                raise ValueError("saved campaign has no verified full active duration")
        except (OSError, ValueError) as exc:
            reason = f"saved campaign verification failed: {exc}"
    final_corpus = Path(str(campaign.get("final_corpus_dir") or ""))
    if (int(campaign.get("execs_done") or 0) <= 0
            or not campaign.get("copy_out_ok")
            or not final_corpus.is_dir()
            or int(campaign.get("final_corpus_file_count") or 0) <= 0
            or campaign.get("corpus_archive_error")):
        archive_error = str(campaign.get("corpus_archive_error") or "")
        reason = (f"campaign corpus archive invalid: {archive_error}" if archive_error
                  else "campaign did not produce a verified final corpus")
    elif measure:
        cov_tag = builder.deterministic_image_tag(run.name, fuzz_target, "coverage", generator="elfuzz")
        cov_build = builder.build_elfuzz_sut(
            benchmark_dir=package / "fuzzbench_benchmark", image_tag=cov_tag,
            fuzz_target=fuzz_target, work_dir=run / "sut/coverage",
            engine=builder.ELFUZZ_COVERAGE_ENGINE,
            sanitizer=builder.ELFUZZ_COVERAGE_SANITIZER,
            timeout_seconds=7200,
        )
        if not cov_build.get("binary_extracted"):
            reason = "coverage target build failed"
        else:
            cov = builder.run_coverage(
                image_tag=cov_tag, binary_path=f"/out/{fuzz_target}",
                corpus_dir=final_corpus, work_dir=run,
                timeout_seconds=21600 if fuzz_target == "php-fuzz-parser" else 3600,
                require_coverage_report=True,
                coverage_format="lcov",
            )
            report = Path(str(cov.get("coverage_report_path") or ""))
            if cov.get("copy_out_ok") and report.is_file():
                try:
                    coverage = hgb_coverage.summarize_coverage_report(
                        report, project=str(source_meta.get("project") or manifest.get("project") or ""))
                    coverage["coverage_report_path"] = str(report)
                    coverage["inputs_replayed"] = cov.get("inputs_replayed", 0)
                except hgb_coverage.CoverageError as exc:
                    reason = f"coverage report invalid: {exc}"
            else:
                reason = "coverage report missing after campaign replay"
    if reason:
        status = "quality_failure"
    elif not measure:
        status = "corpus_ready"
    else:
        status = ("evaluated" if (coverage.get("line_coverage") or {}).get("covered") is not None
                  else "quality_failure")
    result = {
        "status": status, "reason": reason, "baseline": "elfuzz", "target": source_meta.get("target"),
        "profile": source_meta.get("profile", "alpha"), "protocol": source_meta.get("protocol", "paper-native"),
        "method_variant": "saved-input-libfuzzer", "source_run": str(source),
        "campaign": campaign, "coverage": coverage, "phase": "B",
    }
    for name in ("result.json", "metadata.json"):
        write_json_atomic(run / name, result)
    return 0 if status in {"evaluated", "corpus_ready"} else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", choices=sorted(BASELINES), required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--source-run", required=True)
    parser.add_argument("--canonical-source-run",
                        help="G2Fuzz Phase A source whose FuzzBench package is shared by all baselines for this target")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--campaign-seconds", type=int, default=86400)
    parser.add_argument("--cpu", type=int, required=True)
    parser.add_argument("--memory-gib", type=int, default=8)
    parser.add_argument("--recover-existing", action="store_true",
                        help="reuse a completed campaign in an existing harness Phase B run")
    parser.add_argument("--stage", choices=("all", "runner", "measurer"), default="all",
                        help="run fuzzing and coverage together, or persist the corpus for a separate measurer")
    args = parser.parse_args()
    if args.stage == "runner" and args.recover_existing:
        parser.error("runner stage must create a new Phase B campaign")
    if args.stage == "measurer" and not args.recover_existing:
        parser.error("measurer stage requires --recover-existing")
    if args.campaign_seconds < 1 or args.memory_gib < 1 or args.cpu < 0:
        parser.error("campaign, CPU, and memory limits must be positive")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.run_id):
        parser.error("--run-id contains unsupported characters")
    # Phase B lets Docker finish its own build, campaign, and copy operations.
    # The fuzzer's duration is controlled inside its container instead.
    os.environ["HGB_PHASE_B_REPLAY"] = "1"
    selected, source = phase_a_source(args.baseline, args.source_run)
    selected_meta = read_json(selected / "metadata.json")
    meta = read_json(source / "metadata.json")
    saved_target = source_target(selected, source)
    if saved_target != args.target:
        raise ValueError(f"Phase A target mismatch: {saved_target} != {args.target}")
    host = host_command(source)
    if host.get("generator") != args.baseline or host.get("target") != args.target:
        raise ValueError("Phase A host command has a different baseline or target")
    package = Path(host.get("target_package", "")).resolve(strict=True)
    canonical_build = bool(args.canonical_source_run)
    if canonical_build:
        canonical_selected, canonical_source = phase_a_source("g2fuzz", args.canonical_source_run)
        if source_target(canonical_selected, canonical_source) != args.target:
            raise ValueError("canonical target package source has a different target")
        canonical_host = host_command(canonical_source)
        if canonical_host.get("generator") != "g2fuzz":
            raise ValueError("canonical target package source is not G2Fuzz")
        package = Path(canonical_host.get("target_package", "")).resolve(strict=True)
    if not package.is_relative_to(ROOT / "workspace"):
        raise ValueError(f"Phase A target package is outside workspace: {package}")
    manifest = read_json(package / "target_manifest.json")
    if manifest.get("target") != args.target:
        raise ValueError("Phase A target package manifest has a different target")
    image = host.get("image", "")
    needs_baseline_image = (args.baseline in HARNESS_BASELINES
                            or (args.baseline == "g2fuzz" and not args.recover_existing))
    if needs_baseline_image and not docker_image_exists(image):
        raise ValueError(f"Phase A baseline image is missing: {image}")
    run = ROOT / "workspace" / args.baseline / args.target / args.run_id
    if run.exists():
        if not args.recover_existing or args.baseline not in HARNESS_BASELINES | {"elfuzz", "g2fuzz"}:
            raise ValueError(f"Phase B run already exists: {run}")
        previous = read_json(run / "phase_b_source.json")
        if (previous.get("baseline") != args.baseline or previous.get("target") != args.target
                or previous.get("selected_phase_a_run") != str(selected)):
            raise ValueError("existing Phase B run provenance does not match the requested source")
        if (read_json(run / "evaluation/result.json").get("status") == "evaluated"
                and not canonical_build):
            raise ValueError("refreshing an evaluated Phase B run requires the shared target package")
        backup = run / "recovery_before"
        backup.mkdir(exist_ok=True)
        for relative in ("metadata.json", "result.json", "evaluation/result.json",
                         "evaluation/candidates/cand_001.json", "evaluator.log"):
            prior = run / relative
            if prior.is_file():
                dest = backup / relative
                dest.parent.mkdir(parents=True, exist_ok=True)
                if not dest.exists():
                    shutil.copy2(prior, dest)
    else:
        if args.recover_existing:
            raise ValueError(f"Phase B run does not exist: {run}")
        run.mkdir(parents=True)
    # Third-party fuzzers may write relative filenames. Keep those files in
    # this pair's workspace even when the user launched Phase B from the root.
    os.chdir(run)
    source_statistics = selected / "statistics.json"
    if source_statistics.is_file():
        shutil.copy2(source_statistics, run / "statistics.json")
    write_json_atomic(run / "phase_b_source.json", {
        "phase": "B", "selected_phase_a_run": str(selected), "source_run": str(source),
        "baseline": args.baseline, "target": args.target,
        "canonical_target_package": str(package) if canonical_build else "",
    })
    if args.baseline in HARNESS_BASELINES:
        return run_harness(args.baseline, selected, source, run, package, image,
                           args.campaign_seconds, args.cpu, args.memory_gib,
                           recover_existing=args.recover_existing,
                           canonical_build=canonical_build, stage=args.stage)
    if args.baseline == "g2fuzz":
        if args.recover_existing:
            return finish_g2_coverage(run, package, args.target, args.cpu, args.memory_gib,
                                      0, args.campaign_seconds)
        return run_g2(source, run, package, image, args.target,
                      args.campaign_seconds, args.cpu, args.memory_gib,
                      measure=args.stage != "runner")
    return run_elfuzz(source, run, package, args.campaign_seconds,
                      args.cpu, args.memory_gib,
                      recover_existing=args.recover_existing,
                      canonical_build=canonical_build,
                      measure=args.stage != "runner")


if __name__ == "__main__":
    raise SystemExit(main())
