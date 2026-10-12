#!/usr/bin/env python3
"""Phase B: fuzz a verified Phase A artifact without invoking an LLM generator."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
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


def run_harness(baseline: str, selected: Path, source: Path, run: Path, package: Path,
                image: str, budget: int, cpu: int, memory_gib: int) -> int:
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
        "-e", "HGB_PHASE_B_REPLAY=1",
        "--entrypoint", "/opt/hgb/venv/bin/python", image,
        "/opt/hgb/bin/hgb_harness_evaluator.py",
        "--generator", baseline, "--target-root", "/target", "--evaluator-root", "/evaluator",
        "--candidate", f"/workspace/generated_harnesses/{candidate.name}",
        "--phase-a-result", "/phase-a/evaluation/result.json",
        "--keep-going-campaign",
        "--work-dir", "/workspace/evaluation",
        "--project", str(manifest.get("project") or ""),
        "--fuzz-target", str(manifest.get("fuzz_target") or ""),
        "--profile", profile, "--protocol", protocol,
        "--campaign-seconds", str(budget), "--build-timeout-seconds", "7200",
        "--strict", "--build-coverage-image", "--stop-on-first-success",
        "--intended-apis", ",".join(intended),
    ]
    if manifest.get("target") == "bloaty_fuzz_target":
        cmd.extend(["--coverage-format", "lcov"])
    if docker_image_exists(coverage_image):
        cmd.extend(["--prebuilt-coverage-image", coverage_image])
    if baseline == "ckgfuzzer" and profile in {"reproduction-eta", "reproduction-zeta"}:
        cmd.append("--run-native-control")
    env = os.environ.copy()
    env.update({"HGB_DOCKER_CPUS": "1", "HGB_DOCKER_CPUSET": str(cpu),
                "HGB_DOCKER_MEMORY": f"{memory_gib}g", "HGB_PHASE_B_REPLAY": "1"})
    with (run / "evaluator.log").open("w", encoding="utf-8") as log:
        code = subprocess.run(cmd, cwd=run, env=env, stdout=log,
                              stderr=subprocess.STDOUT, check=False).returncode
    result = read_json(run / "evaluation/result.json")
    meta = dict(source_meta)
    meta.update({"run_type": "phase_b_saved_harness", "source_run": str(source),
                 "selected_phase_a_run": str(selected),
                 "status": result.get("status") or "infra_failure",
                 "reason": result.get("reason") or (f"evaluator exited {code}" if code else ""),
                 "campaign": result.get("campaign") or {},
                 "coverage": result.get("coverage") or {},
                 "profile": profile, "protocol": protocol})
    for name in ("metadata.json", "result.json"):
        (run / name).write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    return code if code else (0 if result.get("status") == "evaluated" else 1)


def run_g2(source: Path, run: Path, package: Path, image: str,
           target: str, budget: int, cpu: int, memory_gib: int) -> int:
    if not (source / "target/target.afl").is_file() or not (source / "target/target.cmp").is_file():
        raise ValueError("Phase A G2Fuzz target pair is missing")
    if not (source / "seeds/g2_generated").is_dir():
        raise ValueError("Phase A G2Fuzz generated inputs are missing")
    meta = read_json(source / "metadata.json")
    cmd = [
        "docker", "run", "--rm", "--pull=never", "--init", *docker_limits(cpu, memory_gib),
        "-v", f"{run}:/workspace", "-v", f"{source}:/source:ro",
        "-v", f"{package}:/target:ro",
        "-v", f"{ROOT / 'docker/common'}:/opt/hgb/bin:ro",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-e", f"G2FUZZ_AFL_TIMEOUT_SECONDS={budget}", "-e", "AFL_NO_AFFINITY=1",
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
    with (run / "replay.log").open("w", encoding="utf-8") as log:
        return subprocess.run(cmd, cwd=run, stdout=log,
                              stderr=subprocess.STDOUT, check=False).returncode


def run_elfuzz(source: Path, run: Path, package: Path,
               budget: int, cpu: int, memory_gib: int) -> int:
    import hgb_coverage
    import hgb_fuzzbench_builder as builder

    build = read_json(source / "target/build.json")
    native_image = str(build.get("native_image_tag") or "")
    source_meta = read_json(source / "metadata.json")
    fuzz_target = str(source_meta.get("fuzz_target") or "")
    if not native_image or not fuzz_target or not docker_image_exists(native_image):
        raise ValueError("Phase A ELFuzz native FuzzBench image is missing")
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
                       "HGB_DOCKER_MEMORY": f"{memory_gib}g"})
    campaign = builder.run_campaign(
        image_tag=native_image, binary_path=f"/out/{fuzz_target}",
        corpus_dir=seed_dir, work_dir=run, campaign_seconds=budget,
        keep_going=True,
    )
    coverage: dict[str, Any] = {"line_coverage": {"covered": None}}
    reason = ""
    final_corpus = Path(str(campaign.get("final_corpus_dir") or ""))
    if int(campaign.get("execs_done") or 0) <= 0 or not campaign.get("copy_out_ok") or not final_corpus.is_dir():
        reason = "campaign did not produce a verified final corpus"
    else:
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
                timeout_seconds=3600, require_coverage_report=True,
            )
            report = Path(str(cov.get("coverage_report_path") or ""))
            if cov.get("copy_out_ok") and report.is_file():
                coverage = hgb_coverage.summarize_coverage_report(report)
                coverage["coverage_report_path"] = str(report)
                coverage["inputs_replayed"] = cov.get("inputs_replayed", 0)
            else:
                reason = "coverage report missing after campaign replay"
    status = "evaluated" if not reason and (coverage.get("line_coverage") or {}).get("covered") is not None else "quality_failure"
    result = {
        "status": status, "reason": reason, "baseline": "elfuzz", "target": source_meta.get("target"),
        "profile": source_meta.get("profile", "alpha"), "protocol": source_meta.get("protocol", "paper-native"),
        "method_variant": "saved-input-libfuzzer", "source_run": str(source),
        "campaign": campaign, "coverage": coverage, "phase": "B",
    }
    for name in ("result.json", "metadata.json"):
        (run / name).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0 if status == "evaluated" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", choices=sorted(BASELINES), required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--source-run", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--campaign-seconds", type=int, default=86400)
    parser.add_argument("--cpu", type=int, required=True)
    parser.add_argument("--memory-gib", type=int, default=8)
    args = parser.parse_args()
    if args.campaign_seconds < 1 or args.memory_gib < 1 or args.cpu < 0:
        parser.error("campaign, CPU, and memory limits must be positive")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.run_id):
        parser.error("--run-id contains unsupported characters")
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
    if not package.is_relative_to(ROOT / "workspace"):
        raise ValueError(f"Phase A target package is outside workspace: {package}")
    manifest = read_json(package / "target_manifest.json")
    if manifest.get("target") != args.target:
        raise ValueError("Phase A target package manifest has a different target")
    image = host.get("image", "")
    if args.baseline != "elfuzz" and not docker_image_exists(image):
        raise ValueError(f"Phase A baseline image is missing: {image}")
    run = ROOT / "workspace" / args.baseline / args.target / args.run_id
    if run.exists():
        raise ValueError(f"Phase B run already exists: {run}")
    run.mkdir(parents=True)
    # Third-party fuzzers may write relative filenames. Keep those files in
    # this pair's workspace even when the user launched Phase B from the root.
    os.chdir(run)
    source_statistics = selected / "statistics.json"
    if source_statistics.is_file():
        shutil.copy2(source_statistics, run / "statistics.json")
    (run / "phase_b_source.json").write_text(json.dumps({
        "phase": "B", "selected_phase_a_run": str(selected), "source_run": str(source),
        "baseline": args.baseline, "target": args.target,
    }, indent=2, sort_keys=True) + "\n")
    if args.baseline in HARNESS_BASELINES:
        return run_harness(args.baseline, selected, source, run, package, image,
                           args.campaign_seconds, args.cpu, args.memory_gib)
    if args.baseline == "g2fuzz":
        return run_g2(source, run, package, image, args.target,
                      args.campaign_seconds, args.cpu, args.memory_gib)
    return run_elfuzz(source, run, package, args.campaign_seconds,
                      args.cpu, args.memory_gib)


if __name__ == "__main__":
    raise SystemExit(main())
