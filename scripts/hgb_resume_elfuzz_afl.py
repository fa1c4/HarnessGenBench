#!/usr/bin/env python3
"""Resume saved ELFuzz generations with exact-target AFL and LLVM coverage.

No model is called. The generated programs and inputs are copied unchanged;
the script validates them in the native FuzzBench image, builds an AFL variant
of that benchmark, and fuzzes the generated corpus with pinned ELFuzz AFL++.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker/common"))
import elfuzz_target_pipeline as pipeline  # noqa: E402
import hgb_coverage  # noqa: E402
import hgb_fuzzbench_builder as builder  # noqa: E402


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def target_package(source: Path) -> Path:
    for line in (source / "host_command.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("target_package="):
            return Path(line.split("=", 1)[1])
    raise ValueError("source run has no target_package")


def existing_build(target_dir: Path, variant: str) -> dict:
    paths = sorted(target_dir.glob(f"*/{variant}/build.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if variant == "coverage":
        paths += sorted(target_dir.glob("*/coverage/build.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in paths:
        record = read_json(path)
        if record.get("build_exit_code") == 0 and record.get("binary_extracted") and Path(record.get("binary_path", "")).is_file():
            image = record.get("image_tag", "")
            if image and subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=60).returncode == 0:
                return record
    return {}


def ensure_build(target_dir: Path, retry: Path, benchmark: Path, fuzz_target: str, variant: str) -> dict:
    record = existing_build(target_dir, variant)
    if record:
        return record
    engine, sanitizer = ("afl", "address") if variant == "afl" else (builder.ELFUZZ_COVERAGE_ENGINE, builder.ELFUZZ_COVERAGE_SANITIZER)
    tag = builder.deterministic_image_tag(run_id=retry.name, target=target_dir.name, candidate_id=variant, generator="elfuzz")
    record = builder.build_elfuzz_sut(benchmark_dir=benchmark, image_tag=tag, fuzz_target=fuzz_target,
                                      work_dir=retry / variant, engine=engine, sanitizer=sanitizer, timeout_seconds=3600)
    write_json(retry / variant / "build.json", record)
    if record.get("build_exit_code") != 0 or not record.get("binary_extracted"):
        raise RuntimeError(f"{variant} FuzzBench build failed: {retry / variant / 'build.log'}")
    return record


def pinned_afl_binary() -> Path:
    dest = ROOT / "workspace/elfuzz/afl_tools_20261009/afl-fuzz"
    if dest.is_file():
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    image = "ghcr.io/osuseclab/elfuzz:25.08.0"
    create = subprocess.run(["docker", "create", "--pull=never", image, "true"], capture_output=True, text=True, check=True)
    cid = create.stdout.strip()
    try:
        subprocess.run(["docker", "cp", f"{cid}:/usr/bin/afl-fuzz", str(dest)], check=True)
    finally:
        subprocess.run(["docker", "rm", cid], capture_output=True, check=False)
    return dest


def container_afl_binary(image: str, retry: Path) -> Path:
    """Build AFL++ against the target image's libc when host AFL cannot run."""
    cache = ROOT / "workspace/elfuzz/afl_tools_20261009/compatible/afl-fuzz"
    if cache.is_file():
        check = subprocess.run(["docker", "run", "--rm", "--pull=never", "-v", f"{cache}:/opt/afl-fuzz:ro",
                                image, "/opt/afl-fuzz", "-h"], capture_output=True, timeout=60, check=False)
        if b"afl-fuzz" in check.stdout + check.stderr and b"GLIBC_" not in check.stdout + check.stderr:
            return cache
    cache.parent.mkdir(parents=True, exist_ok=True)
    log = retry / "afl_compat_build.log"
    command = ["docker", "run", "--rm", "--pull=never",
               "-v", f"{ROOT / 'artifacts/g2fuzz'}:/mnt/afl:ro",
               "-v", f"{cache.parent}:/tmp/output", image, "sh", "-lc",
               "cp -a /mnt/afl /tmp/afl-src && cd /tmp/afl-src && make clean && make -j4 afl-fuzz && cp afl-fuzz /tmp/output/afl-fuzz"]
    with log.open("wb") as out:
        built = subprocess.run(command, stdout=out, stderr=subprocess.STDOUT, timeout=900, check=False)
    if built.returncode != 0 or not cache.is_file():
        raise RuntimeError(f"compatible AFL++ build failed: {log}")
    return cache


def restore_afl_runtime_files(record: dict) -> None:
    """Keep FuzzBench /out sidecars beside the extracted AFL executable."""
    out_dir = Path(record["binary_path"]).parent
    image = record["image_tag"]
    create = subprocess.run(["docker", "create", "--pull=never", image, "true"], capture_output=True, text=True, check=True)
    cid = create.stdout.strip()
    try:
        subprocess.run(["docker", "cp", f"{cid}:/out/.", str(out_dir)], check=True, timeout=300)
    finally:
        subprocess.run(["docker", "rm", cid], capture_output=True, check=False)


def validate(source: Path, retry: Path, native_image: str, binary: str, adapter: dict) -> list[Path]:
    produced = source / "generated_inputs/produced"
    if not produced.is_dir():
        raise RuntimeError("source run has no produced inputs")
    valid = []
    rows = []
    mode = adapter.get("input_mode", "file")
    argv = adapter.get("argv", ["@@"])
    # Docker startup on a busy FuzzBench host can exceed the target's own
    # five-second execution limit. Allow startup separately from target work.
    timeout = max(30, int(adapter.get("timeout_seconds", 5)) + 25)
    for index, path in enumerate(sorted(p for p in produced.iterdir() if p.is_file() and p.stat().st_size)):
        data = path.read_bytes()
        if not pipeline.lightweight_validate(data, str(adapter.get("validity_check", "none"))):
            rows.append({"source": str(path), "valid": False, "reason": "format_check"})
            continue
        host_input = retry / "validation" / f"input_{index:05d}"
        host_input.parent.mkdir(parents=True, exist_ok=True)
        host_input.write_bytes(data)
        dest = f"/tmp/hgb_input_{index:05d}"
        args = [dest if arg == "@@" else str(arg) for arg in argv]
        if mode == "stdin":
            cmd = ["docker", "run", "--rm", "--pull=never", "-i", native_image, f"/out/{binary}", *[x for x in args if x != dest]]
            stdin = data
        else:
            cmd = ["docker", "run", "--rm", "--pull=never", "-v", f"{host_input.resolve()}:{dest}:ro",
                   native_image, f"/out/{binary}", *args]
            stdin = None
        try:
            completed = subprocess.run(cmd, input=stdin, capture_output=True, timeout=timeout, check=False)
            ok = completed.returncode in (0, 1)
            reason = "none" if ok else f"target_exit_{completed.returncode}"
            rc = completed.returncode
        except subprocess.TimeoutExpired:
            ok, reason, rc = False, "target_timeout", 124
        rows.append({"source": str(path), "sha256": sha256(path), "valid": ok, "reason": reason,
                     "exit_code": rc, "containerized": True})
        if ok:
            valid.append(path)
        if len(valid) >= 5:
            break
    write_json(retry / "generated_inputs/validation/results.json",
               {"valid_count": len(valid), "invalid_count": len(rows) - len(valid), "results": rows})
    if not valid:
        raise RuntimeError("no generated input passes format and exact-container target validation")
    return valid


def run_afl(retry: Path, afl: Path, binary: Path, valid: list[Path], seconds: int,
            container_image: str = "") -> tuple[dict, list[Path]]:
    seeds = retry / "campaign/seeds"
    seeds.mkdir(parents=True)
    for index, path in enumerate(valid):
        shutil.copy2(path, seeds / f"seed_{index:05d}")
    output = retry / "campaign/afl"
    if container_image:
        output.mkdir(parents=True)
        command = ["docker", "run", "--rm", "--pull=never", "--user", f"{os.getuid()}:{os.getgid()}",
                   "-v", f"{afl.resolve()}:/opt/afl-fuzz:ro", "-v", f"{seeds.resolve()}:/tmp/seeds:ro",
                   "-v", f"{output.resolve()}:/tmp/afl_out",
                   *[item for key, value in {"AFL_NO_UI": "1", "AFL_SKIP_CPUFREQ": "1",
                        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1", "AFL_NO_AFFINITY": "1",
                        "AFL_SKIP_CRASHES": "1"}.items() for item in ("-e", f"{key}={value}")],
                   container_image, "/opt/afl-fuzz", "-i", "/tmp/seeds", "-o", "/tmp/afl_out",
                   "-V", str(seconds), "-t", "5000", "-m", "none", "--", f"/out/{binary.name}", "@@"]
    else:
        command = [str(afl), "-i", str(seeds), "-o", str(output), "-V", str(seconds), "-t", "5000", "-m", "none", "--", str(binary), "@@"]
    (retry / "campaign/command.txt").write_text(" ".join(command) + "\n", encoding="utf-8")
    env = os.environ.copy()
    env.update({"AFL_NO_UI": "1", "AFL_SKIP_CPUFREQ": "1", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
                "AFL_NO_AFFINITY": "1", "AFL_SKIP_CRASHES": "1"})
    with (retry / "campaign/afl.log").open("wb") as log:
        try:
            completed = subprocess.run(command, cwd=retry / "campaign", stdout=log, stderr=subprocess.STDOUT, env=env,
                                       timeout=seconds + 120, check=False)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("AFL campaign exceeded time limit without clean shutdown") from exc
    stats_file = output / "default/fuzzer_stats"
    if completed.returncode != 0 or not stats_file.is_file():
        raise RuntimeError(f"AFL campaign failed (exit {completed.returncode}): {retry / 'campaign/afl.log'}")
    raw_stats = stats_file.read_text(encoding="utf-8", errors="replace")
    stats = {}
    for line in raw_stats.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            stats[key.strip()] = value.strip()
    queue = sorted(p for p in (output / "default/queue").iterdir() if p.is_file())
    if not all(k in stats for k in ("start_time", "last_update", "execs_done")) or int(stats["execs_done"]) <= 0 or not queue:
        raise RuntimeError("AFL campaign lacks real execution statistics or queue")
    shutil.copy2(stats_file, retry / "campaign/fuzzer_stats")
    shutil.copy2(retry / "campaign/afl.log", retry / "campaign/target_runtime.log")
    queue_dir = retry / "campaign/queue"
    queue_dir.mkdir(parents=True)
    for index, path in enumerate(queue):
        shutil.copy2(path, queue_dir / f"queue_{index:06d}")
    return stats, sorted(queue_dir.iterdir())


def coverage_replay(retry: Path, coverage_build: dict, binary: str, valid: list[Path], queue: list[Path]) -> dict:
    corpus = retry / "coverage/corpus"
    corpus.mkdir(parents=True)
    for index, path in enumerate([*valid, *queue]):
        shutil.copy2(path, corpus / f"input_{index:06d}")
    image = coverage_build["image_tag"]
    lcov = retry / "coverage/coverage.lcov"
    shell = ("set -e; mkdir -p /tmp/cov; "
             f"LLVM_PROFILE_FILE=/tmp/cov/coverage.profraw /out/{binary} -runs=0 /tmp/corpus >/tmp/cov/run.log 2>&1; "
             "llvm-profdata merge -o /tmp/cov/merged.profdata /tmp/cov/*.profraw; "
             f"llvm-cov export -summary-only -format=text /out/{binary} -instr-profile=/tmp/cov/merged.profdata")
    command = ["docker", "run", "--rm", "--pull=never", "-v", f"{corpus.resolve()}:/tmp/corpus:ro", image, "sh", "-lc", shell]
    with lcov.open("wb") as out, (retry / "coverage/replay.stderr.log").open("wb") as err:
        completed = subprocess.run(command, stdout=out, stderr=err, timeout=900, check=False)
    if completed.returncode != 0:
        raise RuntimeError(f"LLVM coverage replay exited {completed.returncode}")
    measured = hgb_coverage.summarize_coverage_report(lcov)
    lines = measured["line_coverage"]
    if int(lines.get("covered") or 0) <= 0:
        raise RuntimeError("LLVM coverage replay covered zero source lines")
    return {"complete": True, "coverage_mode": measured["source"], "report_exists": True,
            "report_path": str(lcov), "inputs_replayed": len(valid) + len(queue),
            "line_coverage": lines, "function_coverage": measured["function_coverage"],
            "region_coverage": measured["region_coverage"], "covered_lines": lines["covered"],
            "total_lines": lines["total"], "edge_coverage": {"status": "unavailable", "value": None}}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("source_run", type=Path)
    ap.add_argument("retry_id")
    ap.add_argument("--afl-seconds", type=int)
    ap.add_argument("--afl-runtime", choices=("host", "container"), default="host")
    args = ap.parse_args()
    if not args.retry_id.replace("_", "").replace("-", "").isalnum():
        ap.error("retry_id must be alphanumeric, underscore, or hyphen")
    source = args.source_run.resolve()
    original = read_json(source / "result.json")
    if original.get("generator") != "elfuzz":
        ap.error("source run must be ELFuzz")
    source_budget = int(read_json(source / "config/budget.json").get("campaign_seconds") or 1800)
    args.afl_seconds = args.afl_seconds if args.afl_seconds is not None else source_budget
    if args.afl_seconds < 30:
        ap.error("AFL duration must be at least 30 seconds")
    for name in ("target_build", "synthesis", "evolution", "production"):
        if (original.get("stages", {}).get(name) or {}).get("status") != "complete":
            ap.error(f"source {name} stage is incomplete")
    target = original["target"]
    target_dir = ROOT / "workspace/elfuzz" / target
    retry = target_dir / args.retry_id
    if retry.exists():
        ap.error(f"retry already exists: {retry}")
    retry.mkdir(parents=True)
    write_json(retry / "api_traces/summary.json", {"usage_accounting_version": 1, "total_count": 0,
               "retry_count": 0, "input_tokens": 0, "output_tokens": 0, "error_count": 0})
    write_json(retry / "evaluation_retry_count.json", {"count": 1, "retry_ids": [args.retry_id]})
    write_json(retry / "metadata.json", {"generator": "elfuzz", "target": target, "status": "running",
               "run_type": "offline_resume_generated_inputs", "source_run": str(source)})
    stats_cmd = [sys.executable, str(ROOT / "docker/common/hgb_record_statistics.py"), "--workspace", str(retry),
                 "--baseline", "elfuzz", "--target", target, "--run-id", args.retry_id]
    subprocess.run([*stats_cmd, "--exit-code", "0", "--status", "running"], check=True)
    try:
        package = target_package(source)
        manifest = read_json(package / "generator_input/target_manifest.json")
        binary = manifest["fuzz_target"]
        benchmark = package / "fuzzbench_benchmark"
        if not benchmark.is_dir():
            benchmark = package / "generator_input/fuzzbench_benchmark"
        adapter = read_json(source / "target/adapter_manifest.json")
        native = read_json(source / "target/build.json")
        native_image = native.get("native_image_tag")
        if not native_image:
            raise RuntimeError("source has no exact native FuzzBench image")
        valid = validate(source, retry, native_image, binary, adapter)
        afl_build = ensure_build(target_dir, retry, benchmark, binary, "afl")
        restore_afl_runtime_files(afl_build)
        afl_binary = (container_afl_binary(afl_build["image_tag"], retry) if args.afl_runtime == "container"
                      else pinned_afl_binary())
        stats, queue = run_afl(retry, afl_binary, Path(afl_build["binary_path"]).resolve(), valid,
                               args.afl_seconds, afl_build["image_tag"] if args.afl_runtime == "container" else "")
        coverage_build = ensure_build(target_dir, retry, benchmark, binary, "coverage")
        coverage = coverage_replay(retry, coverage_build, binary, valid, queue)
        program_count = len(list((source / "synthesis/fuzzer_programs").rglob("*.py")))
        if program_count <= 0:
            raise RuntimeError("source has no saved ELFuzz fuzzer programs")
        campaign = {"execs_done": int(stats["execs_done"]), "queue_count": len(queue),
                    "duration_seconds": args.afl_seconds, "configured_duration_seconds": source_budget,
                    "crashes": len(list((retry / "campaign/afl/default/crashes").glob("id:*"))),
                    "hangs": len(list((retry / "campaign/afl/default/hangs").glob("id:*")))}
        runtime = {"engine": "afl++", "source": "G2Fuzz AFL++ source rebuilt for target libc" if args.afl_runtime == "container" else "pinned ELFuzz image",
                   "containerized": args.afl_runtime == "container",
                   "exact_fuzzbench_afl": True, "image_tag": afl_build["image_tag"],
                   "binary_sha256": sha256(Path(afl_build["binary_path"])),
                   "execs_done": campaign["execs_done"], "queue_count": campaign["queue_count"]}
        write_json(retry / "campaign/target_runtime.json", runtime)
        result = copy.deepcopy(original)
        campaign_complete = args.afl_seconds >= source_budget
        result.update({"status": "evaluated" if campaign_complete else "partial_completed",
                       "reason": "none" if campaign_complete else "AFL campaign shorter than configured alpha budget",
                       "run_type": "offline_resume_generated_inputs",
                       "source_run": str(source), "campaign": campaign, "coverage": coverage,
                       "faithful_afl_campaign": True, "exact_fuzzbench_afl": True})
        stages = result.setdefault("stages", {})
        stages["generated_input_validation"] = {"status": "complete", "reason": "none", "valid_count": len(valid),
                                                 "invalid_count": len(read_json(retry / "generated_inputs/validation/results.json").get("results", [])) - len(valid),
                                                 "containerized": True}
        stages["campaign"] = {"status": "complete", "reason": "none", **campaign, "afl_seconds": args.afl_seconds,
                              "exact_fuzzbench_afl": True}
        stages["coverage"] = {"status": "complete", "reason": "none", **coverage}
        result.setdefault("metrics", {})["coverage"] = coverage
        result["metrics"]["campaign"] = campaign
        for name in ("result.json", "metadata.json"):
            write_json(retry / name, result)
        write_json(retry / "reevaluation_provenance.json", {"source_run": str(source), "afl_build": afl_build,
                   "coverage_build": coverage_build, "afl_binary_sha256": sha256(afl_binary),
                   "generated_inputs": [{"path": str(p), "sha256": sha256(p)} for p in valid]})
        subprocess.run([*stats_cmd, "--exit-code", "0"], check=True)
        print(json.dumps({"target": target, "run": str(retry), "execs_done": campaign["execs_done"],
                          "queue_count": campaign["queue_count"], "covered_lines": coverage["covered_lines"]}))
        return 0
    except Exception as exc:
        write_json(retry / "resume_failure.json", {"status": "failed", "reason": str(exc), "source_run": str(source)})
        write_json(retry / "metadata.json", {"generator": "elfuzz", "target": target, "status": "failed",
                   "reason": str(exc), "run_type": "offline_resume_generated_inputs", "source_run": str(source)})
        subprocess.run([*stats_cmd, "--exit-code", "1"], check=False)
        print(f"ELFuzz offline resume failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
