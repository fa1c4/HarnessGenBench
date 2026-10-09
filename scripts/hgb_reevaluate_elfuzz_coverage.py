#!/usr/bin/env python3
"""Replay saved ELFuzz corpora on a pinned FuzzBench LLVM coverage build.

This uses no model or input generator. It preserves the source run and writes a
new evaluated run only when the original pipeline stages and real replay pass.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker/common"))
import hgb_coverage  # noqa: E402
import hgb_fuzzbench_builder as builder  # noqa: E402


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def faithful_afl_campaign(source: Path) -> bool:
    evidence_path = source / "campaign/target_runtime.json"
    evidence = read_json(evidence_path) if evidence_path.is_file() else {}
    stats_path = source / "campaign/fuzzer_stats"
    stats = stats_path.read_text(encoding="utf-8", errors="replace") if stats_path.is_file() else ""
    runtime_log = source / "campaign/target_runtime.log"
    log = runtime_log.read_text(encoding="utf-8", errors="replace") if runtime_log.is_file() else ""
    return (bool(evidence.get("containerized")) and "start_time" in stats and "last_update" in stats
            and "Traceback (most recent call last)" not in log and "FileNotFoundError" not in log)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("source_run", type=Path)
    ap.add_argument("retry_id")
    args = ap.parse_args()
    source = args.source_run.resolve()
    if not args.retry_id.replace("_", "").replace("-", "").isalnum():
        ap.error("retry_id must be alphanumeric, underscore, or hyphen")
    original = read_json(source / "result.json")
    if original.get("generator") != "elfuzz" or original.get("status") != "evaluated":
        ap.error("source must be an evaluated ELFuzz run")
    stages = original.get("stages") or {}
    for name in ("target_build", "synthesis", "evolution", "production", "generated_input_validation", "campaign"):
        if (stages.get(name) or {}).get("status") != "complete":
            ap.error(f"source stage {name} is incomplete")
    if int((original.get("campaign") or {}).get("execs_done") or 0) <= 0:
        ap.error("source campaign has zero executions")
    target = original["target"]
    retry = ROOT / "workspace/elfuzz" / target / args.retry_id
    if retry.exists():
        ap.error(f"retry directory already exists: {retry}")
    target_package = ""
    for line in (source / "host_command.txt").read_text(encoding="utf-8").splitlines():
        if line.startswith("target_package="):
            target_package = line.split("=", 1)[1]
    package = Path(target_package)
    manifest = read_json(package / "generator_input/target_manifest.json")
    fuzz_target = manifest["fuzz_target"]
    benchmark = package / "fuzzbench_benchmark"
    if not benchmark.is_dir():
        benchmark = package / "generator_input/fuzzbench_benchmark"
    if not benchmark.is_dir():
        ap.error(f"missing exact FuzzBench benchmark: {benchmark}")
    retry.mkdir(parents=True)
    corpus = retry / "coverage/corpus"
    corpus.mkdir(parents=True)
    provenance = []
    for source_class, directory in (("elfuzz_generated", source / "generated_inputs/produced"),
                                    ("campaign_queue", source / "campaign/queue")):
        for index, path in enumerate(sorted(directory.iterdir()) if directory.is_dir() else []):
            if not path.is_file() or path.stat().st_size == 0:
                continue
            dest = corpus / f"{source_class}_{index:06d}"
            shutil.copy2(path, dest)
            provenance.append({"source_class": source_class, "source": str(path), "sha256": hashlib.sha256(dest.read_bytes()).hexdigest()})
    if not provenance:
        ap.error("source has no generated or campaign input files")
    write_json(retry / "coverage/input_provenance.json", {"inputs": provenance})
    image_tag = builder.deterministic_image_tag(run_id=args.retry_id, target=target, candidate_id="coverage", generator="elfuzz")
    built = builder.build_elfuzz_sut(
        benchmark_dir=benchmark, image_tag=image_tag, fuzz_target=fuzz_target,
        work_dir=retry / "coverage/build", engine=builder.ELFUZZ_COVERAGE_ENGINE,
        sanitizer=builder.ELFUZZ_COVERAGE_SANITIZER, timeout_seconds=3600,
    )
    write_json(retry / "coverage/build.json", built)
    if not built.get("binary_extracted") or built.get("build_exit_code") != 0:
        print(f"coverage build failed: {retry / 'coverage/build/build.log'}", file=sys.stderr)
        return 1
    lcov = retry / "coverage/coverage.lcov"
    stderr = retry / "coverage/replay.stderr.log"
    image_binary = f"/out/{fuzz_target}"
    shell = (
        "set -e; mkdir -p /tmp/cov; "
        f"LLVM_PROFILE_FILE=/tmp/cov/coverage.profraw {image_binary} -runs=0 /tmp/corpus >/tmp/cov/run.log 2>&1; "
        "llvm-profdata merge -o /tmp/cov/merged.profdata /tmp/cov/*.profraw; "
        f"llvm-cov export -summary-only -format=text {image_binary} -instr-profile=/tmp/cov/merged.profdata"
    )
    cmd = ["docker", "run", "--rm", "--pull=never", "-v", f"{corpus.resolve()}:/tmp/corpus:ro",
           image_tag, "sh", "-lc", shell]
    with lcov.open("wb") as out, stderr.open("wb") as err:
        try:
            run = subprocess.run(cmd, stdout=out, stderr=err, timeout=900, check=False)
        except subprocess.TimeoutExpired:
            print(f"coverage replay timed out: {retry}", file=sys.stderr)
            return 1
    if run.returncode != 0:
        print(f"coverage replay exited {run.returncode}: {stderr}", file=sys.stderr)
        return 1
    try:
        measured = hgb_coverage.summarize_coverage_report(lcov)
    except hgb_coverage.CoverageError as exc:
        print(f"coverage report invalid: {exc}", file=sys.stderr)
        return 1
    lines = measured["line_coverage"]
    if int(lines.get("covered") or 0) <= 0:
        print("coverage replay covered zero lines", file=sys.stderr)
        return 1
    coverage = {
        "complete": True, "coverage_mode": measured["source"], "report_exists": True,
        "report_path": str(lcov), "inputs_replayed": len(provenance),
        "line_coverage": lines, "function_coverage": measured["function_coverage"],
        "region_coverage": measured["region_coverage"], "covered_lines": lines["covered"],
        "total_lines": lines["total"], "edge_coverage": {"status": "unavailable", "value": None},
        "execs_done": int(original["campaign"]["execs_done"]),
    }
    write_json(retry / "coverage/summary.json", coverage)
    result = copy.deepcopy(original)
    campaign_faithful = faithful_afl_campaign(source)
    result.update({"status": "evaluated" if campaign_faithful else "partial_completed",
                   "reason": "offline LLVM coverage replay of saved ELFuzz corpus" if campaign_faithful
                   else "real LLVM coverage replay; original upstream AFL campaign failed and used a local fallback",
                   "run_type": "reevaluated_generated_inputs", "source_run": str(source),
                   "coverage": coverage, "faithful_afl_campaign": campaign_faithful})
    result.setdefault("stages", {})["coverage"] = {"status": "complete", "reason": "none", **coverage}
    result.setdefault("metrics", {})["coverage"] = coverage
    for name in ("result.json", "metadata.json"):
        write_json(retry / name, result)
    write_json(retry / "evaluation_retry_count.json", {"count": 1, "retry_ids": [args.retry_id]})
    subprocess.run([sys.executable, str(ROOT / "docker/common/hgb_record_statistics.py"),
                    "--workspace", str(retry), "--baseline", "elfuzz", "--target", target,
                    "--run-id", args.retry_id, "--exit-code", "0"], check=True)
    print(json.dumps({"target": target, "run": str(retry), "covered_lines": lines["covered"],
                      "campaign_execs": original["campaign"]["execs_done"]}))
    return 0


if __name__ == "__main__":
    exit_code = main()
    if len(sys.argv) >= 3:
        source_run = Path(sys.argv[1]).resolve()
        retry_run = ROOT / "workspace/elfuzz" / source_run.parent.name / sys.argv[2]
        if retry_run.is_dir():
            write_json(retry_run / "api_traces/summary.json", {"usage_accounting_version": 1,
                       "total_count": 0, "retry_count": 0, "input_tokens": 0, "output_tokens": 0,
                       "error_count": 0})
            write_json(retry_run / "evaluation_retry_count.json", {"count": 1, "retry_ids": [sys.argv[2]]})
            if not (retry_run / "metadata.json").is_file():
                write_json(retry_run / "metadata.json", {"generator": "elfuzz", "target": source_run.parent.name,
                           "status": "failed", "reason": "offline LLVM coverage replay failed",
                           "source_run": str(source_run)})
            subprocess.run([sys.executable, str(ROOT / "docker/common/hgb_record_statistics.py"),
                            "--workspace", str(retry_run), "--baseline", "elfuzz",
                            "--target", source_run.parent.name, "--run-id", sys.argv[2],
                            "--exit-code", str(exit_code)], check=False)
    raise SystemExit(exit_code)
