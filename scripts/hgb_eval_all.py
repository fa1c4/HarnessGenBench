#!/usr/bin/env python3
"""Reproduce valuable targets in two phases: generation, then saved-artifact fuzzing.

Phase A records or creates verified generated harnesses/inputs. Phase B consumes
only those saved artifacts and runs a separate, fixed-budget fuzzing campaign.
The CSV is updated atomically after each job.
"""

from __future__ import annotations

import argparse
import csv
import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
BASELINES = ("ckgfuzzer", "promefuzz", "oss-fuzz-gen", "g2fuzz", "elfuzz")
METRICS = (
    "status", "campaign_seconds", "campaign_elapsed_seconds", "execs_done",
    "covered_lines", "crashes", "read_tokens", "write_tokens",
    "retry_count", "driver_fix_rounds", "run", "reason",
)
FIELDS = ["target", *[f"{b}_{m}" for b in BASELINES for m in METRICS]]


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def plan(root: Path) -> tuple[list[str], dict[tuple[str, str], str]]:
    targets = read_json(root / "metadata/fuzzbench_targets.json")["target_sets"]["valuable"]["targets"]
    adapters = yaml.safe_load((root / "metadata/elfuzz_target_adapters.yaml").read_text(encoding="utf-8"))
    elf_scope = {item["target"]: item.get("applicability") for item in adapters["targets"]}
    overrides = yaml.safe_load((root / "metadata/oss_fuzz_gen_target_overrides.yaml").read_text(encoding="utf-8"))
    ofg_scope = overrides.get("targets", {})
    scope = {}
    for target in targets:
        for baseline in BASELINES:
            if baseline == "elfuzz" and elf_scope.get(target) != "applicable":
                scope[baseline, target] = "N/A"
            elif baseline == "oss-fuzz-gen" and ofg_scope.get(target, {}).get("applicability") == "not_applicable":
                scope[baseline, target] = "N/A"
            else:
                scope[baseline, target] = "pending"
    return targets, scope


def save_csv(path: Path, targets: list[str], rows: dict[tuple[str, str], dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", newline="", encoding="utf-8", dir=path.parent, delete=False) as handle:
        temp = Path(handle.name)
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        for target in targets:
            row = {"target": target}
            for baseline in BASELINES:
                data = rows[baseline, target]
                for metric in METRICS:
                    row[f"{baseline}_{metric}"] = data.get(metric, "")
            writer.writerow(row)
    temp.replace(path)


def campaign_elapsed(baseline: str, run: Path, campaign: dict[str, Any]) -> float | None:
    value = campaign.get("campaign_wall_seconds")
    if value is not None:
        return float(value)
    if baseline == "g2fuzz":
        saved = read_json(run / "result.json")
        stats_record = ((saved.get("stages") or {}).get("campaign") or {}).get("fuzzer_stats") or {}
        if stats_record:
            try:
                return float(int(stats_record["last_update"]) - int(stats_record["start_time"]))
            except (KeyError, TypeError, ValueError):
                pass
    if baseline in ("ckgfuzzer", "promefuzz", "oss-fuzz-gen"):
        return None
    if baseline == "elfuzz":
        source = Path(read_json(run / "result.json").get("source_run") or run)
        stats = source / "campaign/fuzzer_stats"
    else:
        stats = run / "campaign/output/default/fuzzer_stats"
    try:
        if not stats.is_file():
            return None
    except OSError:
        return None
    fields = {}
    try:
        lines = stats.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            fields[key.strip()] = value.strip()
    try:
        return float(int(fields["last_update"]) - int(fields["start_time"]))
    except (KeyError, ValueError):
        return None


def result_row(root: Path, baseline: str, target: str, run: Path, budget: int, exit_code: int) -> dict[str, Any]:
    meta = read_json(run / "metadata.json")
    result = read_json(run / ("evaluation/result.json" if baseline in BASELINES[:3] else "result.json"))
    statistics = read_json(run / "statistics.json")
    campaign = result.get("campaign") or (result.get("metrics") or {}).get("campaign") or {}
    coverage = result.get("coverage") or (result.get("metrics") or {}).get("coverage") or {}
    elapsed = campaign_elapsed(baseline, run, campaign)
    status = str(meta.get("status") or result.get("status") or f"failed_exit_{exit_code}")
    reason = str(meta.get("reason") or result.get("reason") or "")
    if status == "evaluated":
        if result.get("status") != "evaluated":
            status, reason = "incomplete", "missing evaluated result"
        elif elapsed is None:
            status, reason = "duration_unverified", "no measured campaign duration"
        elif elapsed < budget - 60:
            status, reason = "short_campaign", f"measured {elapsed:.0f}s; required {budget}s"
    return {
        "status": status,
        "campaign_seconds": budget,
        "campaign_elapsed_seconds": "" if elapsed is None else round(elapsed, 3),
        "execs_done": campaign.get("execs_done", ""),
        "covered_lines": (coverage.get("line_coverage") or {}).get("covered", ""),
        "crashes": campaign.get("crashes", ""),
        "read_tokens": statistics.get("read_tokens", ""),
        "write_tokens": statistics.get("write_tokens", ""),
        "retry_count": statistics.get("retry_count", ""),
        "driver_fix_rounds": statistics.get("driver_fix_rounds", ""),
        "run": str(run.relative_to(root)),
        "reason": reason,
    }


def run_job(root: Path, baseline: str, target: str, package: Path, run_id: str, budget: int,
            generation_timeout: int, log_dir: Path, cpu: int, memory_gib: int = 8) -> dict[str, Any]:
    safe = re.sub(r"[^A-Za-z0-9_]+", "_", f"{baseline}_{target}")
    pair_id = f"{run_id}_{safe}"
    run = root / "workspace" / baseline / target / pair_id
    env = os.environ.copy()
    env.update({
        "HGB_CAMPAIGN_SECONDS": str(budget),
        "PROME_FUZZ_CAMPAIGN_SECONDS": str(budget),
        "OFG_CAMPAIGN_SECONDS": str(budget),
        "ELFUZZ_AFL_SECONDS": str(budget),
        "G2FUZZ_AFL_TIMEOUT_SECONDS": str(budget),
        "HGB_DOCKER_RUN_TIMEOUT_SECONDS": str(budget + generation_timeout + 14400),
        "HGB_DOCKER_CPUS": "1",
        "HGB_DOCKER_CPUSET": str(cpu),
        "HGB_DOCKER_MEMORY": f"{memory_gib}g",
        "HGB_CKG_EVALUATOR_TIMEOUT_SECONDS": str(budget + 7200),
        "HGB_EVAL_ALL_STOP_AFTER_SUCCESS": "1",
        "HGB_PROMEFUZZ_EVAL_BUILD_TIMEOUT": "7200",
        "PROME_FUZZ_NATIVE_BUILD_TIMEOUT_SECONDS": "7200",
        "OMP_NUM_THREADS": "1", "OPENBLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1", "NUMEXPR_NUM_THREADS": "1",
        "TOKENIZERS_PARALLELISM": "false", "AFL_NO_AFFINITY": "1",
        "HGB_SKIP_IMAGE_PREFLIGHT": "1",
        "HGB_TARGET_REQUIRE_SPLIT": "1",
        "DOCKER_NAME": f"hgb-tgi-{pair_id}",
    })
    protocol = "paper-native" if baseline in ("g2fuzz", "elfuzz") else "blind-project"
    profile = "reproduction-eta" if baseline == "ckgfuzzer" else "alpha"
    cmd = ["bash", str(root / "scripts/hgb_generate_harness.sh"),
           "--generator", baseline, "--target", target, "--target-package", str(package),
           "--run-id", pair_id, "--profile", profile, "--protocol", protocol,
           "--timeout", str(generation_timeout), "--save-mode", "compact"]
    log_path = log_dir / f"{safe}.log"
    started = time.time()
    with log_path.open("w", encoding="utf-8") as log:
        log.write("command=" + " ".join(cmd) + "\n")
        log.flush()
        completed = subprocess.run(cmd, cwd=log_dir, env=env, stdout=log, stderr=subprocess.STDOUT, check=False)
    row = result_row(root, baseline, target, run, budget, completed.returncode)
    row["reason"] = row["reason"] or (f"exit {completed.returncode}; see {log_path.relative_to(root)}" if completed.returncode else "")
    row["job_wall_seconds"] = round(time.time() - started, 3)
    return row


def audited_sources(root: Path, audit: Path) -> dict[tuple[str, str], str]:
    if not audit.is_file():
        return {}
    data = read_json(audit)
    sources = {}
    for record in data.get("rows", []):
        if not isinstance(record, dict) or record.get("status") != "verified":
            continue
        key = (str(record.get("baseline") or ""), str(record.get("target") or ""))
        if key[0] in BASELINES and record.get("run"):
            sources[key] = str(record["run"])
    return sources


def latest_audit(root: Path) -> Path:
    audits = sorted((root / "workspace/oss-fuzz-gen").glob("valuable_reproduction_audit_*.json"))
    return audits[-1] if audits else root / "workspace/oss-fuzz-gen/valuable_reproduction_audit.json"


def source_ready(baseline: str, target: str, raw: str) -> tuple[bool, str]:
    """Validate Phase A evidence before allowing an LLM-free Phase B job."""
    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        import hgb_replay_saved as replay
        selected, source = replay.phase_a_source(baseline, raw)
        if replay.source_target(selected, source) != target:
            return False, "source target mismatch"
        host = replay.host_command(source)
        if host.get("generator") != baseline or host.get("target") != target:
            return False, "saved host command baseline/target mismatch"
        package = Path(host.get("target_package") or "")
        if read_json(package / "target_manifest.json").get("target") != target:
            return False, "saved target package missing"
        if baseline in BASELINES[:3]:
            replay.selected_harness(selected)
        elif baseline == "g2fuzz":
            if not all((source / "target" / name).is_file() for name in ("target.afl", "target.cmp")):
                return False, "saved G2Fuzz target pair missing"
            seeds = source / "seeds/g2_generated"
            if not seeds.is_dir() or not any(p.is_file() for p in seeds.rglob("*")):
                return False, "saved G2Fuzz inputs missing"
        else:
            produced = source / "generated_inputs/produced"
            if not produced.is_dir() or not any(p.is_file() and p.stat().st_size for p in produced.rglob("*")):
                return False, "saved ELFuzz inputs missing"
            if not read_json(source / "target/build.json").get("native_image_tag"):
                return False, "saved ELFuzz target image tag missing"
        return True, str(selected)
    except (OSError, ValueError, KeyError) as exc:
        return False, str(exc)


def save_manifest(path: Path, sources: dict[tuple[str, str], str],
                  targets: list[str], scope: dict[tuple[str, str], str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    records = []
    for target in targets:
        for baseline in BASELINES:
            if scope[baseline, target] == "N/A":
                records.append({"baseline": baseline, "target": target, "status": "N/A"})
                continue
            raw = sources.get((baseline, target), "")
            ready, detail = source_ready(baseline, target, raw) if raw else (False, "no Phase A artifact")
            records.append({"baseline": baseline, "target": target,
                            "status": "ready" if ready else "missing",
                            "source_run": detail if ready else raw, "reason": "" if ready else detail})
    payload = {"schema_version": 1, "phase": "A", "generated_at": datetime.now().isoformat(),
               "records": records}
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        temp = Path(handle.name)
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    temp.replace(path)


def manifest_sources(path: Path) -> dict[tuple[str, str], str]:
    data = read_json(path)
    return {(item["baseline"], item["target"]): str(item["source_run"])
            for item in data.get("records", [])
            if isinstance(item, dict) and item.get("status") == "ready" and item.get("source_run")}


def run_replay_job(root: Path, baseline: str, target: str, source: str,
                   run_id: str, budget: int, log_dir: Path,
                   cpu: int, memory_gib: int) -> dict[str, Any]:
    safe = re.sub(r"[^A-Za-z0-9_]+", "_", f"{baseline}_{target}")
    pair_id = f"{run_id}_{safe}"
    run = root / "workspace" / baseline / target / pair_id
    cmd = [sys.executable, str(root / "scripts/hgb_replay_saved.py"),
           "--baseline", baseline, "--target", target, "--source-run", source,
           "--run-id", pair_id, "--campaign-seconds", str(budget),
           "--cpu", str(cpu), "--memory-gib", str(memory_gib)]
    log_path = log_dir / f"{safe}.log"
    started = time.time()
    with log_path.open("w", encoding="utf-8") as log:
        log.write("command=" + " ".join(cmd) + "\n")
        log.flush()
        completed = subprocess.run(cmd, cwd=log_dir, stdout=log, stderr=subprocess.STDOUT, check=False)
    row = result_row(root, baseline, target, run, budget, completed.returncode)
    row["reason"] = row["reason"] or (
        f"exit {completed.returncode}; see {log_path.relative_to(root)}" if completed.returncode else "")
    row["job_wall_seconds"] = round(time.time() - started, 3)
    return row


def host_memory_gib() -> int:
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        if line.startswith("MemTotal:"):
            return max(1, int(line.split()[1]) // (1024 * 1024))
    raise RuntimeError("unable to read host memory")


def default_run_id(phase: str, date: str, campaign_seconds: int,
                   generation_campaign_seconds: int) -> str:
    phase_letter = "a" if phase == "generate" else "b"
    duration = generation_campaign_seconds if phase == "generate" else campaign_seconds
    return f"eval_all_phase_{phase_letter}_{date.replace('-', '')}_{duration}s"


def latest_complete_manifest(root: Path, date: str,
                             scope: dict[tuple[str, str], str]) -> Path | None:
    """Find the newest saved Phase A selection no later than the output date."""
    applicable = {pair for pair, status in scope.items() if status == "pending"}
    candidates = (
        list((root / "workspace/eval_all").glob("????-??-??.phase_a.json"))
        + list((root / "results/eval_all").glob("????-??-??.phase_a.json"))
    )
    for candidate in sorted(candidates, key=lambda path: (
            path.name[:10], path.parent == root / "workspace/eval_all"), reverse=True):
        if candidate.name[:10] <= date and applicable.issubset(manifest_sources(candidate)):
            return candidate
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("generate", "fuzz"), default="fuzz",
                        help="generate/check Phase A artifacts or fuzz saved Phase A artifacts (default: fuzz)")
    parser.add_argument("--parallel-worker", type=int, default=64, help="Maximum concurrent baseline/target jobs (default: 64)")
    parser.add_argument("--campaign-seconds", type=int, default=86400, help="Per-job fuzz campaign budget (default: 86400)")
    parser.add_argument("--generation-campaign-seconds", type=int, default=300,
                        help="Short verification campaign for newly generated Phase A artifacts (default: 300)")
    parser.add_argument("--generation-timeout-seconds", type=int, default=21600)
    parser.add_argument("--memory-per-job-gib", type=int, default=8,
                        help="Docker RAM cap for each active pair (default: 8 GiB)")
    parser.add_argument("--memory-budget-gib", type=int, default=0,
                        help="Maximum combined pair RAM; 0 uses 70%% of host RAM")
    parser.add_argument("--source-audit", type=Path, help="Verified Phase A audit JSON; defaults to the latest local audit")
    parser.add_argument("--manifest", type=Path, help="Phase A artifact manifest; defaults to workspace/eval_all/<date>.phase_a.json")
    parser.add_argument("--date", default=datetime.now().strftime("%Y-%m-%d"))
    parser.add_argument("--run-id", help="Defaults to eval_all_phase_<a/b>_<date>_<campaign-seconds>s")
    parser.add_argument("--output", type=Path, help="Override workspace/eval_all/<date>.csv")
    parser.add_argument("--plan", action="store_true", help="Write planned/N/A CSV without Docker or target preparation")
    parser.add_argument("--resume", action="store_true", help="Reuse the date CSV, keeping completed rows and retrying all others")
    parser.add_argument("--rebuild-images", action="store_true", help="Rebuild all baseline images before launching jobs")
    args = parser.parse_args()
    if (args.parallel_worker < 1 or args.campaign_seconds < 1 or args.generation_campaign_seconds < 1
            or args.generation_timeout_seconds < 1 or args.memory_per_job_gib < 1
            or args.memory_budget_gib < 0):
        parser.error("worker count, memory cap, and time budgets must be positive")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.date):
        parser.error("--date must be YYYY-MM-DD")
    args.run_id = args.run_id or default_run_id(
        args.phase, args.date, args.campaign_seconds, args.generation_campaign_seconds)
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.run_id):
        parser.error("--run-id must contain only letters, digits, underscore, or hyphen")
    default_name = f"{args.date}.phase_a.csv" if args.phase == "generate" else f"{args.date}.csv"
    output = (args.output or ROOT / "workspace/eval_all" / default_name).resolve()
    manifest = (args.manifest or ROOT / "workspace/eval_all" / f"{args.date}.phase_a.json").resolve()
    for label, path in (("output", output), ("manifest", manifest)):
        if path.resolve().parent == ROOT:
            parser.error(f"--{label} may not create a file in the repository root: {path}")
    if output.exists() and not args.resume:
        parser.error(f"output already exists: {output}; pass --resume or --output")
    if args.resume and not output.exists():
        parser.error(f"--resume requires an existing CSV: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    lock_handle = (output.parent / f"{output.name}.lock").open("w")
    try:
        fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error(f"another evaluation coordinator owns {output}")
    targets, scope = plan(ROOT)
    if not manifest.is_file() and args.manifest is None:
        previous = latest_complete_manifest(ROOT, args.date, scope)
        if previous is not None:
            manifest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(previous, manifest)
            print(f"Phase A manifest: {manifest} (copied from {previous})", flush=True)
    if manifest.is_file():
        sources = manifest_sources(manifest)
    else:
        audit = args.source_audit or latest_audit(ROOT)
        sources = audited_sources(ROOT, audit)
        save_manifest(manifest, sources, targets, scope)
        sources = manifest_sources(manifest)
    rows = {(b, t): {"status": "N/A" if scope[b, t] == "N/A" else "pending",
                     **({m: "N/A" for m in METRICS if m != "status"} if scope[b, t] == "N/A" else {})}
            for t in targets for b in BASELINES}
    for target in targets:
        for baseline in BASELINES:
            if scope[baseline, target] == "N/A":
                continue
            ready, detail = source_ready(baseline, target, sources.get((baseline, target), "")) \
                if (baseline, target) in sources else (False, "no verified Phase A artifact")
            if args.phase == "generate" and ready:
                rows[baseline, target] = {"status": "generated", "run": detail}
            elif args.phase == "fuzz" and not ready:
                rows[baseline, target] = {"status": "missing_artifact", "reason": detail}
    if args.resume:
        with output.open(newline="", encoding="utf-8") as existing:
            old_rows = {record["target"]: record for record in csv.DictReader(existing)}
        for target in targets:
            record = old_rows.get(target, {})
            for baseline in BASELINES:
                if (scope[baseline, target] == "pending" and args.phase == "fuzz"
                        and record.get(f"{baseline}_status") == "evaluated"):
                    rows[baseline, target] = {metric: record.get(f"{baseline}_{metric}", "") for metric in METRICS}
    save_csv(output, targets, rows)
    jobs = [(b, t) for t in targets for b in BASELINES if scope[b, t] == "pending"]
    remaining = sum(rows[b, t]["status"] == "pending" for b, t in jobs)
    print(f"phase={args.phase}; planned {len(jobs)} applicable pairs ({remaining} jobs); "
          f"{len(targets) * len(BASELINES) - len(jobs)} N/A; requested_workers={args.parallel_worker}; "
          f"campaign={args.campaign_seconds}s", flush=True)
    print(output, flush=True)
    if args.plan:
        return 0
    if not remaining:
        failures = [(b, t) for b, t in jobs
                    if rows[b, t]["status"] not in (("generated",) if args.phase == "generate" else ("evaluated",))]
        print(f"phase={args.phase}: {len(jobs) - len(failures)}/{len(jobs)} ready; manifest={manifest}", flush=True)
        return 1 if failures else 0
    if subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode:
        print("Docker is unavailable; no jobs started", file=sys.stderr)
        return 2
    log_dir = ROOT / "workspace/eval_all" / args.run_id
    log_dir.mkdir(parents=True, exist_ok=False)
    os.chdir(log_dir)
    cpus = sorted(os.sched_getaffinity(0))
    if not cpus:
        print("No usable CPUs in process affinity mask", file=sys.stderr)
        return 2
    memory_budget = args.memory_budget_gib or max(args.memory_per_job_gib, int(host_memory_gib() * 0.70))
    effective_workers = min(args.parallel_worker, len(cpus),
                            max(1, memory_budget // args.memory_per_job_gib))
    print(f"effective_workers={effective_workers}; per_job_memory={args.memory_per_job_gib}GiB; "
          f"aggregate_cap={effective_workers * args.memory_per_job_gib}GiB", flush=True)
    if args.phase == "fuzz":
        pending = [(b, t) for b, t in jobs if rows[b, t]["status"] == "pending"]
        active = {}
        with ThreadPoolExecutor(max_workers=effective_workers) as executor:
            while pending or active:
                while pending and len(active) < effective_workers:
                    baseline, target = pending.pop(0)
                    used_cpus = {item[2] for item in active.values()}
                    cpu = next((value for value in cpus if value not in used_cpus), cpus[len(active) % len(cpus)])
                    rows[baseline, target]["status"] = "running"
                    future = executor.submit(
                        run_replay_job, ROOT, baseline, target, sources[baseline, target],
                        args.run_id, args.campaign_seconds, log_dir, cpu, args.memory_per_job_gib)
                    active[future] = (baseline, target, cpu)
                save_csv(output, targets, rows)
                if not active:
                    break
                done, _ = wait(active, return_when=FIRST_COMPLETED)
                for future in done:
                    baseline, target, _ = active.pop(future)
                    try:
                        rows[baseline, target] = future.result()
                    except Exception as exc:
                        rows[baseline, target] = {"status": "runner_failed", "reason": str(exc)}
                    print(f"{baseline} {target}: {rows[baseline, target]['status']}", flush=True)
                save_csv(output, targets, rows)
        failures = [(b, t) for b, t in jobs if rows[b, t]["status"] != "evaluated"]
        print(f"Phase B: {len(jobs) - len(failures)}/{len(jobs)} evaluated for >= "
              f"{args.campaign_seconds - 60}s; CSV: {output}", flush=True)
        return 1 if failures else 0
    # Phase A prepares only pairs that lack a verified saved artifact. Its
    # short evaluator campaign verifies generation; Phase B owns the long run.
    for baseline in BASELINES:
        if not any(rows[b, t]["status"] == "pending" and b == baseline for b, t in jobs):
            continue
        image_log = log_dir / f"image_{baseline}.log"
        shell = ('source "$1/scripts/lib/common.sh"; load_hgb_config; '
                 'image="$(hgb_image_name "$2" "$2" "$1")"; '
                 'if [[ "$3" == 1 ]] || ! docker image inspect "$image" >/dev/null 2>&1; '
                 'then hgb_build_image "$2" "$2" "$1"; else printf "reusing %s\\n" "$image"; fi')
        with image_log.open("w", encoding="utf-8") as log:
            code = subprocess.run(["bash", "-c", shell, "bash", str(ROOT), baseline,
                                   "1" if args.rebuild_images else "0"], cwd=log_dir,
                                  stdout=log, stderr=subprocess.STDOUT, check=False).returncode
        if code:
            for b, t in jobs:
                if b == baseline:
                    rows[b, t] = {"status": "image_build_failed", "reason": str(image_log.relative_to(ROOT))}
            save_csv(output, targets, rows)
            print(f"image build failed: {baseline}; see {image_log}", file=sys.stderr, flush=True)
    packages = {}
    for target in targets:
        if not any(rows[b, target]["status"] == "pending" for b in BASELINES):
            continue
        package = ROOT / "workspace/target-packages" / args.run_id / target
        package.parent.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env.update({"HGB_TARGET_REQUIRE_SPLIT": "1", "HGB_BASELINE_PROFILE": "alpha", "HGB_BASELINE_PROTOCOL": "blind-project"})
        prep_log = log_dir / f"package_{target}.log"
        with prep_log.open("w", encoding="utf-8") as log:
            code = subprocess.run(["bash", str(ROOT / "scripts/hgb_prepare_target.sh"), "--target", target,
                                   "--run-id", args.run_id, "--output", str(package)], cwd=log_dir, env=env,
                                  stdout=log, stderr=subprocess.STDOUT, check=False).returncode
        if code or not (package / "generator_input/target_manifest.json").is_file():
            for baseline in BASELINES:
                if rows[baseline, target]["status"] == "pending":
                    rows[baseline, target] = {"status": "package_failed", "reason": str(prep_log.relative_to(ROOT))}
            save_csv(output, targets, rows)
        else:
            packages[target] = package
    pending = [(b, t) for b, t in jobs if rows[b, t]["status"] == "pending"]
    active = {}
    with ThreadPoolExecutor(max_workers=effective_workers) as executor:
        while pending or active:
            while pending and len(active) < effective_workers:
                baseline, target = pending.pop(0)
                used_cpus = {item[2] for item in active.values()}
                cpu = next((value for value in cpus if value not in used_cpus), cpus[len(active) % len(cpus)])
                rows[baseline, target]["status"] = "running"
                future = executor.submit(run_job, ROOT, baseline, target, packages[target], args.run_id,
                                         args.generation_campaign_seconds, args.generation_timeout_seconds, log_dir,
                                         cpu, args.memory_per_job_gib)
                active[future] = (baseline, target, cpu)
            save_csv(output, targets, rows)
            if not active:
                break
            done, _ = wait(active, return_when=FIRST_COMPLETED)
            for future in done:
                baseline, target, _ = active.pop(future)
                try:
                    result = future.result()
                    if result["status"] == "evaluated":
                        sources[baseline, target] = result["run"]
                        result["status"] = "generated"
                        save_manifest(manifest, sources, targets, scope)
                    rows[baseline, target] = result
                except Exception as exc:
                    rows[baseline, target] = {"status": "runner_failed", "reason": str(exc)}
                print(f"{baseline} {target}: {rows[baseline, target]['status']}", flush=True)
            save_csv(output, targets, rows)
    failures = [(b, t) for b, t in jobs if rows[b, t]["status"] != "generated"]
    print(f"Phase A: {len(jobs) - len(failures)}/{len(jobs)} generated and verified; "
          f"manifest={manifest}; CSV={output}", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
