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
import math
import os
import re
import signal
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
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
    "covered_lines", "raw_covered_lines", "sut_covered_lines", "sut_total_lines", "sut_source_files",
    "coverage_contract",
    "crashes", "read_tokens", "write_tokens",
    "retry_count", "driver_fix_rounds", "run", "reason",
)
FIELDS = ["target", *[f"{b}_{m}" for b in BASELINES for m in METRICS]]
# Limit Docker API traffic and stagger starts on a busy shared daemon.
MEMORY_SAMPLE_INTERVAL_SECONDS = 15
MEMORY_LAUNCH_BATCH = 4


class JobProcesses:
    """Own the replay process groups started by one evaluation coordinator."""

    def __init__(self) -> None:
        self.interrupted = threading.Event()
        self._lock = threading.Lock()
        self._processes: set[subprocess.Popen[Any]] = set()

    def add(self, process: subprocess.Popen[Any]) -> None:
        with self._lock:
            self._processes.add(process)
            if self.interrupted.is_set():
                self._signal(process, signal.SIGTERM)

    def discard(self, process: subprocess.Popen[Any]) -> None:
        with self._lock:
            self._processes.discard(process)

    @staticmethod
    def _signal(process: subprocess.Popen[Any], signum: int) -> None:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signum)
            except ProcessLookupError:
                pass

    def stop(self, signum: int = signal.SIGTERM) -> None:
        self.interrupted.set()
        with self._lock:
            processes = list(self._processes)
        for process in processes:
            self._signal(process, signum)


def stop_eval_containers(run_id: str) -> None:
    """Stop only containers labelled by this evaluation run."""
    try:
        def listed_ids() -> list[str]:
            result = subprocess.run(
                ["docker", "ps", "-aq", "--filter", f"label=hgb.eval_all_run={run_id}"],
                capture_output=True, text=True, timeout=15, check=False)
            if result.returncode:
                raise RuntimeError(result.stderr.strip() or "docker ps failed")
            return result.stdout.split()

        for _ in range(2):
            container_ids = listed_ids()
            if not container_ids:
                return
            # A single docker rm with dozens of IDs can time out before it
            # reaches the last container. Continue with later batches even if
            # one batch is slow or a --rm container disappears meanwhile.
            for start in range(0, len(container_ids), 12):
                try:
                    subprocess.run(["docker", "rm", "-f", *container_ids[start:start + 12]],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=45, check=False)
                except subprocess.TimeoutExpired:
                    continue
        remaining = listed_ids()
        if remaining:
            print(f"Docker container cleanup incomplete: {len(remaining)} containers remain "
                  f"for {run_id}", file=sys.stderr)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"Docker container cleanup failed: {exc}", file=sys.stderr)


def reap_embedding_service(root: Path) -> None:
    """Close an auto-started service after killed Phase A workers release or die."""
    try:
        result = subprocess.run(
            [sys.executable, str(root / "scripts/hgb_embedding_service.py"), "reap"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=130, check=False)
        if result.returncode:
            print("Embedding service cleanup failed; inspect its lease state", file=sys.stderr)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"Embedding service cleanup failed: {exc}", file=sys.stderr)


def run_tracked(cmd: list[str], *, cwd: Path, stdout: Any,
                env: dict[str, str] | None, processes: JobProcesses | None) -> int:
    """Keep a long-running child in its own group for prompt signal cleanup."""
    if processes is None:
        return subprocess.run(cmd, cwd=cwd, env=env, stdout=stdout,
                              stderr=subprocess.STDOUT, check=False).returncode
    process = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=stdout,
                               stderr=subprocess.STDOUT, start_new_session=True)
    processes.add(process)
    try:
        return process.wait()
    finally:
        processes.discard(process)


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


def job_key(trial: int, baseline: str, target: str, trials: int) -> tuple[Any, ...]:
    return (baseline, target) if trials == 1 else (trial, baseline, target)


def scheduled_jobs(targets: list[str], scope: dict[tuple[str, str], str],
                   trials: int) -> list[tuple[int, str, str]]:
    """Place a pair's trials together so they can occupy workers concurrently."""
    return [(trial, baseline, target)
            for target in targets for baseline in BASELINES
            if scope[baseline, target] == "pending"
            for trial in range(1, trials + 1)]


def save_csv(path: Path, targets: list[str], rows: dict[tuple[Any, ...], dict[str, Any]],
             trials: int = 1) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", newline="", encoding="utf-8", dir=path.parent, delete=False) as handle:
        temp = Path(handle.name)
        writer = csv.DictWriter(handle, fieldnames=(["trial", *FIELDS] if trials > 1 else FIELDS))
        writer.writeheader()
        for trial in range(1, trials + 1):
            for target in targets:
                row = {"target": target}
                if trials > 1:
                    row["trial"] = trial
                for baseline in BASELINES:
                    data = rows[job_key(trial, baseline, target, trials)]
                    for metric in METRICS:
                        row[f"{baseline}_{metric}"] = data.get(metric, "")
                writer.writerow(row)
    temp.replace(path)


def save_trial_summary(path: Path, targets: list[str],
                       rows: dict[tuple[Any, ...], dict[str, Any]], trials: int) -> None:
    """Keep raw trial rows and a separate aggregate that exposes failures."""
    fields = ("baseline", "target", "status", "evaluated_trials", "total_trials",
              "mean_covered_lines", "stdev_covered_lines", "trial_statuses")
    with tempfile.NamedTemporaryFile("w", newline="", encoding="utf-8",
                                     dir=path.parent, delete=False) as handle:
        temp = Path(handle.name)
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for target in targets:
            for baseline in BASELINES:
                entries = [rows[job_key(trial, baseline, target, trials)]
                           for trial in range(1, trials + 1)]
                statuses = [str(entry.get("status") or "pending") for entry in entries]
                covered = [int(entry["covered_lines"]) for entry in entries
                           if entry.get("status") == "evaluated" and
                           str(entry.get("covered_lines", "")).isdigit()]
                status = ("N/A" if all(value == "N/A" for value in statuses) else
                          "evaluated" if all(value == "evaluated" for value in statuses) else
                          "partial" if covered else "failed")
                writer.writerow({
                    "baseline": baseline, "target": target, "status": status,
                    "evaluated_trials": len(covered), "total_trials": trials,
                    "mean_covered_lines": round(statistics.mean(covered), 3) if covered else "",
                    "stdev_covered_lines": round(statistics.stdev(covered), 3) if len(covered) > 1 else "",
                    "trial_statuses": ";".join(statuses),
                })
    temp.replace(path)


def minimum_campaign_elapsed(budget: int) -> int:
    """Allow only timer granularity and bounded shutdown overhead."""
    return max(0, budget - min(60, max(2, round(budget * 0.01))))


def completed_csv_trial(record: dict[str, str], baseline: str, budget: int) -> bool:
    if (record.get(f"{baseline}_status") != "evaluated"
            or record.get(f"{baseline}_campaign_seconds") != str(budget)
            or record.get(f"{baseline}_coverage_contract") != "canonical-g2-lcov-v1"):
        return False
    try:
        return float(record.get(f"{baseline}_campaign_elapsed_seconds") or 0) >= minimum_campaign_elapsed(budget)
    except (TypeError, ValueError):
        return False


def recovered_csv_trial(root: Path, record: dict[str, str], baseline: str,
                        target: str, budget: int, selected_source: str) -> dict[str, Any] | None:
    """Reuse a failed CSV row whose saved Phase B run was repaired in place."""
    raw = record.get(f"{baseline}_run") or ""
    if not raw or raw == "N/A":
        return None
    try:
        run = (root / raw).resolve(strict=True)
        if not run.is_relative_to(root / "workspace" / baseline / target):
            return None
        provenance = read_json(run / "phase_b_source.json")
        if (provenance.get("baseline") != baseline or provenance.get("target") != target
                or provenance.get("selected_phase_a_run") != selected_source
                or not provenance.get("canonical_target_package")):
            return None
        result = read_json(run / ("evaluation/result.json" if baseline in BASELINES[:3] else "result.json"))
        campaign = result.get("campaign") or (result.get("metrics") or {}).get("campaign") or {}
        configured = campaign.get("configured_duration_seconds")
        if configured is not None and int(configured) != budget:
            return None
        row = result_row(root, baseline, target, run, budget, 0)
        return row if row["status"] == "evaluated" and row["coverage_contract"] == "canonical-g2-lcov-v1" else None
    except (OSError, TypeError, ValueError):
        return None


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
    provenance = read_json(run / "phase_b_source.json")
    campaign = result.get("campaign") or (result.get("metrics") or {}).get("campaign") or {}
    coverage = result.get("coverage") or (result.get("metrics") or {}).get("coverage") or {}
    sut = coverage.get("sut_line_coverage") or {}
    raw_covered = (coverage.get("line_coverage") or {}).get("covered", "")
    elapsed = campaign_elapsed(baseline, run, campaign)
    status = str(meta.get("status") or result.get("status") or f"failed_exit_{exit_code}")
    reason = str(meta.get("reason") or result.get("reason") or "")
    if status == "evaluated":
        if result.get("status") != "evaluated":
            status, reason = "incomplete", "missing evaluated result"
        elif elapsed is None:
            status, reason = "duration_unverified", "no measured campaign duration"
        elif elapsed < minimum_campaign_elapsed(budget):
            status, reason = "short_campaign", f"measured {elapsed:.0f}s; required {budget}s"
    return {
        "status": status,
        "campaign_seconds": budget,
        "campaign_elapsed_seconds": "" if elapsed is None else round(elapsed, 3),
        "execs_done": campaign.get("execs_done", ""),
        "covered_lines": sut.get("covered", raw_covered),
        "raw_covered_lines": raw_covered,
        "sut_covered_lines": sut.get("covered", ""),
        "sut_total_lines": sut.get("total", ""),
        "sut_source_files": sut.get("source_files", ""),
        "coverage_contract": ("canonical-g2-lcov-v1"
                              if provenance.get("canonical_target_package") and
                              str(coverage.get("coverage_report_path") or coverage.get("report_path") or "").endswith(".lcov")
                              else ""),
        "crashes": campaign.get("crashes", ""),
        "read_tokens": statistics.get("read_tokens", ""),
        "write_tokens": statistics.get("write_tokens", ""),
        "retry_count": statistics.get("retry_count", ""),
        "driver_fix_rounds": statistics.get("driver_fix_rounds", ""),
        "run": str(run.relative_to(root)),
        "reason": reason,
    }


def run_job(root: Path, baseline: str, target: str, package: Path, run_id: str, budget: int,
            generation_timeout: int, log_dir: Path, cpu: int, memory_gib: int = 8,
            processes: JobProcesses | None = None) -> dict[str, Any]:
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
        "HGB_EVAL_ALL_RUN_ID": run_id,
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
        exit_code = run_tracked(cmd, cwd=log_dir, env=env, stdout=log, processes=processes)
    row = result_row(root, baseline, target, run, budget, exit_code)
    row["reason"] = row["reason"] or (f"exit {exit_code}; see {log_path.relative_to(root)}" if exit_code else "")
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
                   cpu: int, memory_gib: int, trial: int = 1, trials: int = 1,
                   processes: JobProcesses | None = None,
                   canonical_source: str = "") -> dict[str, Any]:
    safe = re.sub(r"[^A-Za-z0-9_]+", "_", f"{baseline}_{target}")
    trial_prefix = f"trial_{trial:03d}_" if trials > 1 else ""
    pair_id = f"{run_id}_{trial_prefix}{safe}"
    run = root / "workspace" / baseline / target / pair_id
    cmd = [sys.executable, str(root / "scripts/hgb_replay_saved.py"),
           "--baseline", baseline, "--target", target, "--source-run", source,
           "--run-id", pair_id, "--campaign-seconds", str(budget),
           "--cpu", str(cpu), "--memory-gib", str(memory_gib)]
    if canonical_source:
        cmd.extend(["--canonical-source-run", canonical_source])
    log_path = log_dir / f"{safe}{f'.trial_{trial:03d}' if trials > 1 else ''}.log"
    started = time.time()
    with log_path.open("w", encoding="utf-8") as log:
        log.write("command=" + " ".join(cmd) + "\n")
        log.flush()
        if processes is None:
            exit_code = subprocess.run(cmd, cwd=log_dir, stdout=log,
                                       stderr=subprocess.STDOUT, check=False).returncode
        else:
            env = os.environ.copy()
            env["HGB_EVAL_ALL_RUN_ID"] = run_id
            process = subprocess.Popen(cmd, cwd=log_dir, env=env, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            processes.add(process)
            try:
                exit_code = process.wait()
            finally:
                processes.discard(process)
    row = result_row(root, baseline, target, run, budget, exit_code)
    if processes is not None and processes.interrupted.is_set():
        row["status"] = "interrupted"
        row["reason"] = "evaluation stopped by signal"
        return row
    row["reason"] = row["reason"] or (
        f"exit {exit_code}; see {log_path.relative_to(root)}" if exit_code else "")
    row["job_wall_seconds"] = round(time.time() - started, 3)
    return row


def host_memory_gib() -> int:
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        if line.startswith("MemTotal:"):
            return max(1, int(line.split()[1]) // (1024 * 1024))
    raise RuntimeError("unable to read host memory")


def host_available_memory_gib() -> float:
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) / (1024 * 1024)
    raise RuntimeError("unable to read available host memory")


def eval_container_memory_gib(run_id: str) -> float:
    """Sum current cgroup charges of this run's outer and campaign containers."""
    ids = subprocess.check_output(
        ["docker", "ps", "-q", "--no-trunc", "--filter", f"label=hgb.eval_all_run={run_id}"],
        text=True, timeout=15).split()
    if not ids:
        return 0.0
    usage = 0
    sampled = 0
    for container_id in ids:
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise RuntimeError("docker ps did not return full container IDs")
        paths = (Path("/sys/fs/cgroup/system.slice") / f"docker-{container_id}.scope/memory.current",
                 Path("/sys/fs/cgroup/docker") / container_id / "memory.current")
        for path in paths:
            try:
                usage += int(path.read_text(encoding="utf-8"))
                sampled += 1
                break
            except FileNotFoundError:
                continue  # The container may have exited after docker ps.
    if not sampled:
        raise RuntimeError("Docker cgroup v2 memory counters are unavailable")
    return usage / (1024 ** 3)


def adaptive_worker_capacity(requested: int, cpus: int, active: int,
                             memory_budget_gib: float, container_cap_gib: int,
                             eval_usage_gib: float, available_gib: float,
                             host_total_gib: float) -> tuple[int, float]:
    """Admit jobs using measured RAM with room for unobserved startup growth."""
    # The initial allowance covers builds before Docker creates a container.
    # Double the observed mean to allow running jobs to grow after admission.
    estimated_job_gib = max(1.0, container_cap_gib / 4,
                            2 * eval_usage_gib / max(1, active))
    host_reserve_gib = max(32.0, host_total_gib * 0.20)
    active_growth_gib = max(0.0, active * estimated_job_gib - eval_usage_gib)
    new_job_headroom_gib = max(0.0, available_gib - host_reserve_gib - active_growth_gib)
    budget_capacity = max(1, math.floor(memory_budget_gib / estimated_job_gib))
    host_capacity = active + math.floor(new_job_headroom_gib / estimated_job_gib)
    return min(requested, cpus, budget_capacity, host_capacity), estimated_job_gib


def default_run_id(phase: str, date: str, campaign_seconds: int,
                   generation_campaign_seconds: int) -> str:
    phase_letter = "a" if phase == "generate" else "b"
    duration = generation_campaign_seconds if phase == "generate" else campaign_seconds
    return f"eval_all_phase_{phase_letter}_{date.replace('-', '')}_{duration}s"


def write_coverage_products(output: Path) -> bool:
    """Recount saved LCOV on target code and the shared executable line set."""
    audit_dir = output.parent if output.is_relative_to(ROOT / "workspace") else ROOT / "workspace/eval_all"
    audit_dir.mkdir(parents=True, exist_ok=True)
    stem = output.stem
    artifacts = {
        "--output": audit_dir / f"{stem}.coverage_audit.csv",
        "--corrected-output": audit_dir / f"{stem}.coverage_corrected.csv",
        "--source-sets-output": audit_dir / f"{stem}.coverage_source_sets.csv",
        "--common-source-output": audit_dir / f"{stem}.coverage_common.csv",
    }
    cmd = [sys.executable, str(ROOT / "scripts/hgb_audit_coverage_integrity.py"),
           "--input", str(output)]
    for flag, destination in artifacts.items():
        cmd.extend([flag, str(destination)])
    log = audit_dir / f"{stem}.audit.log"
    with log.open("w", encoding="utf-8") as handle:
        code = subprocess.run(cmd, cwd=ROOT, stdout=handle,
                              stderr=subprocess.STDOUT, check=False).returncode
    if code:
        print(f"coverage audit failed (exit {code}); see {log}", file=sys.stderr, flush=True)
        return False
    print(f"Common-source coverage: {artifacts['--common-source-output']}", flush=True)
    return True


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
    parser.add_argument("--trials", type=int, default=1,
                        help="Independent Phase B campaigns per applicable artifact (default: 1)")
    parser.add_argument("--campaign-seconds", type=int, default=86400, help="Per-job fuzz campaign budget (default: 86400)")
    parser.add_argument("--generation-campaign-seconds", type=int, default=300,
                        help="Short verification campaign for newly generated Phase A artifacts (default: 300)")
    parser.add_argument("--generation-timeout-seconds", type=int, default=21600)
    parser.add_argument("--memory-per-job-gib", type=int, default=8,
                        help="Docker RAM cap for each container (default: 8 GiB)")
    parser.add_argument("--memory-budget-gib", type=int, default=0,
                        help="Phase B measured RAM budget; 0 uses 70%% of host RAM")
    parser.add_argument("--source-audit", type=Path, help="Verified Phase A audit JSON; defaults to the latest local audit")
    parser.add_argument("--manifest", type=Path, help="Phase A artifact manifest; defaults to workspace/eval_all/<date>.phase_a.json")
    parser.add_argument("--date", default=datetime.now().strftime("%Y-%m-%d"))
    parser.add_argument("--run-id", help="Defaults to eval_all_phase_<a/b>_<date>_<campaign-seconds>s")
    parser.add_argument("--output", type=Path, help="Override workspace/eval_all/<date>.csv")
    parser.add_argument("--plan", action="store_true", help="Write planned/N/A CSV without Docker or target preparation")
    parser.add_argument("--resume", action="store_true", help="Reuse the date CSV, keeping completed rows and retrying all others")
    parser.add_argument("--rebuild-images", action="store_true", help="Rebuild all baseline images before launching jobs")
    args = parser.parse_args()
    if (args.parallel_worker < 1 or args.trials < 1 or args.campaign_seconds < 1 or args.generation_campaign_seconds < 1
            or args.generation_timeout_seconds < 1 or args.memory_per_job_gib < 1
            or args.memory_budget_gib < 0):
        parser.error("worker count, memory cap, and time budgets must be positive")
    if args.phase != "fuzz" and args.trials != 1:
        parser.error("--trials applies only to --phase fuzz")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.date):
        parser.error("--date must be YYYY-MM-DD")
    args.run_id = args.run_id or default_run_id(
        args.phase, args.date, args.campaign_seconds, args.generation_campaign_seconds)
    if args.trials > 1 and args.run_id == default_run_id(
            args.phase, args.date, args.campaign_seconds, args.generation_campaign_seconds):
        args.run_id += f"_trials{args.trials}"
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.run_id):
        parser.error("--run-id must contain only letters, digits, underscore, or hyphen")
    default_name = (f"{args.date}.phase_a.csv" if args.phase == "generate" else
                    f"{args.date}.trials{args.trials}.csv" if args.trials > 1 else f"{args.date}.csv")
    output = (args.output or ROOT / "workspace/eval_all" / default_name).resolve()
    manifest = (args.manifest or ROOT / "workspace/eval_all" / f"{args.date}.phase_a.json").resolve()
    for label, path in (("output", output), ("manifest", manifest)):
        if path.resolve().parent == ROOT:
            parser.error(f"--{label} may not create a file in the repository root: {path}")
    if output.exists() and not args.resume:
        parser.error(f"output already exists: {output}; pass --resume or --output")
    if args.resume and not output.exists():
        parser.error(f"--resume requires an existing CSV: {output}")
    if args.resume and not args.plan:
        # Failed or interrupted trials need fresh run directories. Preserve
        # completed rows in the CSV while keeping each retry auditable.
        args.run_id += "_resume_" + datetime.now().strftime("%Y%m%dT%H%M%S%f")
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
    rows = {job_key(trial, b, t, args.trials):
            {"status": "N/A" if scope[b, t] == "N/A" else "pending",
             **({m: "N/A" for m in METRICS if m != "status"} if scope[b, t] == "N/A" else {})}
            for trial in range(1, args.trials + 1) for t in targets for b in BASELINES}
    ready_pairs: set[tuple[str, str]] = set()
    for target in targets:
        for baseline in BASELINES:
            if scope[baseline, target] == "N/A":
                continue
            ready, detail = source_ready(baseline, target, sources.get((baseline, target), "")) \
                if (baseline, target) in sources else (False, "no verified Phase A artifact")
            if ready:
                ready_pairs.add((baseline, target))
            if args.phase == "generate" and ready:
                rows[baseline, target] = {"status": "generated", "run": detail}
            elif args.phase == "fuzz" and not ready:
                for trial in range(1, args.trials + 1):
                    rows[job_key(trial, baseline, target, args.trials)] = {
                        "status": "missing_artifact", "reason": detail}
    if args.phase == "fuzz":
        for target in targets:
            if ("g2fuzz", target) in ready_pairs:
                continue
            for baseline in BASELINES:
                if scope[baseline, target] == "pending":
                    for trial in range(1, args.trials + 1):
                        rows[job_key(trial, baseline, target, args.trials)] = {
                            "status": "missing_artifact",
                            "reason": "G2Fuzz Phase A target package is required as the shared coverage build source"}
    if args.resume:
        with output.open(newline="", encoding="utf-8") as existing:
            reader = csv.DictReader(existing)
            if ("trial" in (reader.fieldnames or [])) != (args.trials > 1):
                parser.error("--resume CSV trial schema does not match --trials")
            old_rows = {(int(record.get("trial") or 1), record["target"]): record
                        for record in reader}
        if args.trials > 1 and {trial for trial, _ in old_rows} != set(range(1, args.trials + 1)):
            parser.error("--resume CSV has a different number of trials")
        for trial in range(1, args.trials + 1):
            for target in targets:
                record = old_rows.get((trial, target), {})
                for baseline in BASELINES:
                    if (scope[baseline, target] == "pending" and args.phase == "fuzz"
                            and (baseline, target) in ready_pairs
                            and completed_csv_trial(record, baseline, args.campaign_seconds)):
                        _, selected = source_ready(baseline, target, sources[baseline, target])
                        refreshed = recovered_csv_trial(ROOT, record, baseline, target,
                                                       args.campaign_seconds, selected)
                        rows[job_key(trial, baseline, target, args.trials)] = refreshed or {
                            metric: record.get(f"{baseline}_{metric}", "") for metric in METRICS}
                    elif (scope[baseline, target] == "pending" and args.phase == "fuzz"
                          and (baseline, target) in ready_pairs):
                        _, selected = source_ready(baseline, target, sources[baseline, target])
                        recovered = recovered_csv_trial(ROOT, record, baseline, target,
                                                        args.campaign_seconds, selected)
                        if recovered is not None:
                            rows[job_key(trial, baseline, target, args.trials)] = recovered
    save_csv(output, targets, rows, args.trials)
    jobs = scheduled_jobs(targets, scope, args.trials)
    remaining = sum(rows[job_key(trial, b, t, args.trials)]["status"] == "pending"
                    for trial, b, t in jobs)
    print(f"phase={args.phase}; planned {len(jobs)} applicable jobs ({remaining} pending); "
          f"{args.trials * len(targets) * len(BASELINES) - len(jobs)} N/A; "
          f"trials={args.trials}; requested_workers={args.parallel_worker}; "
          f"campaign={args.campaign_seconds}s", flush=True)
    print(output, flush=True)
    if args.plan:
        return 0
    if not remaining:
        failures = [(trial, b, t) for trial, b, t in jobs
                    if rows[job_key(trial, b, t, args.trials)]["status"] not in
                    (("generated",) if args.phase == "generate" else ("evaluated",))]
        if args.phase == "fuzz" and args.trials > 1:
            summary = output.with_name(output.stem + ".summary.csv")
            save_trial_summary(summary, targets, rows, args.trials)
            print(f"Trial summary: {summary}", flush=True)
        print(f"phase={args.phase}: {len(jobs) - len(failures)}/{len(jobs)} ready; manifest={manifest}", flush=True)
        audited = write_coverage_products(output) if args.phase == "fuzz" else True
        return 1 if failures or not audited else 0
    try:
        docker_ready = subprocess.run(
            ["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=15, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        docker_ready = False
    if not docker_ready:
        print("Docker is unavailable or unresponsive; no jobs started", file=sys.stderr)
        return 2
    log_dir = ROOT / "workspace/eval_all" / args.run_id
    log_dir.mkdir(parents=True, exist_ok=False)
    os.chdir(log_dir)
    cpus = sorted(os.sched_getaffinity(0))
    if not cpus:
        print("No usable CPUs in process affinity mask", file=sys.stderr)
        return 2
    memory_budget = args.memory_budget_gib or max(args.memory_per_job_gib, int(host_memory_gib() * 0.70))
    worker_ceiling = min(args.parallel_worker, len(cpus))
    effective_workers = (worker_ceiling if args.phase == "fuzz" else
                         min(worker_ceiling, max(1, memory_budget // args.memory_per_job_gib)))
    print(f"worker_ceiling={effective_workers}; container_memory_cap={args.memory_per_job_gib}GiB; "
          f"memory_budget={memory_budget}GiB; "
          f"admission={'measured' if args.phase == 'fuzz' else 'fixed'}", flush=True)
    if args.phase == "fuzz":
        pending = [(trial, b, t) for trial, b, t in jobs
                   if rows[job_key(trial, b, t, args.trials)]["status"] == "pending"]
        active = {}
        processes = JobProcesses()
        prior_sigint = signal.getsignal(signal.SIGINT)
        prior_sigterm = signal.getsignal(signal.SIGTERM)
        def interrupt(_signum: int, _frame: Any) -> None:
            processes.interrupted.set()
        signal.signal(signal.SIGINT, interrupt)
        signal.signal(signal.SIGTERM, interrupt)
        try:
            with ThreadPoolExecutor(max_workers=effective_workers) as executor:
                stopped = False
                stop_started = 0.0
                forced = False
                next_memory_sample = 0.0
                admission_capacity = 0
                last_reported_capacity = None
                while pending or active:
                    admission_open = False
                    if processes.interrupted.is_set() and not stopped:
                        stopped = True
                        stop_started = time.monotonic()
                        print("Interrupt received; stopping evaluation jobs and containers", flush=True)
                        processes.stop()
                        stop_eval_containers(args.run_id)
                        pending.clear()
                    if stopped and active and not forced and time.monotonic() - stop_started >= 3:
                        forced = True
                        processes.stop(signal.SIGKILL)
                        stop_eval_containers(args.run_id)
                    if not stopped and pending and time.monotonic() >= next_memory_sample:
                        try:
                            eval_usage = eval_container_memory_gib(args.run_id)
                            available = host_available_memory_gib()
                            admission_capacity, estimate = adaptive_worker_capacity(
                                effective_workers, len(cpus), len(active), memory_budget,
                                args.memory_per_job_gib, eval_usage, available, host_memory_gib())
                            if admission_capacity != last_reported_capacity:
                                print(f"memory admission: capacity={admission_capacity}; "
                                      f"active={len(active)}; eval={eval_usage:.1f}GiB; "
                                      f"available={available:.1f}GiB; "
                                      f"estimated_job={estimate:.1f}GiB", flush=True)
                                last_reported_capacity = admission_capacity
                        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
                            admission_capacity = min(
                                effective_workers, max(1, memory_budget // args.memory_per_job_gib))
                            if admission_capacity != last_reported_capacity:
                                print(f"memory sampling failed; using fixed capacity "
                                      f"{admission_capacity}: {exc}", file=sys.stderr, flush=True)
                                last_reported_capacity = admission_capacity
                        next_memory_sample = time.monotonic() + MEMORY_SAMPLE_INTERVAL_SECONDS
                        admission_open = True
                    launched = 0
                    changed = False
                    while (admission_open and not stopped and pending and len(active) < admission_capacity
                           and launched < MEMORY_LAUNCH_BATCH):
                        trial, baseline, target = pending.pop(0)
                        used_cpus = {item[3] for item in active.values()}
                        cpu = next((value for value in cpus if value not in used_cpus), cpus[len(active) % len(cpus)])
                        rows[job_key(trial, baseline, target, args.trials)]["status"] = "running"
                        future = executor.submit(
                            run_replay_job, ROOT, baseline, target, sources[baseline, target],
                            args.run_id, args.campaign_seconds, log_dir, cpu,
                            args.memory_per_job_gib, trial, args.trials, processes,
                            sources.get(("g2fuzz", target), ""))
                        active[future] = (trial, baseline, target, cpu)
                        launched += 1
                        changed = True
                    if changed:
                        save_csv(output, targets, rows, args.trials)
                    if active:
                        done, _ = wait(active, timeout=1, return_when=FIRST_COMPLETED)
                    else:
                        done = set()
                        if pending and not stopped:
                            time.sleep(1)
                    for future in done:
                        trial, baseline, target, _ = active.pop(future)
                        key = job_key(trial, baseline, target, args.trials)
                        try:
                            rows[key] = future.result()
                        except Exception as exc:
                            rows[key] = {"status": "runner_failed", "reason": str(exc)}
                        print(f"trial {trial}/{args.trials} {baseline} {target}: {rows[key]['status']}", flush=True)
                    if done:
                        save_csv(output, targets, rows, args.trials)
                if stopped:
                    for trial, baseline, target, _ in active.values():
                        rows[job_key(trial, baseline, target, args.trials)] = {
                            "status": "interrupted", "reason": "evaluation stopped by signal"}
                    save_csv(output, targets, rows, args.trials)
        finally:
            signal.signal(signal.SIGINT, prior_sigint)
            signal.signal(signal.SIGTERM, prior_sigterm)
        if processes.interrupted.is_set():
            if args.trials > 1:
                save_trial_summary(output.with_name(output.stem + ".summary.csv"),
                                   targets, rows, args.trials)
            return 130
        failures = [(trial, b, t) for trial, b, t in jobs
                    if rows[job_key(trial, b, t, args.trials)]["status"] != "evaluated"]
        if args.trials > 1:
            summary = output.with_name(output.stem + ".summary.csv")
            save_trial_summary(summary, targets, rows, args.trials)
            print(f"Trial summary: {summary}", flush=True)
        print(f"Phase B: {len(jobs) - len(failures)}/{len(jobs)} evaluated for >= "
              f"{minimum_campaign_elapsed(args.campaign_seconds)}s; CSV: {output}", flush=True)
        audited = write_coverage_products(output)
        return 1 if failures or not audited else 0
    # Phase A prepares only pairs that lack a verified saved artifact. Its
    # short evaluator campaign verifies generation; Phase B owns the long run.
    phase_a_processes = JobProcesses()
    prior_sigint = signal.getsignal(signal.SIGINT)
    prior_sigterm = signal.getsignal(signal.SIGTERM)
    def phase_a_interrupt(_signum: int, _frame: Any) -> None:
        print("Interrupt received; stopping generation jobs and containers", flush=True)
        phase_a_processes.stop(signal.SIGKILL)
        stop_eval_containers(args.run_id)
        reap_embedding_service(ROOT)
        raise KeyboardInterrupt
    signal.signal(signal.SIGINT, phase_a_interrupt)
    signal.signal(signal.SIGTERM, phase_a_interrupt)
    for baseline in BASELINES:
        if not any(rows[b, t]["status"] == "pending" and b == baseline for _, b, t in jobs):
            continue
        image_log = log_dir / f"image_{baseline}.log"
        shell = ('source "$1/scripts/lib/common.sh"; load_hgb_config; '
                 'image="$(hgb_image_name "$2" "$2" "$1")"; '
                 'if [[ "$3" == 1 ]] || ! docker image inspect "$image" >/dev/null 2>&1; '
                 'then hgb_build_image "$2" "$2" "$1"; else printf "reusing %s\\n" "$image"; fi')
        with image_log.open("w", encoding="utf-8") as log:
            code = run_tracked(["bash", "-c", shell, "bash", str(ROOT), baseline,
                                "1" if args.rebuild_images else "0"], cwd=log_dir,
                               env=None, stdout=log, processes=phase_a_processes)
        if code:
            for _, b, t in jobs:
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
            code = run_tracked(["bash", str(ROOT / "scripts/hgb_prepare_target.sh"), "--target", target,
                                "--run-id", args.run_id, "--output", str(package)], cwd=log_dir,
                               env=env, stdout=log, processes=phase_a_processes)
        if code or not (package / "generator_input/target_manifest.json").is_file():
            for baseline in BASELINES:
                if rows[baseline, target]["status"] == "pending":
                    rows[baseline, target] = {"status": "package_failed", "reason": str(prep_log.relative_to(ROOT))}
            save_csv(output, targets, rows)
        else:
            packages[target] = package
    pending = [(b, t) for _, b, t in jobs if rows[b, t]["status"] == "pending"]
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
                                         cpu, args.memory_per_job_gib, phase_a_processes)
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
    failures = [(b, t) for _, b, t in jobs if rows[b, t]["status"] != "generated"]
    reap_embedding_service(ROOT)
    signal.signal(signal.SIGINT, prior_sigint)
    signal.signal(signal.SIGTERM, prior_sigterm)
    print(f"Phase A: {len(jobs) - len(failures)}/{len(jobs)} generated and verified; "
          f"manifest={manifest}; CSV={output}", flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
