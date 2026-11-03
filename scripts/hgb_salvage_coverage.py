#!/usr/bin/env python3
"""Replay intact zero-exec harness corpora for unverified source coverage.

This is an independent salvage path. It never changes the evaluation CSV or
the original run results, never fuzzes, and never claims a verified campaign.
The default is a read-only dry run. Docker is used only with --run.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import tarfile
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker/common"))
import hgb_coverage
import hgb_fuzzbench_builder as builder

BASELINES = ("ckgfuzzer", "promefuzz", "oss-fuzz-gen")
ZERO_EXEC_REASON = "campaign recorded execs_done <= 0"
SALVAGE_STATUS = "coverage_salvaged_unverified"


@dataclass(frozen=True)
class ArchiveScan:
    corpus_hashes: dict[str, str]
    error: str = ""

    @property
    def count(self) -> int:
        return len(self.corpus_hashes)


@dataclass(frozen=True)
class Job:
    trial: str
    baseline: str
    target: str
    run: Path
    corpus: Path
    archive: Path
    archive_sha256: str
    corpus_count: int
    candidate_sha256: str
    context: Path
    package: Path
    project: str
    fuzz_target: str

    @property
    def label(self) -> str:
        return f"trial {self.trial} {self.baseline} {self.target}"


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_relative(raw: str) -> PurePosixPath:
    path = PurePosixPath(raw)
    if (not raw or raw.startswith("/") or "\\" in raw or "//" in raw
            or any(part in {"", ".", ".."} for part in raw.split("/"))):
        raise ValueError(f"unsafe archive or overlay path: {raw!r}")
    return path


def scan_archive(path: Path) -> ArchiveScan:
    """Hash every complete corpus member; retain only the safe prefix on error."""
    hashes: dict[str, str] = {}
    try:
        with tarfile.open(path, mode="r|", bufsize=1024 * 1024) as archive:
            for member in archive:
                name = safe_relative(member.name)
                if not (member.isfile() or member.isdir()):
                    raise ValueError(f"archive contains special member: {member.name}")
                if not member.isfile():
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError(f"archive member cannot be read: {member.name}")
                digest = hashlib.sha256()
                size = 0
                with stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                        size += len(chunk)
                if size != member.size:
                    raise tarfile.ReadError(f"short archive member: {member.name}")
                if len(name.parts) == 2 and name.parts[0] == "corpus":
                    key = name.parts[1]
                    if key in hashes:
                        raise ValueError(f"duplicate corpus member: {key}")
                    hashes[key] = digest.hexdigest()
    except (tarfile.TarError, EOFError, OSError) as exc:
        return ArchiveScan(hashes, f"{type(exc).__name__}: {exc}")
    return ArchiveScan(hashes)


def canonical_sources(csv_path: Path, manifest_path: Path) -> dict[tuple[str, str], Path]:
    match = re.match(r"^(\d{4}-\d{2}-\d{2})(?:\.|$)", csv_path.name)
    if not match or manifest_path.name != f"{match.group(1)}.phase_a.json":
        raise ValueError("Phase A manifest must match the CSV date")
    sources: dict[tuple[str, str], Path] = {}
    for record in read_json(manifest_path).get("records", []):
        if record.get("status") != "ready":
            continue
        baseline = str(record.get("baseline") or "")
        target = str(record.get("target") or "")
        if baseline not in (*BASELINES, "g2fuzz"):
            continue
        source = Path(str(record.get("source_run") or "")).resolve(strict=True)
        if not source.is_relative_to(ROOT / "workspace" / baseline / target):
            raise ValueError(f"Phase A source is outside its pair workspace: {source}")
        key = (baseline, target)
        if key in sources:
            raise ValueError(f"duplicate Phase A source: {key}")
        sources[key] = source
    return sources


def canonical_package(source: Path) -> Path:
    meta = read_json(source / "metadata.json")
    underlying = Path(str(meta.get("source_run") or source)).resolve(strict=True)
    if not underlying.is_relative_to(ROOT / "workspace" / "g2fuzz"):
        raise ValueError("canonical G2 source points outside G2 workspace")
    fields = {}
    for line in (underlying / "host_command.txt").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key] = value
    package = Path(fields["target_package"]).resolve(strict=True)
    if not any(package.is_relative_to(ROOT / "workspace" / parent)
               for parent in ("target-packages", "targets")):
        raise ValueError("canonical target package is outside package workspace")
    return package


def validate_job(record: dict[str, str], baseline: str,
                 sources: dict[tuple[str, str], Path]) -> tuple[Job | None, str]:
    target = record["target"]
    trial = record.get("trial") or "1"
    if record.get(f"{baseline}_status") != "quality_failure" or record.get(f"{baseline}_reason") != ZERO_EXEC_REASON:
        return None, "outside zero-exec quality-failure selection"
    raw_run = record.get(f"{baseline}_run") or ""
    run = (ROOT / raw_run).resolve(strict=True)
    if not run.is_relative_to(ROOT / "workspace" / baseline / target):
        raise ValueError("run is outside its baseline/target workspace")
    work = run / "evaluation/cand_001"
    campaign = read_json(work / "campaign/campaign.json")
    original = read_json(run / "evaluation/result.json")
    if original.get("status") != "quality_failure" or original.get("reason") != ZERO_EXEC_REASON:
        raise ValueError("original result is no longer the zero-exec quality failure")
    if int(campaign.get("execs_done") or 0) != 0:
        raise ValueError("saved campaign has recorded executions; use strict recovery")
    archive = work / "campaign/corpus.tar"
    if not archive.is_file():
        raise ValueError("saved corpus.tar is missing")
    scan = scan_archive(archive)
    archive_error = str(campaign.get("corpus_archive_error") or "")
    if scan.error or archive_error:
        return None, (f"partial archive: {scan.count} complete corpus prefix files; "
                      f"archive error={scan.error or archive_error}; no partial coverage")
    if scan.count == 0:
        raise ValueError("archive has no corpus files")
    if scan.count != int(campaign.get("final_corpus_file_count") or 0):
        raise ValueError("archive count differs from saved campaign count")
    corpus = work / "corpus"
    extracted: dict[str, str] = {}
    for path in corpus.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"extracted corpus contains symlink: {path}")
        if path.is_file():
            rel = path.relative_to(corpus)
            if len(rel.parts) != 1:
                raise ValueError("nested extracted corpus is unsupported")
            extracted[rel.name] = sha256_file(path)
    if extracted != scan.corpus_hashes:
        raise ValueError("extracted corpus differs from complete archive")
    phase_b = read_json(run / "phase_b_source.json")
    if phase_b.get("baseline") != baseline or phase_b.get("target") != target:
        raise ValueError("Phase B provenance baseline/target mismatch")
    selected = Path(str(phase_b.get("selected_phase_a_run") or "")).resolve(strict=True)
    if selected != sources.get((baseline, target)):
        raise ValueError("selected Phase A source differs from same-date manifest")
    g2_source = sources.get(("g2fuzz", target))
    if g2_source is None:
        raise ValueError("same-date manifest has no canonical G2 source")
    package = Path(str(phase_b.get("canonical_target_package") or "")).resolve(strict=True)
    if package != canonical_package(g2_source):
        raise ValueError("Phase B package differs from canonical G2 package")
    manifest = read_json(package / "generator_input/target_manifest.json")
    if manifest.get("target") != target:
        raise ValueError("target package manifest target mismatch")
    project = str(manifest.get("project") or "")
    fuzz_target = str(manifest.get("fuzz_target") or "")
    if not project or not fuzz_target:
        raise ValueError("target package has no project or fuzz target")
    provenance = read_json(run / "replay_provenance.json")
    if Path(str(provenance.get("selected_phase_a_run") or "")).resolve(strict=True) != selected:
        raise ValueError("candidate provenance selected source mismatch")
    staged_files = list((run / "generated_harnesses").iterdir())
    if len(staged_files) != 1 or not staged_files[0].is_file():
        raise ValueError("expected one staged candidate source")
    candidate_sha = sha256_file(staged_files[0])
    if provenance.get("selected_harness_sha256") != candidate_sha:
        raise ValueError("staged candidate hash mismatch")
    context = run / "evaluation/sealed_context/sealed_context"
    native = read_json(context / "native_harness_path.json")
    destination = str(native.get("container_destination") or "")
    if not destination.startswith("/src/"):
        raise ValueError("invalid native candidate destination")
    relative = safe_relative(destination.removeprefix("/src/"))
    overlay = context / "hgb_candidate_overlay" / str(relative)
    if not overlay.is_file() or sha256_file(overlay) != candidate_sha:
        raise ValueError("sealed candidate overlay differs from staged source")
    dockerfile = (context / "Dockerfile").read_text(encoding="utf-8")
    expected_copy = f"COPY hgb_candidate_overlay/{relative} {destination}"
    if expected_copy not in dockerfile or "# HGB sealed evaluator candidate build." not in dockerfile:
        raise ValueError("sealed Dockerfile has no verified candidate COPY")
    return Job(trial, baseline, target, run, corpus, archive, sha256_file(archive),
               scan.count, candidate_sha, context, package, project, fuzz_target), ""


def fsync_tree(path: Path) -> None:
    for item in sorted(path.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if item.is_file():
            with item.open("rb") as handle:
                os.fsync(handle.fileno())
        elif item.is_dir():
            fsync_dir(item)
    fsync_dir(path)


def fsync_dir(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_json(path: Path, data: dict) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        fsync_dir(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def salvage_one(job: Job) -> Path:
    """Build a coverage image and replay saved inputs, without fuzzing."""
    salvage = job.run / "coverage_salvage"
    salvage.mkdir(exist_ok=True)
    result_path = salvage / "result.json"
    if result_path.exists():
        raise ValueError("salvage result already exists; refusing to overwrite it")
    attempt_id = uuid.uuid4().hex
    stage = salvage / f".attempt-{attempt_id}"
    stage.mkdir()
    tag = builder.deterministic_image_tag(
        job.run.name, job.fuzz_target, f"salvage-{attempt_id[:8]}", generator=job.baseline)
    docker_defaults = {
        "HGB_DOCKER_CPUS": "1",
        "HGB_DOCKER_CPUSET": str(min(os.sched_getaffinity(0))),
        "HGB_DOCKER_MEMORY": "8g",
    }
    previous_env = {key: os.environ.get(key) for key in (*docker_defaults, "HGB_PHASE_B_REPLAY")}
    for key, value in docker_defaults.items():
        os.environ.setdefault(key, value)
    os.environ["HGB_PHASE_B_REPLAY"] = "1"
    try:
        build = builder.build_coverage_image(
            context_dir=job.context, dockerfile=job.context / "Dockerfile",
            image_tag=tag, fuzz_target=job.fuzz_target, work_dir=stage / "build",
            timeout_seconds=7200, sanitizer="coverage")
        if build.build_exit_code != 0 or not build.binary_verified or not build.image_digest:
            raise ValueError(f"coverage image build failed (exit={build.build_exit_code}, "
                             f"binary_verified={build.binary_verified})")
        replay = builder.run_coverage(
            image_tag=tag, binary_path=build.binary_path, corpus_dir=job.corpus,
            work_dir=stage, timeout_seconds=21600, require_coverage_report=True,
            coverage_format="lcov")
    finally:
        for key, value in previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    report = stage / "coverage/coverage.lcov"
    if (replay.get("exit_code") != 0 or not replay.get("copy_in_ok")
            or not replay.get("copy_out_ok") or not report.is_file()
            or report.stat().st_size == 0
            or Path(str(replay.get("coverage_report_path") or "")) != report):
        raise ValueError("coverage replay failed or did not copy a nonempty LCOV")
    log = stage / "coverage/coverage.log"
    marker = re.search(r"HGB_INPUTS_REPLAYED=(\d+)", log.read_text(encoding="utf-8"))
    if not marker or int(marker.group(1)) != job.corpus_count:
        raise ValueError("coverage log does not prove every saved input was replayed")
    # Raw salvage remains useful even when the candidate reached no SUT lines.
    # Record the zero honestly; this path does not grant evaluated status.
    summary = hgb_coverage.summarize_coverage_report(
        report, project=job.project, require_project_coverage=False)
    report_sha = sha256_file(report)
    fsync_tree(stage)
    final = salvage / f"attempt-{attempt_id}"
    os.replace(stage, final)
    fsync_dir(salvage)
    final_report = final / "coverage/coverage.lcov"
    atomic_json(result_path, {
        "status": SALVAGE_STATUS,
        "reason": "real corpus replay coverage; original campaign has zero recorded target executions",
        "campaign_duration_verified": False,
        "campaign_execs_verified": False,
        "baseline": job.baseline,
        "target": job.target,
        "trial": job.trial,
        "original_run": str(job.run),
        "original_status": "quality_failure",
        "corpus_archive": str(job.archive),
        "corpus_archive_sha256": job.archive_sha256,
        "corpus_file_count": job.corpus_count,
        "inputs_replayed": int(marker.group(1)),
        "candidate_sha256": job.candidate_sha256,
        "coverage_image_tag": tag,
        "coverage_image_digest": build.image_digest,
        "coverage_report_path": str(final_report),
        "coverage_report_sha256": report_sha,
        "coverage": summary,
    })
    return result_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", type=Path,
                        default=ROOT / "workspace/eval_all/2026-11-02.trials5.csv")
    parser.add_argument("--manifest", type=Path,
                        help="same-date Phase A manifest; defaults to <CSV date>.phase_a.json")
    parser.add_argument("--run", action="store_true",
                        help="explicitly build coverage images and replay intact saved corpora")
    parser.add_argument("--max-jobs", type=int, default=0,
                        help="limit executed jobs; dry-run still reports all candidates")
    args = parser.parse_args(argv)
    if args.max_jobs < 0:
        parser.error("--max-jobs must be nonnegative")
    csv_path = args.csv.resolve(strict=True)
    if not csv_path.is_relative_to(ROOT / "workspace"):
        parser.error("CSV must be under workspace")
    match = re.match(r"^(\d{4}-\d{2}-\d{2})(?:\.|$)", csv_path.name)
    if not match:
        parser.error("CSV name must start with YYYY-MM-DD")
    manifest = (args.manifest or csv_path.with_name(f"{match.group(1)}.phase_a.json")).resolve(strict=True)
    try:
        sources = canonical_sources(csv_path, manifest)
    except (KeyError, OSError, TypeError, ValueError) as exc:
        parser.error(f"cannot validate Phase A sources: {exc}")
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    jobs: list[Job] = []
    partial = 0
    skipped = 0
    for row in rows:
        for baseline in BASELINES:
            if row.get(f"{baseline}_reason") != ZERO_EXEC_REASON:
                continue
            label = f"trial {row.get('trial') or '1'} {baseline} {row.get('target') or ''}"
            try:
                job, reason = validate_job(row, baseline, sources)
                if job is None:
                    if reason.startswith("partial archive"):
                        partial += 1
                    else:
                        skipped += 1
                    print(f"skip {label}: {reason}", flush=True)
                    continue
                if (job.run / "coverage_salvage/result.json").exists():
                    skipped += 1
                    print(f"skip {label}: salvage result already exists", flush=True)
                    continue
                jobs.append(job)
                print(f"eligible {job.label}: {job.corpus_count} intact corpus files", flush=True)
            except (KeyError, OSError, TypeError, ValueError) as exc:
                skipped += 1
                print(f"skip {label}: {exc}", flush=True)
    jobs.sort(key=lambda job: (job.corpus_count, job.target, job.baseline, job.trial))
    print(f"selection: {len(jobs)} eligible, {partial} partial archives, {skipped} other skips", flush=True)
    if not args.run:
        print("dry-run: no Docker and no files written; pass --run to replay coverage", flush=True)
        return 0
    selected = jobs[:args.max_jobs] if args.max_jobs else jobs
    failed = 0
    for job in selected:
        try:
            result = salvage_one(job)
            print(f"saved {job.label}: {result}", flush=True)
        except (OSError, ValueError, hgb_coverage.CoverageError) as exc:
            failed += 1
            print(f"failed {job.label}: {exc}", flush=True)
    print(f"run: {len(selected) - failed}/{len(selected)} coverage salvages saved", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
