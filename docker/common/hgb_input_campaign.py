#!/usr/bin/env python3
"""Input-generator campaign and coverage helpers for HarnessGenBench.

ELFuzz is an ``input_generator``: it evolves input-producing fuzzer programs
against a fixed native FuzzBench target, then runs a final campaign with the
generated corpus and measures real coverage.  This module owns the HGB contract
around those steps so the ELFuzz pipeline does not label AFL ``paths_total`` as
edge coverage and does not mark campaign/coverage complete without real target
executions and a coverage report.

All Docker/subprocess invocations go through a ``runner`` callable so the
offline pytest suite can substitute fake runners without touching Docker.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

try:
    import hgb_coverage  # type: ignore
    from hgb_coverage import CoverageError, summarize_coverage_report, write_coverage_outputs
except ImportError:  # pragma: no cover - resolved via sys.path below
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import hgb_coverage  # type: ignore
        from hgb_coverage import CoverageError, summarize_coverage_report, write_coverage_outputs
    except ImportError:
        CoverageError = RuntimeError  # type: ignore[misc,assignment]
        summarize_coverage_report = None  # type: ignore[assignment]
        write_coverage_outputs = None  # type: ignore[assignment]


Runner = Callable[[Sequence[str], int], "CommandResult"]


@dataclass
class CommandResult:
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str


def _run(command: Sequence[str], timeout_seconds: int) -> CommandResult:
    completed = subprocess.run(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        check=False,
        timeout=timeout_seconds,
    )
    return CommandResult(list(command), completed.returncode, completed.stdout or "", completed.stderr or "")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# Plan elfuzz_reproduction_delta.md section 3: strict produced-input
# classification.  Prompts, manifests, lineage, config, metadata, stats, logs,
# fuzzer programs, preseed/corpus/queue metadata, and LLVM profraw/profdata are
# never counted as produced inputs.
PRODUCED_INPUT_EXCLUDED_SUFFIXES = {
    ".py", ".log", ".json", ".jsonl", ".yaml", ".yml", ".toml", ".txt", ".md",
    ".sh", ".cfg", ".ini", ".conf", ".profraw", ".profdata",
}
PRODUCED_INPUT_EXCLUDED_STEMS = {
    "manifest", "metadata", "config", "lineage", "fuzzer_stats", "stats",
    "preseed", "seed_corpus", "input_corpus", "corpus_manifest", "corpus",
    "seed_fuzzer", "evolved", "run", "queue",
}
PRODUCED_INPUT_EXCLUDED_PREFIXES = (
    "prompt_", "manifest", "lineage", "config", "metadata", "stats", "preseed",
    "corpus", "seed_fuzzer", "evolved",
)


def is_produced_input(path: Path) -> bool:
    """Return True only for actual input payloads (plan section 3)."""
    name = path.name.lower()
    stem = path.stem.lower()
    if path.suffix.lower() in PRODUCED_INPUT_EXCLUDED_SUFFIXES:
        return False
    if stem in PRODUCED_INPUT_EXCLUDED_STEMS or stem.startswith("config"):
        return False
    if any(name.startswith(prefix) for prefix in PRODUCED_INPUT_EXCLUDED_PREFIXES):
        return False
    if stem.startswith("preseed") or stem.endswith("_preseed"):
        return False
    return path.is_file()


def _excluded_reason(path: Path) -> str:
    name = path.name.lower()
    if name.startswith("prompt_"):
        return "prompt_artifact"
    if path.suffix.lower() == ".py" or name.startswith(("seed_fuzzer", "evolved")):
        return "fuzzer_program"
    if path.suffix.lower() in {".profraw", ".profdata"}:
        return "coverage_profile"
    if name.startswith(("manifest", "lineage", "config", "metadata", "stats")):
        return "metadata_artifact"
    if name.startswith(("preseed", "corpus")) or stem_starts_preseed(path):
        return "seed_corpus_artifact"
    return "non_input_file"


def stem_starts_preseed(path: Path) -> bool:
    return path.stem.lower().startswith("preseed") or path.stem.lower().endswith("_preseed")


def write_produced_input_provenance(produced_dir: Path, dest: Path) -> dict[str, Any]:
    """Write the plan-section-3.4 provenance manifest for produced inputs.

    Counts only real input payloads, records excluded files with a reason, and
    records accepted files with sha256/size.  ``prompt_001``-style prompts are
    excluded so they can never inflate the produced-input count.
    """
    produced_dir = Path(produced_dir)
    accepted: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    if produced_dir.is_dir():
        for path in sorted(produced_dir.rglob("*")):
            if not path.is_file():
                continue
            if is_produced_input(path):
                accepted.append({
                    "path": str(path.relative_to(produced_dir)),
                    "sha256": sha256_file(path),
                    "size": path.stat().st_size,
                })
            else:
                excluded.append({"path": str(path.relative_to(produced_dir)), "reason": _excluded_reason(path)})
    manifest = {
        "produced_input_count": len(accepted),
        "excluded_files": excluded,
        "accepted_files": accepted,
    }
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def build_final_corpus(
    *,
    seeds_dir: Path | None,
    produced_dir: Path | None,
    evolved_dir: Path | None,
    dest: Path,
) -> dict[str, Any]:
    """Merge common FuzzBench seeds, valid ELFuzz inputs, and evolved inputs.

    Provenance labels are preserved in ``dest/../corpus_provenance.jsonl`` so
    format specs, Python sources, logs, and adapter files are never counted as
    generated inputs.  Only real input files are admitted to the corpus.
    """

    dest.mkdir(parents=True, exist_ok=True)
    provenance_path = dest.parent / "corpus_provenance.jsonl"
    records: list[dict[str, Any]] = []

    def admit(path: Path, source: str) -> None:
        if not path.is_file():
            return
        name = path.name
        candidate = dest / name
        index = 1
        while candidate.exists():
            candidate = dest / f"{path.stem}_{index}{path.suffix}"
            index += 1
        shutil.copy2(path, candidate)
        records.append(
            {
                "sha256": sha256_file(candidate),
                "size": candidate.stat().st_size,
                "path": str(candidate),
                "source": source,
                "origin": str(path),
            }
        )

    if seeds_dir and Path(seeds_dir).is_dir():
        for path in sorted(Path(seeds_dir).rglob("*")):
            if path.is_file():
                admit(path, "fuzzbench_seed")
    if produced_dir and Path(produced_dir).is_dir():
        for path in sorted(Path(produced_dir).rglob("*")):
            if path.is_file():
                admit(path, "elfuzz_generated")
    if evolved_dir and Path(evolved_dir).is_dir():
        for path in sorted(Path(evolved_dir).rglob("*")):
            if path.is_file():
                admit(path, "elfuzz_evolved")
    provenance_path.parent.mkdir(parents=True, exist_ok=True)
    with provenance_path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, sort_keys=True) + "\n")
    return {
        "corpus_dir": str(dest),
        "corpus_count": len(records),
        "provenance": str(provenance_path),
        "sources": {
            "fuzzbench_seed": sum(1 for r in records if r["source"] == "fuzzbench_seed"),
            "elfuzz_generated": sum(1 for r in records if r["source"] == "elfuzz_generated"),
            "elfuzz_evolved": sum(1 for r in records if r["source"] == "elfuzz_evolved"),
        },
    }


def verify_campaign_execs(stats: dict[str, Any]) -> dict[str, Any]:
    """Reject a campaign that produced zero target executions.

    AFL ``paths_total`` is not a substitute for executions: a campaign that
    queued paths but executed nothing is not a real campaign.
    """

    execs_done = int(stats.get("execs_done") or 0)
    paths_total = int(stats.get("paths_total") or stats.get("queued_paths") or 0)
    return {
        "execs_done": execs_done,
        "paths_total": paths_total,
        "has_executions": execs_done > 0,
        "paths_only": paths_total > 0 and execs_done <= 0,
    }


def coverage_from_campaign(
    *,
    stats: dict[str, Any],
    report_path: Path | None = None,
    queue_count: int = 0,
) -> dict[str, Any]:
    """Build a coverage summary that never labels AFL ``paths_total`` as edges.

    A real LLVM/lcov coverage report (when present) supplies
    line/function/region coverage.  Edge coverage is reported as
    ``{"status": "unavailable"}`` when no edge-level report exists, because AFL
    ``paths_total`` is a queue length, not edge coverage.  Coverage cannot
    complete from AFL path count alone: ``complete`` requires nonzero target
    executions and a coverage report path that exists.
    """

    execs_done = int(stats.get("execs_done") or 0)
    paths_total = int(stats.get("paths_total") or stats.get("queued_paths") or 0)
    summary: dict[str, Any] = {
        "coverage_mode": "elfuzz_campaign",
        "edge_coverage": {"status": "unavailable", "value": None},
        "line_coverage": None,
        "function_coverage": None,
        "regions": None,
        "execs_done": execs_done,
        "queue_count": int(queue_count),
        "paths_total": paths_total,
        "report_path": str(report_path) if report_path else None,
        "report_exists": bool(report_path and Path(report_path).is_file()),
        "has_executions": execs_done > 0,
        "complete": False,
    }
    if report_path and Path(report_path).is_file() and summarize_coverage_report is not None:
        try:
            parsed = summarize_coverage_report(report_path)
            summary["line_coverage"] = parsed.get("line_coverage")
            summary["function_coverage"] = parsed.get("function_coverage")
            summary["regions"] = parsed.get("regions")
            summary["coverage_mode"] = parsed.get("source", "elfuzz_campaign")
        except CoverageError:
            summary["report_parse_error"] = True
    # Coverage cannot complete from AFL path count alone.
    summary["complete"] = bool(summary["has_executions"] and summary["report_exists"])
    return summary


def run_coverage_replay(
    *,
    target_binary: Path,
    corpus_dir: Path,
    work_dir: Path,
    runner: Runner = _run,
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Replay the final corpus under a coverage-instrumented target binary.

    Generates an LLVM source-based coverage report when the binary is
    instrumented; otherwise returns an empty result so the caller falls back to
    the campaign execution summary.  This never fabricates coverage.
    """

    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    cov_dir = work_dir / "cov"
    cov_dir.mkdir(parents=True, exist_ok=True)
    corpus_dir = Path(corpus_dir)
    if not Path(target_binary).is_file():
        return {"exit_code": 127, "report_path": None, "log": str(work_dir / "coverage.log")}
    cmd = [
        "sh",
        "-lc",
        f"mkdir -p /tmp/cov /tmp/corpus && cp -r {corpus_dir}/. /tmp/corpus/ && "
        f"LLVM_PROFILE_FILE=/tmp/cov/coverage.profraw {target_binary} -runs=0 /tmp/corpus && "
        f"llvm-profdata merge -o /tmp/cov/merged.profdata /tmp/cov/*.profraw && "
        f"llvm-cov export -format=text -summary-only {target_binary} "
        f"-instr-profile=/tmp/cov/merged.profdata > {cov_dir}/coverage.json 2>{cov_dir}/cov.err; "
        f"cat {cov_dir}/coverage.json",
    ]
    try:
        result = runner(cmd, timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        result = CommandResult(list(cmd), 124, "", f"coverage replay timed out: {exc}")
    (work_dir / "coverage.log").write_text(
        f"$ {' '.join(cmd)}\n[stdout]\n{result.stdout}\n[stderr]\n{result.stderr}\n[exit]\n{result.exit_code}\n",
        encoding="utf-8",
    )
    report = cov_dir / "coverage.json"
    return {
        "exit_code": result.exit_code,
        "report_path": str(report) if report.is_file() else None,
        "raw_text": result.stdout,
        "log": str(work_dir / "coverage.log"),
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="ELFuzz input-generator campaign/coverage helper")
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify-campaign")
    verify.add_argument("--execs-done", type=int, default=0)
    verify.add_argument("--paths-total", type=int, default=0)
    cov = sub.add_parser("coverage-from-campaign")
    cov.add_argument("--execs-done", type=int, default=0)
    cov.add_argument("--paths-total", type=int, default=0)
    cov.add_argument("--report", default="")
    cov.add_argument("--queue-count", type=int, default=0)
    args = parser.parse_args()
    if args.command == "verify-campaign":
        print(json.dumps(verify_campaign_execs({"execs_done": args.execs_done, "paths_total": args.paths_total}), indent=2, sort_keys=True))
        return 0
    if args.command == "coverage-from-campaign":
        print(json.dumps(coverage_from_campaign(stats={"execs_done": args.execs_done, "paths_total": args.paths_total}, report_path=Path(args.report) if args.report else None, queue_count=args.queue_count), indent=2, sort_keys=True))
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
