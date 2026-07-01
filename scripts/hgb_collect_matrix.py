#!/usr/bin/env python3
"""Collect HarnessGenBench generator-target matrix metadata."""

from __future__ import annotations

import argparse
import collections
import csv
import json
from pathlib import Path
from typing import Any


SOFT_STATUSES = {
    "not_harness_generator",
    "needs_ofg_benchmark_yaml",
    "no_api_candidates",
    "missing_codeql",
    "upstream_cli_not_found",
    "needs_compile_commands",
    "source_input_missing",
    "soft_skip",
    "soft_skip_target_binaries_missing",
}
PARTIAL_STATUSES = {"partial_completed"}
NOT_APPLICABLE_STATUSES = {"not_applicable", "target_not_supported_by_elfuzz"}
COMPLETED_STATUSES = {"completed", "dry_run_ok"}
TRANSIENT_DIR_NAMES = {
    "g2fuzz_output",
    "ofg-work",
    "oss-fuzz",
    "pip-cache",
    "promefuzz_build",
    "promefuzz_out",
}

REMEDIATIONS = (
    ("missing_codeql", "Mount or install CodeQL: set HGB_CODEQL_DIR=/path/to/codeql or build CKGFuzzer with HGB_INSTALL_CODEQL=1; use CKGFUZZER_SKIP_CODEQL=1 only as a fallback."),
    ("needs_compile_commands", "Improve target package build replay or enable Bear/CMake compile_commands generation for PromeFuzz."),
    ("needs_ofg_benchmark_yaml", "Generate or provide an OSS-Fuzz-Gen function-level benchmark YAML for this target."),
    ("no_api_candidates", "Improve source packaging/API extraction for this target before running function-level harness generators."),
    ("source_input_missing", "Fix Dockerfile source parsing or add metadata/fuzzbench_source_overrides.json for this target."),
    ("not_applicable", "Treat this pair as unsupported by the generator unless a target adapter is added."),
    ("target_not_supported_by_elfuzz", "Treat this pair as unsupported by ELFuzz unless a target adapter or supported-target mapping is added."),
    ("program_gen timed out", "Increase HGB_GENERATION_TIMEOUT_SECONDS or accept partial_completed G2FUZZ inputs."),
    ("program_gen exited 124", "Increase HGB_GENERATION_TIMEOUT_SECONDS or classify generated seeds as partial_completed."),
    ("run_all_experiments exited", "Inspect OSS-Fuzz-Gen run.log; common fixes are writable --oss-fuzz-dir and generated benchmark YAML."),
    ("PromeFuzz stage exited", "Inspect the failing PromeFuzz stage log; ensure runtime artifact is writable and compile_commands.json is valid."),
)


def remediation_for(status: str, reason: str) -> str:
    haystack = f"{status} {reason}"
    for needle, remediation in REMEDIATIONS:
        if needle in haystack:
            return remediation
    return "Inspect the pair workspace logs and metadata for the generator-specific failure."


def read_rows(matrix_dir: Path) -> list[dict[str, str]]:
    matrix_file = matrix_dir / "matrix.tsv"
    if not matrix_file.exists():
        return []
    with matrix_file.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def load_metadata(path: str) -> dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}

def path_size(path: Path) -> int:
    if not path.exists():
        return 0
    total = 0
    try:
        total += path.lstat().st_size
    except OSError:
        return 0
    if path.is_file() or path.is_symlink():
        return total
    for child in path.rglob("*"):
        try:
            total += child.lstat().st_size
        except OSError:
            continue
    return total


def human_bytes(size: int) -> str:
    value = float(size)
    for unit in ("B", "K", "M", "G", "T"):
        if value < 1024 or unit == "T":
            if unit == "B":
                return f"{int(value)}B"
            return f"{value:.1f}{unit}"
        value /= 1024
    return f"{size}B"


def workspace_root_for(matrix_dir: Path) -> Path:
    if matrix_dir.parent.name == "matrix":
        return matrix_dir.parent.parent
    return matrix_dir.parent

def read_key_value_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def storage_report(matrix_dir: Path, records: list[dict[str, Any]]) -> dict[str, Any]:
    workspace_root = workspace_root_for(matrix_dir)
    target_dirs: set[Path] = set()
    generator_dirs: set[Path] = set()
    generated_dirs: set[Path] = set()
    log_dirs: set[Path] = set()
    transient_dirs: set[Path] = set()
    for record in records:
        row = record["row"]
        meta = record["metadata"]
        workspace_s = row.get("workspace") or ""
        if workspace_s:
            workspace = Path(workspace_s)
            if workspace.exists():
                generator_dirs.add(workspace)
                host_command = read_key_value_file(workspace / "host_command.txt")
                host_target_package = host_command.get("target_package")
                if host_target_package:
                    target_dir = Path(host_target_package)
                    if target_dir.exists():
                        target_dirs.add(target_dir)
                for name in ("generated_harnesses", "generated_inputs"):
                    candidate = workspace / name
                    if candidate.exists():
                        generated_dirs.add(candidate)
                candidate = workspace / "logs"
                if candidate.exists():
                    log_dirs.add(candidate)
                for name in TRANSIENT_DIR_NAMES:
                    candidate = workspace / name
                    if candidate.exists():
                        transient_dirs.add(candidate)
        target_manifest = meta.get("target_manifest")
        if target_manifest:
            target_dir = Path(str(target_manifest)).parent
            if target_dir.exists():
                target_dirs.add(target_dir)
    shared_target_root = workspace_root / "target-packages" / matrix_dir.name
    if not target_dirs and shared_target_root.exists():
        shared_children = [p for p in shared_target_root.iterdir() if p.is_dir()]
        if shared_children:
            target_dirs.update(shared_children)
        else:
            target_dirs.add(shared_target_root)
    return {
        "workspace_root": str(workspace_root),
        "matrix_dir_bytes": path_size(matrix_dir),
        "target_package_count": len(target_dirs),
        "target_package_bytes": sum(path_size(p) for p in target_dirs),
        "generator_workspace_count": len(generator_dirs),
        "generator_workspace_bytes": sum(path_size(p) for p in generator_dirs),
        "generated_artifact_bytes": sum(path_size(p) for p in generated_dirs),
        "log_bytes": sum(path_size(p) for p in log_dirs),
        "transient_bytes": sum(path_size(p) for p in transient_dirs),
    }


def collect(matrix_dir: Path) -> dict[str, Any]:
    rows = read_rows(matrix_dir)
    records: list[dict[str, Any]] = []
    for row in rows:
        metadata = load_metadata(row.get("metadata", ""))
        records.append({"row": row, "metadata": metadata})
    total = len(records)
    statuses = collections.Counter((r["metadata"].get("status") or r["row"].get("status") or "missing_metadata") for r in records)
    completed = sum(statuses[s] for s in COMPLETED_STATUSES)
    partial_completed = sum(statuses[s] for s in PARTIAL_STATUSES)
    not_applicable = sum(statuses[s] for s in NOT_APPLICABLE_STATUSES)
    soft_skipped = sum(count for status, count in statuses.items() if status in SOFT_STATUSES)
    missing_api_key = statuses.get("missing_api_key", 0)
    failed = total - completed - partial_completed - not_applicable - soft_skipped - missing_api_key
    harness_counts: collections.Counter[str] = collections.Counter()
    input_counts: collections.Counter[str] = collections.Counter()
    reasons: collections.Counter[str] = collections.Counter()
    remediation_counts: collections.Counter[str] = collections.Counter()
    for record in records:
        meta = record["metadata"]
        gen = meta.get("generator") or meta.get("fuzzer") or record["row"].get("generator") or "unknown"
        harness_counts[gen] += int(meta.get("generated_harness_count") or meta.get("generated_driver_count") or 0)
        input_counts[gen] += int(meta.get("generated_input_count") or meta.get("generated_seed_count") or 0)
        reason = meta.get("reason") or record["row"].get("status") or "unknown"
        if reason and reason != "none":
            reason_s = str(reason)
            status_s = str(meta.get("status") or record["row"].get("status") or "")
            reasons[reason_s] += 1
            if status_s not in COMPLETED_STATUSES:
                remediation_counts[remediation_for(status_s, reason_s)] += 1
    return {
        "matrix_dir": str(matrix_dir),
        "total_pairs": total,
        "completed_pairs": completed,
        "failed_pairs": failed,
        "partial_completed_pairs": partial_completed,
        "soft_skipped_pairs": soft_skipped,
        "not_applicable_pairs": not_applicable,
        "missing_api_key_count": missing_api_key,
        "statuses": dict(statuses),
        "generated_harness_counts_by_generator": dict(harness_counts),
        "generated_input_counts_by_generator": dict(input_counts),
        "top_failure_reasons": reasons.most_common(10),
        "top_remediations": remediation_counts.most_common(10),
        "storage": storage_report(matrix_dir, records),
    }


def write_outputs(matrix_dir: Path, summary: dict[str, Any]) -> None:
    (matrix_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (matrix_dir / "summary.tsv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(["metric", "value"])
        for key in (
            "total_pairs",
            "completed_pairs",
            "partial_completed_pairs",
            "failed_pairs",
            "soft_skipped_pairs",
            "not_applicable_pairs",
            "missing_api_key_count",
        ):
            writer.writerow([key, summary[key]])
        storage = summary.get("storage", {})
        for key in (
            "matrix_dir_bytes",
            "target_package_bytes",
            "generator_workspace_bytes",
            "generated_artifact_bytes",
            "log_bytes",
            "transient_bytes",
        ):
            writer.writerow([key, storage.get(key, 0)])
    lines = [
        "# HarnessGenBench Matrix Summary",
        "",
        f"- Total pairs: `{summary['total_pairs']}`",
        f"- Completed pairs: `{summary['completed_pairs']}`",
        f"- Partial completed pairs: `{summary['partial_completed_pairs']}`",
        f"- Failed pairs: `{summary['failed_pairs']}`",
        f"- Soft-skipped pairs: `{summary['soft_skipped_pairs']}`",
        f"- Not-applicable pairs: `{summary['not_applicable_pairs']}`",
        f"- Missing API key count: `{summary['missing_api_key_count']}`",
        "",
        "## Statuses",
        "",
    ]
    for status, count in sorted(summary["statuses"].items()):
        lines.append(f"- `{status}`: {count}")
    storage = summary.get("storage", {})
    if storage:
        lines.extend(["", "## Storage", ""])
        lines.append(f"- Matrix directory: `{human_bytes(int(storage.get('matrix_dir_bytes', 0)))}`")
        lines.append(f"- Target packages: `{storage.get('target_package_count', 0)}` packages, `{human_bytes(int(storage.get('target_package_bytes', 0)))}`")
        lines.append(f"- Generator workspaces: `{storage.get('generator_workspace_count', 0)}` workspaces, `{human_bytes(int(storage.get('generator_workspace_bytes', 0)))}`")
        lines.append(f"- Generated artifacts: `{human_bytes(int(storage.get('generated_artifact_bytes', 0)))}`")
        lines.append(f"- Logs: `{human_bytes(int(storage.get('log_bytes', 0)))}`")
        lines.append(f"- Known transient dirs: `{human_bytes(int(storage.get('transient_bytes', 0)))}`")
    if summary["generated_harness_counts_by_generator"] or summary["generated_input_counts_by_generator"]:
        lines.extend(["", "## Generated Artifacts", ""])
        for generator, count in sorted(summary["generated_harness_counts_by_generator"].items()):
            lines.append(f"- `{generator}` harnesses: {count}")
        for generator, count in sorted(summary["generated_input_counts_by_generator"].items()):
            lines.append(f"- `{generator}` inputs: {count}")
    if summary["top_failure_reasons"]:
        lines.extend(["", "## Top Reasons", ""])
        for reason, count in summary["top_failure_reasons"]:
            lines.append(f"- {count} x {reason}")
    if summary.get("top_remediations"):
        lines.extend(["", "## Actionable Remediations", ""])
        for remediation, count in summary["top_remediations"]:
            lines.append(f"- {count} x {remediation}")
    (matrix_dir / "HGB_MATRIX_SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("matrix_dir")
    args = parser.parse_args()
    matrix_dir = Path(args.matrix_dir).resolve()
    matrix_dir.mkdir(parents=True, exist_ok=True)
    write_outputs(matrix_dir, collect(matrix_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
