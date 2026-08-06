#!/usr/bin/env python3
"""Synthesize target-aware OSS-Fuzz-Gen benchmark YAML from Introspector data.

Builds a benchmark YAML (``functions``, ``language``, ``project``,
``target_name``, ``target_path``) from real Fuzz Introspector function records
and public build/source evidence — never from the exact target reference
harness. Records the full selection (selected + rejected + scores) in
``selection.json``.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ofg_introspector_adapter import select_functions

CPP_EXTS = {".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"}
C_EXTS = {".c", ".h"}


def detect_language(source_dir: str | Path) -> str:
    """Detect ``c`` or ``c++`` from the project source tree."""
    source = Path(source_dir)
    cpp_count = 0
    c_count = 0
    if source.is_dir():
        for p in source.rglob("*"):
            if not p.is_file():
                continue
            ext = p.suffix.lower()
            if ext in CPP_EXTS:
                cpp_count += 1
            elif ext in C_EXTS:
                c_count += 1
    return "c++" if cpp_count >= c_count else "c"


def synthesize_benchmark(
    *,
    records: list[dict[str, Any]],
    project: str,
    target_name: str,
    fuzz_target: str = "",
    source_dir: str | Path = "",
    max_functions: int = 3,
    target_path: str = "",
) -> dict[str, Any]:
    """Build the benchmark dict and selection metadata."""
    selection = select_functions(
        records,
        max_functions=max_functions,
        project=project,
        target_name=target_name,
        fuzz_target=fuzz_target,
    )
    selected = selection["selected"]
    if not selected:
        raise ValueError("introspector selection produced no usable functions")
    language = detect_language(source_dir) if source_dir else "c++"
    functions = []
    for record in selected:
        functions.append({
            "name": record["name"],
            "params": record.get("params") or [],
            "return_type": record.get("return_type") or "int",
            "signature": record.get("signature") or record["name"],
        })
    if not target_path:
        target_path = f"/src/{project}/{fuzz_target or target_name}.{'cc' if language == 'c++' else 'c'}"
    benchmark = {
        "functions": functions,
        "language": language,
        "project": project,
        "target_name": fuzz_target or target_name,
        "target_path": target_path,
        "use_project_examples": False,
    }
    return {
        "benchmark": benchmark,
        "selection": {
            "selection_source": "introspector",
            "selected": selected,
            "rejected": selection["rejected"],
            "all_scored": selection["all_scored"],
            "max_functions": max_functions,
            "project": project,
            "target_name": target_name,
            "fuzz_target": fuzz_target,
            "language": language,
        },
    }


def write_outputs(
    result: dict[str, Any],
    *,
    benchmark_path: str | Path,
    selection_path: str | Path,
) -> None:
    benchmark_path = Path(benchmark_path)
    selection_path = Path(selection_path)
    benchmark_path.parent.mkdir(parents=True, exist_ok=True)
    selection_path.parent.mkdir(parents=True, exist_ok=True)
    import yaml
    benchmark_path.write_text(
        yaml.safe_dump(result["benchmark"], sort_keys=False), encoding="utf-8",
    )
    selection_path.write_text(
        json.dumps(result["selection"], indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )


def build_examples_manifest(
    *,
    source_dir: str | Path,
    allowed_examples: list[dict[str, str]] | None = None,
    denied_examples: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Record every example's source and allow/deny reason."""
    return {
        "allowed": allowed_examples or [],
        "denied": denied_examples or [],
        "policy": (
            "public cross-project examples bundled by upstream; "
            "normal examples/tests from pinned project source after excluding "
            "every fuzz harness; same-project non-target fuzz harnesses only "
            "when an explicit protocol allows them"
        ),
    }


def collect_allowed_examples(
    source_dir: str | Path,
    *,
    allow_same_project_fuzz: bool = False,
    max_bytes: int = 20000,
) -> dict[str, Any]:
    """Collect normal project examples/tests, excluding every fuzz harness."""
    source = Path(source_dir)
    allowed: list[dict[str, str]] = []
    denied: list[dict[str, str]] = []
    if not source.is_dir():
        return {"allowed": allowed, "denied": denied}
    exts = C_EXTS | CPP_EXTS | {".py"}
    for path in sorted(source.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in exts:
            continue
        rel = str(path.relative_to(source))
        rel_l = rel.lower()
        is_fuzz = ("fuzz" in rel_l and "LLVMFuzzerTestOneInput" in
                   path.read_text(encoding="utf-8", errors="replace")[:4096])
        if is_fuzz and not allow_same_project_fuzz:
            denied.append({"path": rel, "reason": "fuzz_harness_excluded"})
            continue
        if is_fuzz:
            allowed.append({"path": rel, "source": "same_project_fuzz", "reason": "explicit_protocol_allowed"})
            continue
        if any(part in rel_l for part in ("/test", "/tests", "/testing")):
            denied.append({"path": rel, "reason": "test_only_excluded"})
            continue
        allowed.append({"path": rel, "source": "project_source", "reason": "normal_example_or_test"})
    return {"allowed": allowed, "denied": denied}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--target-name", required=True)
    parser.add_argument("--fuzz-target", default="")
    parser.add_argument("--max-functions", type=int, default=3)
    parser.add_argument("--benchmark-out", required=True)
    parser.add_argument("--selection-out", required=True)
    args = parser.parse_args()
    from ofg_introspector_adapter import parse_all_functions, validate_reports
    ok, message = validate_reports(args.report_dir)
    if not ok:
        print(f"introspector_validation_failed: {message}", file=__import__("sys").stderr)
        return 1
    records = parse_all_functions(args.report_dir, str(args.source_dir))
    result = synthesize_benchmark(
        records=records,
        project=args.project,
        target_name=args.target_name,
        fuzz_target=args.fuzz_target,
        source_dir=args.source_dir,
        max_functions=args.max_functions,
    )
    write_outputs(result, benchmark_path=args.benchmark_out, selection_path=args.selection_out)
    print(json.dumps({"validation": message, "selected": len(result["selection"]["selected"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
