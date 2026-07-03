#!/usr/bin/env python3
"""Run upstream OSS-Fuzz-Gen with HGB-local compatibility shims."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

OFG_LOCAL_INTROSPECTOR_SHIM = "enabled"


def env_bool(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _upstream_arg_value(args: list[str], *names: str) -> str:
    for index, value in enumerate(args):
        for name in names:
            if value == name and index + 1 < len(args):
                return args[index + 1]
            prefix = f"{name}="
            if value.startswith(prefix):
                return value[len(prefix):]
    return ""


def _load_benchmark_data(upstream_args: list[str]) -> dict[str, Any]:
    benchmark_yaml = _upstream_arg_value(upstream_args, "-y", "--benchmark-yaml")
    if not benchmark_yaml:
        return {}
    try:
        data = yaml.safe_load(Path(benchmark_yaml).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    return data if isinstance(data, dict) else {}


def _benchmark_function_maps(data: dict[str, Any]) -> tuple[dict[str, str], list[dict[str, Any]]]:
    signatures: dict[str, str] = {}
    functions_out: list[dict[str, Any]] = []
    for function in data.get("functions") or []:
        if not isinstance(function, dict):
            continue
        name = str(function.get("name") or "")
        signature = str(function.get("signature") or "")
        if not signature and name:
            signature = name
        if name and signature:
            signatures[name] = signature
        if signature:
            raw_name = name or signature.split("(", 1)[0].split()[-1]
            functions_out.append({
                "function_signature": signature,
                "raw-function-name": raw_name,
                "raw_function_name": raw_name,
                "return-type": function.get("return_type") or function.get("return-type") or "",
                "return_type": function.get("return_type") or function.get("return-type") or "",
                "function_arguments": [p.get("type", "") for p in function.get("params") or [] if isinstance(p, dict)],
                "arg-types": [p.get("type", "") for p in function.get("params") or [] if isinstance(p, dict)],
                "debug_summary": {"name": raw_name},
            })
    return signatures, functions_out


def _install_local_introspector_shim(upstream_args: list[str]) -> None:
    if os.environ.get("OFG_INTROSPECTOR_MODE", "local").strip().lower() == "remote":
        return

    from data_prep import introspector  # pylint: disable=import-outside-toplevel

    data = _load_benchmark_data(upstream_args)
    signatures, functions_out = _benchmark_function_maps(data)
    project = str(data.get("project") or "")

    def _project_ok(query_project: str) -> bool:
        return not project or not query_project or query_project == project

    def query_introspector_function_signature(query_project: str, function_name: str) -> str:
        if not _project_ok(query_project):
            return ""
        if function_name in signatures:
            return signatures[function_name]
        for name, signature in signatures.items():
            if function_name in {signature, signature.split("(", 1)[0], name.split("::")[-1]}:
                return signature
        return ""

    def query_introspector_all_signatures(query_project: str) -> list[str]:
        if not _project_ok(query_project):
            return []
        return [function["function_signature"] for function in functions_out]

    def query_introspector_all_functions(query_project: str) -> list[dict[str, Any]]:
        if not _project_ok(query_project):
            return []
        return list(functions_out)

    def query_introspector_function_source(*_args, **_kwargs) -> str:
        return ""

    def query_introspector_function_line(*_args, **_kwargs) -> list[int]:
        return [-1, -1]

    def query_introspector_function_props(*_args, **_kwargs) -> dict[str, Any]:
        return {}

    def query_introspector_function_debug_arg_types(*_args, **_kwargs) -> list[Any]:
        return []

    def query_introspector_language_stats() -> dict[str, Any]:
        return {}

    def _query_introspector(*_args, **_kwargs):
        return None

    for name, value in {
        "query_introspector_function_signature": query_introspector_function_signature,
        "query_introspector_all_signatures": query_introspector_all_signatures,
        "query_introspector_all_functions": query_introspector_all_functions,
        "query_introspector_function_source": query_introspector_function_source,
        "query_introspector_function_line": query_introspector_function_line,
        "query_introspector_function_props": query_introspector_function_props,
        "query_introspector_function_debug_arg_types": query_introspector_function_debug_arg_types,
        "query_introspector_language_stats": query_introspector_language_stats,
        "_query_introspector": _query_introspector,
    }.items():
        setattr(introspector, name, value)
    print("OFG_LOCAL_INTROSPECTOR_SHIM: enabled", file=sys.stderr)


def _patch_oss_fuzz_postprocess_logging() -> None:
    from experiment import oss_fuzz_checkout  # pylint: disable=import-outside-toplevel

    original = oss_fuzz_checkout.postprocess_oss_fuzz

    def wrapped_postprocess_oss_fuzz() -> None:
        try:
            original()
        except subprocess.CalledProcessError as err:
            print("ofg_oss_fuzz_dependency_setup_failed: OSS-Fuzz postprocess command failed", file=sys.stderr)
            print(f"command: {err.cmd}", file=sys.stderr)
            for label, value in (("stdout", err.stdout), ("stderr", err.stderr), ("output", err.output)):
                if not value:
                    continue
                if isinstance(value, bytes):
                    value = value.decode("utf-8", errors="replace")
                print(f"--- {label} ---", file=sys.stderr)
                print(str(value), file=sys.stderr)
            raise

    oss_fuzz_checkout.postprocess_oss_fuzz = wrapped_postprocess_oss_fuzz


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", default="/opt/hgb/artifacts/oss-fuzz-gen")
    parser.add_argument("upstream_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    upstream_args = list(args.upstream_args)
    if upstream_args and upstream_args[0] == "--":
        upstream_args = upstream_args[1:]

    os.environ.setdefault("LLM_NUM_EXP", os.environ.get("OFG_NUM_EXP", "1"))
    os.environ.setdefault("LLM_NUM_EVA", os.environ.get("OFG_NUM_EVA", "1"))

    artifact = Path(args.artifact).resolve()
    sys.path.insert(0, str(artifact))
    os.chdir(artifact)

    import run_all_experiments  # pylint: disable=import-error,import-outside-toplevel

    _patch_oss_fuzz_postprocess_logging()
    _install_local_introspector_shim(upstream_args)

    if env_bool("OFG_SKIP_COVERAGE_GAINS", "1"):

        def _skip_coverage_gains(*_args, **_kwargs):
            return None

        class _NoopProcess:
            def __init__(self, *_args, **_kwargs):
                pass

            def start(self) -> None:
                pass

            def kill(self) -> None:
                pass

        run_all_experiments.extend_report_with_coverage_gains = _skip_coverage_gains
        run_all_experiments.extend_report_with_coverage_gains_process = _skip_coverage_gains
        run_all_experiments._process_total_coverage_gain = lambda: {}
        run_all_experiments.Process = _NoopProcess

    sys.argv = ["run_all_experiments.py", *upstream_args]
    result = run_all_experiments.main()
    return int(result or 0)


if __name__ == "__main__":
    raise SystemExit(main())
