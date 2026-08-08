#!/usr/bin/env python3
"""Run upstream OSS-Fuzz-Gen with HGB-local compatibility/observability shims.

In method-faithful profiles (alpha, paper-faithful) this wrapper installs only
compatibility/observability patches: it must never read the exact target
reference harness, never replace coverage with empty results, never replace
processes with no-ops, and never install the local introspector shim. Those
compat-only behaviors are confined to ``compat-smoke`` (which is excluded from
the aggregate).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml


def env_bool(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def active_profile() -> str:
    return (os.environ.get("HGB_BASELINE_PROFILE") or
            os.environ.get("HGB_PROFILE") or "alpha").strip().lower()


def active_protocol() -> str:
    return (os.environ.get("HGB_BASELINE_PROTOCOL") or
            os.environ.get("HGB_PROTOCOL") or "blind-project").strip().lower()


def is_method_faithful() -> bool:
    return active_profile() in {"alpha", "paper-faithful", "reproduction-gamma"}


def is_compat_smoke() -> bool:
    return active_profile() == "compat-smoke"


def is_blind() -> bool:
    return active_protocol() == "blind-project"


# ---------------------------------------------------------------------------
# Patch registry: record every monkey patch with a stable hash and reason so
# the audit can prove only compatibility/observability patches are active.
# ---------------------------------------------------------------------------

PATCH_REGISTRY: list[dict[str, str]] = []


def _record_patch(name: str, reason: str, enabled: bool) -> None:
    digest = hashlib.sha256(f"{name}:{reason}:{enabled}".encode()).hexdigest()[:16]
    PATCH_REGISTRY.append({
        "patch": name,
        "reason": reason,
        "enabled": enabled,
        "hash": digest,
    })


def patch_audit() -> list[dict[str, str]]:
    return list(PATCH_REGISTRY)


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


# ---------------------------------------------------------------------------
# Local introspector shim: compat-smoke ONLY. Forbidden in alpha/paper.
# ---------------------------------------------------------------------------


def _install_local_introspector_shim(upstream_args: list[str]) -> None:
    enabled = is_compat_smoke() and os.environ.get(
        "OFG_INTROSPECTOR_MODE", "local").strip().lower() == "local"
    _record_patch("local_introspector_shim",
                  "compat-smoke local introspector shim", enabled)
    if not enabled:
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
    print("OFG_LOCAL_INTROSPECTOR_SHIM: enabled (compat-smoke only)", file=sys.stderr)


# ---------------------------------------------------------------------------
# Observability patches (always enabled; they do not change method decisions).
# ---------------------------------------------------------------------------


def _patch_oss_fuzz_postprocess_logging() -> None:
    _record_patch("oss_fuzz_postprocess_logging",
                  "observability: surface OSS-Fuzz postprocess failures", True)
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


def _patch_project_target_downloads() -> None:
    """Prevent GCS target downloads in blind-project.

    This patch never reads the reference harness; it only redirects the
    upstream GCS target download to a neutral, non-existent path so OSS-Fuzz-Gen
    cannot fetch the current target answer.
    """
    allow = env_bool("OFG_ALLOW_GCS_TARGET_DOWNLOAD", "0")
    enabled = not allow
    _record_patch("project_target_download_redirect",
                  "compatibility: block GCS target answer download", enabled)
    if not enabled:
        return

    from data_prep import project_targets  # pylint: disable=import-outside-toplevel

    def _local_fuzz_target_dir(_project_name: str) -> str:
        # Never expose the reference harness to the generator. Use a neutral
        # non-existent path so any accidental read fails loudly.
        return "/nonexistent-hgb-reference-harnesses"

    project_targets._get_fuzz_target_dir = _local_fuzz_target_dir  # pylint: disable=protected-access
    print("OFG_SKIP_GCS_TARGET_DOWNLOAD: target answer download blocked", file=sys.stderr)


def _install_hgb_llm_trace() -> None:
    """Patch OSS-Fuzz-Gen LLM calls to save sampled HGB traces."""
    _record_patch("hgb_llm_trace",
                  "observability: sample LLM API traces", True)
    if "/opt/hgb/bin" not in sys.path:
        sys.path.insert(0, "/opt/hgb/bin")
    try:
        import hgb_llm_trace  # type: ignore
        from llm_toolkit import models as llm_models  # pylint: disable=import-outside-toplevel
    except Exception as exc:  # noqa: BLE001 - tracing is best-effort.
        print(f"HGB_LLM_TRACE: disabled for OSS-Fuzz-Gen: {exc}", file=sys.stderr)
        return

    gpt_cls = getattr(llm_models, "GPT", None)
    if gpt_cls is None or getattr(gpt_cls, "_hgb_trace_installed", False):
        return

    original_create = gpt_cls._create_chat_completion

    def traced_create(self, client: Any, kwargs: dict[str, Any]) -> Any:
        model = str(kwargs.get("model") or getattr(self, "name", ""))
        return hgb_llm_trace.trace_call(
            lambda: original_create(self, client, kwargs),
            stage="oss-fuzz-gen",
            provider="openai-compatible",
            operation="chat.completions.create",
            model=model,
            request=kwargs,
        )

    gpt_cls._create_chat_completion = traced_create

    original_tools = gpt_cls.chat_llm_with_tools

    def traced_chat_llm_with_tools(self, client: Any, prompt: Any, tools: Any) -> Any:
        prompt_messages = prompt.get() if prompt else []
        request = {
            "model": self._completion_model_name(),
            "input": list(getattr(self, "messages", [])) + list(prompt_messages),
            "tools": tools,
        }
        return hgb_llm_trace.trace_call(
            lambda: original_tools(self, client, prompt, tools),
            stage="oss-fuzz-gen",
            provider="openai-compatible",
            operation="responses.create",
            model=str(request["model"]),
            request=request,
        )

    gpt_cls.chat_llm_with_tools = traced_chat_llm_with_tools
    gpt_cls._hgb_trace_installed = True
    print("HGB_LLM_TRACE: OSS-Fuzz-Gen hooks installed", file=sys.stderr)


# ---------------------------------------------------------------------------
# Repair iteration observability: retain each repair round without changing
# upstream repair logic.
# ---------------------------------------------------------------------------


def _install_repair_observability() -> None:
    _record_patch("repair_observability",
                  "observability: retain each repair round", True)
    try:
        from agent import fix_agent_loop  # pylint: disable=import-outside-toplevel
    except Exception:  # noqa: BLE001
        return
    if getattr(fix_agent_loop, "_hgb_repair_obs_installed", False):
        return

    original_run = getattr(fix_agent_loop, "run", None)
    if original_run is None:
        return

    def observed_run(*args: Any, **kwargs: Any) -> Any:
        result = original_run(*args, **kwargs)
        try:
            work_dir = Path(os.environ.get("HGB_GENERATION_WORK_DIR", "/workspace/ofg-work"))
            repair_dir = work_dir / "repair_iterations"
            repair_dir.mkdir(parents=True, exist_ok=True)
            existing = len(list(repair_dir.glob("round_*.txt")))
            log_path = work_dir / "build.log"
            if log_path.is_file():
                (repair_dir / f"round_{existing + 1}.txt").write_text(
                    log_path.read_text(encoding="utf-8", errors="replace")[-8192:],
                    encoding="utf-8",
                )
        except OSError:
            pass
        return result

    fix_agent_loop.run = observed_run
    fix_agent_loop._hgb_repair_obs_installed = True


# ---------------------------------------------------------------------------
# Coverage skip: compat-smoke ONLY. Forbidden in alpha/paper.
# ---------------------------------------------------------------------------


def _patch_coverage_skip() -> None:
    enabled = is_compat_smoke() and env_bool("OFG_SKIP_COVERAGE_GAINS", "0")
    _record_patch("coverage_skip",
                  "compat-smoke coverage skip", enabled)
    if not enabled:
        return

    from experiment import builder_runner, evaluator, textcov  # pylint: disable=import-outside-toplevel

    def _empty_textcov(*_args, **_kwargs) -> textcov.Textcov:
        return textcov.Textcov()

    def _empty_summary(*_args, **_kwargs) -> dict[str, Any]:
        return {}

    def _skip_get_coverage_local(self, generated_project: str,
                                 benchmark_target_name: str):
        del self, generated_project, benchmark_target_name
        print("OFG_SKIP_LOCAL_COVERAGE: returning empty coverage (compat-smoke)", file=sys.stderr)
        return textcov.Textcov(), {}

    builder_runner.BuilderRunner.get_coverage_local = _skip_get_coverage_local
    evaluator.load_existing_textcov = _empty_textcov
    evaluator.load_existing_jvm_textcov = _empty_textcov
    evaluator.load_existing_python_textcov = _empty_textcov
    evaluator.load_existing_rust_textcov = _empty_textcov
    evaluator.load_existing_coverage_summary = _empty_summary
    evaluator.Evaluator.load_existing_textcov = _empty_textcov
    evaluator.Evaluator._load_existing_coverage_summary = _empty_summary  # pylint: disable=protected-access
    print("OFG_SKIP_LOCAL_COVERAGE: enabled (compat-smoke only)", file=sys.stderr)


def _install_coverage_gains_noop() -> None:
    enabled = is_compat_smoke() and env_bool("OFG_SKIP_COVERAGE_GAINS", "0")
    _record_patch("coverage_gains_noop",
                  "compat-smoke coverage-gains no-op process", enabled)
    if not enabled:
        return

    import run_all_experiments  # pylint: disable=import-outside-toplevel,reimported

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
    print("OFG_COVERAGE_GAINS_NOOP: enabled (compat-smoke only)", file=sys.stderr)


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
    _patch_project_target_downloads()
    _patch_coverage_skip()
    _install_hgb_llm_trace()
    _install_repair_observability()
    _install_local_introspector_shim(upstream_args)
    _install_coverage_gains_noop()

    # Validate method-faithful invariants after patches are registered.
    if is_method_faithful():
        if env_bool("OFG_SKIP_COVERAGE_GAINS", "0"):
            print("ofg_profile_violation: OFG_SKIP_COVERAGE_GAINS=1 is forbidden in "
                  f"{active_profile()}", file=sys.stderr)
            return 65
        if os.environ.get("OFG_INTROSPECTOR_MODE", "remote").strip().lower() == "local":
            print("ofg_profile_violation: OFG_INTROSPECTOR_MODE=local is forbidden in "
                  f"{active_profile()}", file=sys.stderr)
            return 65

    sys.argv = ["run_all_experiments.py", *upstream_args]
    result = run_all_experiments.main()
    return int(result or 0)


if __name__ == "__main__":
    raise SystemExit(main())
