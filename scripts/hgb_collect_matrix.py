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
    "missing_processor_binaries",
    "upstream_cli_not_found",
    "needs_compile_commands",
    "source_input_missing",
    "soft_skip",
    "soft_skip_target_binaries_missing",
    "elfuzz_missing_hf_token_or_model_access",
    "promefuzz_no_usable_docs",
    "promefuzz_no_api_candidates",
    "ckg_no_compilable_sources",
    "missing_oss_fuzz_checkout",
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
    "promefuzz_native_build",
}

REMEDIATIONS = (
    ('ofg_llm_rate_limited', 'The OpenAI-compatible provider returned 429; reduce HGB_LLM_PARALLELISM, increase HGB_LLM_MIN_INTERVAL_SECONDS, or rerun after the provider reset time.'),
    ('ofg_post_success_validation_timeout', 'OSS-Fuzz-Gen produced a compiling referenced harness before later validation timed out; preserve the artifact or reduce post-generation validation work.'),
    ('ofg_function_not_referenced', 'The harness compiled but referenced a weak/helper symbol instead of the selected function; improve API selection or lower repair rounds.'),
    ('ofg_low_confidence_api_candidate', 'The selected upstream benchmark YAML had only low-confidence functions; fallback to synthesized target-aware YAML or improve reference-harness API extraction.'),
    ('ofg_empty_fix_prompt', 'OSS-Fuzz-Gen stopped repair because there were no actionable build errors; inspect selected API quality and generated source.'),
    ('ofg_bad_api_candidate', 'HGB rejected the selected benchmark APIs as test, perf, third-party, or target-mismatched symbols; use synthesized target-aware YAML or improve API extraction hints.'),
    ('ofg_empty_unit_test_prompt', 'The selected benchmark YAML only has test files and no functions; default runs skip it. Set OFG_ALLOW_TEST_BENCHMARKS=1 only when test-to-harness prompts are intended.'),
    ('ofg_coverage_artifact_missing', 'OSS-Fuzz-Gen compiled or ran a candidate but local coverage artifacts were unavailable; keep OFG_SKIP_COVERAGE_GAINS=1 and rebuild so OFG_SKIP_LOCAL_COVERAGE is active.'),
    ('OFG_SKIP_LOCAL_COVERAGE', 'Local coverage extraction is disabled for matrix generation; generated harnesses should be preserved even if coverage would have failed.'),
    ('OFG_PROJECT_IMAGE_BUILD_PARALLELISM', 'Reduce concurrent OSS-Fuzz project image builds or prebuild/cache project images when Docker/network pressure causes timeouts.'),
    ('ofg_empty_llm_response', 'The OpenAI-compatible endpoint returned empty content; verify the model/base URL supports chat completions and inspect raw response logs.'),
    ('ofg_oss_fuzz_helper_prompt_eof', 'Rebuild OSS-Fuzz-Gen so build_image passes an explicit --pull/--no-pull policy; default HGB behavior answers yes with --pull and never waits for stdin.'),
    ('ofg_docker_pull_timeout', 'Set OFG_BUILD_IMAGE_PULL=0 to use cached base images, reduce OFG_PROJECT_IMAGE_BUILD_PARALLELISM, pre-pull/cache the OSS-Fuzz project image, or rely on target source fallback where possible.'),
    ('ofg_project_image_build_failed', 'Inspect OSS-Fuzz project image build logs; common causes are unavailable Docker/network, unsupported project Dockerfile, or missing source fallback.'),
    ('ofg_recompile_timeout', 'The generated harness reached compile/repair but exceeded the row budget; keep OFG_NUM_SAMPLES=1, reduce repair rounds, or inspect the generated candidate.'),
    ('G2Fuzz LLM API credentials were rejected', 'Set a valid OpenAI-compatible API key/base URL/model for G2Fuzz before rerunning.'),
    ('G2Fuzz LLM API returned empty response', 'Verify the selected model returns non-empty chat content; reduce prompt size or switch models if the endpoint emits empty messages.'),
    ('G2Fuzz LLM API request timed out', 'Reduce G2FUZZ_MAX_FORMATS/G2FUZZ_TRY_NUM or increase G2FUZZ_LLM_REQUEST_TIMEOUT_SECONDS/HGB_LLM_REQUEST_TIMEOUT_SECONDS; the single-request default is 1200s.'),
    ('CKGFuzzer LLM API key or embedding credentials were rejected', 'Verify CKGFuzzer chat and embedding base URLs, model names, and API keys before rerunning.'),
    ('CKGFuzzer LLM API returned empty response', 'Verify the selected model returns non-empty chat content for CKGFuzzer prompts.'),
    ('CKGFuzzer LLM API request timed out', 'Reduce CKGFUZZER_MAX_SUMMARY_APIS/CKGFUZZER_MAX_PLANNER_APIS or increase CKGFUZZER_LLM_REQUEST_TIMEOUT_SECONDS/HGB_LLM_REQUEST_TIMEOUT_SECONDS; deterministic local summaries remain preferred.'),
    ('PromeFuzz LLM or embedding API credentials were rejected', 'Verify PromeFuzz embedding/chat base URLs, model names, and API keys before rerunning.'),
    ('PromeFuzz LLM API returned empty response', 'Verify the selected model returns non-empty chat content for PromeFuzz prompts.'),
    ('PromeFuzz LLM or embedding request timed out', 'Reduce PROME_FUZZ_MAX_APIS/doc size or increase PROME_FUZZ_LLM_REQUEST_TIMEOUT_SECONDS/HGB_LLM_REQUEST_TIMEOUT_SECONDS; the single-request default is 1200s.'),
    ('ofg_benchmark_trim_failed', 'Run OSS-Fuzz-Gen benchmark trimming with /opt/hgb/venv/bin/python or rebuild the image so PyYAML is available.'),
    ('ofg_invalid_api_key', 'Set a valid OpenAI-compatible API key/base URL; OSS-Fuzz-Gen preflight rejects invalid 401/403 credentials before generation.'),
    ('ofg_oss_fuzz_dependency_setup_failed', 'Rebuild OSS-Fuzz-Gen so OSS-Fuzz infra/build/functions requirements are installed into /opt/hgb/venv and symlinked into the checkout.'),
    ('ofg_llm_request_timeout', 'Reduce OFG_NUM_SAMPLES/OFG_NUM_EXP/OFG_NUM_EVA or increase OFG_LLM_REQUEST_TIMEOUT_SECONDS/HGB_LLM_REQUEST_TIMEOUT_SECONDS; the single-request default is 1200s.'),
    ('OFG_LOCAL_INTROSPECTOR_SHIM', 'Default local introspector shim is active; set OFG_INTROSPECTOR_MODE=remote only when remote FI access is required.'),
    ('deepseek_invalid_n', 'Rebuild OSS-Fuzz-Gen with the DeepSeek/OpenAI-compatible adapter that omits n for single-sample requests.'),
    ('ofg_nonretryable_llm_request', 'Inspect the OpenAI-compatible request parameters; 400 invalid_request_error is non-retryable and should fail fast.'),
    ('ofg_docker_unavailable', 'Use the HGB target source fallback or mount /var/run/docker.sock for OSS-Fuzz-Gen when local OSS-Fuzz image fallback is required.'),
    ('ofg_bad_benchmark_fallback', 'Disable project-level benchmark fallback or provide a target-specific OSS-Fuzz-Gen YAML for this target.'),
    ('ofg_introspector_timeout', 'Keep OFG_SKIP_COVERAGE_GAINS=1 and verify ofg_run_wrapper disables coverage aggregation/background reporting.'),
    ('program_gen timed out after preserving', 'G2Fuzz produced preseeded or generated inputs before timeout; accept partial_completed or increase HGB_GENERATION_TIMEOUT_SECONDS.'),
    ('ELFuzz TGI startup timed out', 'Set HF_TOKEN/model access, verify Docker can start TGI, or lower ELFUZZ_TGI_WAITING_SECONDS for cached models.'),
    ('elfuzz_missing_hf_token_or_model_access', 'Set HF_TOKEN, configure elfuzz tgi.huggingface_token, or set ELFUZZ_LOCAL_MODEL_CACHE_READY=1 only when the model is already cached and accessible.'),
    ('PromeFuzz NLTK data is unavailable', 'Rebuild the PromeFuzz image so NLTK data is downloaded into /opt/hgb/nltk_data during docker build.'),
    ('PromeFuzz PDF document parsing failed', 'Rebuild the PromeFuzz image with pdfminer.six or remove unsupported PDFs from /target/docs.'),
    ('promefuzz_no_usable_docs', 'Filter or replace empty/invalid target docs; PROME_FUZZ_SKIP_BAD_DOCS=1 skips bad docs but at least one usable document is needed for comprehension.'),
    ('promefuzz_no_api_candidates', 'Improve PromeFuzz API extraction/compile_commands for this target; generation is skipped when preprocess finds zero APIs.'),
    ('PromeFuzz provider rejected a non-retryable request', 'The OpenAI-compatible provider rejected the request (for example, insufficient balance, invalid credentials, or an unavailable model). Restore provider access and rerun; HGB stops PromeFuzz instead of retrying indefinitely.'),
    ('CKGFuzzer fuzzing stage exited 124', 'Reduce CKGFUZZER_MAX_SUMMARY_APIS/CKGFUZZER_MAX_PLANNER_APIS or keep deterministic local summaries enabled.'),
    ('CKGFuzzer repo stage exited', 'Inspect CKGFuzzer repo.log; common fixes are Docker socket access, CodeQL wrapper build replay, and target package source layout.'),
    ('ckg_no_compilable_sources', 'Fix target build replay for CKGFuzzer or inspect the CodeQL wrapper fallback compile log; CodeQL needs at least one compiled C/C++ translation unit.'),
    ('missing_oss_fuzz_checkout', 'Rebuild OSS-Fuzz-Gen with OFG_INSTALL_OSS_FUZZ=1, set OFG_OSS_FUZZ_DIR to a valid checkout, or set OFG_ALLOW_RUNTIME_CLONE=1 when network is available.'),
    ("missing_codeql", "Mount or install CodeQL: set HGB_CODEQL_DIR=/path/to/codeql or build CKGFuzzer with HGB_INSTALL_CODEQL=1; use CKGFUZZER_SKIP_CODEQL=1 only as a fallback."),
    ("missing_processor_binaries", "Rebuild the PromeFuzz image so setup.sh builds preprocessor and cgprocessor during docker build."),
    ("needs_compile_commands", "Improve target package build replay or enable Bear/CMake compile_commands generation for PromeFuzz."),
    ('PromeFuzz generation completed without producing a sanitized target harness', 'PromeFuzz exhausted generation without a final native-build-validated harness; inspect generate.log and native_build.log, then improve target build compatibility or API selection.'),
    ("needs_ofg_benchmark_yaml", "Generate or provide an OSS-Fuzz-Gen function-level benchmark YAML for this target."),
    ("no_api_candidates", "Improve source packaging/API extraction for this target before running function-level harness generators."),
    ("source_input_missing", "Fix Dockerfile source parsing or add metadata/fuzzbench_source_overrides.json for this target."),
    ("not_applicable", "Treat this pair as unsupported by the generator unless a target adapter is added."),
    ("target_not_supported_by_elfuzz", "Treat this pair as unsupported by ELFuzz unless a target adapter or supported-target mapping is added."),
    ("program_gen timed out", "Increase HGB_GENERATION_TIMEOUT_SECONDS or accept partial_completed G2FUZZ inputs."),
    ("program_gen exited 124", "Increase HGB_GENERATION_TIMEOUT_SECONDS or classify generated seeds as partial_completed."),
    ("oss-fuzz Python requirements install failed", "Rebuild OSS-Fuzz-Gen with native Python build dependencies; inspect run.log for the failing pip package."),
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
    build_script_counts: collections.Counter[str] = collections.Counter()
    log_candidate_counts: collections.Counter[str] = collections.Counter()
    input_counts: collections.Counter[str] = collections.Counter()
    reasons: collections.Counter[str] = collections.Counter()
    remediation_counts: collections.Counter[str] = collections.Counter()
    api_trace_total_count = 0
    api_trace_sample_count = 0
    for record in records:
        meta = record["metadata"]
        gen = meta.get("generator") or meta.get("fuzzer") or record["row"].get("generator") or "unknown"
        harness_counts[gen] += int(meta.get("generated_harness_count") or meta.get("generated_driver_count") or 0)
        build_script_counts[gen] += int(meta.get("generated_build_script_count") or 0)
        log_candidate_counts[gen] += int(meta.get("generated_log_candidate_count") or 0)
        input_counts[gen] += int(meta.get("generated_input_count") or meta.get("generated_seed_count") or 0)
        api_trace_total_count += int(meta.get("api_trace_total_count") or 0)
        api_trace_sample_count += int(meta.get("api_trace_sample_count") or 0)
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
        "generated_build_script_counts_by_generator": dict(build_script_counts),
        "generated_log_candidate_counts_by_generator": dict(log_candidate_counts),
        "generated_input_counts_by_generator": dict(input_counts),
        "api_trace_total_count": api_trace_total_count,
        "api_trace_sample_count": api_trace_sample_count,
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
            "api_trace_total_count",
            "api_trace_sample_count",
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
        "## API Traces",
        "",
        f"- Total calls: `{summary.get('api_trace_total_count', 0)}`",
        f"- Sampled calls: `{summary.get('api_trace_sample_count', 0)}`",
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
    if (summary["generated_harness_counts_by_generator"] or
            summary.get("generated_build_script_counts_by_generator") or
            summary.get("generated_log_candidate_counts_by_generator") or
            summary["generated_input_counts_by_generator"]):
        lines.extend(["", "## Generated Artifacts", ""])
        for generator, count in sorted(summary["generated_harness_counts_by_generator"].items()):
            lines.append(f"- `{generator}` harnesses: {count}")
        for generator, count in sorted(summary.get("generated_build_script_counts_by_generator", {}).items()):
            if count:
                lines.append(f"- `{generator}` build scripts: {count}")
        for generator, count in sorted(summary.get("generated_log_candidate_counts_by_generator", {}).items()):
            if count:
                lines.append(f"- `{generator}` log-extracted harness candidates: {count}")
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
