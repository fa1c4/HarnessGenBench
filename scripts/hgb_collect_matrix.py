#!/usr/bin/env python3
"""Collect HarnessGenBench generator-target matrix metadata."""

from __future__ import annotations

import argparse
import collections
import csv
import json
import sys
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
    "elfuzz_docker_socket_unavailable",
    "elfuzz_gpu_unavailable",
    "generator_preflight_docker_layerdb_collision",
    "promefuzz_no_usable_docs",
    "promefuzz_no_api_candidates",
    "ckg_no_compilable_sources",
    "missing_oss_fuzz_checkout",
}
PARTIAL_STATUSES = {"partial_completed"}
NOT_APPLICABLE_STATUSES = {"not_applicable", "target_not_supported_by_elfuzz"}
# For harness generators with strict evaluated semantics (CKGFuzzer alpha),
# only "evaluated" counts as completed. "completed" and "dry_run_ok" are not
# successful evaluations for harness-generator rows.
HARNESS_GENERATOR_STRICT_COMPLETED = {"evaluated"}

# Strict reproduction profiles. ``reproduction-epsilon`` is the canonical
# strict profile (epsilon plan); ``reproduction-delta`` is its backward-
# compatible alias. Both enforce the same paper-equivalent invariants.
STRICT_REPRODUCTION_PROFILES = {"reproduction-delta", "reproduction-epsilon"}
# For input generators and non-strict harness runs, the broader set applies.
COMPLETED_STATUSES = {"completed", "dry_run_ok", "evaluated"}
# Statuses that must never be counted as successful.
NEVER_SUCCESS_STATUSES = {"dry_run", "partial_completed", "soft_skip", "generation_completed"}
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
    ('G2Fuzz LLM API request timed out', 'Reduce G2FUZZ_MAX_FORMATS/G2FUZZ_TRY_NUM or increase G2FUZZ_LLM_REQUEST_TIMEOUT_SECONDS/HGB_LLM_REQUEST_TIMEOUT_SECONDS; the single-request default is 900s.'),
    ('CKGFuzzer LLM API key or embedding credentials were rejected', 'Verify CKGFuzzer chat and embedding base URLs, model names, and API keys before rerunning.'),
    ('CKGFuzzer LLM API returned empty response', 'Verify the selected model returns non-empty chat content for CKGFuzzer prompts.'),
    ('CKGFuzzer LLM API request timed out', 'Reduce CKGFUZZER_MAX_SUMMARY_APIS/CKGFUZZER_MAX_PLANNER_APIS or increase CKGFUZZER_LLM_REQUEST_TIMEOUT_SECONDS/HGB_LLM_REQUEST_TIMEOUT_SECONDS; deterministic local summaries remain preferred.'),
    ('PromeFuzz LLM or embedding API credentials were rejected', 'Verify PromeFuzz embedding/chat base URLs, model names, and API keys before rerunning.'),
    ('PromeFuzz LLM API returned empty response', 'Verify the selected model returns non-empty chat content for PromeFuzz prompts.'),
    ('PromeFuzz LLM or embedding request timed out', 'Reduce PROME_FUZZ_MAX_APIS/doc size or increase PROME_FUZZ_LLM_REQUEST_TIMEOUT_SECONDS/HGB_LLM_REQUEST_TIMEOUT_SECONDS; the single-request default is 900s.'),
    ('ofg_benchmark_trim_failed', 'Run OSS-Fuzz-Gen benchmark trimming with /opt/hgb/venv/bin/python or rebuild the image so PyYAML is available.'),
    ('ofg_invalid_api_key', 'Set a valid OpenAI-compatible API key/base URL; OSS-Fuzz-Gen preflight rejects invalid 401/403 credentials before generation.'),
    ('ofg_oss_fuzz_dependency_setup_failed', 'Rebuild OSS-Fuzz-Gen so OSS-Fuzz infra/build/functions requirements are installed into /opt/hgb/venv and symlinked into the checkout.'),
    ('ofg_llm_request_timeout', 'Reduce OFG_NUM_SAMPLES/OFG_NUM_EXP/OFG_NUM_EVA or increase OFG_LLM_REQUEST_TIMEOUT_SECONDS/HGB_LLM_REQUEST_TIMEOUT_SECONDS; the single-request default is 900s.'),
    ('OFG_LOCAL_INTROSPECTOR_SHIM', 'Default local introspector shim is active; set OFG_INTROSPECTOR_MODE=remote only when remote FI access is required.'),
    ('deepseek_invalid_n', 'Rebuild OSS-Fuzz-Gen with the DeepSeek/OpenAI-compatible adapter that omits n for single-sample requests.'),
    ('ofg_nonretryable_llm_request', 'Inspect the OpenAI-compatible request parameters; 400 invalid_request_error is non-retryable and should fail fast.'),
    ('ofg_docker_unavailable', 'Use the HGB target source fallback or mount /var/run/docker.sock for OSS-Fuzz-Gen when local OSS-Fuzz image fallback is required.'),
    ('ofg_bad_benchmark_fallback', 'Disable project-level benchmark fallback or provide a target-specific OSS-Fuzz-Gen YAML for this target.'),
    ('ofg_introspector_timeout', 'Keep OFG_SKIP_COVERAGE_GAINS=1 and verify ofg_run_wrapper disables coverage aggregation/background reporting.'),
    ('program_gen timed out after preserving', 'G2Fuzz produced preseeded or generated inputs before timeout; accept partial_completed or increase HGB_GENERATION_TIMEOUT_SECONDS.'),
    ('ELFuzz TGI startup timed out', 'Set HF_TOKEN/model access, verify Docker can start TGI, or lower ELFUZZ_TGI_WAITING_SECONDS for cached models.'),
    ('elfuzz_missing_hf_token_or_model_access', 'Set HF_TOKEN, configure elfuzz tgi.huggingface_token, or set ELFUZZ_LOCAL_MODEL_CACHE_READY=1 only when the model is already cached and accessible.'),
    ('elfuzz_gpu_unavailable', 'ELFuzz starts TGI with --gpus all; configure NVIDIA Container Toolkit and make a usable GPU visible to Docker before rerunning.'),
    ('generator_preflight_docker_layerdb_collision', 'Docker storage reported a layerdb collision. Stop competing builds and have the Docker administrator repair the daemon; then retry with HGB_RETRY_DOCKER_LAYERDB_BUILD=1. HGB will not prune /data/docker automatically.'),
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


def evaluated_row_violations(meta: dict[str, Any]) -> list[str]:
    """Return invariant violations for an ``evaluated`` row.

    Harness-generator rows (per the beta reproduction contract) must have a
    real coverage report (non-null covered lines), a campaign with
    ``execs_done > 0``, and a per-candidate evaluator JSON (selected_candidate).

    Input-generator rows (G2Fuzz) must additionally have a completed
    ``target_pair_build`` (auto-built ``.afl``/``.cmp`` evidence), at least one
    valid G2-generated input, ``execs_done > 0``, a nonempty queue, and a real
    coverage report.  AFL ``paths_total`` is never accepted as coverage.
    """
    if str(meta.get("status")) != "evaluated":
        return []
    violations: list[str] = []
    family = str(meta.get("task_family") or meta.get("capability") or "")
    cov = meta.get("metrics", {}).get("coverage") or meta.get("coverage") or {}
    if not isinstance(cov, dict):
        cov = {}
    line_cov = cov.get("line_coverage")
    if not isinstance(line_cov, dict):
        line_cov = {}
    campaign = meta.get("metrics", {}).get("campaign") or meta.get("campaign") or {}
    if not isinstance(campaign, dict):
        campaign = {}
    if family == "input_generator":
        gen = str(meta.get("generator") or meta.get("fuzzer") or meta.get("baseline") or "")
        # ELFuzz input-generator contract (plan elfuzz_reproduction_delta.md
        # section 6/7): evaluated requires at least one generated fuzzer
        # program, at least one produced input, at least one valid input
        # executed on the native SUT, a campaign with execs_done > 0, and a
        # real coverage report (report_exists, line_coverage.covered > 0).
        # AFL paths_total is never accepted as coverage.
        if gen == "elfuzz":
            elf = meta.get("elfuzz") or {}
            if not isinstance(elf, dict):
                elf = {}
            input_gen = meta.get("input_generation", {})
            if not isinstance(input_gen, dict):
                input_gen = {}
            if int(elf.get("fuzzer_programs", input_gen.get("fuzzer_program_count", 0)) or 0) <= 0:
                violations.append("evaluated elfuzz row has no generated fuzzer program")
            if int(meta.get("generated_input_count", elf.get("generated_inputs", 0)) or 0) <= 0:
                violations.append("evaluated elfuzz row has no produced input")
            if int(elf.get("valid_generated_inputs", input_gen.get("valid_generated_input_count", 0)) or 0) <= 0:
                violations.append("evaluated elfuzz row has no valid generated input executed on the SUT")
            if int(campaign.get("execs_done", 0) or 0) <= 0:
                violations.append("evaluated row has campaign.execs_done <= 0")
            cov_report = cov.get("report_exists")
            if cov_report is not True:
                violations.append("evaluated elfuzz row has coverage.report_exists != true")
            if line_cov.get("covered") is None:
                violations.append("evaluated row has coverage.line_coverage.covered == null")
            elif int(line_cov.get("covered", 0) or 0) <= 0:
                violations.append("evaluated elfuzz row has coverage.line_coverage.covered <= 0")
            edge = cov.get("edge_coverage")
            if isinstance(edge, dict) and edge.get("status") != "unavailable":
                violations.append("evaluated elfuzz row must not report AFL paths as edge coverage")
            elfuzz_profile = str(meta.get("profile", ""))
            if elfuzz_profile in STRICT_REPRODUCTION_PROFILES:
                if str(meta.get("method_variant", "")) != "paper-faithful":
                    violations.append(f"evaluated {elfuzz_profile} elfuzz row has method_variant != paper-faithful")
                if bool(meta.get("exclude_from_aggregate") or meta.get("excluded_from_aggregate")):
                    violations.append(f"evaluated {elfuzz_profile} elfuzz row is excluded_from_aggregate")
                build = meta.get("build") or {}
                if isinstance(build, dict) and not build.get("uses_fuzzbench_docker_environment"):
                    violations.append(f"evaluated {elfuzz_profile} elfuzz row did not build from the FuzzBench Docker environment")
            return violations
        # G2Fuzz beta contract (plan section 11).
        target_pair = meta.get("target_pair_build", {})
        if isinstance(target_pair, dict) and target_pair.get("status") != "completed":
            violations.append("evaluated input-generator row has no completed target_pair_build")
        if not (target_pair.get("afl_binary") and target_pair.get("cmp_binary")):
            violations.append("evaluated input-generator row lacks .afl/.cmp build evidence")
        profile_s = str(meta.get("profile") or "")
        # Gamma/delta/epsilon contract: also require .cov build evidence.
        if profile_s in ("reproduction-gamma", "reproduction-delta", "reproduction-epsilon"):
            if not target_pair.get("cov_binary"):
                violations.append(f"evaluated {profile_s} input-generator row lacks .cov build evidence")
            cov_gamma = meta.get("coverage_gamma") or {}
            if isinstance(cov_gamma, dict) and int(cov_gamma.get("inputs_replayed", 0) or 0) <= 0:
                violations.append(f"evaluated {profile_s} input-generator row has coverage_gamma.inputs_replayed <= 0")
        # Strict reproduction contract (plan g2fuzz_reproduction_delta.md
        # section 7): the target triple must be verified, at least one
        # generator and one G2-generated payload must exist, and covered lines
        # must be > 0.
        if profile_s in STRICT_REPRODUCTION_PROFILES:
            target_triple = meta.get("target_triple") or {}
            if isinstance(target_triple, dict):
                if not target_triple.get("uses_fuzzbench_docker_environment"):
                    violations.append(f"evaluated {profile_s} g2fuzz row did not build from the FuzzBench Docker environment")
                variants = target_triple.get("variants") or {}
                for v in ("afl", "cmp", "cov"):
                    if not (isinstance(variants, dict) and variants.get(v, {}).get("verified")):
                        violations.append(f"evaluated {profile_s} g2fuzz row has target_triple.variants.{v}.verified != true")
            else:
                violations.append(f"evaluated {profile_s} g2fuzz row lacks target_triple")
            program_generation = meta.get("program_generation") or {}
            if isinstance(program_generation, dict) and int(program_generation.get("generator_count", 0) or 0) <= 0:
                violations.append(f"evaluated {profile_s} g2fuzz row has program_generation.generator_count <= 0")
            seed_prov = meta.get("seed_provenance_delta") or meta.get("seed_provenance") or {}
            if isinstance(seed_prov, dict) and int(seed_prov.get("g2_generated_count", seed_prov.get("g2_generated", 0)) or 0) <= 0:
                violations.append(f"evaluated {profile_s} g2fuzz row has seed_provenance.g2_generated_count <= 0")
            if line_cov.get("covered") is not None and int(line_cov.get("covered", 0) or 0) <= 0:
                violations.append(f"evaluated {profile_s} g2fuzz row has coverage.line_coverage.covered <= 0")
            # Epsilon G2-2/G2-3: the instrumentation check must pass and a
            # runtime environment record must exist.
            instr = meta.get("instrumentation_check") or {}
            if isinstance(instr, dict) and not instr.get("all_passed"):
                violations.append(f"evaluated {profile_s} g2fuzz row has instrumentation_check.all_passed != true")
            runtime_env = meta.get("runtime_environment") or {}
            if isinstance(runtime_env, dict) and not runtime_env:
                violations.append(f"evaluated {profile_s} g2fuzz row has no runtime_environment record")
        input_gen = meta.get("input_generation", {})
        if not isinstance(input_gen, dict) or int(input_gen.get("valid_g2_generated_count", 0) or 0) <= 0:
            violations.append("evaluated input-generator row has no valid G2-generated input")
        if int(campaign.get("execs_done", 0) or 0) <= 0:
            violations.append("evaluated row has campaign.execs_done <= 0")
        if int(campaign.get("queue_count", 0) or 0) <= 0:
            violations.append("evaluated input-generator row has campaign.queue_count <= 0")
        if line_cov.get("covered") is None:
            violations.append("evaluated row has coverage.line_coverage.covered == null")
        edge = cov.get("edge_coverage")
        if isinstance(edge, dict) and edge.get("status") != "unavailable":
            violations.append("evaluated input-generator row must not report AFL paths as edge coverage")
        return violations
    if family and family != "harness_generator":
        return []
    if line_cov.get("covered") is None:
        violations.append("evaluated row has coverage.line_coverage.covered == null")
    if int(campaign.get("execs_done", 0) or 0) <= 0:
        violations.append("evaluated row has campaign.execs_done <= 0")
    if not meta.get("selected_candidate"):
        violations.append("evaluated row has no per-candidate evaluator JSON")
    # Strict reproduction (reproduction-epsilon / reproduction-delta)
    # paper-equivalent invariants (plan section 7).
    profile_str = str(meta.get("profile", ""))
    if profile_str in STRICT_REPRODUCTION_PROFILES:
        if str(meta.get("method_variant", "")) != "paper-faithful":
            violations.append(f"evaluated {profile_str} row has method_variant != paper-faithful")
        if bool(meta.get("excluded_from_aggregate")):
            violations.append(f"evaluated {profile_str} row is excluded_from_aggregate")
        if line_cov.get("covered") is not None and int(line_cov.get("covered", 0) or 0) <= 0:
            violations.append(f"evaluated {profile_str} row has coverage.line_coverage.covered <= 0")
        sel = meta.get("selected_candidate") or {}
        if isinstance(sel, dict):
            copy_audit = sel.get("copy_audit") or {}
            if copy_audit.get("exact_copy"):
                violations.append(f"evaluated {profile_str} row has copy_audit.exact_copy == true")
            build = sel.get("build") or {}
            overlay_audit = build.get("overlay_audit") or {}
            if overlay_audit and overlay_audit.get("matches_candidate") is not True:
                violations.append(f"evaluated {profile_str} row has build.overlay_audit.matches_candidate != true")
        # OSS-Fuzz-Gen-specific strict invariants (plan
        # oss-fuzz-gen_reproduction_delta.md section 7): a clean prompt audit,
        # a real (non-shim) introspector with nonzero functions, and a valid
        # runtime coverage diff (or an explicitly unavailable native control).
        gen_name = str(meta.get("generator") or meta.get("fuzzer") or meta.get("baseline") or "")
        if gen_name == "oss-fuzz-gen":
            prompt_audit = meta.get("prompt_audit") or {}
            if isinstance(prompt_audit, dict):
                if prompt_audit.get("exact_reference_harness_in_prompt"):
                    violations.append(f"evaluated {profile_str} ofg row has prompt_audit.exact_reference_harness_in_prompt == true")
                if prompt_audit.get("selected_harness_api_metadata_used"):
                    violations.append(f"evaluated {profile_str} ofg row has prompt_audit.selected_harness_api_metadata_used == true")
            else:
                violations.append(f"evaluated {profile_str} ofg row has no prompt_audit")
            introspector = meta.get("introspector") or meta.get("introspector_provenance") or {}
            if isinstance(introspector, dict):
                if introspector.get("used_local_shim"):
                    violations.append(f"evaluated {profile_str} ofg row has introspector.used_local_shim == true")
                if int(introspector.get("function_count", 0) or 0) <= 0:
                    violations.append(f"evaluated {profile_str} ofg row has introspector.function_count <= 0")
            else:
                violations.append(f"evaluated {profile_str} ofg row has no introspector provenance")
            coverage_diff = meta.get("coverage_diff") or (meta.get("metrics") or {}).get("coverage_diff") or {}
            if isinstance(coverage_diff, dict) and coverage_diff:
                if coverage_diff.get("runtime_coverage_valid") is False:
                    violations.append(f"evaluated {profile_str} ofg row has coverage_diff.runtime_coverage_valid == false")
    return violations


def extract_ckgfuzzer_row(meta: dict[str, Any]) -> dict[str, Any]:
    """Extract the plan-section-9 CKGFuzzer row fields from metadata.

    Returns a dict with the canonical CKGFuzzer matrix columns so the
    collector can emit a per-target breakdown with real runtime evidence,
    coverage, graph stats, and reference-leak/copy audit flags.
    """
    stages = meta.get("stages") or {}
    if not isinstance(stages, dict):
        stages = {}
    cov = meta.get("metrics", {}).get("coverage") or meta.get("coverage") or {}
    if not isinstance(cov, dict):
        cov = {}
    campaign = meta.get("metrics", {}).get("campaign") or meta.get("campaign") or {}
    if not isinstance(campaign, dict):
        campaign = {}
    line_cov = cov.get("line_coverage") or {}
    region_cov = cov.get("region_coverage") or cov.get("regions") or {}
    func_cov = cov.get("function_coverage") or {}
    candidate = meta.get("candidate") or {}
    if not isinstance(candidate, dict):
        candidate = {}
    ckg = meta.get("ckgfuzzer") or {}
    if not isinstance(ckg, dict):
        ckg = {}
    leak_audit = meta.get("reference_leakage_audit") or {}
    if not isinstance(leak_audit, dict):
        leak_audit = {}
    build = meta.get("build") or {}
    if not isinstance(build, dict):
        build = {}
    selected = meta.get("selected_candidate") or {}
    if not isinstance(selected, dict):
        selected = {}
    sel_build = selected.get("build") or build or {}
    overlay_audit = sel_build.get("overlay_audit") or meta.get("overlay_audit") or {}
    if not isinstance(overlay_audit, dict):
        overlay_audit = {}
    copy_audit = meta.get("copy_audit") or candidate.get("copy_audit") or selected.get("copy_audit") or {}
    if not isinstance(copy_audit, dict):
        copy_audit = {}
    exact_copy = bool(copy_audit.get("exact_copy", candidate.get("exact_copy", False)))
    matches_candidate = overlay_audit.get("matches_candidate")
    profile = str(meta.get("profile", ""))
    method_variant = str(meta.get("method_variant", ""))
    line_covered = line_cov.get("covered") if isinstance(line_cov, dict) else None
    execs_done = int(campaign.get("execs_done", 0) or 0)
    # Strict reproduction paper-equivalent gate (plan section 7 / E7).
    # reproduction-epsilon is the canonical strict profile; reproduction-delta
    # is its backward-compatible alias. A row is paper-equivalent only when it
    # is evaluated, paper-faithful, not excluded, has real coverage (lines > 0),
    # real campaign executions (> 0), no exact reference copy, and a candidate
    # overlay that matches the candidate SHA256.
    _strict_paper_equivalent = (
        method_variant == "paper-faithful"
        and str(meta.get("status", "")) == "evaluated"
        and not bool(meta.get("excluded_from_aggregate"))
        and isinstance(line_covered, int) and line_covered > 0
        and execs_done > 0
        and not exact_copy
        and matches_candidate is True
    )
    paper_equivalent_delta = bool(profile == "reproduction-delta" and _strict_paper_equivalent)
    paper_equivalent_epsilon = bool(profile == "reproduction-epsilon" and _strict_paper_equivalent)
    paper_equivalent_strict = bool(paper_equivalent_delta or paper_equivalent_epsilon)
    return {
        "target": meta.get("target", ""),
        "status": str(meta.get("status", "")),
        "applicability": str(meta.get("applicability", "")),
        "profile": profile,
        "method_variant": method_variant,
        "candidate_build": str(stages.get("candidate_build", "")),
        "sanitizer_smoke": str(stages.get("sanitizer_smoke", "")),
        "api_reachability": str(stages.get("api_reachability", "")),
        "campaign": str(stages.get("campaign", "")),
        "coverage": str(stages.get("coverage", "")),
        "line_coverage": line_covered,
        "region_coverage": region_cov.get("covered") if isinstance(region_cov, dict) else None,
        "function_coverage": func_cov.get("covered") if isinstance(func_cov, dict) else None,
        "execs_done": execs_done,
        "crashes": int(campaign.get("crashes", 0) or 0),
        "hangs": int(campaign.get("timeouts", 0) or 0),
        "llm_calls": int(meta.get("api_trace_total_count", 0) or 0),
        "embedding_calls": int(meta.get("embedding_calls", 0) or meta.get("api_trace_total_count", 0) or 0),
        "codeql_graph_nodes": int(ckg.get("codeql_graph_nodes", meta.get("codeql_graph_nodes", 0) or 0) or 0),
        "codeql_graph_edges": int(ckg.get("codeql_graph_edges", meta.get("codeql_graph_edges", 0) or 0) or 0),
        "reference_canary_leak": bool(candidate.get("contains_reference_canary") or leak_audit.get("leaked")),
        "near_duplicate_reference": bool(candidate.get("near_duplicate_reference")),
        "exact_copy": exact_copy,
        "matches_candidate": matches_candidate,
        "paper_equivalent_delta": paper_equivalent_delta,
        "paper_equivalent_epsilon": paper_equivalent_epsilon,
        "paper_equivalent_strict": paper_equivalent_strict,
        "exclude_from_aggregate": bool(meta.get("excluded_from_aggregate")),
    }


def extract_ofg_row(meta: dict[str, Any]) -> dict[str, Any]:
    """Extract the OSS-Fuzz-Gen reproduction-delta row fields from metadata.

    Per plan oss-fuzz-gen_reproduction_delta.md section 7, an OFG row is
    paper-equivalent only when every real stage has evidence: build success,
    candidate overlay matching the candidate, nonzero campaign executions, real
    coverage with covered lines > 0, a real (non-shim) introspector, a clean
    prompt audit, and a valid runtime coverage diff (or an explicitly
    unavailable native control reported separately).
    """
    stages = meta.get("stages") or {}
    if not isinstance(stages, dict):
        stages = {}
    metrics = meta.get("metrics") or {}
    if not isinstance(metrics, dict):
        metrics = {}
    cov = metrics.get("coverage") or meta.get("coverage") or {}
    if not isinstance(cov, dict):
        cov = {}
    campaign = metrics.get("campaign") or meta.get("campaign") or {}
    if not isinstance(campaign, dict):
        campaign = {}
    line_cov = cov.get("line_coverage") or {}
    if not isinstance(line_cov, dict):
        line_cov = {}
    build = meta.get("build") or metrics.get("build") or {}
    if not isinstance(build, dict):
        build = {}
    selected = meta.get("selected_candidate") or {}
    if not isinstance(selected, dict):
        selected = {}
    sel_build = selected.get("build") or build or {}
    overlay_audit = sel_build.get("overlay_audit") or meta.get("overlay_audit") or {}
    if not isinstance(overlay_audit, dict):
        overlay_audit = {}
    prompt_audit = meta.get("prompt_audit") or {}
    if not isinstance(prompt_audit, dict):
        prompt_audit = {}
    introspector = meta.get("introspector") or meta.get("introspector_provenance") or {}
    if not isinstance(introspector, dict):
        introspector = {}
    coverage_diff = meta.get("coverage_diff") or metrics.get("coverage_diff") or {}
    if not isinstance(coverage_diff, dict):
        coverage_diff = {}
    profile = str(meta.get("profile", ""))
    method_variant = str(meta.get("method_variant", ""))
    line_covered = line_cov.get("covered")
    execs_done = int(campaign.get("execs_done", 0) or 0)
    matches_candidate = overlay_audit.get("matches_candidate")
    runtime_coverage_valid = coverage_diff.get("runtime_coverage_valid")
    cov_diff_status = str(coverage_diff.get("status", ""))
    # A row is coverage-diff-acceptable when the runtime coverage diff is
    # valid, OR the native control could not be built and the diff is reported
    # unavailable with a non-paper-equivalent flag (plan section 6.7).
    cov_diff_ok = (
        runtime_coverage_valid is True
        or (cov_diff_status == "unavailable" and bool(meta.get("excluded_from_aggregate")))
    )
    _strict_paper_equivalent = bool(
        method_variant == "paper-faithful"
        and str(meta.get("status", "")) == "evaluated"
        and not bool(meta.get("excluded_from_aggregate"))
        and isinstance(line_covered, int) and line_covered > 0
        and execs_done > 0
        and matches_candidate is True
        and prompt_audit.get("exact_reference_harness_in_prompt") is False
        and prompt_audit.get("selected_harness_api_metadata_used") is False
        and introspector.get("used_local_shim") is False
        and int(introspector.get("function_count", 0) or 0) > 0
        and cov_diff_ok
    )
    paper_equivalent_delta = bool(profile == "reproduction-delta" and _strict_paper_equivalent)
    paper_equivalent_epsilon = bool(profile == "reproduction-epsilon" and _strict_paper_equivalent)
    paper_equivalent_strict = bool(paper_equivalent_delta or paper_equivalent_epsilon)
    return {
        "target": meta.get("target", ""),
        "status": str(meta.get("status", "")),
        "applicability": str(meta.get("applicability", "")),
        "profile": profile,
        "method_variant": method_variant,
        "candidate_overlay": str(stages.get("candidate_overlay", "")),
        "candidate_build": str(stages.get("candidate_build", "")),
        "sanitizer_smoke": str(stages.get("sanitizer_smoke", "")),
        "campaign": str(stages.get("campaign", "")),
        "coverage": str(stages.get("coverage", "")),
        "line_coverage": line_covered,
        "execs_done": execs_done,
        "matches_candidate": matches_candidate,
        "overlay_audit": overlay_audit,
        "prompt_audit": prompt_audit,
        "introspector": introspector,
        "coverage_diff": coverage_diff,
        "runtime_coverage_valid": runtime_coverage_valid,
        "cov_diff_status": cov_diff_status,
        "paper_equivalent_delta": paper_equivalent_delta,
        "paper_equivalent_epsilon": paper_equivalent_epsilon,
        "paper_equivalent_strict": paper_equivalent_strict,
        "exclude_from_aggregate": bool(meta.get("excluded_from_aggregate")),
    }


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
                for name in ("generated_harnesses", "generated_inputs", "seeds/g2_generated", "generators/source"):
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


def _load_target_set(target_set: str) -> set[str] | None:
    """Load a named target set from fuzzbench_targets.json. Returns None if not found."""
    if not target_set:
        return None
    for candidate in (Path("metadata/fuzzbench_targets.json"), Path(__file__).resolve().parent.parent / "metadata" / "fuzzbench_targets.json"):
        if candidate.is_file():
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
                raw = data.get("target_sets", {}).get(target_set, {})
                targets = raw.get("targets", raw) if isinstance(raw, dict) else raw
                return set(str(t) for t in (targets or []))
            except (json.JSONDecodeError, OSError):
                continue
    return None


def _apply_filters(records: list[dict[str, Any]], *, generator: str = "", target_set: str = "", task_family: str = "", profile: str = "", method_profile: str = "") -> list[dict[str, Any]]:
    """Filter records by generator, target-set, task-family, profile, method-profile."""
    if not any([generator, target_set, task_family, profile, method_profile]):
        return records
    target_filter = _load_target_set(target_set)
    filtered: list[dict[str, Any]] = []
    for record in records:
        meta = record["metadata"]
        row = record["row"]
        gen = meta.get("generator") or meta.get("fuzzer") or row.get("generator") or ""
        if generator and gen != generator:
            continue
        if target_filter and row.get("target", "") not in target_filter:
            continue
        fam = str(meta.get("task_family") or meta.get("capability") or "")
        if task_family and fam != task_family:
            continue
        if profile and str(meta.get("profile") or "") != profile:
            continue
        if method_profile and str(meta.get("method_profile") or "") != method_profile:
            continue
        filtered.append(record)
    return filtered


def collect(matrix_dir: Path, *, strict: bool = False, split_by: str = "", generator: str = "", target_set: str = "", task_family: str = "", profile: str = "", method_profile: str = "", require_evaluated: bool = False) -> dict[str, Any]:
    rows = read_rows(matrix_dir)
    records: list[dict[str, Any]] = []
    for row in rows:
        metadata = load_metadata(row.get("metadata", ""))
        records.append({"row": row, "metadata": metadata})
    # Apply filters before computing the summary.
    records = _apply_filters(records, generator=generator, target_set=target_set, task_family=task_family, profile=profile, method_profile=method_profile)
    total = len(records)
    # --require-evaluated: every applicable (non-excluded, non-not-applicable)
    # harness-generator row in the filtered set must be ``evaluated``.  This is
    # the gamma acceptance gate: a build-only or failed row fails the matrix
    # loudly instead of being silently counted.
    require_evaluated_violations: list[dict[str, Any]] = []
    if require_evaluated:
        for record in records:
            meta = record["metadata"]
            if bool(meta.get("excluded_from_aggregate")):
                continue
            status_s = str(meta.get("status") or record["row"].get("status") or "missing_metadata")
            if status_s in NOT_APPLICABLE_STATUSES:
                continue
            family = str(meta.get("task_family") or meta.get("capability") or "harness_generator")
            if family != "harness_generator":
                continue
            if status_s not in HARNESS_GENERATOR_STRICT_COMPLETED:
                require_evaluated_violations.append({
                    "generator": record["row"].get("generator", ""),
                    "target": record["row"].get("target", ""),
                    "status": status_s,
                })
    # Strict-mode validation: an evaluated harness-generator row must have a
    # real coverage report and nonzero campaign execs.  Violations are reported
    # and, in strict mode, the row is downgraded for counting so the aggregate
    # never includes a build-only "evaluated" row.
    evaluated_violations: list[dict[str, Any]] = []
    if strict:
        for record in records:
            meta = record["metadata"]
            v = evaluated_row_violations(meta)
            if v:
                evaluated_violations.append({
                    "target": record["row"].get("target", ""),
                    "generator": record["row"].get("generator", ""),
                    "violations": v,
                })
    statuses = collections.Counter((r["metadata"].get("status") or r["row"].get("status") or "missing_metadata") for r in records)
    # Determine which records are excluded from aggregate (compat-smoke or
    # explicitly flagged). Excluded rows are still counted in total and
    # per-status, but never in completed/failed scientific aggregates.
    aggregate_records: list[dict[str, Any]] = []
    excluded_records: list[dict[str, Any]] = []
    for record in records:
        meta = record["metadata"]
        excluded = bool(meta.get("excluded_from_aggregate"))
        profile = str(meta.get("profile") or meta.get("ckgfuzzer_profile") or "")
        if profile == "compat-smoke":
            excluded = True
        if excluded:
            excluded_records.append(record)
        else:
            aggregate_records.append(record)
    agg_statuses = collections.Counter(
        (r["metadata"].get("status") or r["row"].get("status") or "missing_metadata")
        for r in aggregate_records
    )
    completed = 0
    for r in aggregate_records:
        meta = r["metadata"]
        status_s = str(meta.get("status") or r["row"].get("status") or "missing_metadata")
        family = str(meta.get("task_family") or meta.get("capability") or "harness_generator")
        # For harness generators, only "evaluated" counts as completed.
        # "completed", "dry_run_ok" are not successful evaluations.
        if family == "harness_generator":
            if status_s in HARNESS_GENERATOR_STRICT_COMPLETED:
                completed += 1
        else:
            if status_s in COMPLETED_STATUSES:
                completed += 1
    partial_completed = sum(agg_statuses[s] for s in PARTIAL_STATUSES)
    not_applicable = sum(agg_statuses[s] for s in NOT_APPLICABLE_STATUSES)
    # not_applicable_pairs counts Invalid/not_applicable rows across ALL records
    # (including excluded ones) so an excluded Invalid ELFuzz row still counts as
    # not-applicable rather than vanishing from the valuable-set breakdown
    # (plan elfuzz_reproduction_delta.md section 2).
    not_applicable_pairs = sum(
        1 for r in records
        if (r["metadata"].get("status") or r["row"].get("status") or "missing_metadata") in NOT_APPLICABLE_STATUSES
    )
    soft_skipped = sum(count for status, count in agg_statuses.items() if status in SOFT_STATUSES)
    missing_api_key = agg_statuses.get("missing_api_key", 0)
    excluded_count = len(excluded_records)
    failed = len(aggregate_records) - completed - partial_completed - not_applicable - soft_skipped - missing_api_key
    harness_counts: collections.Counter[str] = collections.Counter()
    build_script_counts: collections.Counter[str] = collections.Counter()
    log_candidate_counts: collections.Counter[str] = collections.Counter()
    input_counts: collections.Counter[str] = collections.Counter()
    task_family_counts: collections.Counter[str] = collections.Counter()
    status_counts_by_task_family: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    reasons: collections.Counter[str] = collections.Counter()
    remediation_counts: collections.Counter[str] = collections.Counter()
    api_trace_total_count = 0
    api_trace_sample_count = 0
    applicable_evaluated = 0
    applicable_quality_failure = 0
    applicable_infra_failure = 0
    coverage_by_applicable_evaluated: list[dict[str, Any]] = []
    ckgfuzzer_target_rows: list[dict[str, Any]] = []
    # OSS-Fuzz-Gen reproduction-delta per-target rows (plan section 7).
    ofg_target_rows: list[dict[str, Any]] = []
    # G2Fuzz paper-core/extension split (plan g2fuzz_reproduction_delta.md
    # section 7).  paper-core and extension results are aggregated separately
    # and never combined into one paper-equivalent ranking.
    g2fuzz_paper_core_evaluated = 0
    g2fuzz_extension_evaluated = 0
    g2fuzz_failures = 0
    g2fuzz_infra_failures = 0
    for record in records:
        meta = record["metadata"]
        gen = meta.get("generator") or meta.get("fuzzer") or record["row"].get("generator") or "unknown"
        status_s = str(meta.get("status") or record["row"].get("status") or "missing_metadata")
        family = str(meta.get("task_family") or meta.get("capability") or ("input_generator" if gen in {"g2fuzz", "elfuzz"} else "harness_generator"))
        task_family_counts[family] += 1
        status_counts_by_task_family[family][status_s] += 1
        # Collect per-target CKGFuzzer matrix rows (plan section 9).
        if gen == "ckgfuzzer":
            ckgfuzzer_target_rows.append(extract_ckgfuzzer_row(meta))
        # Collect per-target OSS-Fuzz-Gen reproduction-delta rows (plan
        # oss-fuzz-gen_reproduction_delta.md section 7).
        if gen == "oss-fuzz-gen":
            ofg_target_rows.append(extract_ofg_row(meta))
        # Aggregate artifact counts by task family so harness and input
        # generators never share a single counter.
        harness_counts[gen] += int(meta.get("generated_harness_count") or meta.get("generated_driver_count") or 0)
        build_script_counts[gen] += int(meta.get("generated_build_script_count") or 0)
        log_candidate_counts[gen] += int(meta.get("generated_log_candidate_count") or 0)
        input_counts[gen] += int(meta.get("generated_input_count") or meta.get("generated_seed_count") or 0)
        api_trace_total_count += int(meta.get("api_trace_total_count") or 0)
        api_trace_sample_count += int(meta.get("api_trace_sample_count") or 0)
        reason = meta.get("reason") or record["row"].get("status") or "unknown"
        if reason and reason != "none":
            reason_s = str(reason)
            reasons[reason_s] += 1
            if status_s not in COMPLETED_STATUSES:
                remediation_counts[remediation_for(status_s, reason_s)] += 1
        # Applicable-row breakdown: Invalid (not_applicable) rows are excluded
        # from the success/failure denominator and from coverage aggregates.
        if status_s not in NOT_APPLICABLE_STATUSES and not bool(meta.get("excluded_from_aggregate")) and str(meta.get("applicability", "")) != "Invalid":
            if status_s == "evaluated":
                applicable_evaluated += 1
                cov = meta.get("coverage") or {}
                if isinstance(cov, dict) and cov:
                    coverage_by_applicable_evaluated.append(
                        {"target": meta.get("target", ""), "generator": gen, "coverage": cov}
                    )
            elif status_s == "quality_failure":
                applicable_quality_failure += 1
            elif status_s == "infra_failure":
                applicable_infra_failure += 1
        # G2Fuzz paper-core/extension split (plan section 7).  Count only
        # applicable, non-excluded rows.  method_variant distinguishes
        # paper-core from extension; fall back to method_profile/paper_core.
        if gen == "g2fuzz" and status_s not in NOT_APPLICABLE_STATUSES and not bool(meta.get("excluded_from_aggregate")) and str(meta.get("applicability", "")) != "Invalid":
            variant = str(meta.get("method_variant") or "")
            if not variant:
                variant = "paper-core" if (meta.get("paper_core") or str(meta.get("method_profile", "")) == "paper-faithful") else "extension"
            if status_s == "evaluated":
                if variant == "paper-core":
                    g2fuzz_paper_core_evaluated += 1
                else:
                    g2fuzz_extension_evaluated += 1
            elif status_s == "infra_failure":
                g2fuzz_infra_failures += 1
            elif status_s not in COMPLETED_STATUSES and status_s not in PARTIAL_STATUSES and status_s not in SOFT_STATUSES:
                g2fuzz_failures += 1
    # applicable_pairs counts rows that are applicable (not not_applicable and
    # not Invalid) across ALL records, mirroring not_applicable_pairs so the two
    # sum to the valuable-set size regardless of exclude_from_aggregate.
    applicable_pairs = sum(
        1 for r in records
        if (r["metadata"].get("status") or r["row"].get("status") or "missing_metadata") not in NOT_APPLICABLE_STATUSES
        and str(r["metadata"].get("applicability", "")) != "Invalid"
    )
    # method_profile split (G2Fuzz beta plan section 3): paper-faithful and
    # extension aggregates are reported separately when --split-by method_profile.
    method_profile_groups: dict[str, dict[str, Any]] = {}
    if split_by == "method_profile":
        for record in records:
            meta = record["metadata"]
            profile = str(meta.get("method_profile") or "")
            if not profile:
                continue
            group = method_profile_groups.setdefault(profile, {"total": 0, "evaluated": 0, "quality_failure": 0, "infra_failure": 0, "other": 0})
            group["total"] += 1
            status_s = str(meta.get("status") or record["row"].get("status") or "missing_metadata")
            if status_s == "evaluated":
                group["evaluated"] += 1
            elif status_s == "quality_failure":
                group["quality_failure"] += 1
            elif status_s == "infra_failure":
                group["infra_failure"] += 1
            else:
                group["other"] += 1
    return {
        "matrix_dir": str(matrix_dir),
        "split_by": split_by,
        "method_profile_groups": method_profile_groups,
        "total_pairs": total,
        "aggregate_pairs": len(aggregate_records),
        "excluded_pairs": excluded_count,
        "completed_pairs": completed,
        "failed_pairs": failed,
        "partial_completed_pairs": partial_completed,
        "soft_skipped_pairs": soft_skipped,
        "not_applicable_pairs": not_applicable_pairs,
        "applicable_pairs": applicable_pairs,
        "applicable_evaluated_pairs": applicable_evaluated,
        "applicable_quality_failure_pairs": applicable_quality_failure,
        "applicable_infra_failure_pairs": applicable_infra_failure,
        # G2Fuzz paper-core/extension split (plan g2fuzz_reproduction_delta.md
        # section 7).  Reported separately; never combined into one ranking.
        "g2fuzz_paper_core_evaluated": g2fuzz_paper_core_evaluated,
        "g2fuzz_extension_evaluated": g2fuzz_extension_evaluated,
        "g2fuzz_failures": g2fuzz_failures,
        "g2fuzz_infra_failures": g2fuzz_infra_failures,
        "coverage_by_applicable_evaluated": coverage_by_applicable_evaluated,
        "missing_api_key_count": missing_api_key,
        "require_evaluated_violations": require_evaluated_violations,
        "statuses": dict(statuses),
        "aggregate_statuses": dict(agg_statuses),
        "generated_harness_counts_by_generator": dict(harness_counts),
        "generated_build_script_counts_by_generator": dict(build_script_counts),
        "generated_log_candidate_counts_by_generator": dict(log_candidate_counts),
        "generated_input_counts_by_generator": dict(input_counts),
        "task_family_counts": dict(task_family_counts),
        "status_counts_by_task_family": {family: dict(counter) for family, counter in status_counts_by_task_family.items()},
        "api_trace_total_count": api_trace_total_count,
        "api_trace_sample_count": api_trace_sample_count,
        "top_failure_reasons": reasons.most_common(10),
        "top_remediations": remediation_counts.most_common(10),
        "storage": storage_report(matrix_dir, records),
        "evaluated_row_violations": evaluated_violations,
        "ckgfuzzer_target_rows": ckgfuzzer_target_rows,
        "ckgfuzzer_paper_equivalent_delta": sum(1 for r in ckgfuzzer_target_rows if r.get("paper_equivalent_delta")),
        "ckgfuzzer_paper_equivalent_epsilon": sum(1 for r in ckgfuzzer_target_rows if r.get("paper_equivalent_epsilon")),
        "ckgfuzzer_paper_equivalent_strict": sum(1 for r in ckgfuzzer_target_rows if r.get("paper_equivalent_strict")),
        # OSS-Fuzz-Gen reproduction-delta/epsilon per-target rows and the count
        # of paper-equivalent rows (plan oss-fuzz-gen_reproduction_delta.md
        # section 7).  Compatibility-fallback rows are reported separately and
        # never counted as paper-equivalent.
        "ofg_target_rows": ofg_target_rows,
        "ofg_paper_equivalent_delta": sum(1 for r in ofg_target_rows if r.get("paper_equivalent_delta")),
        "ofg_paper_equivalent_epsilon": sum(1 for r in ofg_target_rows if r.get("paper_equivalent_epsilon")),
        "ofg_paper_equivalent_strict": sum(1 for r in ofg_target_rows if r.get("paper_equivalent_strict")),
        "ofg_compat_fallback_rows": [
            r for r in ofg_target_rows
            if str(r.get("profile", "")) in STRICT_REPRODUCTION_PROFILES and bool(r.get("exclude_from_aggregate"))
        ],
    }


def write_outputs(matrix_dir: Path, summary: dict[str, Any]) -> None:
    (matrix_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (matrix_dir / "summary.tsv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter="\t")
        writer.writerow(["metric", "value"])
        for key in (
            "total_pairs",
            "aggregate_pairs",
            "excluded_pairs",
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
        f"- Aggregate pairs (scientific): `{summary.get('aggregate_pairs', summary['total_pairs'])}`",
        f"- Excluded pairs (compat-smoke): `{summary.get('excluded_pairs', 0)}`",
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
    if summary.get("task_family_counts"):
        lines.extend(["", "## Task Families", ""])
        by_family = summary.get("status_counts_by_task_family", {})
        for family, count in sorted(summary["task_family_counts"].items()):
            statuses = by_family.get(family, {})
            evaluated = statuses.get("evaluated", 0)
            if family == "harness_generator":
                completed_family = evaluated
            else:
                completed_family = sum(statuses.get(status, 0) for status in COMPLETED_STATUSES)
            lines.append(f"- `{family}`: {count} pairs, {completed_family} completed/evaluated, {evaluated} evaluated")
    groups = summary.get("method_profile_groups", {})
    if groups:
        lines.extend(["", "## Method Profile Groups", ""])
        for profile, group in sorted(groups.items()):
            lines.append(
                f"- `{profile}`: {group.get('total', 0)} pairs, "
                f"{group.get('evaluated', 0)} evaluated, "
                f"{group.get('quality_failure', 0)} quality_failure, "
                f"{group.get('infra_failure', 0)} infra_failure, "
                f"{group.get('other', 0)} other"
            )
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
    parser.add_argument("--strict", action="store_true",
                        help="validate evaluated rows have coverage and execs_done>0")
    parser.add_argument("--generators", default="")
    parser.add_argument("--targets", default="")
    parser.add_argument("--split-by", dest="split_by", default="",
                        help="split aggregates by a metadata field (e.g. method_profile)")
    parser.add_argument("--generator", default="",
                        help="filter rows by generator name (e.g. g2fuzz)")
    parser.add_argument("--target-set", dest="target_set", default="",
                        help="filter rows by a named target set from fuzzbench_targets.json (e.g. valuable)")
    parser.add_argument("--task-family", dest="task_family", default="",
                        help="filter rows by task family (e.g. input_generator)")
    parser.add_argument("--profile", default="",
                        help="filter rows by profile (e.g. reproduction-gamma)")
    parser.add_argument("--method-profile", dest="method_profile", default="",
                        help="filter rows by method profile (e.g. paper-faithful or extension)")
    parser.add_argument("--require-evaluated", action="store_true",
                        help="require every applicable harness-generator row to be evaluated; exit nonzero otherwise")
    args = parser.parse_args()
    matrix_dir = Path(args.matrix_dir).resolve()
    matrix_dir.mkdir(parents=True, exist_ok=True)
    summary = collect(
        matrix_dir,
        strict=args.strict,
        split_by=args.split_by,
        generator=args.generator,
        target_set=args.target_set,
        task_family=args.task_family,
        profile=args.profile,
        method_profile=args.method_profile,
        require_evaluated=args.require_evaluated,
    )
    write_outputs(matrix_dir, summary)
    if args.strict and summary.get("evaluated_row_violations"):
        print(f"ERROR: {len(summary['evaluated_row_violations'])} evaluated row(s) lack coverage/execs:", file=sys.stderr)
        for v in summary["evaluated_row_violations"]:
            print(f"  {v['generator']}/{v['target']}: {'; '.join(v['violations'])}", file=sys.stderr)
        return 2
    if args.require_evaluated and summary.get("require_evaluated_violations"):
        print(f"ERROR: {len(summary['require_evaluated_violations'])} applicable harness-generator row(s) are not evaluated:", file=sys.stderr)
        for v in summary["require_evaluated_violations"]:
            print(f"  {v['generator']}/{v['target']}: status={v['status']}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
