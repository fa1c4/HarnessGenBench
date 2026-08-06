from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


profile = _load_module("ckgfuzzer_profile", "docker/common/ckgfuzzer_profile.py")


# ---------------------------------------------------------------------------
# 1. alpha refuses mock embedding and local summary/combination flags.
# ---------------------------------------------------------------------------


def test_alpha_refuses_mock_embedding() -> None:
    violations = profile.validate_profile("alpha", "blind-project", {
        "CKGFUZZER_EMBEDDING_MODEL": "mock",
    })
    assert any("mock" in v.lower() or "embedding" in v.lower() for v in violations)


def test_alpha_refuses_local_api_summary() -> None:
    violations = profile.validate_profile("alpha", "blind-project", {
        "CKGFUZZER_EMBEDDING_MODEL": "openai-text-embedding-3-small",
        "CKGFUZZER_LOCAL_API_SUMMARY": "1",
    })
    assert any("LOCAL_API_SUMMARY" in v for v in violations)


def test_alpha_refuses_local_api_combination() -> None:
    violations = profile.validate_profile("alpha", "blind-project", {
        "CKGFUZZER_EMBEDDING_MODEL": "openai-text-embedding-3-small",
        "CKGFUZZER_LOCAL_API_COMBINATION": "1",
    })
    assert any("LOCAL_API_COMBINATION" in v for v in violations)


def test_alpha_refuses_empty_embedding_model() -> None:
    violations = profile.validate_profile("alpha", "blind-project", {
        "CKGFUZZER_EMBEDDING_MODEL": "",
    })
    assert any("embedding" in v.lower() for v in violations)


def test_alpha_accepts_real_embedding() -> None:
    violations = profile.validate_profile("alpha", "blind-project", {
        "CKGFUZZER_EMBEDDING_MODEL": "openai-text-embedding-3-small",
    })
    assert violations == []


# ---------------------------------------------------------------------------
# 2. compat-smoke is explicitly excluded from aggregate.
# ---------------------------------------------------------------------------


def test_compat_smoke_result_excluded_from_aggregate() -> None:
    result = profile.build_result(
        profile="compat-smoke",
        protocol="blind-project",
        target="test_target",
        stages={n: "completed" for n in profile.STAGE_NAMES},
    )
    assert result["excluded_from_aggregate"] is True
    assert result["method_variant"] == "compat-smoke"


def test_alpha_result_not_excluded_from_aggregate() -> None:
    result = profile.build_result(
        profile="alpha",
        protocol="blind-project",
        target="test_target",
        stages={n: "completed" for n in profile.STAGE_NAMES},
    )
    assert result["excluded_from_aggregate"] is False
    assert result["method_variant"] == "alpha"


# ---------------------------------------------------------------------------
# 3. CKG generator mount cannot access evaluator-only paths.
# ---------------------------------------------------------------------------


def test_blind_generator_isolation_in_common_sh() -> None:
    common = (REPO_ROOT / "scripts/lib/common.sh").read_text(encoding="utf-8")
    # The host runner must conditionally include HGB_TARGET_REFERENCE_DIR.
    assert "reference_dir_args" in common
    assert "hgb_generator_is_blind" in common


def test_entrypoint_blind_project_ignores_reference_dir() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert "blind-project" in entrypoint
    assert "reference_isolation" in entrypoint
    assert "hgb_neutral_usage.c" in entrypoint


def test_common_sh_does_not_unconditionally_export_reference_dir() -> None:
    common = (REPO_ROOT / "scripts/lib/common.sh").read_text(encoding="utf-8")
    # The unconditional -e HGB_TARGET_REFERENCE_DIR line should be gone;
    # it is now inside reference_dir_args which is conditional.
    assert "reference_dir_args+=(-e HGB_TARGET_REFERENCE_DIR" in common


# ---------------------------------------------------------------------------
# 4. selected-reference API metadata is never read in blind mode.
# ---------------------------------------------------------------------------


def test_entrypoint_blind_mode_does_not_use_selected_harness_report() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    # In blind-project, the api-report and report-mode should be cleared.
    assert 'HGB_SELECTED_API_REPORT=""' in entrypoint
    assert 'HGB_API_REPORT_MODE=""' in entrypoint
    # The extract args should not pass reference-dir in blind-project.
    assert '"$ckg_protocol" != "blind-project"' in entrypoint


def test_baseline_contract_defaults_to_blind_project() -> None:
    contracts = (REPO_ROOT / "metadata/baseline_contracts.yaml").read_text(encoding="utf-8")
    assert "ckgfuzzer" in contracts
    assert "harness_generator" in contracts
    assert "blind-project" in contracts
    assert "alpha" in contracts
    assert "paper-faithful" in contracts
    assert "compat-smoke" in contracts


# ---------------------------------------------------------------------------
# 5. a canary reference token never reaches CKG prompts/logs/API lists.
# ---------------------------------------------------------------------------


def test_canary_leakage_audit_detects_token(tmp_path: Path) -> None:
    canary = "HGB_REF_CANARY_testtoken123"
    gen_input = tmp_path / "generator_input"
    gen_input.mkdir()
    (gen_input / "api_list.json").write_text('["api_one"]', encoding="utf-8")
    (gen_input / "prompt.txt").write_text("normal prompt", encoding="utf-8")

    # No leakage.
    result = profile.audit_leakage(gen_input, canary)
    assert result["leaked"] is False

    # Inject canary into a file.
    (gen_input / "leaked.txt").write_text(f"prefix {canary} suffix", encoding="utf-8")
    result = profile.audit_leakage(gen_input, canary)
    assert result["leaked"] is True
    assert result["hit_count"] >= 1
    assert any("leaked.txt" in h["file"] for h in result["hits"])


def test_entrypoint_has_leakage_audit_hook() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert "HGB_REF_CANARY" in entrypoint
    assert "ckgfuzzer_profile.py audit" in entrypoint
    assert "ckg_reference_leakage" in entrypoint


# ---------------------------------------------------------------------------
# 6. an empty CodeQL graph fails before generation.
# ---------------------------------------------------------------------------


def test_empty_graph_fails_in_alpha() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert "ckg_method_faithful" in entrypoint
    assert "alpha/paper-faithful does not allow source-only fallback" in entrypoint
    assert "hgb_result_set_stage" in entrypoint
    assert "knowledge_graph failed" in entrypoint


def test_result_status_failed_for_empty_graph() -> None:
    stages = profile.default_stages()
    profile.mark_stage(stages, "target_prepared", "completed")
    profile.mark_stage(stages, "codeql_database", "completed")
    profile.mark_stage(stages, "knowledge_graph", "failed")
    assert profile.result_status_from_stages(stages) == "failed"


# ---------------------------------------------------------------------------
# 7. a valid fake CodeQL graph reaches generation.
# ---------------------------------------------------------------------------


def test_valid_graph_reaches_generation_in_entrypoint() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    # Graph validation should mark knowledge_graph completed on success.
    assert "knowledge_graph completed" in entrypoint
    # And should proceed to generation.
    assert "generation completed" in entrypoint


def test_result_status_evaluated_for_all_completed() -> None:
    stages = {n: "completed" for n in profile.STAGE_NAMES}
    assert profile.result_status_from_stages(stages) == "evaluated"


# ---------------------------------------------------------------------------
# 8. generation command uses compilation checking, not --skip_check_compilation.
# ---------------------------------------------------------------------------


def test_alpha_does_not_skip_compilation_check() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert "ckg_compilation_args" in entrypoint
    assert "ckg_method_faithful" in entrypoint
    # In method-faithful mode, --skip_check_compilation is NOT added.
    assert 'ckg_compilation_args+=(--skip_check_compilation)' in entrypoint
    # The condition guards it: only when NOT method-faithful.
    assert 'if [[ "$ckg_method_faithful" != "1" ]]' in entrypoint


def test_run_baseline_refuses_skip_check_compilation_in_alpha() -> None:
    runner = (REPO_ROOT / "scripts/hgb_run_baseline.sh").read_text(encoding="utf-8")
    assert "CKGFUZZER_SKIP_CHECK_COMPILATION" in runner
    assert "forbidden" in runner.lower() or "forbidden" in runner


# ---------------------------------------------------------------------------
# 9. compiler-wrapper diagnostics are returned to a fake repair loop.
# ---------------------------------------------------------------------------


def test_entrypoint_preserves_repair_diagnostics() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    # The runtime patch should preserve non-string error handling.
    assert "non-string result from check_compilation" in entrypoint
    assert "lowered_result" in entrypoint


# ---------------------------------------------------------------------------
# 10. no-op candidate fails API reachability.
# ---------------------------------------------------------------------------


def test_no_reachability_means_not_evaluated() -> None:
    stages = profile.default_stages()
    for s in profile.STAGE_NAMES:
        profile.mark_stage(stages, s, "completed")
    profile.mark_stage(stages, "api_reachability", "failed")
    assert profile.result_status_from_stages(stages) == "failed"


def test_entrypoint_tracks_api_reachability_stage() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert "api_reachability" in entrypoint


# ---------------------------------------------------------------------------
# 11. native-build-valid candidate reaches `evaluated` in a fixture target.
# ---------------------------------------------------------------------------


def test_all_stages_completed_yields_evaluated() -> None:
    stages = {n: "completed" for n in profile.STAGE_NAMES}
    result = profile.build_result(
        profile="alpha",
        protocol="blind-project",
        target="fixture_target",
        stages=stages,
    )
    assert result["status"] == "evaluated"
    assert result["stages"]["candidate_build"] == "completed"
    assert result["stages"]["sanitizer_smoke"] == "completed"
    assert result["stages"]["campaign"] == "completed"
    assert result["stages"]["coverage"] == "completed"


# ---------------------------------------------------------------------------
# 12. every current valuable target has a valid preflight/override decision.
# ---------------------------------------------------------------------------


def test_all_valuable_targets_have_preflight_decision() -> None:
    import json
    registry = json.loads((REPO_ROOT / "metadata/fuzzbench_targets.json").read_text(encoding="utf-8"))
    valuable = registry.get("target_sets", {}).get("valuable", {}).get("targets", [])
    assert len(valuable) == 20, f"expected 20 valuable targets, got {len(valuable)}"
    overrides = profile.load_target_overrides(REPO_ROOT / "metadata")
    for target in valuable:
        result = profile.preflight_target(target, overrides)
        assert result["valid"], f"target {target} preflight failed: {result.get('reason')}"


def test_target_overrides_file_exists() -> None:
    path = REPO_ROOT / "metadata/ckgfuzzer_target_overrides.yaml"
    assert path.is_file(), f"missing target overrides: {path}"
    overrides = profile.load_target_overrides(REPO_ROOT / "metadata")
    assert "targets" in overrides
    assert len(overrides["targets"]) >= 20


def test_target_overrides_have_no_harness_source() -> None:
    """The overrides file must not contain target harness source or API names."""
    overrides = profile.load_target_overrides(REPO_ROOT / "metadata")
    targets = overrides.get("targets", {})
    assert len(targets) >= 20
    for target_name, entry in targets.items():
        # No target entry should contain harness source code or API call sequences.
        for key, value in entry.items():
            if isinstance(value, str):
                assert "LLVMFuzzerTestOneInput" not in value, f"{target_name}.{key} contains harness source"
                assert "LLVMFuzzerInitialize" not in value, f"{target_name}.{key} contains harness source"
            elif isinstance(value, list):
                for item in value:
                    assert "LLVMFuzzerTestOneInput" not in str(item), f"{target_name}.{key} contains harness source"


# ---------------------------------------------------------------------------
# 13. matrix collector treats only `evaluated` as completed for CKG alpha.
# ---------------------------------------------------------------------------


def _make_matrix_dir(tmp_path: Path, rows: list[dict]) -> Path:
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    matrix_file = matrix_dir / "matrix.tsv"
    header = "generator\ttarget\tstatus\tmetadata\n"
    lines = [header]
    for row in rows:
        lines.append(f"{row['generator']}\t{row['target']}\t{row['status']}\t{row['metadata']}\n")
    matrix_file.write_text("".join(lines), encoding="utf-8")
    return matrix_dir


def _write_metadata(tmp_path: Path, name: str, data: dict) -> str:
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_matrix_collector_only_counts_evaluated_for_harness_generator(tmp_path: Path) -> None:
    collector = _load_module("hgb_collect_matrix", "scripts/hgb_collect_matrix.py")
    meta1 = _write_metadata(tmp_path, "meta1", {
        "generator": "ckgfuzzer",
        "task_family": "harness_generator",
        "profile": "alpha",
        "status": "evaluated",
    })
    meta2 = _write_metadata(tmp_path, "meta2", {
        "generator": "ckgfuzzer",
        "task_family": "harness_generator",
        "profile": "alpha",
        "status": "completed",
    })
    meta3 = _write_metadata(tmp_path, "meta3", {
        "generator": "ckgfuzzer",
        "task_family": "harness_generator",
        "profile": "alpha",
        "status": "partial_completed",
    })
    rows = [
        {"generator": "ckgfuzzer", "target": "t1", "status": "evaluated", "metadata": meta1},
        {"generator": "ckgfuzzer", "target": "t2", "status": "completed", "metadata": meta2},
        {"generator": "ckgfuzzer", "target": "t3", "status": "partial_completed", "metadata": meta3},
    ]
    matrix_dir = _make_matrix_dir(tmp_path, rows)
    summary = collector.collect(matrix_dir)
    assert summary["total_pairs"] == 3
    # Only "evaluated" counts as completed for harness_generator alpha.
    assert summary["completed_pairs"] == 1
    assert summary["partial_completed_pairs"] == 1
    assert summary["failed_pairs"] == 1


def test_matrix_collector_excludes_compat_smoke_from_aggregate(tmp_path: Path) -> None:
    collector = _load_module("hgb_collect_matrix", "scripts/hgb_collect_matrix.py")
    meta1 = _write_metadata(tmp_path, "meta1", {
        "generator": "ckgfuzzer",
        "task_family": "harness_generator",
        "profile": "compat-smoke",
        "status": "evaluated",
        "excluded_from_aggregate": True,
    })
    meta2 = _write_metadata(tmp_path, "meta2", {
        "generator": "ckgfuzzer",
        "task_family": "harness_generator",
        "profile": "alpha",
        "status": "evaluated",
    })
    rows = [
        {"generator": "ckgfuzzer", "target": "t1", "status": "evaluated", "metadata": meta1},
        {"generator": "ckgfuzzer", "target": "t2", "status": "evaluated", "metadata": meta2},
    ]
    matrix_dir = _make_matrix_dir(tmp_path, rows)
    summary = collector.collect(matrix_dir)
    assert summary["total_pairs"] == 2
    assert summary["excluded_pairs"] == 1
    assert summary["aggregate_pairs"] == 1
    assert summary["completed_pairs"] == 1


def test_matrix_collector_never_combines_task_families(tmp_path: Path) -> None:
    collector = _load_module("hgb_collect_matrix", "scripts/hgb_collect_matrix.py")
    meta1 = _write_metadata(tmp_path, "meta1", {
        "generator": "ckgfuzzer",
        "task_family": "harness_generator",
        "profile": "alpha",
        "status": "evaluated",
        "generated_harness_count": 1,
    })
    meta2 = _write_metadata(tmp_path, "meta2", {
        "generator": "g2fuzz",
        "task_family": "input_generator",
        "status": "evaluated",
        "generated_input_count": 10,
    })
    rows = [
        {"generator": "ckgfuzzer", "target": "t1", "status": "evaluated", "metadata": meta1},
        {"generator": "g2fuzz", "target": "t2", "status": "evaluated", "metadata": meta2},
    ]
    matrix_dir = _make_matrix_dir(tmp_path, rows)
    summary = collector.collect(matrix_dir)
    assert summary["task_family_counts"]["harness_generator"] == 1
    assert summary["task_family_counts"]["input_generator"] == 1
    # Harness and input counts are separate.
    assert summary["generated_harness_counts_by_generator"]["ckgfuzzer"] == 1
    assert summary["generated_input_counts_by_generator"]["g2fuzz"] == 10
    # g2fuzz has no harness count (or zero), ckgfuzzer has no input count (or zero).
    assert summary["generated_harness_counts_by_generator"].get("g2fuzz", 0) == 0
    assert summary["generated_input_counts_by_generator"].get("ckgfuzzer", 0) == 0
