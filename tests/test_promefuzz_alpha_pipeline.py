from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "docker/common"))


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


profile = _load_module("promefuzz_profile", "docker/common/promefuzz_profile.py")
build_context = _load_module("promefuzz_build_context", "docker/common/promefuzz_build_context.py")
evaluator = _load_module("promefuzz_evaluator", "docker/common/promefuzz_evaluator.py")


# ---------------------------------------------------------------------------
# Fixture: a tiny C library with a CMake build, an example consumer, a
# generated header, a static library, and a fuzz target. Exercises the full
# build-context path without external services.
# ---------------------------------------------------------------------------


def _make_fixture_target(tmp_path: Path) -> tuple[Path, Path]:
    src = tmp_path / "project"
    src.mkdir()
    (src / "lib").mkdir()
    (src / "lib" / "foo.h").write_text(
        "#ifndef FOO_H\n#define FOO_H\nint foo(const char *s, int n);\nint bar(int);\n#endif\n",
        encoding="utf-8",
    )
    (src / "lib" / "foo.c").write_text(
        '#include "foo.h"\nint foo(const char *s, int n){ int r=0; for(int i=0;i<n;i++) r^=s[i]; return r; }\n'
        "int bar(int x){ return x * 3; }\n",
        encoding="utf-8",
    )
    (src / "examples").mkdir()
    (src / "examples" / "use_foo.c").write_text(
        '#include "../lib/foo.h"\nint main(void){ return foo("abc",3) + bar(1); }\n',
        encoding="utf-8",
    )
    (src / "fuzz_foo.c").write_text(
        "#include <stdint.h>\n#include <stddef.h>\n#include \"lib/foo.h\"\n"
        "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){ return foo((const char*)d, (int)n); }\n",
        encoding="utf-8",
    )
    (src / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.10)\nproject(foo C)\n"
        "add_library(foo STATIC lib/foo.c)\n"
        "target_include_directories(foo PUBLIC lib)\n"
        "add_executable(use_foo examples/use_foo.c)\n"
        "target_link_libraries(use_foo foo)\n",
        encoding="utf-8",
    )
    target_root = tmp_path / "target"
    (target_root / "source_input").mkdir(parents=True)
    shutil.copytree(src, target_root / "source_input" / "foo", dirs_exist_ok=True)
    bench = target_root / "fuzzbench_benchmark"
    bench.mkdir()
    (bench / "build.sh").write_text(
        "cd $SRC/foo && cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON && cmake --build build\n",
        encoding="utf-8",
    )
    (bench / "Dockerfile").write_text("FROM base\nWORKDIR $SRC/foo\n", encoding="utf-8")
    (target_root / "target_manifest.json").write_text(
        json.dumps({
            "selected_reference_harness_files": ["source_input/foo/fuzz_foo.c"],
            "project": "foo", "fuzz_target": "fuzz_foo", "target": "foo_fuzz_foo",
        }),
        encoding="utf-8",
    )
    ref = target_root / "reference_harnesses" / "selected"
    ref.mkdir(parents=True)
    (ref / "fuzz_foo.c").write_text(
        "// HGB_REF_CANARY_LEAK_TOKEN\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){return 0;}\n",
        encoding="utf-8",
    )
    return target_root, target_root / "source_input" / "foo"


# ---------------------------------------------------------------------------
# 1. generator/evaluator mount isolation and canary leakage prevention
# ---------------------------------------------------------------------------


def test_blind_generator_isolation_includes_promefuzz() -> None:
    common = (REPO_ROOT / "scripts/lib/common.sh").read_text(encoding="utf-8")
    assert "reference_dir_args" in common
    assert "hgb_generator_is_blind" in common
    assert "promefuzz" in common


def test_entrypoint_blind_project_ignores_reference_dir() -> None:
    entrypoint = (REPO_ROOT / "docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")
    assert "blind-project" in entrypoint
    assert "reference_isolation" in entrypoint
    # The selected-harness API report and report mode are cleared.
    assert 'HGB_SELECTED_API_REPORT=""' in entrypoint
    assert 'HGB_API_REPORT_MODE' in entrypoint
    # extract_api_list is never passed --reference-dir in blind/api-oracle.
    assert "--reference-dir" not in entrypoint


def test_canary_leakage_audit_detects_token(tmp_path: Path) -> None:
    canary = "HGB_REF_CANARY_testtoken123"
    gen_input = tmp_path / "generator_input"
    gen_input.mkdir()
    (gen_input / "api.json").write_text('["foo"]', encoding="utf-8")
    result = profile.audit_leakage(gen_input, canary)
    assert result["leaked"] is False
    (gen_input / "leaked.txt").write_text(f"prefix {canary} suffix", encoding="utf-8")
    result = profile.audit_leakage(gen_input, canary)
    assert result["leaked"] is True
    assert result["hit_count"] >= 1


def test_entrypoint_has_leakage_audit_hook() -> None:
    entrypoint = (REPO_ROOT / "docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")
    assert "HGB_REF_CANARY" in entrypoint
    assert "promefuzz_profile.py audit" in entrypoint
    assert "promefuzz_reference_leakage" in entrypoint


# ---------------------------------------------------------------------------
# 2. alpha rejects selected-reference API reports
# ---------------------------------------------------------------------------


def test_alpha_rejects_selected_harness_fallback_mode() -> None:
    violations = profile.validate_profile("alpha", "blind-project", {
        "PROME_FUZZ_EMBEDDING_MODEL": "text-embedding-3-small",
        "PROME_FUZZ_EMBEDDING_LLM_TYPE": "openai",
        "HGB_API_SELECTION_MODE": "selected_harness_fallback",
    })
    assert any("HGB_API_SELECTION_MODE" in v for v in violations)


def test_alpha_rejects_report_first_mode() -> None:
    violations = profile.validate_profile("alpha", "blind-project", {
        "PROME_FUZZ_EMBEDDING_MODEL": "text-embedding-3-small",
        "PROME_FUZZ_EMBEDDING_LLM_TYPE": "openai",
        "HGB_API_REPORT_MODE": "report_first",
    })
    assert any("HGB_API_REPORT_MODE" in v for v in violations)


def test_run_baseline_refuses_selected_harness_in_alpha() -> None:
    runner = (REPO_ROOT / "scripts/hgb_run_baseline.sh").read_text(encoding="utf-8")
    assert "promefuzz" in runner
    assert "HGB_API_SELECTION_MODE" in runner
    assert "forbidden" in runner.lower()


# ---------------------------------------------------------------------------
# 3. alpha rejects synthetic compile DB
# ---------------------------------------------------------------------------


def test_alpha_rejects_synthetic_compile_db_env() -> None:
    violations = profile.validate_profile("alpha", "blind-project", {
        "PROME_FUZZ_EMBEDDING_MODEL": "text-embedding-3-small",
        "PROME_FUZZ_EMBEDDING_LLM_TYPE": "openai",
        "HGB_PROMEFUZZ_SYNTHETIC_COMPILE_DB": "1",
    })
    assert any("SYNTHETIC_COMPILE_DB" in v for v in violations)


def test_entrypoint_alpha_fails_on_missing_real_build_context() -> None:
    entrypoint = (REPO_ROOT / "docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")
    assert "promefuzz_build_context_failed" in entrypoint
    assert "promefuzz_method_faithful" in entrypoint
    # compat-smoke may still soft-skip; alpha must not.
    assert "hgb_soft_skip needs_compile_commands" in entrypoint


# ---------------------------------------------------------------------------
# 4. real fixture build capture yields a normalized non-empty compile DB
# ---------------------------------------------------------------------------


def test_real_fixture_capture_yields_nonempty_compile_db(tmp_path: Path) -> None:
    target_root, src = _make_fixture_target(tmp_path)
    work = tmp_path / "work"
    manifest = build_context.capture_build_context(
        target_root=target_root, work_dir=work, fuzz_target="fuzz_foo",
        language="c", profile="alpha", capture_method="cmake_export", source_root=src,
    )
    assert manifest["valid"] is True
    assert manifest["synthetic"] is False
    assert manifest["real_capture"] is True
    assert manifest["entry_count"] >= 2
    db = json.loads((work / "build_context" / "compile_commands.json").read_text(encoding="utf-8"))
    assert isinstance(db, list) and len(db) >= 2
    files = {Path(entry["file"]).name for entry in db}
    assert "foo.c" in files
    assert "use_foo.c" in files


# ---------------------------------------------------------------------------
# 5. generated files and real compile flags survive filtering
# ---------------------------------------------------------------------------


def test_compile_db_filtering_keeps_real_flags(tmp_path: Path) -> None:
    target_root, src = _make_fixture_target(tmp_path)
    work = tmp_path / "work"
    manifest = build_context.capture_build_context(
        target_root=target_root, work_dir=work, fuzz_target="fuzz_foo",
        language="c", profile="alpha", capture_method="cmake_export", source_root=src,
    )
    db = json.loads((work / "build_context" / "compile_commands.json").read_text(encoding="utf-8"))
    # At least one retained entry carries a real -I include flag from the build.
    has_include = any(
        any(arg.startswith("-I") for arg in build_context._parse_args_field(entry))
        for entry in db
    )
    assert has_include
    # The compile DB path is recorded and non-empty.
    assert Path(manifest["compile_commands_path"]).is_file()


def test_hgb_compile_db_filter_drops_probes_keeps_target_source(tmp_path: Path) -> None:
    compile_db_mod = _load_module("hgb_compile_db", "docker/common/hgb_compile_db.py")
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "library.cc").write_text("int library() { return 0; }\n", encoding="utf-8")
    cmake_dir = tmp_path / "build" / "CMakeFiles" / "3.28.0" / "CompilerIdCXX"
    cmake_dir.mkdir(parents=True)
    probe = cmake_dir / "CMakeCXXCompilerId.cpp"
    probe.write_text("int main() {}\n", encoding="utf-8")
    database = tmp_path / "compile_commands.json"
    database.write_text(json.dumps([
        {"directory": str(source_root), "file": str(source_root / "library.cc"), "command": "clang++ -c library.cc"},
        {"directory": str(cmake_dir), "file": str(probe), "command": "clang++ -c CMakeCXXCompilerId.cpp"},
        {"directory": str(source_root), "file": "missing.cc", "command": "clang++ -c missing.cc"},
    ]), encoding="utf-8")
    total, retained = compile_db_mod.filter_file(database, database, [source_root])
    assert (total, retained) == (3, 1)
    result = json.loads(database.read_text(encoding="utf-8"))
    assert [entry["file"] for entry in result] == [str(source_root / "library.cc")]


# ---------------------------------------------------------------------------
# 6. link extraction builds a minimal consumer
# ---------------------------------------------------------------------------


def test_link_extraction_builds_minimal_consumer(tmp_path: Path) -> None:
    target_root, src = _make_fixture_target(tmp_path)
    work = tmp_path / "work"
    manifest = build_context.capture_build_context(
        target_root=target_root, work_dir=work, fuzz_target="fuzz_foo",
        language="c", profile="alpha", capture_method="cmake_export", source_root=src,
    )
    # driver_build_args must contain the recovered static library path.
    assert any(arg.endswith("libfoo.a") for arg in manifest["driver_build_args"]), manifest["driver_build_args"]
    probe = tmp_path / "linkprobe"
    ok, msg = build_context.verify_link_set(
        source_root=src, driver_build_args=manifest["driver_build_args"],
        work_dir=probe, language="c",
    )
    assert ok, msg


# ---------------------------------------------------------------------------
# 7. consumer manifest excludes all fuzz harnesses
# ---------------------------------------------------------------------------


def test_consumer_manifest_excludes_fuzz_harnesses(tmp_path: Path) -> None:
    target_root, src = _make_fixture_target(tmp_path)
    work = tmp_path / "work"
    manifest = build_context.capture_build_context(
        target_root=target_root, work_dir=work, fuzz_target="fuzz_foo",
        language="c", profile="alpha", capture_method="cmake_export", source_root=src,
    )
    cases = json.loads((work / "knowledge" / "consumer_cases.json").read_text(encoding="utf-8"))
    for case in cases["consumers"]:
        assert "fuzz_foo" not in case["file"]
        assert "LLVMFuzzerTestOneInput" not in Path(case["file"]).read_text(encoding="utf-8", errors="replace")
    # The example consumer is allowed.
    assert any(Path(c["file"]).name == "use_foo.c" for c in cases["consumers"])


def test_consumer_manifest_excludes_explicit_fuzz_source(tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    (root / "normal.c").write_text("int normal(void){ return 1; }\n", encoding="utf-8")
    (root / "fuzz_target.c").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char *d, long n){ return 0; }\n",
        encoding="utf-8",
    )
    manifest = build_context.build_consumer_manifest(root)
    names = {Path(c["file"]).name for c in manifest["consumers"]}
    assert "normal.c" in names
    assert "fuzz_target.c" not in names


# ---------------------------------------------------------------------------
# 8. alpha uses real embedding interface; compat-smoke alone may use hash
# ---------------------------------------------------------------------------


def test_alpha_rejects_mock_embedding() -> None:
    violations = profile.validate_profile("alpha", "blind-project", {
        "PROME_FUZZ_EMBEDDING_MODEL": "hgb-hash-embedding",
        "PROME_FUZZ_EMBEDDING_LLM_TYPE": "mock",
    })
    assert any("embedding" in v.lower() for v in violations)


def test_alpha_rejects_hash_embedding_model() -> None:
    violations = profile.validate_profile("alpha", "blind-project", {
        "PROME_FUZZ_EMBEDDING_MODEL": "hgb-hash-embedding",
        "PROME_FUZZ_EMBEDDING_LLM_TYPE": "openai",
    })
    assert any("embedding" in v.lower() for v in violations)


def test_alpha_accepts_real_embedding() -> None:
    violations = profile.validate_profile("alpha", "blind-project", {
        "PROME_FUZZ_EMBEDDING_MODEL": "text-embedding-3-small",
        "PROME_FUZZ_EMBEDDING_LLM_TYPE": "openai",
    })
    assert violations == []


def test_compat_smoke_result_excluded_from_aggregate() -> None:
    result = profile.build_result(
        profile="compat-smoke", protocol="blind-project", target="t",
        stages={n: "completed" for n in profile.STAGE_NAMES},
    )
    assert result["excluded_from_aggregate"] is True
    assert result["method_variant"] == "compat-smoke"


def test_alpha_result_not_excluded_from_aggregate() -> None:
    result = profile.build_result(
        profile="alpha", protocol="blind-project", target="t",
        stages={n: "completed" for n in profile.STAGE_NAMES},
    )
    assert result["excluded_from_aggregate"] is False
    assert result["status"] == "evaluated"


def test_entrypoint_alpha_defaults_real_embedding() -> None:
    entrypoint = (REPO_ROOT / "docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")
    assert 'PROME_FUZZ_EMBEDDING_LLM_TYPE="${PROME_FUZZ_EMBEDDING_LLM_TYPE:-openai}"' in entrypoint
    assert 'PROME_FUZZ_EMBEDDING_LLM_TYPE="${PROME_FUZZ_EMBEDDING_LLM_TYPE:-mock}"' in entrypoint


# ---------------------------------------------------------------------------
# 9. preprocess/comprehend stage validation
# ---------------------------------------------------------------------------


def test_entrypoint_validates_preprocess_and_comprehend_stages() -> None:
    entrypoint = (REPO_ROOT / "docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")
    assert "api_preprocess completed" in entrypoint
    assert "knowledge completed" in entrypoint
    assert "promefuzz_no_api_candidates" in entrypoint


def test_stage_status_evaluated_only_when_all_complete() -> None:
    stages = profile.default_stages()
    assert profile.result_status_from_stages(stages) == "failed"
    for s in profile.STAGE_NAMES:
        profile.mark_stage(stages, s, "completed")
    assert profile.result_status_from_stages(stages) == "evaluated"
    profile.mark_stage(stages, "knowledge", "failed")
    assert profile.result_status_from_stages(stages) == "failed"


# ---------------------------------------------------------------------------
# 10. ALL-COVER command and budget selection
# ---------------------------------------------------------------------------


def test_entrypoint_has_all_cover_budgets_and_pool_size() -> None:
    entrypoint = (REPO_ROOT / "docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")
    assert "PROME_FUZZ_ALL_COVER_CANDIDATES" in entrypoint
    assert "PROME_FUZZ_ALL_COVER_MAX_WALL_SECONDS" in entrypoint
    assert "PROME_FUZZ_ALL_COVER_MAX_LLM_CALLS" in entrypoint
    assert "PROME_FUZZ_ALL_COVER_REPAIR_ATTEMPTS" in entrypoint
    assert "--pool-size" in entrypoint
    # Budgets default to nontrivial values (not 1/1/1 compat-smoke budgets).
    assert 'PROME_FUZZ_ALL_COVER_CANDIDATES="${PROME_FUZZ_ALL_COVER_CANDIDATES:-4}"' in entrypoint


# ---------------------------------------------------------------------------
# 11. native build feedback reaches candidate repair logic
# ---------------------------------------------------------------------------


def test_entrypoint_wires_native_build_wrapper_into_generator() -> None:
    entrypoint = (REPO_ROOT / "docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")
    assert "PROME_FUZZ_DRIVER_BUILD_WRAPPER=/opt/hgb/bin/promefuzz_target_build.sh" in entrypoint
    assert '["bash", build_wrapper, str(src_path), str(bin_path)]' in entrypoint
    assert 'bash /opt/hgb/bin/promefuzz_target_build.sh "$baseline_source" "$baseline_binary"' in entrypoint


# ---------------------------------------------------------------------------
# 12. stale/failed candidates are not retained as final
# ---------------------------------------------------------------------------


def test_entrypoint_retains_only_final_driver_dir() -> None:
    entrypoint = (REPO_ROOT / "docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")
    assert "final_driver_dir" in entrypoint
    assert "temporary_driver_dir" in entrypoint
    assert "temporary retry sources were not retained as results" in entrypoint
    # The collection loop reads from final_driver_dir, not temporary_driver_dir.
    assert 'find "$final_driver_dir"' in entrypoint


# ---------------------------------------------------------------------------
# 13. no-op candidate fails reachability
# ---------------------------------------------------------------------------


def test_noop_candidate_fails_reachability() -> None:
    reject = evaluator.reject_noop_harness
    noop = (
        "int LLVMFuzzerTestOneInput(const unsigned char *data, long size) {\n"
        "  (void)data; (void)size;\n  return 0;\n}\n"
    )
    assert reject(noop) == "noop_harness_no_project_calls"
    real = (
        "int LLVMFuzzerTestOneInput(const unsigned char *data, long size) {\n"
        "  return foo((const char *)data, (int)size);\n}\n"
    )
    assert reject(real) == ""


def test_entrypoint_runs_common_evaluator_for_reachability() -> None:
    entrypoint = (REPO_ROOT / "docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")
    assert "promefuzz_evaluator.py" in entrypoint
    assert "api_reachability completed" in entrypoint
    assert "promefuzz_no_verified_harness" in entrypoint


# ---------------------------------------------------------------------------
# 14. fixture candidate reaches `evaluated`
# ---------------------------------------------------------------------------


def test_fixture_candidate_reaches_evaluated() -> None:
    stages = {n: "completed" for n in profile.STAGE_NAMES}
    result = profile.build_result(
        profile="alpha", protocol="blind-project", target="foo_fuzz_foo", stages=stages,
    )
    assert result["status"] == "evaluated"
    for stage in ("candidate_build", "sanitizer_smoke", "api_reachability", "campaign", "coverage"):
        assert result["stages"][stage] == "completed"


def test_evaluator_reuses_common_ofg_evaluator() -> None:
    import ofg_evaluator
    # promefuzz_evaluator must delegate to the common evaluator, not duplicate it.
    assert evaluator.ofg_evaluator is ofg_evaluator
    assert callable(evaluator.evaluate_candidates)


# ---------------------------------------------------------------------------
# 15. all current valuable targets have a deterministic preflight decision
# ---------------------------------------------------------------------------


def test_all_valuable_targets_have_preflight_decision() -> None:
    registry = json.loads((REPO_ROOT / "metadata/fuzzbench_targets.json").read_text(encoding="utf-8"))
    valuable = registry.get("target_sets", {}).get("valuable", {}).get("targets", [])
    assert len(valuable) == 20, f"expected 20 valuable targets, got {len(valuable)}"
    overrides = profile.load_target_overrides(REPO_ROOT / "metadata")
    for target in valuable:
        result = profile.preflight_target(target, overrides, valuable_targets=valuable)
        assert result["valid"], f"target {target} preflight failed: {result.get('reason')}"


def test_target_overrides_file_exists_and_has_no_harness_source() -> None:
    path = REPO_ROOT / "metadata/promefuzz_target_overrides.yaml"
    assert path.is_file(), f"missing target overrides: {path}"
    overrides = profile.load_target_overrides(REPO_ROOT / "metadata")
    assert "targets" in overrides
    assert len(overrides["targets"]) >= 20
    for target_name, entry in overrides["targets"].items():
        for key, value in entry.items():
            if isinstance(value, str):
                assert "LLVMFuzzerTestOneInput" not in value, f"{target_name}.{key} contains harness source"
            elif isinstance(value, list):
                for item in value:
                    assert "LLVMFuzzerTestOneInput" not in str(item), f"{target_name}.{key} contains harness source"


def test_baseline_contract_registers_promefuzz() -> None:
    contracts = (REPO_ROOT / "metadata/baseline_contracts.yaml").read_text(encoding="utf-8")
    assert "name: promefuzz" in contracts
    assert "task_family: harness_generator" in contracts
    assert "default_protocol: blind-project" in contracts
    assert "strict_success_status: evaluated" in contracts


# ---------------------------------------------------------------------------
# 16. matrix counts only `evaluated` as successful alpha runs
# ---------------------------------------------------------------------------


def _make_matrix_dir(tmp_path: Path, rows: list[dict]) -> Path:
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    matrix_file = matrix_dir / "matrix.tsv"
    lines = ["generator\ttarget\tstatus\tmetadata\n"]
    for row in rows:
        lines.append(f"{row['generator']}\t{row['target']}\t{row['status']}\t{row['metadata']}\n")
    matrix_file.write_text("".join(lines), encoding="utf-8")
    return matrix_dir


def _write_metadata(tmp_path: Path, name: str, data: dict) -> str:
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def test_matrix_collector_only_counts_evaluated_for_promefuzz_alpha(tmp_path: Path) -> None:
    collector = _load_module("hgb_collect_matrix", "scripts/hgb_collect_matrix.py")
    meta1 = _write_metadata(tmp_path, "m1", {
        "generator": "promefuzz", "task_family": "harness_generator",
        "profile": "alpha", "status": "evaluated",
    })
    meta2 = _write_metadata(tmp_path, "m2", {
        "generator": "promefuzz", "task_family": "harness_generator",
        "profile": "alpha", "status": "completed",
    })
    meta3 = _write_metadata(tmp_path, "m3", {
        "generator": "promefuzz", "task_family": "harness_generator",
        "profile": "alpha", "status": "partial_completed",
    })
    rows = [
        {"generator": "promefuzz", "target": "t1", "status": "evaluated", "metadata": meta1},
        {"generator": "promefuzz", "target": "t2", "status": "completed", "metadata": meta2},
        {"generator": "promefuzz", "target": "t3", "status": "partial_completed", "metadata": meta3},
    ]
    matrix_dir = _make_matrix_dir(tmp_path, rows)
    summary = collector.collect(matrix_dir)
    assert summary["total_pairs"] == 3
    assert summary["completed_pairs"] == 1
    assert summary["partial_completed_pairs"] == 1
    assert summary["failed_pairs"] == 1


def test_matrix_collector_excludes_promefuzz_compat_smoke(tmp_path: Path) -> None:
    collector = _load_module("hgb_collect_matrix", "scripts/hgb_collect_matrix.py")
    meta1 = _write_metadata(tmp_path, "m1", {
        "generator": "promefuzz", "task_family": "harness_generator",
        "profile": "compat-smoke", "status": "evaluated", "excluded_from_aggregate": True,
    })
    meta2 = _write_metadata(tmp_path, "m2", {
        "generator": "promefuzz", "task_family": "harness_generator",
        "profile": "alpha", "status": "evaluated",
    })
    rows = [
        {"generator": "promefuzz", "target": "t1", "status": "evaluated", "metadata": meta1},
        {"generator": "promefuzz", "target": "t2", "status": "evaluated", "metadata": meta2},
    ]
    matrix_dir = _make_matrix_dir(tmp_path, rows)
    summary = collector.collect(matrix_dir)
    assert summary["excluded_pairs"] == 1
    assert summary["aggregate_pairs"] == 1
    assert summary["completed_pairs"] == 1
