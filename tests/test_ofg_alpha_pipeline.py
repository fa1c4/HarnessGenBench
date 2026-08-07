from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace


sys.path.insert(0, str(Path("docker/common").resolve()))
sys.path.insert(0, str(Path("scripts").resolve()))


def load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ofg_profile = load_module("ofg_profile", "docker/common/ofg_profile.py")
ofg_introspector = load_module("ofg_introspector_adapter", "docker/common/ofg_introspector_adapter.py")
ofg_synthesis = load_module("ofg_benchmark_synthesis", "docker/common/ofg_benchmark_synthesis.py")
ofg_evaluator = load_module("ofg_evaluator", "docker/common/ofg_evaluator.py")
ofg_api_rank = load_module("ofg_api_rank", "docker/common/ofg_api_rank.py")
ofg_run_wrapper = load_module("ofg_run_wrapper_test", "docker/common/ofg_run_wrapper.py")
ofg_trim = load_module("ofg_trim_benchmark", "docker/common/ofg_trim_benchmark.py")
matrix_collector = load_module("hgb_collect_matrix", "scripts/hgb_collect_matrix.py")


def _write_introspector_fixture(report_dir: Path, *, stub_only: bool = False) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    functions = [
        {"name": "jsoncpp_parse", "function_signature": "int jsoncpp_parse(const char*)",
         "source_file": "/src/jsoncpp/json_reader.cpp", "return-type": "int",
         "function_arguments": ["const char*"], "complexity": 12, "hit_count": 0},
        {"name": "LLVMFuzzerTestOneInput", "function_signature": "int LLVMFuzzerTestOneInput(const uint8_t*, size_t)",
         "source_file": "/src/hgb_introspector_stub.c", "return-type": "int",
         "function_arguments": ["const uint8_t*", "size_t"]},
        {"name": "free", "function_signature": "void free(void*)",
         "source_file": "/src/jsoncpp/json_value.cpp", "return-type": "void",
         "function_arguments": ["void*"]},
    ]
    if stub_only:
        functions = [{"name": "stub_only", "function_signature": "int stub_only()",
                      "source_file": "/src/hgb_introspector_stub.c", "return-type": "int",
                      "function_arguments": []}]
    (report_dir / "all_functions.json").write_text(json.dumps(functions), encoding="utf-8")
    (report_dir / "calltree.json").write_text(
        json.dumps({"function_name": "jsoncpp_parse", "children": []}), encoding="utf-8",
    )
    (report_dir / "type_info.json").write_text(json.dumps({"types": []}), encoding="utf-8")
    (report_dir / "report_manifest.json").write_text(
        json.dumps({"project": "jsoncpp", "project_name": "jsoncpp"}), encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# 1. exact reference harness cannot be opened by the generator
# ---------------------------------------------------------------------------


def test_reference_harness_dir_is_not_passed_to_oss_fuzz_gen_in_blind(monkeypatch) -> None:
    common_sh = Path("scripts/lib/common.sh").read_text(encoding="utf-8")
    # hgb_generator_is_blind must cover oss-fuzz-gen in blind-project.
    assert "oss-fuzz-gen" in common_sh
    # The blind gate must withhold HGB_TARGET_REFERENCE_DIR.
    assert 'reference_dir_args+=(-e HGB_TARGET_REFERENCE_DIR=/target/reference_harnesses)' in common_sh
    assert "hgb_generator_is_blind" in common_sh
    # The wrapper must not read HGB_TARGET_REFERENCE_DIR as an example source.
    wrapper = Path("docker/common/ofg_run_wrapper.py").read_text(encoding="utf-8")
    assert "_read_reference_targets" not in wrapper
    assert "HGB_TARGET_REFERENCE_DIR" not in wrapper or "blocked" in wrapper


def test_ofg_run_wrapper_has_no_reference_example_loader() -> None:
    wrapper = Path("docker/common/ofg_run_wrapper.py").read_text(encoding="utf-8")
    assert "_patch_project_examples" not in wrapper
    assert "OFG_LOCAL_PROJECT_EXAMPLES: using HGB reference harnesses" not in wrapper


# ---------------------------------------------------------------------------
# 2. canary token does not reach examples, benchmark YAML, ranking, prompts, logs
# ---------------------------------------------------------------------------


def test_canary_leakage_audit_detects_and_reports(tmp_path: Path) -> None:
    canary = ofg_profile.generate_canary_token()
    leaked = tmp_path / "leaked"
    clean = tmp_path / "clean"
    leaked.mkdir()
    clean.mkdir()
    (leaked / "prompt.txt").write_text(f"here is the answer: {canary}", encoding="utf-8")
    (clean / "benchmark.yaml").write_text("functions: []\n", encoding="utf-8")
    result = ofg_profile.audit_leakage(clean, canary, extra_dirs=[leaked])
    assert result["leaked"] is True
    assert result["hit_count"] >= 1
    clean_result = ofg_profile.audit_leakage(clean, canary)
    assert clean_result["leaked"] is False


# ---------------------------------------------------------------------------
# 3. ofg_api_rank.py has no reference-based scoring in blind alpha
# ---------------------------------------------------------------------------


def test_api_rank_reference_scoring_disabled_in_blind(monkeypatch) -> None:
    monkeypatch.delenv("OFG_REFERENCE_DIAGNOSTIC", raising=False)
    record = {"name": "jsoncpp_parse", "signature": "int jsoncpp_parse(const char*)",
              "return_type": "int", "path": "/src/jsoncpp/json_reader.cpp"}
    # load_reference_calls/text must return empty in blind mode.
    assert ofg_api_rank.load_reference_calls("/target/reference_harnesses") == set()
    assert ofg_api_rank.load_reference_text("/target/reference_harnesses") == ""
    # score_record must not award called_by_harness bonuses for reference text.
    scored = ofg_api_rank.score_record(record, reference_text="jsoncpp_parse( arg")
    assert scored is not None
    reasons = scored[1]
    assert "called_by_harness" not in reasons
    assert "mentioned_by_harness" not in reasons


def test_api_rank_reference_scoring_only_in_diagnostic(monkeypatch) -> None:
    monkeypatch.setenv("OFG_REFERENCE_DIAGNOSTIC", "1")
    record = {"name": "jsoncpp_parse", "signature": "int jsoncpp_parse(const char*)",
              "return_type": "int", "path": "/src/jsoncpp/json_reader.cpp"}
    ref_dir = Path(__file__).parent / "_ref_fixture"
    ref_dir.mkdir(exist_ok=True)
    (ref_dir / "harness.cc").write_text(
        "int LLVMFuzzerTestOneInput(const uint8_t*, size_t) { jsoncpp_parse(0); return 0; }",
        encoding="utf-8",
    )
    try:
        calls = ofg_api_rank.load_reference_calls(str(ref_dir))
        assert "jsoncpp_parse" in calls
        text = ofg_api_rank.load_reference_text(str(ref_dir))
        assert "jsoncpp_parse" in text
    finally:
        (ref_dir / "harness.cc").unlink()
        ref_dir.rmdir()


# ---------------------------------------------------------------------------
# 4. ofg_run_wrapper.py never returns target reference source as an example
# ---------------------------------------------------------------------------


def test_run_wrapper_local_shim_only_in_compat_smoke(monkeypatch) -> None:
    monkeypatch.setenv("HGB_BASELINE_PROFILE", "alpha")
    monkeypatch.setenv("HGB_BASELINE_PROTOCOL", "blind-project")
    assert ofg_run_wrapper.is_method_faithful() is True
    assert ofg_run_wrapper.is_compat_smoke() is False
    # The shim must be disabled in alpha.
    ofg_run_wrapper.PATCH_REGISTRY.clear()
    ofg_run_wrapper._install_local_introspector_shim([])
    shim_patch = [p for p in ofg_run_wrapper.PATCH_REGISTRY if p["patch"] == "local_introspector_shim"]
    assert shim_patch and shim_patch[0]["enabled"] is False


def test_run_wrapper_coverage_skip_only_in_compat_smoke(monkeypatch) -> None:
    monkeypatch.setenv("HGB_BASELINE_PROFILE", "alpha")
    ofg_run_wrapper.PATCH_REGISTRY.clear()
    ofg_run_wrapper._patch_coverage_skip()
    ofg_run_wrapper._install_coverage_gains_noop()
    cov_patch = [p for p in ofg_run_wrapper.PATCH_REGISTRY if p["patch"] == "coverage_skip"]
    assert cov_patch and cov_patch[0]["enabled"] is False
    noop_patch = [p for p in ofg_run_wrapper.PATCH_REGISTRY if p["patch"] == "coverage_gains_noop"]
    assert noop_patch and noop_patch[0]["enabled"] is False


# ---------------------------------------------------------------------------
# 5. normal project examples are allowed and fuzz harnesses are excluded
# ---------------------------------------------------------------------------


def test_examples_exclude_fuzz_harnesses(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "api.c").write_text("int useful_api(void) { return 0; }\n", encoding="utf-8")
    (source / "fuzz_target.c").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long s) { return 0; }\n",
        encoding="utf-8",
    )
    result = ofg_synthesis.collect_allowed_examples(source, allow_same_project_fuzz=False)
    allowed_paths = [e["path"] for e in result["allowed"]]
    denied_paths = [e["path"] for e in result["denied"]]
    assert "api.c" in allowed_paths
    assert "fuzz_target.c" in denied_paths
    denied = next(e for e in result["denied"] if e["path"] == "fuzz_target.c")
    assert denied["reason"] == "fuzz_harness_excluded"


# ---------------------------------------------------------------------------
# 6. pinned OSS-Fuzz artifact behavior and lock non-mutation
# ---------------------------------------------------------------------------


def test_work_index_pins_oss_fuzz_immutably() -> None:
    index = Path("metadata/work_index.yaml").read_text(encoding="utf-8")
    assert "oss-fuzz:" in index
    assert "detached-pinned-immutable" in index
    assert "95272c1a23cb2d796afb1b3be0c2644bbab787f4" in index
    # The Dockerfile must copy the pinned checkout, not clone master.
    dockerfile = Path("docker/oss-fuzz-gen/Dockerfile").read_text(encoding="utf-8")
    assert "COPY artifacts/oss-fuzz /opt/hgb/oss-fuzz" in dockerfile
    assert "git clone --depth 1 --branch" not in dockerfile
    assert "OFG_OSS_FUZZ_COMMIT" in dockerfile


def test_clone_artifacts_reuses_recorded_commit_by_default() -> None:
    script = Path("scripts/clone_artifacts.sh").read_text(encoding="utf-8")
    assert "HGB_REFRESH_ARTIFACTS" in script
    assert "detached-pinned-immutable" in script
    assert "recorded_commit" in script


# ---------------------------------------------------------------------------
# 7. real fixture Introspector report parsing and non-empty function selection
# ---------------------------------------------------------------------------


def test_introspector_parse_and_select_non_empty(tmp_path: Path) -> None:
    report_dir = tmp_path / "introspector"
    _write_introspector_fixture(report_dir)
    ok, message = ofg_introspector.validate_reports(report_dir)
    assert ok is True
    records = ofg_introspector.parse_all_functions(report_dir)
    names = [r["name"] for r in records]
    assert "jsoncpp_parse" in names
    result = ofg_introspector.select_functions(records, max_functions=3, project="jsoncpp",
                                               target_name="jsoncpp_jsoncpp_fuzzer",
                                               fuzz_target="jsoncpp_fuzzer")
    selected_names = [r["name"] for r in result["selected"]]
    assert "jsoncpp_parse" in selected_names
    # fuzz entrypoint and runtime helpers must be rejected.
    rejected_names = [r["name"] for r in result["rejected"]]
    assert "LLVMFuzzerTestOneInput" in rejected_names
    assert "free" in rejected_names


def test_introspector_rejects_stub_only_reports(tmp_path: Path) -> None:
    report_dir = tmp_path / "introspector"
    _write_introspector_fixture(report_dir, stub_only=True)
    ok, message = ofg_introspector.validate_reports(report_dir)
    assert ok is False
    assert "stub" in message


# ---------------------------------------------------------------------------
# 8. benchmark synthesis for C and C++ fixtures
# ---------------------------------------------------------------------------


def test_benchmark_synthesis_cpp_fixture(tmp_path: Path) -> None:
    report_dir = tmp_path / "introspector"
    _write_introspector_fixture(report_dir)
    source = tmp_path / "source"
    source.mkdir()
    (source / "json_reader.cpp").write_text("int jsoncpp_parse(const char* s) { return 0; }\n", encoding="utf-8")
    records = ofg_introspector.parse_all_functions(report_dir)
    result = ofg_synthesis.synthesize_benchmark(
        records=records, project="jsoncpp", target_name="jsoncpp_jsoncpp_fuzzer",
        fuzz_target="jsoncpp_fuzzer", source_dir=source, max_functions=3,
    )
    assert result["benchmark"]["language"] == "c++"
    assert result["benchmark"]["project"] == "jsoncpp"
    assert any(f["name"] == "jsoncpp_parse" for f in result["benchmark"]["functions"])
    assert result["selection"]["selection_source"] == "introspector"


def test_benchmark_synthesis_c_fixture(tmp_path: Path) -> None:
    report_dir = tmp_path / "introspector"
    functions = [
        {"name": "zlib_uncompress", "function_signature": "int zlib_uncompress(unsigned char*, unsigned long*)",
         "source_file": "/src/zlib/uncompr.c", "return-type": "int",
         "function_arguments": ["unsigned char*", "unsigned long*"], "complexity": 8},
    ]
    report_dir.mkdir(parents=True)
    (report_dir / "all_functions.json").write_text(json.dumps(functions), encoding="utf-8")
    (report_dir / "calltree.json").write_text("{}", encoding="utf-8")
    (report_dir / "type_info.json").write_text("{}", encoding="utf-8")
    (report_dir / "report_manifest.json").write_text('{"project": "zlib"}', encoding="utf-8")
    source = tmp_path / "source"
    source.mkdir()
    (source / "uncompr.c").write_text("int zlib_uncompress(unsigned char* d, unsigned long* l) { return 0; }\n", encoding="utf-8")
    records = ofg_introspector.parse_all_functions(report_dir)
    result = ofg_synthesis.synthesize_benchmark(
        records=records, project="zlib", target_name="zlib_zlib_uncompress_fuzzer",
        fuzz_target="zlib_uncompress_fuzzer", source_dir=source, max_functions=1,
    )
    assert result["benchmark"]["language"] == "c"
    assert result["benchmark"]["functions"][0]["name"] == "zlib_uncompress"


# ---------------------------------------------------------------------------
# 9. alpha refuses local introspector shim/coverage skip
# ---------------------------------------------------------------------------


def test_alpha_refuses_local_shim_and_coverage_skip(monkeypatch) -> None:
    monkeypatch.delenv("OFG_REFERENCE_DIAGNOSTIC", raising=False)
    violations = ofg_profile.validate_profile(
        "alpha", "blind-project",
        {"OFG_SKIP_COVERAGE_GAINS": "1", "OFG_INTROSPECTOR_MODE": "remote"},
    )
    assert any("OFG_SKIP_COVERAGE_GAINS" in v for v in violations)
    violations = ofg_profile.validate_profile(
        "alpha", "blind-project",
        {"OFG_SKIP_COVERAGE_GAINS": "0", "OFG_INTROSPECTOR_MODE": "local"},
    )
    assert any("OFG_INTROSPECTOR_MODE" in v for v in violations)
    violations = ofg_profile.validate_profile(
        "alpha", "blind-project",
        {"OFG_NUM_SAMPLES": "1", "OFG_NUM_EXP": "1", "OFG_NUM_EVA": "1"},
    )
    assert any("OFG_NUM_SAMPLES" in v for v in violations)
    # A clean alpha must validate.
    violations = ofg_profile.validate_profile(
        "alpha", "blind-project",
        {"OFG_SKIP_COVERAGE_GAINS": "0", "OFG_INTROSPECTOR_MODE": "remote",
         "OFG_NUM_SAMPLES": "3"},
    )
    assert violations == []


def test_alpha_refuses_reference_usage_and_gcs_download(monkeypatch) -> None:
    violations = ofg_profile.validate_profile(
        "alpha", "blind-project",
        {"HGB_ALLOW_REFERENCE_USAGE": "1", "OFG_ALLOW_GCS_TARGET_DOWNLOAD": "1"},
    )
    assert any("HGB_ALLOW_REFERENCE_USAGE" in v for v in violations)
    assert any("OFG_ALLOW_GCS_TARGET_DOWNLOAD" in v for v in violations)


# ---------------------------------------------------------------------------
# 10. compat-smoke is excluded from aggregate
# ---------------------------------------------------------------------------


def test_compat_smoke_is_excluded_from_aggregate() -> None:
    result = ofg_profile.build_result(profile="compat-smoke", protocol="blind-project", target="t")
    assert result["excluded_from_aggregate"] is True
    assert result["method_variant"] == "compat-smoke"
    violations = ofg_profile.validate_profile(
        "compat-smoke", "blind-project", {"HGB_EXCLUDE_FROM_AGGREGATE": "0"},
    )
    assert any("exclude_from_aggregate" in v.lower() for v in violations)


# ---------------------------------------------------------------------------
# 11. real coverage fixture returns non-empty data
# ---------------------------------------------------------------------------


def test_coverage_skip_disabled_in_alpha_yields_real_path(monkeypatch) -> None:
    # In alpha the wrapper must not install coverage skip patches.
    monkeypatch.setenv("HGB_BASELINE_PROFILE", "alpha")
    ofg_run_wrapper.PATCH_REGISTRY.clear()
    ofg_run_wrapper._patch_coverage_skip()
    ofg_run_wrapper._install_coverage_gains_noop()
    enabled = [p for p in ofg_run_wrapper.PATCH_REGISTRY if p["enabled"]]
    assert not enabled


# ---------------------------------------------------------------------------
# 12. compile/repair iteration retention
# ---------------------------------------------------------------------------


def test_repair_observability_patch_registered() -> None:
    wrapper = Path("docker/common/ofg_run_wrapper.py").read_text(encoding="utf-8")
    assert "_install_repair_observability" in wrapper
    assert "repair_iterations" in wrapper


# ---------------------------------------------------------------------------
# 13. helper-symbol/no-op candidate rejection
# ---------------------------------------------------------------------------


def test_evaluator_rejects_noop_harness() -> None:
    source = "int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long s) { return 0; }\n"
    assert ofg_evaluator.reject_noop_harness(source) == "noop_harness_no_project_calls"
    assert ofg_evaluator.reject_noop_harness("int main() { return 0; }") == "missing_LLVMFuzzerTestOneInput"
    good = (
        "int jsoncpp_parse(const char*);\n"
        "int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long s) {"
        " jsoncpp_parse((const char*)d); return 0; }\n"
    )
    assert ofg_evaluator.reject_noop_harness(good, ["jsoncpp_parse"]) == ""
    wrong = (
        "int other_api(void);\n"
        "int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long s) {"
        " other_api(); return 0; }\n"
    )
    assert ofg_evaluator.reject_noop_harness(wrong, ["jsoncpp_parse"]) == "selected_function_not_referenced"


def test_evaluator_rejects_exact_copy_of_native() -> None:
    native = (
        "int jsoncpp_parse(const char*);\n"
        "int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long s) {"
        " jsoncpp_parse((const char*)d); return 0; }\n"
    )
    audit = ofg_evaluator.exact_copy_audit(native, native)
    assert audit["exact_copy"] is True


# ---------------------------------------------------------------------------
# 14. independent evaluator reaches evaluated for a fixture
# ---------------------------------------------------------------------------


def test_evaluator_reaches_verified_for_fixture(tmp_path: Path) -> None:
    target_root = tmp_path / "target"
    candidates = tmp_path / "candidates"
    eval_dir = tmp_path / "evaluation"
    benchmark = target_root / "fuzzbench_benchmark"
    reference = target_root / "reference_harnesses" / "selected" / "src" / "project"
    reference.mkdir(parents=True)
    benchmark.mkdir(parents=True)
    candidates.mkdir()
    (reference / "native.c").write_text(
        "int jsoncpp_parse(const char*);\n"
        "int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long s) {"
        " jsoncpp_parse((const char*)d); return 0; }\n",
        encoding="utf-8",
    )
    (benchmark / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    candidate = candidates / "candidate.c"
    candidate.write_text(
        "#include <stddef.h>\n"
        "int jsoncpp_parse(const char*);\n"
        "int LLVMFuzzerTestOneInput(const unsigned char* data, unsigned long size) {\n"
        "  if (size < 1) { return 0; }\n"
        "  jsoncpp_parse((const char*)data);\n"
        "  return 0;\n"
        "}\n",
        encoding="utf-8",
    )

    calls: list[list[str]] = []

    llvm_cov = json.dumps({
        "data": [{"totals": {"lines": {"count": 40, "covered": 12},
                              "functions": {"count": 5, "covered": 2},
                              "regions": {"count": 20, "covered": 6}}}],
        "type": "llvm.coverage.json.export", "version": "2.0.1",
    })

    def runner(command, timeout):
        calls.append(list(command))
        cmd = list(command)
        joined = " ".join(cmd)
        if "docker build" in joined:
            return ofg_evaluator.CommandResult(cmd, 0, "build ok", "")
        if "-runs=1" in cmd:
            return ofg_evaluator.CommandResult(cmd, 0, "", "")
        if "-max_total_time=" in joined:
            out = "#500 INITED\n#500 DONE\nstat::number_of_executed_units: 500\n"
            return ofg_evaluator.CommandResult(cmd, 0, out, "")
        if "llvm-cov export" in joined:
            return ofg_evaluator.CommandResult(cmd, 0, llvm_cov, "")
        return ofg_evaluator.CommandResult(cmd, 0, "ok", "")

    result = ofg_evaluator.evaluate_candidates(
        target_root=target_root,
        candidates_dir=candidates,
        work_dir=eval_dir,
        fuzz_target="jsoncpp_fuzzer",
        selected_functions=["jsoncpp_parse"],
        runner=runner,
    )
    assert result["verification_ran"] is True
    assert str(candidate) in result["verified_candidates"]
    assert (eval_dir / "results.json").is_file()
    rec = result["records"][0]
    # The corrected evaluator must overlay at the native path, use a consistent
    # image tag, require nonzero execs, and read coverage from a report file.
    assert rec["overlay"]["performed"] is True
    assert int(rec["campaign"]["execs_done"]) > 0
    assert rec["coverage"]["line_coverage"]["covered"] == 12
    build_tags = [c for c in calls if c[:2] == ["docker", "build"]]
    assert build_tags, "expected a docker build"
    tag = build_tags[0][build_tags[0].index("-t") + 1]
    assert all(tag in c for c in calls if "docker run" in " ".join(c))


# ---------------------------------------------------------------------------
# 15. all current valuable targets have a preflight decision
# ---------------------------------------------------------------------------


def test_all_valuable_targets_have_preflight_decision() -> None:
    overrides = ofg_profile.load_target_overrides(Path("metadata"))
    sys.path.insert(0, str(Path("scripts").resolve()))
    import hgb_targets  # type: ignore
    valuable = hgb_targets.targets_for_set(hgb_targets.load_registry(Path(".")), "valuable")
    assert len(valuable) == 20
    for target in valuable:
        decision = ofg_profile.preflight_target(target, overrides, valuable_targets=valuable)
        assert decision["decision"] in {"default", "override", "not_applicable"}
        # No valuable target should be marked not_valuable.
        assert decision["decision"] != "not_valuable"


def test_target_overrides_have_no_reference_apis() -> None:
    overrides_text = Path("metadata/oss_fuzz_gen_target_overrides.yaml").read_text(encoding="utf-8")
    assert "candidate_api_names" not in overrides_text
    assert "direct_api_names" not in overrides_text
    assert "LLVMFuzzerTestOneInput" not in overrides_text
    assert "harness_snippet" not in overrides_text.lower()


# ---------------------------------------------------------------------------
# 16. only evaluated counts as successful alpha matrix row
# ---------------------------------------------------------------------------


def test_matrix_only_evaluated_counts_for_harness_generator(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    rows = []
    for index, status in enumerate(["evaluated", "completed", "failed", "partial_completed"], start=1):
        workspace = tmp_path / f"ws{index}"
        workspace.mkdir()
        metadata = workspace / "metadata.json"
        metadata.write_text(json.dumps({
            "generator": "oss-fuzz-gen",
            "task_family": "harness_generator",
            "target": f"target_{index}",
            "status": status,
            "reason": "unit",
            "profile": "alpha",
        }), encoding="utf-8")
        rows.append((f"target_{index}", workspace, metadata))
    with (matrix_dir / "matrix.tsv").open("w", encoding="utf-8") as f:
        f.write("generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n")
        for target, workspace, metadata in rows:
            f.write(f"oss-fuzz-gen\t{target}\t{metadata.parent.name}\t{workspace}\t{metadata}\t{workspace}/HGB_SUMMARY.md\n")
    summary = matrix_collector.collect(matrix_dir)
    # Only "evaluated" counts as completed for harness_generator.
    assert summary["completed_pairs"] == 1
    assert summary["task_family_counts"]["harness_generator"] == 4


def test_result_status_from_stages_only_evaluated() -> None:
    stages = ofg_profile.default_stages()
    assert ofg_profile.result_status_from_stages(stages) == "failed"
    for name in ofg_profile.STAGE_NAMES:
        stages[name] = "completed"
    assert ofg_profile.result_status_from_stages(stages) == "evaluated"
    stages["coverage"] = "failed"
    assert ofg_profile.result_status_from_stages(stages) == "failed"
    stages["coverage"] = "pending"
    assert ofg_profile.result_status_from_stages(stages) == "partial_completed"
