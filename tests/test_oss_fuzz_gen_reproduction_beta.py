from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "docker/common"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ofg_profile = _load_module("ofg_profile", "docker/common/ofg_profile.py")
ofg_introspector = _load_module("ofg_introspector_adapter", "docker/common/ofg_introspector_adapter.py")
ofg_synthesis = _load_module("ofg_benchmark_synthesis", "docker/common/ofg_benchmark_synthesis.py")
ofg_api_rank = _load_module("ofg_api_rank", "docker/common/ofg_api_rank.py")
ofg_evaluator = _load_module("ofg_evaluator", "docker/common/ofg_evaluator.py")
hgb_harness_evaluator = _load_module("hgb_harness_evaluator", "docker/common/hgb_harness_evaluator.py")
hgb_result = _load_module("hgb_result", "docker/common/hgb_result.py")
hgb_coverage = _load_module("hgb_coverage", "docker/common/hgb_coverage.py")
hgb_fuzzbench_builder = _load_module("hgb_fuzzbench_builder", "docker/common/hgb_fuzzbench_builder.py")
hgb_target_package = _load_module("hgb_target_package", "docker/common/hgb_target_package.py")
matrix_collector = _load_module("hgb_collect_matrix", "scripts/hgb_collect_matrix.py")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


LLVM_COVERAGE_JSON = json.dumps({
    "data": [{"totals": {"lines": {"count": 100, "covered": 31},
                          "functions": {"count": 10, "covered": 6},
                          "regions": {"count": 50, "covered": 14}},
              "functions": [{"name": "jsoncpp_parse", "count": 5},
                            {"name": "LLVMFuzzerTestOneInput", "count": 12}]}],
    "type": "llvm.coverage.json.export", "version": "2.0.1",
})

LLVM_COVERAGE_NATIVE = json.dumps({
    "data": [{"totals": {"lines": {"count": 100, "covered": 45},
                          "functions": {"count": 10, "covered": 7},
                          "regions": {"count": 50, "covered": 18}},
              "functions": [{"name": "jsoncpp_parse", "count": 8},
                            {"name": "LLVMFuzzerTestOneInput", "count": 15}]}],
    "type": "llvm.coverage.json.export", "version": "2.0.1",
})


def _write_introspector_fixture(report_dir: Path, project: str = "jsoncpp") -> None:
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
    (report_dir / "all_functions.json").write_text(json.dumps(functions), encoding="utf-8")
    (report_dir / "calltree.json").write_text(
        json.dumps({"function_name": "jsoncpp_parse", "children": []}), encoding="utf-8",
    )
    (report_dir / "type_info.json").write_text(json.dumps({"types": []}), encoding="utf-8")
    (report_dir / "report_manifest.json").write_text(
        json.dumps({"project": project, "project_name": project}), encoding="utf-8",
    )


class FakeResult:
    def __init__(self, command, exit_code=0, stdout="", stderr=""):
        self.command = list(command)
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    """A fake Docker runner for offline evaluator tests."""

    def __init__(self, *, campaign_execs=500, coverage_stdout=None, native_coverage_stdout=None,
                 build_exit=0, smoke_crash=False, native_build_exit=0):
        self.commands = []
        self.campaign_execs = campaign_execs
        self.coverage_stdout = coverage_stdout if coverage_stdout is not None else LLVM_COVERAGE_JSON
        self.native_coverage_stdout = native_coverage_stdout if native_coverage_stdout is not None else LLVM_COVERAGE_NATIVE
        self.build_exit = build_exit
        self.smoke_crash = smoke_crash
        self.native_build_exit = native_build_exit
        self._containers = {}

    def __call__(self, command, timeout):
        self.commands.append(list(command))
        cmd = list(command)
        if not cmd:
            return FakeResult(cmd, 1)
        head = cmd[0]
        if head == "docker":
            sub = cmd[1] if len(cmd) > 1 else ""
            if sub == "build":
                return FakeResult(cmd, self.build_exit, "build ok", "")
            if sub == "image" and len(cmd) > 3 and cmd[2] == "inspect":
                return FakeResult(cmd, 0, "sha256:fakeimage\n", "")
            if sub == "create":
                name = ""
                for i, tok in enumerate(cmd):
                    if tok == "--name" and i + 1 < len(cmd):
                        name = cmd[i + 1]
                phase = "unknown"
                if "smoke" in name:
                    phase = "smoke"
                elif "campaign" in name:
                    phase = "campaign"
                elif "coverage" in name:
                    phase = "coverage"
                elif "verify" in name:
                    phase = "verify"
                # Detect native control builds by the image tag (contains
                # "-native") so coverage replays return the native control.
                is_native = any("native" in tok for tok in cmd)
                self._containers[name] = (phase, is_native)
                return FakeResult(cmd, 0, name + "\n", "")
            if sub == "start":
                name = cmd[-1]
                entry = self._containers.get(name, ("unknown", False))
                phase, is_native = entry if isinstance(entry, tuple) else (entry, False)
                if phase == "smoke":
                    stderr = "AddressSanitizer: crash\n" if self.smoke_crash else ""
                    return FakeResult(cmd, 77 if self.smoke_crash else 0, "", stderr)
                if phase == "verify":
                    return FakeResult(cmd, 0, "", "")
                if phase == "campaign":
                    out = f"#{self.campaign_execs} INITED\n#{self.campaign_execs} DONE\n"
                    out += f"stat::number_of_executed_units: {self.campaign_execs}\n"
                    out += "stat::new_units_added: 12\nstat::peak_rss_mb: 100\n"
                    return FakeResult(cmd, 0, out, "")
                if phase == "coverage":
                    stdout = self.native_coverage_stdout if is_native else self.coverage_stdout
                    return FakeResult(cmd, 0, stdout, "")
                return FakeResult(cmd, 0, "", "")
            if sub == "cp":
                return FakeResult(cmd, 0, "", "")
            if sub == "rm":
                return FakeResult(cmd, 0, "", "")
        return FakeResult(cmd, 0, "", "")


def _make_split_package(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Build a split target package and return (package, generator_input, evaluator_only)."""
    pkg = tmp_path / "target_pkg"
    (pkg / "source_input" / "jsoncpp").mkdir(parents=True)
    (pkg / "seeds").mkdir(parents=True)
    (pkg / "reference_harnesses" / "selected" / "source_input" / "jsoncpp").mkdir(parents=True)
    (pkg / "fuzzbench_benchmark").mkdir(parents=True)
    (pkg / "source_input" / "jsoncpp" / "json_reader.cpp").write_text(
        "int jsoncpp_parse(const char* s) { return 0; }\n", encoding="utf-8",
    )
    native_source = (
        "int jsoncpp_parse(const char*);\n"
        "int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long s) {"
        " jsoncpp_parse((const char*)d); return 0; }\n"
    )
    (pkg / "reference_harnesses" / "selected" / "source_input" / "jsoncpp" / "jsoncpp_fuzzer.cc").write_text(
        native_source, encoding="utf-8",
    )
    (pkg / "fuzzbench_benchmark" / "Dockerfile").write_text(
        "FROM scratch\nCOPY source_input/ /src/\n", encoding="utf-8",
    )
    (pkg / "fuzzbench_benchmark" / "build.sh").write_text(
        "#!/bin/sh\nc++ $SRC/jsoncpp/jsoncpp_fuzzer.cc -o $OUT/jsoncpp_fuzzer\n", encoding="utf-8",
    )
    manifest = {
        "schema_version": 1,
        "target": "jsoncpp_jsoncpp_fuzzer",
        "project": "jsoncpp",
        "fuzz_target": "jsoncpp_fuzzer",
        "source_input_dir": "source_input",
        "reference_harness_dir": "reference_harnesses",
        "reference_harness_files": ["source_input/jsoncpp/jsoncpp_fuzzer.cc"],
        "selected_reference_harness_dir": "reference_harnesses/selected",
        "selected_reference_harness_files": ["source_input/jsoncpp/jsoncpp_fuzzer.cc"],
        "selected_reference_harness_count": 1,
        "seed_count": 0,
        "dictionary_count": 0,
    }
    (pkg / "target_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (pkg / "source_repos.json").write_text("[]", encoding="utf-8")
    halves = hgb_target_package.split_package(
        pkg,
        native_harness={
            "selected_reference": "source_input/jsoncpp/jsoncpp_fuzzer.cc",
            "container_destination": "/src/jsoncpp/jsoncpp_fuzzer.cc",
            "language": "c++",
        },
    )
    return pkg, Path(halves["generator_input"]), Path(halves["evaluator_only"])


def _write_candidate(candidates_dir: Path) -> Path:
    candidates_dir.mkdir(parents=True, exist_ok=True)
    candidate = candidates_dir / "cand_001.cc"
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
    return candidate


def _fake_context_provider(target_root, work_dir):
    import shutil

    ctx = work_dir
    if ctx.exists():
        shutil.rmtree(ctx)
    (ctx / "source_input" / "jsoncpp").mkdir(parents=True, exist_ok=True)
    (ctx / "source_input" / "jsoncpp" / "jsoncpp_fuzzer.cc").write_text(
        "// placeholder reference harness\n", encoding="utf-8",
    )
    (ctx / "Dockerfile").write_text("FROM scratch\nCOPY source_input/ /src/\n", encoding="utf-8")
    return {"context_dir": str(ctx), "dockerfile": str(ctx / "Dockerfile"), "mode": "test_sealed"}


# ---------------------------------------------------------------------------
# 1. generator isolation
# ---------------------------------------------------------------------------


def test_blind_generator_mount_excludes_reference_harnesses(tmp_path: Path) -> None:
    pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    audit = hgb_target_package.audit_generator_input(generator_input)
    assert audit["clean"], f"generator_input leaked reference tokens: {audit['hits']}"
    assert not (generator_input / "reference_harnesses").exists()
    assert (evaluator_only / "reference_harnesses").is_dir()
    assert (evaluator_only / "native_harness_path.json").is_file()


def test_ofg_is_registered_as_harness_generator() -> None:
    contracts = (REPO_ROOT / "metadata/baseline_contracts.yaml").read_text(encoding="utf-8")
    assert "name: oss-fuzz-gen" in contracts
    assert "task_family: harness_generator" in contracts
    common = (REPO_ROOT / "scripts/lib/common.sh").read_text(encoding="utf-8")
    assert "oss-fuzz-gen" in common
    assert "hgb_generator_is_blind" in common


# ---------------------------------------------------------------------------
# 2. selected-harness API ranking forbidden
# ---------------------------------------------------------------------------


def test_selected_harness_api_ranking_forbidden_in_blind(monkeypatch) -> None:
    monkeypatch.delenv("OFG_REFERENCE_DIAGNOSTIC", raising=False)
    assert ofg_api_rank.load_reference_calls("/target/reference_harnesses") == set()
    assert ofg_api_rank.load_reference_text("/target/reference_harnesses") == ""
    scored = ofg_api_rank.score_record(
        {"name": "jsoncpp_parse", "signature": "int jsoncpp_parse(const char*)",
         "return_type": "int", "path": "/src/jsoncpp/json_reader.cpp"},
        reference_text="jsoncpp_parse( arg",
    )
    assert scored is not None
    assert "called_by_harness" not in scored[1]
    assert "mentioned_by_harness" not in scored[1]


def test_selected_harness_apis_metadata_not_mounted_for_blind(tmp_path: Path) -> None:
    pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    assert not any("fuzzbench_selected_harness_apis" in p.name for p in generator_input.rglob("*"))


# ---------------------------------------------------------------------------
# 3. exact reference harness example forbidden
# ---------------------------------------------------------------------------


def test_run_wrapper_has_no_reference_example_loader() -> None:
    wrapper = (REPO_ROOT / "docker/common/ofg_run_wrapper.py").read_text(encoding="utf-8")
    assert "_read_reference_targets" not in wrapper
    assert "_patch_project_examples" not in wrapper
    assert "HGB_TARGET_REFERENCE_DIR" not in wrapper or "blocked" in wrapper


def test_examples_exclude_fuzz_harnesses(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "api.c").write_text("int useful_api(void) { return 0; }\n", encoding="utf-8")
    (source / "fuzz_target.c").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long s) { return 0; }\n",
        encoding="utf-8",
    )
    result = ofg_synthesis.collect_allowed_examples(source, allow_same_project_fuzz=False)
    allowed = [e["path"] for e in result["allowed"]]
    denied = [e["path"] for e in result["denied"]]
    assert "api.c" in allowed
    assert "fuzz_target.c" in denied


# ---------------------------------------------------------------------------
# 4. real Introspector required in alpha/paper
# ---------------------------------------------------------------------------


def test_alpha_refuses_local_shim_and_coverage_skip(monkeypatch) -> None:
    monkeypatch.delenv("OFG_REFERENCE_DIAGNOSTIC", raising=False)
    violations = ofg_profile.validate_profile(
        "alpha", "blind-project",
        {"OFG_SKIP_COVERAGE_GAINS": "1", "OFG_INTROSPECTOR_MODE": "local"},
    )
    assert any("OFG_SKIP_COVERAGE_GAINS" in v for v in violations)
    assert any("OFG_INTROSPECTOR_MODE" in v for v in violations)
    violations = ofg_profile.validate_profile(
        "paper-faithful", "blind-project",
        {"OFG_INTROSPECTOR_MODE": "local"},
    )
    assert any("OFG_INTROSPECTOR_MODE" in v for v in violations)


def test_empty_introspector_report_fails_alpha(tmp_path: Path) -> None:
    report_dir = tmp_path / "introspector"
    _write_introspector_fixture(report_dir, stub_only := False)
    # Stub-only report must fail validation.
    stub_dir = tmp_path / "stub"
    functions = [{"name": "stub_only", "function_signature": "int stub_only()",
                  "source_file": "/src/hgb_introspector_stub.c", "return-type": "int",
                  "function_arguments": []}]
    stub_dir.mkdir(parents=True)
    (stub_dir / "all_functions.json").write_text(json.dumps(functions), encoding="utf-8")
    (stub_dir / "calltree.json").write_text("{}", encoding="utf-8")
    (stub_dir / "type_info.json").write_text("{}", encoding="utf-8")
    (stub_dir / "report_manifest.json").write_text('{"project": "jsoncpp"}', encoding="utf-8")
    ok, message = ofg_introspector.validate_reports(stub_dir)
    assert ok is False
    assert "stub" in message


def test_shim_rejected_outside_compat_smoke(tmp_path: Path) -> None:
    # build_introspector_report with compat_shim=False and no oss-fuzz dir fails.
    report = ofg_introspector.build_introspector_report(
        target_root=tmp_path, work_dir=tmp_path / "work",
        project="jsoncpp", fuzz_target="jsoncpp_fuzzer",
        oss_fuzz_dir=None, compat_shim=False,
    )
    assert report.valid is False
    assert "failed_stage=introspector" in report.message


# ---------------------------------------------------------------------------
# 5. project/target-scoped Introspector report selection
# ---------------------------------------------------------------------------


def test_target_scoped_introspector_selection_picks_matching_project(tmp_path: Path) -> None:
    out = tmp_path / "build" / "out"
    # Two inspector directories: one for a different project, one for jsoncpp.
    wrong = out / "wrong_project" / "inspector"
    right = out / "jsoncpp_project" / "inspector"
    _write_introspector_fixture(wrong, project="other_project")
    _write_introspector_fixture(right, project="jsoncpp")
    selected = ofg_introspector.select_inspector_report(out, "jsoncpp", "jsoncpp_fuzzer")
    assert selected is not None
    assert selected == right


def test_build_introspector_report_generates_function_source_map(tmp_path: Path) -> None:
    report_dir = tmp_path / "reports" / "inspector"
    _write_introspector_fixture(report_dir, project="jsoncpp")
    mapping = ofg_introspector.generate_function_source_map(report_dir, "/src")
    assert "jsoncpp_parse" in mapping["functions"]
    assert mapping["functions"]["jsoncpp_parse"]["source_file"]


# ---------------------------------------------------------------------------
# 6. benchmark YAML leak audit
# ---------------------------------------------------------------------------


def test_benchmark_leak_audit_passes_for_clean_synthesis(tmp_path: Path) -> None:
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
    assert result["leak_audit"] == "passed"
    assert result["benchmark_source"] == "synthesized_from_introspector"
    assert result["function_under_test"] == "jsoncpp_parse"


def test_benchmark_leak_audit_detects_embedded_body() -> None:
    benchmark = {
        "functions": [{"name": "jsoncpp_parse", "body": "int LLVMFuzzerTestOneInput() { return 0; }"}],
        "project": "jsoncpp",
    }
    audit = ofg_synthesis.benchmark_leak_audit(benchmark)
    assert audit["leaked"] is True
    assert audit["leak_audit"] == "failed"


def test_benchmark_leak_audit_detects_reference_path() -> None:
    benchmark = {"functions": [], "project": "jsoncpp"}
    audit = ofg_synthesis.benchmark_leak_audit(
        benchmark, reference_paths=["reference_harnesses/selected/jsoncpp_fuzzer.cc"],
    )
    # The benchmark itself doesn't contain the path, so it passes.
    assert audit["leaked"] is False
    benchmark["target_path"] = "reference_harnesses/selected/jsoncpp_fuzzer.cc"
    audit = ofg_synthesis.benchmark_leak_audit(
        benchmark, reference_paths=["reference_harnesses/selected/jsoncpp_fuzzer.cc"],
    )
    assert audit["leaked"] is True


# ---------------------------------------------------------------------------
# 7. pinned Dockerfile/artifact commits
# ---------------------------------------------------------------------------


def test_dockerfile_does_not_clone_floating_master() -> None:
    dockerfile = (REPO_ROOT / "docker/oss-fuzz-gen/Dockerfile").read_text(encoding="utf-8")
    assert "COPY artifacts/oss-fuzz /opt/hgb/oss-fuzz" in dockerfile
    assert "git clone --depth 1 --branch" not in dockerfile
    assert "OFG_OSS_FUZZ_COMMIT" in dockerfile


def test_work_index_pins_oss_fuzz_immutably() -> None:
    index = (REPO_ROOT / "metadata/work_index.yaml").read_text(encoding="utf-8")
    assert "oss-fuzz:" in index
    assert "detached-pinned-immutable" in index
    assert "95272c1a23cb2d796afb1b3be0c2644bbab787f4" in index


def test_clone_artifacts_reuses_recorded_commit_by_default() -> None:
    script = (REPO_ROOT / "scripts/clone_artifacts.sh").read_text(encoding="utf-8")
    assert "HGB_REFRESH_ARTIFACTS" in script
    assert "detached-pinned-immutable" in script
    assert "recorded_commit" in script


# ---------------------------------------------------------------------------
# 8. evaluator overlay copies candidate to native harness path
# ---------------------------------------------------------------------------


def test_evaluator_overlays_candidate_at_exact_native_path(tmp_path: Path) -> None:
    pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    candidates_dir = tmp_path / "candidates"
    _write_candidate(candidates_dir)
    work_dir = tmp_path / "evaluation"
    runner = FakeRunner()
    result = hgb_harness_evaluator.evaluate(
        generator="oss-fuzz-gen",
        target_root=generator_input,
        evaluator_root=evaluator_only,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="jsoncpp",
        fuzz_target="jsoncpp_fuzzer",
        profile="alpha",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        context_provider=_fake_context_provider,
        intended_apis=["jsoncpp_parse"],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["overlaid"] is True
    assert cand_json["native_destination"] == "/src/jsoncpp/jsoncpp_fuzzer.cc"
    assert cand_json["candidate_sha256"] != ""
    # The overlay must have actually written the candidate into the sealed context.
    sealed_harness = work_dir / "sealed_context" / "source_input" / "jsoncpp" / "jsoncpp_fuzzer.cc"
    assert sealed_harness.is_file()
    assert "jsoncpp_parse" in sealed_harness.read_text(encoding="utf-8")
    assert result["candidate_count"] == 1


# ---------------------------------------------------------------------------
# 9. stable image tag across build/smoke/campaign/coverage
# ---------------------------------------------------------------------------


def test_image_tag_consistent_across_all_stages(tmp_path: Path) -> None:
    pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    candidates_dir = tmp_path / "candidates"
    _write_candidate(candidates_dir)
    work_dir = tmp_path / "evaluation"
    runner = FakeRunner()
    hgb_harness_evaluator.evaluate(
        generator="oss-fuzz-gen",
        target_root=generator_input,
        evaluator_root=evaluator_only,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="jsoncpp",
        fuzz_target="jsoncpp_fuzzer",
        profile="alpha",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        context_provider=_fake_context_provider,
        intended_apis=["jsoncpp_parse"],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    tag = cand_json["image_tag"]
    assert tag.startswith("hgb-oss-fuzz-gen-")
    build_cmds = [c for c in runner.commands if c[:2] == ["docker", "build"]]
    assert build_cmds, "expected at least one docker build"
    assert any(tag in c for c in build_cmds)
    # Every docker run for this candidate must use the same tag.
    run_cmds = [c for c in runner.commands if c[:2] == ["docker", "run"]]
    for c in run_cmds:
        assert tag in c, f"docker run used a different tag: {c}"


def test_ofg_evaluator_internal_uses_consistent_tag(tmp_path: Path) -> None:
    target_root = tmp_path / "target"
    (target_root / "fuzzbench_benchmark").mkdir(parents=True)
    (target_root / "reference_harnesses" / "selected" / "src" / "project").mkdir(parents=True)
    (target_root / "reference_harnesses" / "selected" / "src" / "project" / "native.c").write_text(
        "int jsoncpp_parse(const char*);\nint LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long s)"
        " { jsoncpp_parse((const char*)d); return 0; }\n", encoding="utf-8",
    )
    (target_root / "fuzzbench_benchmark" / "Dockerfile").write_text("FROM scratch\nCOPY source_input/ /src/\n", encoding="utf-8")
    candidates = tmp_path / "candidates"
    candidates.mkdir()
    (candidates / "cand.c").write_text(
        "int jsoncpp_parse(const char*);\n"
        "int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long s)"
        " { if (s < 1) return 0; jsoncpp_parse((const char*)d); return 0; }\n", encoding="utf-8",
    )
    runner = FakeRunner()
    ofg_evaluator.evaluate_candidates(
        target_root=target_root, candidates_dir=candidates, work_dir=tmp_path / "eval",
        fuzz_target="jsoncpp_fuzzer", selected_functions=["jsoncpp_parse"], runner=runner,
    )
    build_tags = [c for c in runner.commands if c[:2] == ["docker", "build"]]
    tag = build_tags[0][build_tags[0].index("-t") + 1]
    for c in runner.commands:
        if c[:2] == ["docker", "run"]:
            assert tag in c, f"ofg_evaluator used a different tag for run: {c}"


# ---------------------------------------------------------------------------
# 10. evaluator failure is not swallowed
# ---------------------------------------------------------------------------


def test_evaluator_failure_is_not_swallowed_in_entrypoint() -> None:
    entrypoint = (REPO_ROOT / "docker/oss-fuzz-gen/entrypoint.sh").read_text(encoding="utf-8")
    # The run_evaluator function must not append `|| true` to the evaluator call.
    assert "hgb_harness_evaluator.py" in entrypoint
    eval_block = entrypoint.split("hgb_harness_evaluator.py", 1)[1]
    eval_block = eval_block.split("return $?", 1)[0]
    assert "|| true" not in eval_block
    # The post-evaluator logic must propagate infra_failure.
    assert "infra_failure" in entrypoint
    assert "run_evaluator || eval_code=$?" in entrypoint


def test_evaluator_nonzero_yields_infra_failure_when_no_result(tmp_path: Path) -> None:
    pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    candidates_dir = tmp_path / "candidates"
    _write_candidate(candidates_dir)
    work_dir = tmp_path / "evaluation"
    # A runner where the build itself fails produces a quality_failure, not
    # evaluated; the run-level status must never be "evaluated".
    runner = FakeRunner(build_exit=1)
    result = hgb_harness_evaluator.evaluate(
        generator="oss-fuzz-gen",
        target_root=generator_input,
        evaluator_root=evaluator_only,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="jsoncpp",
        fuzz_target="jsoncpp_fuzzer",
        profile="alpha",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        context_provider=_fake_context_provider,
        intended_apis=["jsoncpp_parse"],
        seeds=[],
    )
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_no_evaluated_status_without_coverage_or_execs(tmp_path: Path) -> None:
    pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    candidates_dir = tmp_path / "candidates"
    _write_candidate(candidates_dir)
    work_dir = tmp_path / "evaluation"
    # Zero campaign executions must not yield evaluated.
    runner = FakeRunner(campaign_execs=0, coverage_stdout="")
    result = hgb_harness_evaluator.evaluate(
        generator="oss-fuzz-gen",
        target_root=generator_input,
        evaluator_root=evaluator_only,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="jsoncpp",
        fuzz_target="jsoncpp_fuzzer",
        profile="alpha",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        context_provider=_fake_context_provider,
        intended_apis=["jsoncpp_parse"],
        seeds=[],
    )
    assert result["status"] != hgb_result.STATUS_EVALUATED


# ---------------------------------------------------------------------------
# 11. coverage must come from a report file, not process exit
# ---------------------------------------------------------------------------


def test_coverage_requires_real_report_not_exit_code(tmp_path: Path) -> None:
    pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    candidates_dir = tmp_path / "candidates"
    _write_candidate(candidates_dir)
    work_dir = tmp_path / "evaluation"
    # Coverage stdout empty -> coverage fails even though campaign succeeds.
    runner = FakeRunner(coverage_stdout="")
    result = hgb_harness_evaluator.evaluate(
        generator="oss-fuzz-gen",
        target_root=generator_input,
        evaluator_root=evaluator_only,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="jsoncpp",
        fuzz_target="jsoncpp_fuzzer",
        profile="alpha",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        context_provider=_fake_context_provider,
        intended_apis=["jsoncpp_parse"],
        seeds=[],
    )
    assert result["status"] != hgb_result.STATUS_EVALUATED
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["coverage"] == "failed"


def test_coverage_diff_computed_against_native_control(tmp_path: Path) -> None:
    cand = hgb_coverage.parse_llvm_coverage_json(LLVM_COVERAGE_JSON)
    native = hgb_coverage.parse_llvm_coverage_json(LLVM_COVERAGE_NATIVE)
    diff = hgb_harness_evaluator.compute_coverage_diff(cand, native)
    assert diff["runtime_coverage_valid"] is True
    assert diff["candidate_lines_covered"] == 31
    assert diff["native_lines_covered"] == 45
    assert diff["new_lines_vs_native"] == 0
    assert diff["line_coverage_diff_percent"] < 0
    assert diff["status"] == "available"


def test_coverage_diff_unavailable_without_native_control() -> None:
    cand = hgb_coverage.parse_llvm_coverage_json(LLVM_COVERAGE_JSON)
    diff = hgb_harness_evaluator.compute_coverage_diff(cand, None)
    assert diff["runtime_coverage_valid"] is True
    assert diff["status"] == "unavailable"
    assert diff["native_lines_covered"] is None


def test_full_loop_yields_evaluated_with_coverage_report(tmp_path: Path) -> None:
    pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    candidates_dir = tmp_path / "candidates"
    _write_candidate(candidates_dir)
    work_dir = tmp_path / "evaluation"
    runner = FakeRunner()
    result = hgb_harness_evaluator.evaluate(
        generator="oss-fuzz-gen",
        target_root=generator_input,
        evaluator_root=evaluator_only,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="jsoncpp",
        fuzz_target="jsoncpp_fuzzer",
        profile="alpha",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        context_provider=_fake_context_provider,
        intended_apis=["jsoncpp_parse"],
        seeds=[],
        run_native_control=True,
    )
    assert result["status"] == hgb_result.STATUS_EVALUATED
    assert int(result["metrics"]["campaign"]["execs_done"]) > 0
    assert result["metrics"]["coverage"]["line_coverage"]["covered"] == 31
    assert result["metrics"]["coverage_diff"]["status"] == "available"
    assert result["metrics"]["coverage_diff"]["candidate_lines_covered"] == 31
    assert result["metrics"]["coverage_diff"]["native_lines_covered"] == 45


# ---------------------------------------------------------------------------
# 12. result semantics and provenance
# ---------------------------------------------------------------------------


def test_evaluated_invariants_require_overlay_execs_and_coverage() -> None:
    bad = hgb_result.build_result(
        profile="alpha", protocol="blind-project", target="t", status="evaluated",
        stages={n: "completed" for n in hgb_result.STAGE_NAMES}, candidate_count=1,
    )
    bad["selected_candidate"] = {"overlaid": True}
    violations = hgb_result.assert_evaluated_invariants(bad)
    assert any("coverage" in v for v in violations) or any("execs_done" in v for v in violations)


def test_entrypoint_records_pinned_commits_and_image_digest() -> None:
    entrypoint = (REPO_ROOT / "docker/oss-fuzz-gen/entrypoint.sh").read_text(encoding="utf-8")
    assert "oss_fuzz_gen_commit" in entrypoint
    assert "oss_fuzz_commit" in entrypoint
    assert "fuzzbench_commit" in entrypoint
    assert "docker_image_digest" in entrypoint
    assert "ofg_num_evaluations" in entrypoint
    assert "ofg_generation_timeout_seconds" in entrypoint


def test_matrix_only_evaluated_counts_for_harness_generator(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    rows = []
    for index, status in enumerate(["evaluated", "quality_failure", "infra_failure"], start=1):
        workspace = tmp_path / f"ws{index}"
        workspace.mkdir()
        metadata = workspace / "metadata.json"
        payload = {
            "generator": "oss-fuzz-gen", "task_family": "harness_generator",
            "target": f"target_{index}", "status": status, "profile": "alpha",
        }
        if status == "evaluated":
            payload["metrics"] = {"campaign": {"execs_done": 100},
                                  "coverage": {"line_coverage": {"covered": 10}}}
            payload["selected_candidate"] = {"overlaid": True}
        metadata.write_text(json.dumps(payload), encoding="utf-8")
        rows.append((f"target_{index}", workspace, metadata))
    with (matrix_dir / "matrix.tsv").open("w", encoding="utf-8") as f:
        f.write("generator\ttarget\tstatus\tworkspace\tmetadata\n")
        for target, workspace, metadata in rows:
            f.write(f"oss-fuzz-gen\t{target}\t{metadata.parent.name}\t{workspace}\t{metadata}\n")
    summary = matrix_collector.collect(matrix_dir)
    assert summary["completed_pairs"] == 1
    assert summary["task_family_counts"]["harness_generator"] == 3


def test_compat_smoke_is_excluded_from_aggregate() -> None:
    result = ofg_profile.build_result(profile="compat-smoke", protocol="blind-project", target="t")
    assert result["excluded_from_aggregate"] is True
    assert result["method_variant"] == "compat-smoke"


def test_entrypoint_uses_target_scoped_introspector_selection() -> None:
    entrypoint = (REPO_ROOT / "docker/oss-fuzz-gen/entrypoint.sh").read_text(encoding="utf-8")
    assert "select_inspector_report" in entrypoint
    # The old first-matching-inspector-directory behavior must be gone.
    assert "find \"$oss_fuzz_dir/build/out\" -type d -name 'inspector'" not in entrypoint


def test_entrypoint_delegates_to_shared_harness_evaluator() -> None:
    entrypoint = (REPO_ROOT / "docker/oss-fuzz-gen/entrypoint.sh").read_text(encoding="utf-8")
    assert "hgb_harness_evaluator.py" in entrypoint
    assert "--generator oss-fuzz-gen" in entrypoint
    assert "--run-native-control" in entrypoint


def test_image_tag_helper_supports_generator_prefix() -> None:
    tag = hgb_fuzzbench_builder.deterministic_image_tag("run1", "target1", "cand_001", generator="oss-fuzz-gen")
    assert tag.startswith("hgb-oss-fuzz-gen-")
    tag2 = hgb_fuzzbench_builder.deterministic_image_tag("run1", "target1", "cand_001")
    assert tag2.startswith("hgb-ckgfuzzer-")
    assert tag != tag2
