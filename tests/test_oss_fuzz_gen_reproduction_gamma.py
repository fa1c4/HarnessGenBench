from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "docker" / "common"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ofg_profile = _load_module("ofg_profile_gamma", "docker/common/ofg_profile.py")
ofg_introspector = _load_module("ofg_introspector_adapter_gamma", "docker/common/ofg_introspector_adapter.py")
ofg_synthesis = _load_module("ofg_benchmark_synthesis_gamma", "docker/common/ofg_benchmark_synthesis.py")
ofg_api_rank = _load_module("ofg_api_rank_gamma", "docker/common/ofg_api_rank.py")
ofg_run_wrapper = _load_module("ofg_run_wrapper_gamma", "docker/common/ofg_run_wrapper.py")
hgb_harness_evaluator = _load_module("hgb_harness_evaluator_gamma", "docker/common/hgb_harness_evaluator.py")
hgb_split_context = _load_module("hgb_split_context_gamma", "docker/common/hgb_split_context.py")
hgb_result = _load_module("hgb_result_gamma", "docker/common/hgb_result.py")
hgb_coverage = _load_module("hgb_coverage_gamma", "docker/common/hgb_coverage.py")
hgb_fuzzbench_builder = _load_module("hgb_fuzzbench_builder_gamma", "docker/common/hgb_fuzzbench_builder.py")
hgb_target_package = _load_module("hgb_target_package_gamma", "docker/common/hgb_target_package.py")
matrix_collector = _load_module("hgb_collect_matrix_gamma", "scripts/hgb_collect_matrix.py")


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
        "native_harness_path": "source_input/jsoncpp/jsoncpp_fuzzer.cc",
        "native_harness_destination": "/src/jsoncpp/jsoncpp_fuzzer.cc",
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


class FakeResult:
    def __init__(self, command, exit_code=0, stdout="", stderr=""):
        self.command = list(command)
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    """A fake Docker runner for offline evaluator tests."""

    def __init__(self, *, campaign_execs=500, coverage_stdout=None, build_exit=0, smoke_crash=False):
        self.commands = []
        self.campaign_execs = campaign_execs
        self.coverage_stdout = coverage_stdout if coverage_stdout is not None else LLVM_COVERAGE_JSON
        self.build_exit = build_exit
        self.smoke_crash = smoke_crash
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
                self._containers[name] = phase
                return FakeResult(cmd, 0, name + "\n", "")
            if sub == "start":
                name = cmd[-1]
                phase = self._containers.get(name, "unknown")
                if phase == "smoke":
                    stderr = "AddressSanitizer: crash\n" if self.smoke_crash else ""
                    return FakeResult(cmd, 77 if self.smoke_crash else 0, "", stderr)
                if phase == "campaign":
                    out = f"#{self.campaign_execs} INITED\n#{self.campaign_execs} DONE\n"
                    out += f"stat::number_of_executed_units: {self.campaign_execs}\n"
                    return FakeResult(cmd, 0, out, "")
                if phase == "coverage":
                    return FakeResult(cmd, 0, self.coverage_stdout, "")
                return FakeResult(cmd, 0, "", "")
            if sub == "cp":
                return FakeResult(cmd, 0, "", "")
            if sub == "rm":
                return FakeResult(cmd, 0, "", "")
        return FakeResult(cmd, 0, "", "")


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
# Profile validation
# ---------------------------------------------------------------------------


def test_reproduction_gamma_is_method_faithful() -> None:
    assert ofg_profile.is_method_faithful("reproduction-gamma")
    assert "reproduction-gamma" in ofg_profile.VALID_PROFILES


def test_reproduction_gamma_rejects_local_introspector_shim() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-gamma", "blind-project",
        {"OFG_INTROSPECTOR_MODE": "local"},
    )
    assert any("OFG_INTROSPECTOR_MODE" in v for v in violations)


def test_reproduction_gamma_rejects_yaml_fallback_and_bad_benchmark_synthesis() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-gamma", "blind-project",
        {"OFG_ALLOW_PROJECT_YAML_FALLBACK": "1", "OFG_SYNTHESIZE_ON_BAD_BENCHMARK": "1"},
    )
    assert any("OFG_ALLOW_PROJECT_YAML_FALLBACK" in v for v in violations)
    assert any("OFG_SYNTHESIZE_ON_BAD_BENCHMARK" in v for v in violations)


def test_reproduction_gamma_accepts_real_introspector_mode() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-gamma", "blind-project",
        {"OFG_INTROSPECTOR_MODE": "real", "OFG_NUM_SAMPLES": "10"},
    )
    assert violations == []


def test_reproduction_gamma_rejects_unknown_introspector_mode() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-gamma", "blind-project",
        {"OFG_INTROSPECTOR_MODE": "fabricated"},
    )
    assert any("OFG_INTROSPECTOR_MODE" in v for v in violations)


def test_reproduction_gamma_maps_to_paper_faithful_method_variant() -> None:
    result = hgb_result.build_result(
        profile="reproduction-gamma", protocol="blind-project", target="t",
        status="evaluated",
        stages={n: "completed" for n in hgb_result.STAGE_NAMES},
    )
    assert result["method_variant"] == "paper-faithful"


# ---------------------------------------------------------------------------
# 1. Split package evaluator can create sealed context
# ---------------------------------------------------------------------------


def test_split_package_evaluator_can_create_sealed_context(tmp_path: Path) -> None:
    pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    ctx = hgb_split_context.SplitTargetContext.load(generator_input, evaluator_only)
    sealed = hgb_split_context.create_sealed_build_context(ctx, tmp_path / "sealed")
    sealed_dir = Path(sealed["context_dir"])
    # The sealed context combines generator-half source_input/source_repos with
    # evaluator-half benchmark_copy/native_harness_path/reference_harnesses.
    assert (sealed_dir / "source_input" / "jsoncpp" / "json_reader.cpp").is_file()
    assert (sealed_dir / "source_repos.json").is_file()
    assert (sealed_dir / "fuzzbench_benchmark" / "Dockerfile").is_file()
    assert (sealed_dir / "native_harness_path.json").is_file()
    assert (sealed_dir / "reference_harnesses").is_dir()
    assert sealed["mode"] == "split_sealed_source_snapshot"


def test_split_context_load_names_missing_evaluator_file(tmp_path: Path) -> None:
    pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    # Remove the benchmark_copy from the evaluator half.
    import shutil
    shutil.rmtree(evaluator_only / "benchmark_copy")
    with pytest.raises(hgb_split_context.VerificationContextError) as exc:
        hgb_split_context.SplitTargetContext.load(generator_input, evaluator_only)
    assert "benchmark_copy" in str(exc.value)


# ---------------------------------------------------------------------------
# 2. OSS-Fuzz-Gen generation context does not include evaluator-only canary
# ---------------------------------------------------------------------------


def test_generation_context_excludes_evaluator_only_canary(tmp_path: Path) -> None:
    pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    # Plant an evaluator-only canary token in the reference harness (evaluator
    # half only) and confirm it never appears in the generator-visible half.
    canary = "HGB_REF_CANARY_gamma_test_token"
    ref = evaluator_only / "reference_harnesses" / "selected" / "source_input" / "jsoncpp" / "jsoncpp_fuzzer.cc"
    ref.write_text(f"// {canary}\n" + ref.read_text(encoding="utf-8"), encoding="utf-8")
    audit = ofg_profile.audit_leakage(generator_input, canary)
    assert audit["leaked"] is False, (
        f"evaluator-only canary leaked into generator_input: {audit['hits']}"
    )
    # The sealed context is evaluator-only; the canary may live there but must
    # never have been copied into the generator_input tree.
    assert not any(canary in p.read_text(encoding="utf-8", errors="replace")
                   for p in generator_input.rglob("*") if p.is_file())


def test_run_wrapper_local_shim_disabled_in_reproduction_gamma(monkeypatch) -> None:
    monkeypatch.setenv("HGB_BASELINE_PROFILE", "reproduction-gamma")
    monkeypatch.setenv("HGB_BASELINE_PROTOCOL", "blind-project")
    assert ofg_run_wrapper.is_method_faithful() is True
    ofg_run_wrapper.PATCH_REGISTRY.clear()
    ofg_run_wrapper._install_local_introspector_shim([])
    shim_patch = [p for p in ofg_run_wrapper.PATCH_REGISTRY if p["patch"] == "local_introspector_shim"]
    assert shim_patch and shim_patch[0]["enabled"] is False


def test_run_wrapper_coverage_skip_disabled_in_reproduction_gamma(monkeypatch) -> None:
    monkeypatch.setenv("HGB_BASELINE_PROFILE", "reproduction-gamma")
    ofg_run_wrapper.PATCH_REGISTRY.clear()
    ofg_run_wrapper._patch_coverage_skip()
    ofg_run_wrapper._install_coverage_gains_noop()
    enabled = [p for p in ofg_run_wrapper.PATCH_REGISTRY if p["enabled"]]
    assert not enabled


# ---------------------------------------------------------------------------
# 3. fuzzbench_selected_harness_apis.json is not read in blind reproduction mode
# ---------------------------------------------------------------------------


def test_selected_harness_apis_metadata_not_in_generator_mount(tmp_path: Path) -> None:
    pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    assert not any("fuzzbench_selected_harness_apis" in p.name for p in generator_input.rglob("*"))


def test_selected_harness_apis_audit_flags_token_in_generator_input(tmp_path: Path) -> None:
    pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    # Plant the forbidden token inside generator_input and confirm the audit
    # catches it (proving the audit is the gate that blocks it).
    (generator_input / "fuzzbench_selected_harness_apis.json").write_text("[]", encoding="utf-8")
    audit = hgb_target_package.audit_generator_input(generator_input)
    assert audit["clean"] is False
    assert any("fuzzbench_selected_harness_apis" in h for h in audit["hits"])


def test_api_rank_reference_scoring_disabled_in_blind_reproduction(monkeypatch) -> None:
    monkeypatch.delenv("OFG_REFERENCE_DIAGNOSTIC", raising=False)
    # In blind reproduction-gamma, reference-derived ranking must be inert.
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


# ---------------------------------------------------------------------------
# 4. Exact native harness is not passed as an example
# ---------------------------------------------------------------------------


def test_exact_native_harness_excluded_from_examples(tmp_path: Path) -> None:
    pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    # The native harness lives only in the evaluator half; the generator half's
    # source_input must not contain it. collect_allowed_examples must deny any
    # file that looks like a fuzz harness (LLVMFuzzerTestOneInput).
    native_rel = "jsoncpp/jsoncpp_fuzzer.cc"
    assert not (generator_input / "source_input" / native_rel).exists(), (
        "native harness leaked into generator-visible source_input"
    )
    result = ofg_synthesis.collect_allowed_examples(
        generator_input / "source_input", allow_same_project_fuzz=False,
    )
    denied = [e["path"] for e in result["denied"]]
    allowed = [e["path"] for e in result["allowed"]]
    # json_reader.cpp is a normal source file and must be allowed.
    assert any(p.endswith("json_reader.cpp") for p in allowed)
    # No fuzz harness may be allowed.
    assert all("fuzz" not in p.lower() for p in allowed)
    # If a fuzz harness were present it would be denied with fuzz_harness_excluded.
    fake_source = tmp_path / "fake_src"
    fake_source.mkdir()
    (fake_source / "fuzz_target.c").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char* d, unsigned long s) { return 0; }\n",
        encoding="utf-8",
    )
    result2 = ofg_synthesis.collect_allowed_examples(fake_source, allow_same_project_fuzz=False)
    assert result2["denied"][0]["reason"] == "fuzz_harness_excluded"


def test_run_wrapper_has_no_reference_example_loader() -> None:
    wrapper = (REPO_ROOT / "docker/common/ofg_run_wrapper.py").read_text(encoding="utf-8")
    assert "_read_reference_targets" not in wrapper
    assert "_patch_project_examples" not in wrapper


# ---------------------------------------------------------------------------
# 5. Local introspector shim is rejected in reproduction-gamma
# ---------------------------------------------------------------------------


def test_local_introspector_shim_rejected_in_reproduction_gamma(tmp_path: Path) -> None:
    # build_introspector_report with compat_shim=False and no oss-fuzz dir fails.
    report = ofg_introspector.build_introspector_report(
        target_root=tmp_path, work_dir=tmp_path / "work",
        project="jsoncpp", fuzz_target="jsoncpp_fuzzer",
        oss_fuzz_dir=None, compat_shim=False,
    )
    assert report.valid is False
    assert "failed_stage=introspector" in report.message


def test_empty_introspector_report_fails_reproduction_gamma(tmp_path: Path) -> None:
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


# ---------------------------------------------------------------------------
# 6. Evaluator CLI accepts the exact flags used by OFG entrypoint
# ---------------------------------------------------------------------------


def test_evaluator_cli_accepts_exact_ofg_flags(tmp_path: Path, monkeypatch) -> None:
    pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    candidate = _write_candidate(tmp_path / "candidates")
    result_dir = tmp_path / "result"

    captured: dict[str, object] = {}

    def fake_evaluate(**kwargs):
        captured.update(kwargs)
        return hgb_result.build_result(
            generator=kwargs["generator"], profile=kwargs["profile"],
            protocol=kwargs["protocol"], target=kwargs["fuzz_target"],
            status=hgb_result.STATUS_EVALUATED,
            stages={n: "completed" for n in hgb_result.STAGE_NAMES},
            candidate_count=1,
        )

    monkeypatch.setattr(hgb_harness_evaluator, "evaluate", fake_evaluate)

    argv = [
        "hgb_harness_evaluator.py",
        "--baseline", "oss-fuzz-gen",
        "--target-root", str(generator_input),
        "--evaluator-root", str(evaluator_only),
        "--candidate", str(candidate),
        "--result-dir", str(result_dir),
        "--campaign-seconds", "30",
        "--build-timeout-seconds", "900",
        "--profile", "reproduction-gamma",
        "--protocol", "blind-project",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    rc = hgb_harness_evaluator.main()
    assert rc == 0
    # The exact flags from the plan must map to the evaluate() kwargs.
    assert captured["generator"] == "oss-fuzz-gen"
    assert captured["protocol"] == "blind-project"
    assert captured["profile"] == "reproduction-gamma"
    assert captured["campaign_seconds"] == 30
    assert captured["build_timeout_seconds"] == 900
    assert captured["fuzz_target"] == "jsoncpp_fuzzer"
    assert captured["project"] == "jsoncpp"
    assert captured["result_dir"] == result_dir


def test_evaluator_cli_derives_fuzz_target_from_manifest(tmp_path: Path, monkeypatch) -> None:
    pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    candidate = _write_candidate(tmp_path / "candidates")
    result_dir = tmp_path / "result"

    captured: dict[str, object] = {}

    def fake_evaluate(**kwargs):
        captured.update(kwargs)
        return hgb_result.build_result(
            generator=kwargs["generator"], profile=kwargs["profile"],
            protocol=kwargs["protocol"], target=kwargs["fuzz_target"],
            status=hgb_result.STATUS_QUALITY_FAILURE,
            stages=hgb_result.default_stages(), candidate_count=1,
        )

    monkeypatch.setattr(hgb_harness_evaluator, "evaluate", fake_evaluate)
    # Note: no --fuzz-target and no --project; both must come from the manifest.
    argv = [
        "hgb_harness_evaluator.py",
        "--baseline", "oss-fuzz-gen",
        "--target-root", str(generator_input),
        "--evaluator-root", str(evaluator_only),
        "--candidate", str(candidate),
        "--result-dir", str(result_dir),
        "--profile", "reproduction-gamma",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    hgb_harness_evaluator.main()
    assert captured["fuzz_target"] == "jsoncpp_fuzzer"
    assert captured["project"] == "jsoncpp"


# ---------------------------------------------------------------------------
# 7. Candidate overlay actually copies candidate into the native path
# ---------------------------------------------------------------------------


def test_candidate_overlay_copies_into_native_path(tmp_path: Path) -> None:
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
        profile="reproduction-gamma",
        protocol="blind-project",
        campaign_seconds=10,
        build_timeout_seconds=120,
        strict=True,
        runner=runner,
        context_provider=_fake_context_provider,
        intended_apis=["jsoncpp_parse"],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["overlaid"] is True
    assert cand_json["native_destination"] == "/src/jsoncpp/jsoncpp_fuzzer.cc"
    # The overlay must have actually written the candidate into the sealed context.
    sealed_harness = work_dir / "sealed_context" / "source_input" / "jsoncpp" / "jsoncpp_fuzzer.cc"
    assert sealed_harness.is_file()
    assert "jsoncpp_parse" in sealed_harness.read_text(encoding="utf-8")
    assert result["candidate_count"] == 1
    assert result["protocol"] == "blind-project"


def test_evaluator_result_dir_writes_additional_result_json(tmp_path: Path) -> None:
    pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    candidates_dir = tmp_path / "candidates"
    _write_candidate(candidates_dir)
    work_dir = tmp_path / "evaluation"
    result_dir = tmp_path / "result"
    runner = FakeRunner()
    hgb_harness_evaluator.evaluate(
        generator="oss-fuzz-gen",
        target_root=generator_input,
        evaluator_root=evaluator_only,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="jsoncpp",
        fuzz_target="jsoncpp_fuzzer",
        profile="reproduction-gamma",
        protocol="blind-project",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        context_provider=_fake_context_provider,
        intended_apis=["jsoncpp_parse"],
        seeds=[],
        result_dir=result_dir,
    )
    assert (result_dir / "result.json").is_file()
    assert (work_dir / "result.json").is_file()


# ---------------------------------------------------------------------------
# 8. Build/run image tag mismatch is impossible or fails loudly
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
        profile="reproduction-gamma",
        protocol="blind-project",
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
    # Every docker run for this candidate must use the same tag (no mismatch).
    run_cmds = [c for c in runner.commands if c[:2] == ["docker", "run"] or c[:2] == ["docker", "create"]]
    for c in run_cmds:
        assert tag in c, f"docker run/create used a different tag: {c}"


def test_deterministic_image_tag_is_stable() -> None:
    tag1 = hgb_fuzzbench_builder.deterministic_image_tag(
        "run1", "jsoncpp_fuzzer", "cand_001", generator="oss-fuzz-gen",
    )
    tag2 = hgb_fuzzbench_builder.deterministic_image_tag(
        "run1", "jsoncpp_fuzzer", "cand_001", generator="oss-fuzz-gen",
    )
    assert tag1 == tag2
    # A different candidate must yield a different tag.
    tag3 = hgb_fuzzbench_builder.deterministic_image_tag(
        "run1", "jsoncpp_fuzzer", "cand_002", generator="oss-fuzz-gen",
    )
    assert tag1 != tag3


# ---------------------------------------------------------------------------
# 9. Coverage stage fails on missing/empty JSON
# ---------------------------------------------------------------------------


def test_coverage_stage_fails_on_empty_report(tmp_path: Path) -> None:
    pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    candidates_dir = tmp_path / "candidates"
    _write_candidate(candidates_dir)
    work_dir = tmp_path / "evaluation"
    runner = FakeRunner(coverage_stdout="")
    result = hgb_harness_evaluator.evaluate(
        generator="oss-fuzz-gen",
        target_root=generator_input,
        evaluator_root=evaluator_only,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="jsoncpp",
        fuzz_target="jsoncpp_fuzzer",
        profile="reproduction-gamma",
        protocol="blind-project",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        context_provider=_fake_context_provider,
        intended_apis=[],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["coverage"] == "failed"
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_coverage_diff_unavailable_without_native_control(tmp_path: Path) -> None:
    cand = hgb_coverage.parse_llvm_coverage_json(LLVM_COVERAGE_JSON)
    diff = hgb_harness_evaluator.compute_coverage_diff(cand, None)
    assert diff["runtime_coverage_valid"] is True
    assert diff["status"] == "unavailable"
    assert diff["native_lines_covered"] is None


# ---------------------------------------------------------------------------
# 10. Build-only output is not evaluated
# ---------------------------------------------------------------------------


def test_build_only_output_is_not_evaluated() -> None:
    stages = hgb_result.default_stages()
    stages["generation"] = "completed"
    stages["candidate_build"] = "completed"
    stages["sanitizer_smoke"] = "pending"
    stages["api_reachability"] = "pending"
    stages["campaign"] = "pending"
    stages["coverage"] = "pending"
    status = hgb_result.result_status_from_stages(stages)
    assert status != hgb_result.STATUS_EVALUATED


def test_no_evaluated_status_without_campaign_or_coverage(tmp_path: Path) -> None:
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
        profile="reproduction-gamma",
        protocol="blind-project",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        context_provider=_fake_context_provider,
        intended_apis=["jsoncpp_parse"],
        seeds=[],
    )
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_full_loop_yields_evaluated_with_reproduction_gamma(tmp_path: Path) -> None:
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
        profile="reproduction-gamma",
        protocol="blind-project",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        context_provider=_fake_context_provider,
        intended_apis=["jsoncpp_parse"],
        seeds=[],
        run_native_control=True,
    )
    assert result["status"] == hgb_result.STATUS_EVALUATED
    assert result["method_variant"] == "paper-faithful"
    assert int(result["metrics"]["campaign"]["execs_done"]) > 0
    assert result["metrics"]["coverage"]["line_coverage"]["covered"] == 31


# ---------------------------------------------------------------------------
# Entrypoint / matrix acceptance
# ---------------------------------------------------------------------------


def test_entrypoint_has_reproduction_gamma_profile_defaults() -> None:
    entrypoint = (REPO_ROOT / "docker/oss-fuzz-gen/entrypoint.sh").read_text(encoding="utf-8")
    assert "reproduction-gamma)" in entrypoint
    assert 'OFG_INTROSPECTOR_MODE="${OFG_INTROSPECTOR_MODE:-real}"' in entrypoint
    assert 'OFG_ALLOW_PROJECT_YAML_FALLBACK="${OFG_ALLOW_PROJECT_YAML_FALLBACK:-0}"' in entrypoint
    assert 'OFG_SYNTHESIZE_ON_BAD_BENCHMARK="${OFG_SYNTHESIZE_ON_BAD_BENCHMARK:-0}"' in entrypoint


def test_run_baseline_accepts_reproduction_gamma_for_ofg() -> None:
    script = (REPO_ROOT / "scripts/hgb_run_baseline.sh").read_text(encoding="utf-8")
    assert "alpha|paper-faithful|reproduction-gamma|compat-smoke)" in script
    assert "oss-fuzz-gen/reproduction-gamma: OFG_ALLOW_PROJECT_YAML_FALLBACK=1 is forbidden" in script
    assert "oss-fuzz-gen/reproduction-gamma: OFG_SYNTHESIZE_ON_BAD_BENCHMARK=1 is forbidden" in script


def test_entrypoint_evaluator_passes_protocol_and_build_timeout() -> None:
    entrypoint = (REPO_ROOT / "docker/oss-fuzz-gen/entrypoint.sh").read_text(encoding="utf-8")
    assert "--protocol \"$hgb_protocol\"" in entrypoint
    assert "--build-timeout-seconds" in entrypoint


def test_baseline_contract_lists_reproduction_gamma_for_ofg() -> None:
    contracts = (REPO_ROOT / "metadata/baseline_contracts.yaml").read_text(encoding="utf-8")
    ofg_block = contracts.split("name: oss-fuzz-gen", 1)[1].split("name: g2fuzz", 1)[0]
    assert "reproduction-gamma" in ofg_block


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
            "target": f"target_{index}", "status": status, "profile": "reproduction-gamma",
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


# ---------------------------------------------------------------------------
# Acceptance command flags (plan section 11)
# ---------------------------------------------------------------------------


def test_require_evaluated_flag_fails_on_non_evaluated_rows(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    workspaces = []
    for index, status in enumerate(["evaluated", "quality_failure"], start=1):
        ws = tmp_path / f"ws{index}"
        ws.mkdir()
        meta = ws / "metadata.json"
        payload = {
            "generator": "oss-fuzz-gen", "task_family": "harness_generator",
            "target": f"target_{index}", "status": status, "profile": "reproduction-gamma",
        }
        if status == "evaluated":
            payload["metrics"] = {"campaign": {"execs_done": 100},
                                  "coverage": {"line_coverage": {"covered": 10}}}
            payload["selected_candidate"] = {"overlaid": True}
        meta.write_text(json.dumps(payload), encoding="utf-8")
        workspaces.append((f"target_{index}", ws, meta))
    with (matrix_dir / "matrix.tsv").open("w", encoding="utf-8") as f:
        f.write("generator\ttarget\tstatus\tworkspace\tmetadata\n")
        for target, ws, meta in workspaces:
            f.write(f"oss-fuzz-gen\t{target}\t{meta.parent.name}\t{ws}\t{meta}\n")
    summary = matrix_collector.collect(matrix_dir, generator="oss-fuzz-gen", require_evaluated=True)
    violations = summary["require_evaluated_violations"]
    assert len(violations) == 1
    assert violations[0]["status"] == "quality_failure"


def test_require_evaluated_flag_passes_when_all_evaluated(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    ws = tmp_path / "ws"
    ws.mkdir()
    meta = ws / "metadata.json"
    meta.write_text(json.dumps({
        "generator": "oss-fuzz-gen", "task_family": "harness_generator",
        "target": "target_1", "status": "evaluated", "profile": "reproduction-gamma",
        "metrics": {"campaign": {"execs_done": 100}, "coverage": {"line_coverage": {"covered": 10}}},
        "selected_candidate": {"overlaid": True},
    }), encoding="utf-8")
    with (matrix_dir / "matrix.tsv").open("w", encoding="utf-8") as f:
        f.write("generator\ttarget\tstatus\tworkspace\tmetadata\n")
        f.write(f"oss-fuzz-gen\ttarget_1\t{meta.parent.name}\t{ws}\t{meta}\n")
    summary = matrix_collector.collect(matrix_dir, generator="oss-fuzz-gen", require_evaluated=True)
    assert summary["require_evaluated_violations"] == []


def test_collect_matrix_cli_has_require_evaluated_flag() -> None:
    script = (REPO_ROOT / "scripts/hgb_collect_matrix.py").read_text(encoding="utf-8")
    assert "--require-evaluated" in script
    assert "require_evaluated=args.require_evaluated" in script


def test_generate_harness_script_accepts_profile_flag() -> None:
    script = (REPO_ROOT / "scripts/hgb_generate_harness.sh").read_text(encoding="utf-8")
    assert "--profile)" in script
    assert "--protocol)" in script
    assert 'export HGB_BASELINE_PROFILE="$profile"' in script


def test_generate_matrix_script_accepts_singular_aliases() -> None:
    script = (REPO_ROOT / "scripts/hgb_generate_matrix.sh").read_text(encoding="utf-8")
    assert "--generators|--generator)" in script
    assert "--targets|--target-set)" in script

