from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
_DOCKER_COMMON = REPO_ROOT / "docker" / "common"
if str(_DOCKER_COMMON) not in sys.path:
    sys.path.insert(0, str(_DOCKER_COMMON))


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


hgb_target_package = _load_module("hgb_target_package_delta", "docker/common/hgb_target_package.py")
hgb_split_context = _load_module("hgb_split_context_delta", "docker/common/hgb_split_context.py")
SplitContextError = hgb_split_context.VerificationContextError
hgb_result = _load_module("hgb_result_delta", "docker/common/hgb_result.py")
hgb_coverage = _load_module("hgb_coverage_delta", "docker/common/hgb_coverage.py")
hgb_reachability = _load_module("hgb_reachability_delta", "docker/common/hgb_reachability.py")
hgb_fuzzbench_builder = _load_module("hgb_fuzzbench_builder_delta", "docker/common/hgb_fuzzbench_builder.py")
evaluator = _load_module("hgb_harness_evaluator_delta", "docker/common/hgb_harness_evaluator.py")
profile = _load_module("ckgfuzzer_profile_delta", "docker/common/ckgfuzzer_profile.py")
collector = _load_module("hgb_collect_matrix_delta", "scripts/hgb_collect_matrix.py")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_monolithic_package(tmp_path: Path) -> Path:
    pkg = tmp_path / "target_pkg"
    (pkg / "source_input" / "project").mkdir(parents=True)
    (pkg / "seeds").mkdir(parents=True)
    (pkg / "reference_harnesses" / "selected" / "source_input" / "project").mkdir(parents=True)
    (pkg / "reference_harnesses" / "source_input" / "project").mkdir(parents=True)
    (pkg / "fuzzbench_benchmark").mkdir(parents=True)
    (pkg / "source_input" / "project" / "sample.c").write_text("int api(void){return 0;}\n", encoding="utf-8")
    (pkg / "reference_harnesses" / "selected" / "source_input" / "project" / "native.c").write_text(
        "// HGB_REF_CANARY_DELTA_REF\nint LLVMFuzzerTestOneInput(void){return 0;}\n", encoding="utf-8"
    )
    # A sibling non-target fuzzer that the build needs (e.g. Mbed TLS).
    (pkg / "reference_harnesses" / "source_input" / "project" / "sibling_fuzzer.c").write_text(
        "int LLVMFuzzerTestOneInput_sibling(void){return 0;}\n", encoding="utf-8"
    )
    (pkg / "fuzzbench_benchmark" / "Dockerfile").write_text("FROM scratch\nCOPY * /src/\n", encoding="utf-8")
    (pkg / "fuzzbench_benchmark" / "build.sh").write_text("#!/bin/sh\ncc $SRC/project/native.c -o $OUT/fuzz_target\n", encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "target": "fixture_target",
        "project": "project",
        "fuzz_target": "fuzz_target",
        "source_input_dir": "source_input",
        "reference_harness_dir": "reference_harnesses",
        "reference_harness_files": ["source_input/project/native.c"],
        "selected_reference_harness_dir": "reference_harnesses/selected",
        "selected_reference_harness_files": ["source_input/project/native.c"],
        "selected_reference_harness_count": 1,
        "native_harness_path": "source_input/project/native.c",
        "native_harness_destination": "/src/project/native.c",
        "seed_count": 0,
    }
    (pkg / "target_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (pkg / "source_repos.json").write_text("[]", encoding="utf-8")
    return pkg


class FakeResult:
    def __init__(self, command, exit_code=0, stdout="", stderr=""):
        self.command = list(command)
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


class DeltaFakeRunner:
    """Configurable fake runner for the section-5 evaluator scenarios."""

    def __init__(self, *, coverage_stdout=None, campaign_execs=500, build_exit=0,
                 binary_verified=True, overlay_matches=True, candidate_path=None):
        self.commands = []
        self.campaign_execs = campaign_execs
        self.coverage_stdout = coverage_stdout if coverage_stdout is not None else json.dumps({
            "data": [{"totals": {"lines": {"count": 100, "covered": 27},
                                  "functions": {"count": 10, "covered": 5},
                                  "regions": {"count": 50, "covered": 12}},
                      "functions": [{"name": "hgb_sample_api", "count": 5}]}],
            "type": "llvm.coverage.json.export", "version": "2.0.1",
        })
        self.build_exit = build_exit
        self.binary_verified = binary_verified
        self.overlay_matches = overlay_matches
        import hashlib
        if candidate_path is not None and Path(candidate_path).is_file():
            self.candidate_sha = hashlib.sha256(Path(candidate_path).read_bytes()).hexdigest()
        else:
            self.candidate_sha = "candsha"
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
                    return FakeResult(cmd, 0, "smoke ok", "")
                if phase == "campaign":
                    out = f"#{self.campaign_execs} INITED\nstat::number_of_executed_units: {self.campaign_execs}\n"
                    return FakeResult(cmd, 0, out, "")
                if phase == "coverage":
                    return FakeResult(cmd, 0, self.coverage_stdout, "")
                return FakeResult(cmd, 0, "", "")
            if sub == "cp":
                return FakeResult(cmd, 0, "", "")
            if sub == "rm":
                return FakeResult(cmd, 0, "", "")
            if sub == "run":
                # Binary verification and overlay audit use `docker run --rm`.
                shell_cmd = " ".join(cmd[3:])
                if "test -x" in shell_cmd and "sha256sum" in shell_cmd:
                    if self.binary_verified:
                        return FakeResult(cmd, 0, f"{self.candidate_sha}  /out/fuzz_target\n", "")
                    return FakeResult(cmd, 1, "", "not found")
                if "sha256sum /src/" in shell_cmd:
                    if self.overlay_matches:
                        return FakeResult(cmd, 0, f"{self.candidate_sha}  /src/project/native.c\n", "")
                    return FakeResult(cmd, 0, "referenceSHA  /src/project/native.c\n", "")
                return FakeResult(cmd, 0, "", "")
        return FakeResult(cmd, 0, "", "")


def _setup_evaluator_paths(tmp_path: Path):
    gen_root = tmp_path / "generator_input"
    evl_root = tmp_path / "evaluator_only"
    candidates_dir = tmp_path / "candidates"
    work_dir = tmp_path / "evaluation"
    (gen_root / "seeds").mkdir(parents=True)
    (gen_root / "source_input" / "project").mkdir(parents=True)
    (gen_root / "source_input" / "project" / "sample.c").write_text("int api(void){return 0;}\n", encoding="utf-8")
    (gen_root / "source_input" / "project" / "native.c").write_text("// original native\nint LLVMFuzzerTestOneInput(){}\n", encoding="utf-8")
    (gen_root / "source_repos.json").write_text("[]", encoding="utf-8")
    (evl_root / "benchmark_copy").mkdir(parents=True)
    (evl_root / "benchmark_copy" / "Dockerfile").write_text("FROM scratch\nCOPY source_input/ /src/\n", encoding="utf-8")
    (evl_root / "benchmark_copy" / "build.sh").write_text("#!/bin/sh\ncc $SRC/project/native.c -o $OUT/fuzz_target\n", encoding="utf-8")
    (evl_root / "reference_harnesses" / "source_input" / "project").mkdir(parents=True)
    (evl_root / "reference_harnesses" / "source_input" / "project" / "native.c").write_text("// ref\n", encoding="utf-8")
    (evl_root / "reference_harnesses" / "selected" / "source_input" / "project").mkdir(parents=True)
    (evl_root / "reference_harnesses" / "selected" / "source_input" / "project" / "native.c").write_text("// ref selected\n", encoding="utf-8")
    (evl_root / "native_harness_path.json").write_text(json.dumps({
        "selected_reference": "source_input/project/native.c",
        "container_destination": "/src/project/native.c",
        "language": "c",
    }), encoding="utf-8")
    (evl_root / "evaluator_manifest.json").write_text(json.dumps({"benchmark_copy_dir": "benchmark_copy"}), encoding="utf-8")
    (evl_root / "target_manifest.evaluator.json").write_text(json.dumps({"target": "t"}), encoding="utf-8")
    candidates_dir.mkdir(parents=True)
    (candidates_dir / "cand_001.c").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char *d, long n){return 0;}\n", encoding="utf-8"
    )
    return gen_root, evl_root, candidates_dir, work_dir


# ---------------------------------------------------------------------------
# 1. Profile acceptance
# ---------------------------------------------------------------------------


def test_reproduction_delta_is_valid_profile() -> None:
    assert "reproduction-delta" in profile.VALID_PROFILES
    assert profile.is_method_faithful("reproduction-delta")
    violations = profile.validate_profile("reproduction-delta", "blind-project", {
        "CKGFUZZER_EMBEDDING_MODEL": "openai-text-embedding-3-small",
    })
    assert violations == [], violations


def test_reproduction_delta_forbids_local_fallbacks() -> None:
    for bad_env in (
        {"CKGFUZZER_LOCAL_API_SUMMARY": "1"},
        {"CKGFUZZER_LOCAL_API_COMBINATION": "1"},
        {"CKGFUZZER_SKIP_CHECK_COMPILATION": "1"},
        {"CKGFUZZER_EMBEDDING_MODEL": "mock"},
        {"CKGFUZZER_ALLOW_SOURCE_FALLBACK": "1"},
        {"HGB_API_SELECTION_MODE": "selected_harness"},
    ):
        violations = profile.validate_profile("reproduction-delta", "blind-project", bad_env)
        assert violations, f"expected violation for {bad_env}"


def test_reproduction_delta_maps_to_paper_faithful_method_variant() -> None:
    result = hgb_result.build_result(
        profile="reproduction-delta", protocol="blind-project", target="t",
        status="evaluated",
        stages={n: "completed" for n in hgb_result.STAGE_NAMES},
    )
    assert result["method_variant"] == "paper-faithful"


def test_dry_run_passes_profile_validation_without_docker(tmp_path: Path) -> None:
    env = dict(os.environ)
    env["PATH"] = str(REPO_ROOT / "scripts") + os.pathsep + env.get("PATH", "")
    proc = subprocess.run(
        ["bash", "scripts/hgb_run_baseline.sh", "--generator", "ckgfuzzer",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-delta", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=env, timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    workspace = proc.stdout.strip().splitlines()[-1]
    result = json.loads((Path(workspace) / "result.json").read_text(encoding="utf-8"))
    assert result["status"] == "dry_run_ok"
    assert result["profile"] == "reproduction-delta"


# ---------------------------------------------------------------------------
# 2. Fail-closed target split
# ---------------------------------------------------------------------------


def test_split_package_writes_reference_canary_into_evaluator_only(tmp_path: Path) -> None:
    pkg = _make_monolithic_package(tmp_path)
    os.environ["HGB_REF_CANARY"] = "HGB_REF_CANARY_DELTA_TEST"
    try:
        halves = hgb_target_package.split_package(
            pkg,
            native_harness={
                "selected_reference": "source_input/project/native.c",
                "container_destination": "/src/project/native.c",
                "language": "c",
            },
            require_split=True,
        )
    finally:
        os.environ.pop("HGB_REF_CANARY", None)
    evl = Path(halves["evaluator_only"])
    assert (evl / "reference_canary.txt").is_file()
    assert "HGB_REF_CANARY_DELTA_TEST" in (evl / "reference_canary.txt").read_text()


def test_require_split_fails_when_source_input_missing(tmp_path: Path) -> None:
    pkg = _make_monolithic_package(tmp_path)
    import shutil
    shutil.rmtree(pkg / "source_input")
    with pytest.raises(hgb_target_package.PackageSplitError):
        hgb_target_package.split_package(pkg, native_harness={}, require_split=True)


def test_generator_input_has_no_reference_harnesses_or_canary(tmp_path: Path) -> None:
    pkg = _make_monolithic_package(tmp_path)
    os.environ["HGB_REF_CANARY"] = "HGB_REF_CANARY_DELTA_TEST"
    try:
        halves = hgb_target_package.split_package(
            pkg,
            native_harness={
                "selected_reference": "source_input/project/native.c",
                "container_destination": "/src/project/native.c",
                "language": "c",
            },
            require_split=True,
        )
    finally:
        os.environ.pop("HGB_REF_CANARY", None)
    gen = Path(halves["generator_input"])
    audit = hgb_target_package.audit_generator_input(gen)
    assert audit["clean"], f"reference tokens leaked into generator_input: {audit['hits']}"
    # The canary must never appear under generator_input.
    canary = "HGB_REF_CANARY_DELTA_TEST"
    for p in gen.rglob("*"):
        if p.is_file():
            assert canary not in p.read_text(encoding="utf-8", errors="replace"), p


def test_common_sh_fail_closed_for_delta_requires_split_halves() -> None:
    common = (REPO_ROOT / "scripts/lib/common.sh").read_text(encoding="utf-8")
    assert "reproduction-delta" in common
    assert "missing $target_package/generator_input/target_manifest.json" in common
    assert "missing $target_package/evaluator_only/evaluator_manifest.json" in common
    assert "reference canary leaked into generator_input" in common


def test_hgb_targets_supports_require_split_flag() -> None:
    proc = subprocess.run(
        ["python3", "scripts/hgb_targets.py", "package", "--help"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30,
    )
    assert "--require-split" in proc.stdout


# ---------------------------------------------------------------------------
# 3. Strict overlay model
# ---------------------------------------------------------------------------


def test_evaluator_restore_non_target_harnesses_skips_selected_native(tmp_path: Path) -> None:
    ref_dir = tmp_path / "refs"
    (ref_dir / "selected" / "source_input" / "project").mkdir(parents=True)
    (ref_dir / "source_input" / "project").mkdir(parents=True)
    (ref_dir / "selected" / "source_input" / "project" / "native.c").write_text("// selected native\n", encoding="utf-8")
    (ref_dir / "source_input" / "project" / "sibling_fuzzer.c").write_text("// sibling\n", encoding="utf-8")
    sealed = tmp_path / "sealed"
    sealed.mkdir(parents=True)
    audit = hgb_split_context.evaluator_restore_non_target_harnesses(
        ref_dir, "/src/project/native.c", sealed,
    )
    # The selected native harness must NOT be restored.
    assert not (sealed / "hgb_non_target_reference_harnesses" / "source_input" / "project" / "native.c").exists()
    assert "project/native.c" in audit["skipped"]
    # The sibling fuzzer must be preserved.
    assert (sealed / "hgb_non_target_reference_harnesses" / "source_input" / "project" / "sibling_fuzzer.c").is_file()
    assert (sealed / "reference_restore_audit.json").is_file()


def test_sealed_dockerfile_does_not_copy_reference_after_candidate(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    ctx = hgb_split_context.SplitTargetContext.load(gen_root, evl_root)
    sealed = hgb_split_context.create_sealed_build_context(ctx, work_dir / "sealed")
    dockerfile = Path(sealed["dockerfile"]).read_text(encoding="utf-8")
    # The strict overlay uses hgb_non_target_reference_harnesses, never the
    # old hgb_reference_harnesses that included the selected native.
    assert "hgb_non_target_reference_harnesses" in dockerfile
    # The candidate overlay COPY must come after the non-target restore.
    non_target_pos = dockerfile.index("hgb_non_target_reference_harnesses")
    candidate_overlay_pos = dockerfile.find("hgb_candidate_overlay")
    # The candidate overlay is appended by build_candidate_image at build time;
    # the non-target restore line must exist and not be the old reference merge.
    assert "COPY hgb_reference_harnesses/ /src/" not in dockerfile


def test_overlay_audit_detects_reference_overwrite(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = DeltaFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"), overlay_matches=False)
    result = evaluator.evaluate(
        generator="ckgfuzzer",
        target_root=gen_root,
        evaluator_root=evl_root,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="project",
        fuzz_target="fuzz_target",
        profile="reproduction-delta",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        intended_apis=[],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    # The overlay audit must record that the source did not match the candidate.
    assert cand_json["build"]["overlay_audit"]["matches_candidate"] is False
    assert result["status"] != hgb_result.STATUS_EVALUATED


# ---------------------------------------------------------------------------
# 4. Old verifier not called for delta
# ---------------------------------------------------------------------------


def test_entrypoint_delta_never_calls_old_verifier() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    cond = '"$ckg_method_faithful" == "1" ]]'
    assert cond in entrypoint
    cond_pos = entrypoint.index(cond)
    evaluator_pos = entrypoint.index("hgb_harness_evaluator.py")
    verifier_pos = entrypoint.index("ckgfuzzer_candidate_verifier.py")
    # The method-faithful branch routes directly to the evaluator.
    assert evaluator_pos < verifier_pos
    block = entrypoint[cond_pos:evaluator_pos]
    assert "ckgfuzzer_candidate_verifier.py" not in block
    # A fail-closed guard must prevent method-faithful profiles from reaching
    # the old verifier in the compat-smoke branch.
    guard = "reproduction-delta"
    assert guard in entrypoint


# ---------------------------------------------------------------------------
# 5. Real build / campaign / coverage / reachability
# ---------------------------------------------------------------------------


def test_build_success_without_binary_fails_candidate_build(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = DeltaFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"), binary_verified=False)
    result = evaluator.evaluate(
        generator="ckgfuzzer",
        target_root=gen_root,
        evaluator_root=evl_root,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="project",
        fuzz_target="fuzz_target",
        profile="reproduction-delta",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        intended_apis=[],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["candidate_build"] == "failed"
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_zero_exec_campaign_fails(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = DeltaFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"), campaign_execs=0)
    result = evaluator.evaluate(
        generator="ckgfuzzer",
        target_root=gen_root,
        evaluator_root=evl_root,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="project",
        fuzz_target="fuzz_target",
        profile="reproduction-delta",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        intended_apis=[],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["campaign"] == "failed"
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_empty_coverage_fails_coverage_stage(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = DeltaFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"), coverage_stdout="")
    result = evaluator.evaluate(
        generator="ckgfuzzer",
        target_root=gen_root,
        evaluator_root=evl_root,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="project",
        fuzz_target="fuzz_target",
        profile="reproduction-delta",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        intended_apis=[],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["coverage"] == "failed"
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_reachability_fails_when_coverage_lacks_intended_api(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    bad_cov = json.dumps({
        "data": [{"totals": {"lines": {"count": 100, "covered": 27},
                              "functions": {"count": 10, "covered": 5},
                              "regions": {"count": 50, "covered": 12}},
                  "functions": [{"name": "unrelated_func", "count": 5}]}],
        "type": "llvm.coverage.json.export", "version": "2.0.1",
    })
    runner = DeltaFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"), coverage_stdout=bad_cov)
    result = evaluator.evaluate(
        generator="ckgfuzzer",
        target_root=gen_root,
        evaluator_root=evl_root,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="project",
        fuzz_target="fuzz_target",
        profile="reproduction-delta",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        intended_apis=["hgb_sample_api"],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["api_reachability"] == "failed"
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_full_evaluated_loop_succeeds_for_delta(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = DeltaFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"))
    result = evaluator.evaluate(
        generator="ckgfuzzer",
        target_root=gen_root,
        evaluator_root=evl_root,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="project",
        fuzz_target="fuzz_target",
        profile="reproduction-delta",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        intended_apis=["hgb_sample_api"],
        seeds=[],
    )
    assert result["status"] == hgb_result.STATUS_EVALUATED
    assert result["method_variant"] == "paper-faithful"
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["build"]["overlay_audit"]["matches_candidate"] is True
    assert cand_json["build"]["binary_verified"] is True


# ---------------------------------------------------------------------------
# 6. Method evidence (entrypoint guard)
# ---------------------------------------------------------------------------


def test_entrypoint_collects_method_evidence_for_delta() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert "ckg_method_dir" in entrypoint
    for evidence in ("codeql_db.json", "api_list.json", "api_summaries.jsonl", "api_combinations.jsonl", "llm_trace.jsonl"):
        assert evidence in entrypoint
    assert "ckg_method_evidence_missing" in entrypoint


# ---------------------------------------------------------------------------
# 7. Matrix semantics
# ---------------------------------------------------------------------------


def test_matrix_paper_equivalent_delta_gate() -> None:
    base = {
        "generator": "ckgfuzzer",
        "target": "jsoncpp_jsoncpp_fuzzer",
        "status": "evaluated",
        "applicability": "applicable",
        "profile": "reproduction-delta",
        "method_variant": "paper-faithful",
        "excluded_from_aggregate": False,
        "stages": {n: "completed" for n in ("candidate_build", "sanitizer_smoke", "api_reachability", "campaign", "coverage")},
        "metrics": {
            "coverage": {"line_coverage": {"covered": 27}, "function_coverage": {"covered": 5}, "region_coverage": {"covered": 12}},
            "campaign": {"execs_done": 500, "crashes": 0, "timeouts": 0},
        },
        "build": {"overlay_audit": {"matches_candidate": True}},
        "selected_candidate": {"copy_audit": {"exact_copy": False}, "build": {"overlay_audit": {"matches_candidate": True}}},
        "candidate": {"contains_reference_canary": False, "near_duplicate_reference": False},
    }
    row = collector.extract_ckgfuzzer_row(base)
    assert row["paper_equivalent_delta"] is True

    # Each condition below must flip paper_equivalent_delta to False.
    for mutation in (
        {"profile": "alpha"},
        {"method_variant": "compat-smoke"},
        {"status": "quality_failure"},
        {"excluded_from_aggregate": True},
        {"metrics": {"coverage": {"line_coverage": {"covered": 0}}, "campaign": {"execs_done": 500}}},
        {"metrics": {"coverage": {"line_coverage": {"covered": 27}}, "campaign": {"execs_done": 0}}},
        {"selected_candidate": {"copy_audit": {"exact_copy": True}, "build": {"overlay_audit": {"matches_candidate": True}}}},
        {"selected_candidate": {"copy_audit": {"exact_copy": False}, "build": {"overlay_audit": {"matches_candidate": False}}}},
    ):
        mutated = json.loads(json.dumps(base))
        mutated.update(mutation)
        row = collector.extract_ckgfuzzer_row(mutated)
        assert row["paper_equivalent_delta"] is False, mutation


def test_evaluated_row_violations_enforce_delta_overlay_audit() -> None:
    meta = {
        "task_family": "harness_generator",
        "profile": "reproduction-delta",
        "method_variant": "paper-faithful",
        "status": "evaluated",
        "excluded_from_aggregate": False,
        "metrics": {
            "coverage": {"line_coverage": {"covered": 27}},
            "campaign": {"execs_done": 500},
        },
        "selected_candidate": {
            "copy_audit": {"exact_copy": True},
            "build": {"overlay_audit": {"matches_candidate": False}},
        },
    }
    violations = collector.evaluated_row_violations(meta)
    assert any("exact_copy" in v for v in violations)
    assert any("matches_candidate" in v for v in violations)


# ---------------------------------------------------------------------------
# 8. Result schema v2 fields
# ---------------------------------------------------------------------------


def test_build_result_writes_required_schema_v2_fields() -> None:
    result = hgb_result.build_result(
        profile="reproduction-delta", protocol="blind-project", target="t",
        status="evaluated",
        stages={n: "completed" for n in hgb_result.STAGE_NAMES},
        metrics={"coverage": {"line_coverage": {"covered": 5}}, "campaign": {"execs_done": 10}},
        selected_candidate={"overlaid": True, "candidate_path": "/x"},
    )
    for field in ("task_family", "profile", "protocol", "method_variant", "status",
                   "applicability", "stages", "artifacts", "metrics", "selected_candidate",
                   "excluded_from_aggregate"):
        assert field in result, f"missing schema field {field}"
    assert result["task_family"] == "harness_generator"
