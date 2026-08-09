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


hgb_target_package = _load_module("hgb_target_package_epsilon", "docker/common/hgb_target_package.py")
hgb_split_context = _load_module("hgb_split_context_epsilon", "docker/common/hgb_split_context.py")
SplitContextError = hgb_split_context.VerificationContextError
hgb_result = _load_module("hgb_result_epsilon", "docker/common/hgb_result.py")
hgb_coverage = _load_module("hgb_coverage_epsilon", "docker/common/hgb_coverage.py")
hgb_reachability = _load_module("hgb_reachability_epsilon", "docker/common/hgb_reachability.py")
hgb_fuzzbench_builder = _load_module("hgb_fuzzbench_builder_epsilon", "docker/common/hgb_fuzzbench_builder.py")
evaluator = _load_module("hgb_harness_evaluator_epsilon", "docker/common/hgb_harness_evaluator.py")
profile = _load_module("ckgfuzzer_profile_epsilon", "docker/common/ckgfuzzer_profile.py")
collector = _load_module("hgb_collect_matrix_epsilon", "scripts/hgb_collect_matrix.py")


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
        "// HGB_REF_CANARY_EPSILON_REF\nint LLVMFuzzerTestOneInput(void){return 0;}\n", encoding="utf-8"
    )
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


class EpsilonFakeRunner:
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


def _run_env():
    env = dict(os.environ)
    env["PATH"] = str(REPO_ROOT / "scripts") + os.pathsep + env.get("PATH", "")
    return env


# ---------------------------------------------------------------------------
# E0. Profile acceptance and strictness
# ---------------------------------------------------------------------------


def test_reproduction_epsilon_is_valid_profile() -> None:
    assert "reproduction-epsilon" in profile.VALID_PROFILES
    assert profile.is_method_faithful("reproduction-epsilon")
    assert "reproduction-epsilon" in profile.STRICT_REPRODUCTION_PROFILES
    violations = profile.validate_profile("reproduction-epsilon", "blind-project", {
        "CKGFUZZER_EMBEDDING_MODEL": "openai-text-embedding-3-small",
    })
    assert violations == [], violations


def test_reproduction_delta_remains_accepted_as_alias() -> None:
    assert "reproduction-delta" in profile.VALID_PROFILES
    assert "reproduction-delta" in profile.STRICT_REPRODUCTION_PROFILES


def test_reproduction_epsilon_forbids_non_paper_shortcuts() -> None:
    # CKG-3: every non-paper shortcut must be rejected in strict profiles.
    for bad_env in (
        {"CKGFUZZER_LOCAL_API_SUMMARY": "1"},
        {"CKGFUZZER_LOCAL_API_COMBINATION": "1"},
        {"CKGFUZZER_SKIP_CHECK_COMPILATION": "1"},
        {"CKGFUZZER_EMBEDDING_MODEL": "mock"},
        {"CKGFUZZER_EMBEDDING_MODEL": "hgb-hash-embedding"},
        {"CKGFUZZER_ALLOW_SOURCE_FALLBACK": "1"},
        {"HGB_API_SELECTION_MODE": "selected_harness"},
        {"HGB_API_SELECTION_MODE": "selected_harness_fallback"},
    ):
        violations = profile.validate_profile("reproduction-epsilon", "blind-project", bad_env)
        assert violations, f"expected violation for {bad_env}"


def test_reproduction_epsilon_maps_to_paper_faithful_method_variant() -> None:
    result = hgb_result.build_result(
        profile="reproduction-epsilon", protocol="blind-project", target="t",
        status="evaluated",
        stages={n: "completed" for n in hgb_result.STAGE_NAMES},
    )
    assert result["method_variant"] == "paper-faithful"


def test_dry_run_canonical_command_passes_profile_validation(tmp_path: Path) -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_run_baseline.sh", "--generator", "ckgfuzzer",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-epsilon",
         "--protocol", "blind-project", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    workspace = proc.stdout.strip().splitlines()[-1]
    result = json.loads((Path(workspace) / "result.json").read_text(encoding="utf-8"))
    assert result["status"] == "dry_run_ok"
    assert result["profile"] == "reproduction-epsilon"
    assert result["method_variant"] == "paper-faithful"


def test_unknown_profile_exits_with_code_2() -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_run_baseline.sh", "--generator", "ckgfuzzer",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-zeta",
         "--protocol", "blind-project", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    assert proc.returncode == 2, proc.stderr
    assert "invalid profile" in proc.stderr


def test_hgb_generate_harness_rejects_unknown_profile_with_code_2() -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_generate_harness.sh", "--generator", "ckgfuzzer",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-zeta", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    assert proc.returncode == 2, proc.stderr
    assert "unknown profile" in proc.stderr


def test_hgb_generate_harness_accepts_reproduction_epsilon() -> None:
    # The lower-level wrapper must accept reproduction-epsilon (E0.3). It does
    # not build Docker in a dry-run shim; it only validates args and forwards.
    proc = subprocess.run(
        ["bash", "scripts/hgb_generate_harness.sh", "--generator", "ckgfuzzer",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-epsilon", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    # It may proceed past profile validation (exit 0 or a later non-2 code);
    # the contract here is that it is NOT rejected as an unknown profile.
    assert proc.returncode != 2
    assert "unknown profile" not in proc.stderr


# ---------------------------------------------------------------------------
# E1. Fail-closed split target package
# ---------------------------------------------------------------------------


def test_common_sh_fail_closed_for_epsilon_requires_split_halves() -> None:
    common = (REPO_ROOT / "scripts/lib/common.sh").read_text(encoding="utf-8")
    assert "hgb_profile_is_strict_reproduction" in common
    assert "reproduction-epsilon" in common
    assert "missing $target_package/generator_input/target_manifest.json" in common
    assert "missing $target_package/evaluator_only/evaluator_manifest.json" in common
    assert "reference canary leaked into generator_input" in common


def test_hgb_targets_infers_require_split_for_epsilon() -> None:
    env = dict(os.environ)
    env["HGB_BASELINE_PROFILE"] = "reproduction-epsilon"
    env["HGB_BASELINE_PROTOCOL"] = "blind-project"
    proc = subprocess.run(
        ["python3", "scripts/hgb_targets.py", "package", "--help"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=env, timeout=30,
    )
    assert "--require-split" in proc.stdout


def test_split_package_writes_reference_canary_into_evaluator_only(tmp_path: Path) -> None:
    pkg = _make_monolithic_package(tmp_path)
    os.environ["HGB_REF_CANARY"] = "HGB_REF_CANARY_EPSILON_TEST"
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
    assert "HGB_REF_CANARY_EPSILON_TEST" in (evl / "reference_canary.txt").read_text()


def test_require_split_fails_when_source_input_missing(tmp_path: Path) -> None:
    pkg = _make_monolithic_package(tmp_path)
    import shutil
    shutil.rmtree(pkg / "source_input")
    with pytest.raises(hgb_target_package.PackageSplitError):
        hgb_target_package.split_package(pkg, native_harness={}, require_split=True)


def test_generator_input_has_no_reference_harnesses_or_canary(tmp_path: Path) -> None:
    pkg = _make_monolithic_package(tmp_path)
    os.environ["HGB_REF_CANARY"] = "HGB_REF_CANARY_EPSILON_TEST"
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
    canary = "HGB_REF_CANARY_EPSILON_TEST"
    for p in gen.rglob("*"):
        if p.is_file():
            assert canary not in p.read_text(encoding="utf-8", errors="replace"), p


# ---------------------------------------------------------------------------
# E2. Candidate overlay and copy-audit authoritative
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
    assert not (sealed / "hgb_non_target_reference_harnesses" / "source_input" / "project" / "native.c").exists()
    assert "project/native.c" in audit["skipped"]
    assert (sealed / "hgb_non_target_reference_harnesses" / "source_input" / "project" / "sibling_fuzzer.c").is_file()


def test_sealed_dockerfile_does_not_copy_reference_after_candidate(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    ctx = hgb_split_context.SplitTargetContext.load(gen_root, evl_root)
    sealed = hgb_split_context.create_sealed_build_context(ctx, work_dir / "sealed")
    dockerfile = Path(sealed["dockerfile"]).read_text(encoding="utf-8")
    assert "hgb_non_target_reference_harnesses" in dockerfile
    assert "COPY hgb_reference_harnesses/ /src/" not in dockerfile


def test_overlay_audit_detects_reference_overwrite_for_epsilon(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = EpsilonFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"), overlay_matches=False)
    result = evaluator.evaluate(
        generator="ckgfuzzer",
        target_root=gen_root,
        evaluator_root=evl_root,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="project",
        fuzz_target="fuzz_target",
        profile="reproduction-epsilon",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        intended_apis=[],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["build"]["overlay_audit"]["matches_candidate"] is False
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_copy_audit_rejects_exact_canary_and_near_duplicate(tmp_path: Path) -> None:
    ref_dir = tmp_path / "refs"
    ref_dir.mkdir()
    (ref_dir / "native.c").write_text("// HGB_REF_CANARY_eps secret\nint LLVMFuzzerTestOneInput(){}\n", encoding="utf-8")
    # Canary leak.
    cand_canary = tmp_path / "cand_canary.c"
    cand_canary.write_text("// HGB_REF_CANARY_eps leaked\nint LLVMFuzzerTestOneInput(){}\n", encoding="utf-8")
    r1 = hgb_split_context.audit_candidate_reference_copy(cand_canary, ref_dir, canary="HGB_REF_CANARY_eps")
    assert r1["contains_reference_canary"] is True
    # Exact/near duplicate.
    ref_text = "int LLVMFuzzerTestOneInput(const unsigned char *d, long n){ return 0; }\n"
    (ref_dir / "dup.c").write_text(ref_text, encoding="utf-8")
    cand_dup = tmp_path / "cand_dup.c"
    cand_dup.write_text(ref_text, encoding="utf-8")
    r2 = hgb_split_context.audit_candidate_reference_copy(cand_dup, ref_dir)
    assert r2["exact_copy"] is True
    assert r2["near_duplicate_reference"] is True


# ---------------------------------------------------------------------------
# CKG-1 / CKG-2 / CKG-3 / CKG-5. Entrypoint routing and method evidence
# ---------------------------------------------------------------------------


def test_entrypoint_epsilon_routes_to_method_faithful_evaluator() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    # reproduction-epsilon is accepted.
    assert "reproduction-epsilon" in entrypoint
    # The method-faithful condition includes epsilon.
    assert '"$ckg_profile" == "reproduction-epsilon"' in entrypoint
    # The old verifier must only appear after the method-faithful evaluator branch.
    cond = '"$ckg_method_faithful" == "1" ]]'
    assert cond in entrypoint
    evaluator_pos = entrypoint.index("hgb_harness_evaluator.py")
    verifier_pos = entrypoint.index("ckgfuzzer_candidate_verifier.py")
    assert evaluator_pos < verifier_pos


def test_entrypoint_epsilon_enforces_method_evidence_and_coverage_image() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    # CKG-2: method evidence files are collected and required for epsilon.
    assert "ckg_method_dir" in entrypoint
    for evidence in ("codeql_db.json", "api_list.json", "api_summaries.jsonl", "api_combinations.jsonl", "llm_trace.jsonl"):
        assert evidence in entrypoint
    assert "ckg_method_evidence_missing" in entrypoint
    # The evidence guard and coverage-image guard both cover epsilon.
    assert 'ckg_profile" == "reproduction-delta" || "$ckg_profile" == "reproduction-epsilon" ]]' in entrypoint
    assert '--build-coverage-image' in entrypoint


def test_entrypoint_epsilon_disables_non_paper_shortcuts() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    # CKG-3: source fallback and selected-harness API mode are forbidden for epsilon.
    assert "CKGFUZZER_ALLOW_SOURCE_FALLBACK" in entrypoint
    assert "selected_harness_fallback" in entrypoint


# ---------------------------------------------------------------------------
# E3 / E4 / E5. Real build / smoke / campaign / coverage / reachability
# ---------------------------------------------------------------------------


def test_smoke_runner_copies_input_into_container(tmp_path: Path) -> None:
    work_dir = tmp_path / "smoke"
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"\x01\x02\x03")
    runner = EpsilonFakeRunner()
    hgb_fuzzbench_builder.run_smoke(
        image_tag="hgb-test",
        binary_path="/out/fuzz_target",
        seeds=[seed],
        work_dir=work_dir,
        runner=runner,
    )
    cp_commands = [c for c in runner.commands if c[:2] == ["docker", "cp"]]
    assert cp_commands, "smoke runner must copy input into container"
    assert any(str(seed) in " ".join(c) for c in cp_commands)


def test_build_success_without_binary_fails_candidate_build(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = EpsilonFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"), binary_verified=False)
    result = evaluator.evaluate(
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-epsilon", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=[], seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["candidate_build"] == "failed"
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_zero_exec_campaign_fails_for_epsilon(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = EpsilonFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"), campaign_execs=0)
    result = evaluator.evaluate(
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-epsilon", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=[], seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["campaign"] == "failed"
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_empty_coverage_fails_coverage_stage(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = EpsilonFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"), coverage_stdout="")
    result = evaluator.evaluate(
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-epsilon", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=[], seeds=[],
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
    runner = EpsilonFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"), coverage_stdout=bad_cov)
    result = evaluator.evaluate(
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-epsilon", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["api_reachability"] == "failed"
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_full_evaluated_loop_succeeds_for_epsilon(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = EpsilonFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"))
    result = evaluator.evaluate(
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-epsilon", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
    )
    assert result["status"] == hgb_result.STATUS_EVALUATED
    assert result["method_variant"] == "paper-faithful"
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["build"]["overlay_audit"]["matches_candidate"] is True
    assert cand_json["build"]["binary_verified"] is True


def test_coverage_export_includes_function_detail() -> None:
    source = (REPO_ROOT / "docker/common/hgb_fuzzbench_builder.py").read_text(encoding="utf-8")
    assert "llvm-cov export -format=text -summary-only" not in source
    assert "llvm-cov export -format=text {binary_path}" in source


# ---------------------------------------------------------------------------
# CKG-6 / E7. Valuable-target matrix semantics
# ---------------------------------------------------------------------------


def test_matrix_paper_equivalent_epsilon_gate() -> None:
    base = {
        "generator": "ckgfuzzer",
        "target": "jsoncpp_jsoncpp_fuzzer",
        "status": "evaluated",
        "applicability": "applicable",
        "profile": "reproduction-epsilon",
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
    assert row["paper_equivalent_epsilon"] is True
    assert row["paper_equivalent_strict"] is True
    assert row["paper_equivalent_delta"] is False

    # Each condition below must flip paper_equivalent_epsilon to False.
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
        assert row["paper_equivalent_epsilon"] is False, mutation


def test_evaluated_row_violations_enforce_epsilon_invariants() -> None:
    meta = {
        "task_family": "harness_generator",
        "profile": "reproduction-epsilon",
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


def test_valuable_target_set_has_twenty_targets() -> None:
    hgb_targets = _load_module("hgb_targets_epsilon", "scripts/hgb_targets.py")
    registry = hgb_targets.load_registry(REPO_ROOT)
    valuable = hgb_targets.targets_for_set(registry, "valuable")
    assert len(valuable) == 20


def test_matrix_runner_wrapper_accepts_epsilon_args() -> None:
    wrapper = (REPO_ROOT / "scripts/hgb_run_baseline_matrix.sh").read_text(encoding="utf-8")
    assert "hgb_generate_matrix.sh" in wrapper
    assert "--profile" in wrapper
    assert "--campaign-seconds" in wrapper
    # The wrapper must translate --generator to --generators and forward --profile.
    assert '--generators "$generators"' in wrapper
    assert '--profile "$profile"' in wrapper
