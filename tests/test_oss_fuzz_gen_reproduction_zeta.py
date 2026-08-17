"""Zeta reproduction tests for the OSS-Fuzz-Gen harness-generator pipeline.

These tests exercise the strictest paper-native OSS-Fuzz-Gen reproduction
contract from ``plans/oss-fuzz-gen_reproduction_zeta.md``.

OSS-Fuzz-Gen is a ``harness_generator``: it uses OSS-Fuzz project context,
Fuzz Introspector, LLM generation, build repair, and coverage evaluation. The
zeta plan adds these requirements on top of epsilon:
* zeta profile acceptance and strict env defaults (real Introspector, no
  reference examples, no selected-harness API ranking, repair loop, coverage,
  sealed split package).
* generation prompt/context rejects selected reference harness body and
  selected-harness API ranking.
* real Introspector manifest required and project/target scoped.
* repair attempt artifacts are persisted.
* shared evaluator rejects no coverage, missing final corpus, loose smoke,
  coverage image fallback, and near-duplicate reference candidate.
* result matrix marks paper_equivalent=false when native control coverage
  diff is unavailable.
"""

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


ofg_profile = _load_module("ofg_profile_zeta", "docker/common/ofg_profile.py")
hgb_result = _load_module("hgb_result_zeta", "docker/common/hgb_result.py")
hgb_fuzzbench_builder = _load_module("hgb_fuzzbench_builder_zeta", "docker/common/hgb_fuzzbench_builder.py")
evaluator = _load_module("hgb_harness_evaluator_zeta", "docker/common/hgb_harness_evaluator.py")
ofg_run_wrapper = _load_module("ofg_run_wrapper_zeta", "docker/common/ofg_run_wrapper.py")
collector = _load_module("hgb_collect_matrix_zeta", "scripts/hgb_collect_matrix.py")


LLVM_COVERAGE_JSON = json.dumps({
    "data": [{"totals": {"lines": {"count": 100, "covered": 27},
                          "functions": {"count": 10, "covered": 5},
                          "regions": {"count": 50, "covered": 12}},
              "functions": [{"name": "hgb_sample_api", "count": 5}]}],
    "type": "llvm.coverage.json.export", "version": "2.0.1",
})


def _run_env():
    env = dict(os.environ)
    env["PATH"] = str(REPO_ROOT / "scripts") + os.pathsep + env.get("PATH", "")
    return env


# ---------------------------------------------------------------------------
# Z0. Profile acceptance and strict env defaults
# ---------------------------------------------------------------------------


def test_reproduction_zeta_is_valid_profile() -> None:
    assert "reproduction-zeta" in ofg_profile.VALID_PROFILES
    assert ofg_profile.is_method_faithful("reproduction-zeta")
    assert "reproduction-zeta" in ofg_profile.STRICT_REPRODUCTION_PROFILES
    assert "reproduction-zeta" in ofg_profile.ZETA_PROFILES


def test_reproduction_zeta_preserves_epsilon_and_delta_aliases() -> None:
    assert "reproduction-epsilon" in ofg_profile.VALID_PROFILES
    assert "reproduction-delta" in ofg_profile.VALID_PROFILES
    assert "reproduction-epsilon" in ofg_profile.STRICT_REPRODUCTION_PROFILES
    assert "reproduction-delta" in ofg_profile.STRICT_REPRODUCTION_PROFILES


def test_reproduction_zeta_rejects_local_introspector_shim() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-zeta", "blind-project",
        {"OFG_ALLOW_LOCAL_INTROSPECTOR_SHIM": "1", "HGB_TARGET_REQUIRE_SPLIT": "1"},
    )
    assert any("OFG_ALLOW_LOCAL_INTROSPECTOR_SHIM" in v for v in violations)


def test_reproduction_zeta_rejects_reference_examples() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-zeta", "blind-project",
        {"OFG_ALLOW_REFERENCE_EXAMPLES": "1", "HGB_TARGET_REQUIRE_SPLIT": "1"},
    )
    assert any("OFG_ALLOW_REFERENCE_EXAMPLES" in v for v in violations)


def test_reproduction_zeta_rejects_selected_harness_api_ranking() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-zeta", "blind-project",
        {"OFG_ALLOW_SELECTED_HARNESS_API_RANKING": "1", "HGB_TARGET_REQUIRE_SPLIT": "1"},
    )
    assert any("OFG_ALLOW_SELECTED_HARNESS_API_RANKING" in v for v in violations)


def test_reproduction_zeta_rejects_repair_loop_disabled() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-zeta", "blind-project",
        {"OFG_ENABLE_REPAIR_LOOP": "0", "HGB_TARGET_REQUIRE_SPLIT": "1"},
    )
    assert any("OFG_ENABLE_REPAIR_LOOP" in v for v in violations)


def test_reproduction_zeta_rejects_coverage_disabled() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-zeta", "blind-project",
        {"OFG_ENABLE_COVERAGE": "0", "HGB_TARGET_REQUIRE_SPLIT": "1"},
    )
    assert any("OFG_ENABLE_COVERAGE" in v for v in violations)


def test_reproduction_zeta_requires_split() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-zeta", "blind-project",
        {},
    )
    assert any("HGB_TARGET_REQUIRE_SPLIT" in v for v in violations)


def test_reproduction_zeta_clean_with_all_required_env() -> None:
    violations = ofg_profile.validate_profile("reproduction-zeta", "blind-project", {
        "OFG_INTROSPECTOR_MODE": "real",
        "HGB_TARGET_REQUIRE_SPLIT": "1",
    })
    assert violations == [], violations


def test_reproduction_zeta_rejects_coverage_skip() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-zeta", "blind-project",
        {"OFG_SKIP_COVERAGE_GAINS": "1", "HGB_TARGET_REQUIRE_SPLIT": "1"},
    )
    assert any("OFG_SKIP_COVERAGE_GAINS" in v for v in violations)


def test_reproduction_zeta_rejects_gcs_target_download() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-zeta", "target-aware",
        {"OFG_ALLOW_GCS_TARGET_DOWNLOAD": "1", "HGB_TARGET_REQUIRE_SPLIT": "1"},
    )
    assert any("OFG_ALLOW_GCS_TARGET_DOWNLOAD" in v for v in violations)


def test_dry_run_canonical_command_passes_zeta_profile_validation() -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_run_baseline.sh", "--generator", "oss-fuzz-gen",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-zeta",
         "--protocol", "blind-project", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    workspace = proc.stdout.strip().splitlines()[-1]
    result = json.loads((Path(workspace) / "result.json").read_text(encoding="utf-8"))
    assert result["status"] == "dry_run_ok"
    assert result["profile"] == "reproduction-zeta"
    assert result["method_variant"] == "paper-faithful"


def test_hgb_generate_harness_accepts_reproduction_zeta() -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_generate_harness.sh", "--generator", "oss-fuzz-gen",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-zeta", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    assert proc.returncode != 2
    assert "unknown profile" not in proc.stderr


def test_ofg_run_wrapper_is_method_faithful_for_zeta(monkeypatch) -> None:
    monkeypatch.setenv("HGB_BASELINE_PROFILE", "reproduction-zeta")
    assert ofg_run_wrapper.is_method_faithful() is True
    assert ofg_run_wrapper.is_strict_reproduction() is True


def test_entrypoint_has_reproduction_zeta_profile_defaults() -> None:
    entrypoint = (REPO_ROOT / "docker/oss-fuzz-gen/entrypoint.sh").read_text(encoding="utf-8")
    assert "reproduction-zeta)" in entrypoint
    assert "OFG_USE_REAL_OSS_FUZZ" in entrypoint
    assert "OFG_ALLOW_LOCAL_INTROSPECTOR_SHIM" in entrypoint
    assert "OFG_ALLOW_REFERENCE_EXAMPLES" in entrypoint
    assert "OFG_ALLOW_SELECTED_HARNESS_API_RANKING" in entrypoint
    assert "OFG_ENABLE_REPAIR_LOOP" in entrypoint
    assert "OFG_ENABLE_COVERAGE" in entrypoint
    assert "HGB_TARGET_REQUIRE_SPLIT=1" in entrypoint


def test_hgb_run_baseline_zeta_section_forces_env() -> None:
    script = (REPO_ROOT / "scripts/hgb_run_baseline.sh").read_text(encoding="utf-8")
    assert "OFG_ALLOW_LOCAL_INTROSPECTOR_SHIM" in script
    assert "OFG_ALLOW_REFERENCE_EXAMPLES" in script
    assert "OFG_ALLOW_SELECTED_HARNESS_API_RANKING" in script
    assert "OFG_ENABLE_REPAIR_LOOP" in script
    assert "OFG_ENABLE_COVERAGE" in script


# ---------------------------------------------------------------------------
# Z1. Generation prompt/context rejects reference leaks
# ---------------------------------------------------------------------------


def test_prompt_audit_rejects_exact_reference_harness_for_zeta() -> None:
    audit = {
        "exact_reference_harness_in_prompt": True,
        "selected_harness_api_metadata_used": False,
    }
    violations = ofg_profile.validate_prompt_audit(audit, profile="reproduction-zeta")
    assert any("exact_reference_harness_in_prompt" in v for v in violations)


def test_prompt_audit_rejects_selected_harness_api_metadata_for_zeta() -> None:
    audit = {
        "exact_reference_harness_in_prompt": False,
        "selected_harness_api_metadata_used": True,
    }
    violations = ofg_profile.validate_prompt_audit(audit, profile="reproduction-zeta")
    assert any("selected_harness_api_metadata_used" in v for v in violations)


def test_prompt_audit_clean_for_zeta() -> None:
    audit = {
        "exact_reference_harness_in_prompt": False,
        "selected_harness_api_metadata_used": False,
    }
    violations = ofg_profile.validate_prompt_audit(audit, profile="reproduction-zeta")
    assert violations == []


# ---------------------------------------------------------------------------
# Z2. Real Introspector manifest required and project/target scoped
# ---------------------------------------------------------------------------


def test_introspector_provenance_rejects_local_shim_for_zeta() -> None:
    provenance = ofg_profile.build_introspector_provenance(
        mode="local", project="jsoncpp", target="jsoncpp_fuzzer", function_count=10,
    )
    violations = ofg_profile.validate_introspector_provenance(provenance, profile="reproduction-zeta")
    assert any("mode=local" in v for v in violations)


def test_introspector_provenance_rejects_zero_functions_for_zeta() -> None:
    provenance = ofg_profile.build_introspector_provenance(
        mode="real", project="jsoncpp", target="jsoncpp_fuzzer", function_count=0,
    )
    violations = ofg_profile.validate_introspector_provenance(provenance, profile="reproduction-zeta")
    assert any("function_count" in v for v in violations)


def test_introspector_provenance_clean_for_zeta() -> None:
    provenance = ofg_profile.build_introspector_provenance(
        mode="real", project="jsoncpp", target="jsoncpp_fuzzer", function_count=10,
        used_local_shim=False,
    )
    violations = ofg_profile.validate_introspector_provenance(provenance, profile="reproduction-zeta")
    assert violations == []


# ---------------------------------------------------------------------------
# Z3. Shared evaluator hardening (already implemented by ckgfuzzer zeta)
# ---------------------------------------------------------------------------


class FakeResult:
    def __init__(self, command, exit_code=0, stdout="", stderr=""):
        self.command = list(command)
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


class ZetaFakeRunner:
    """Configurable fake runner for the shared evaluator scenarios."""

    def __init__(self, *, coverage_stdout=None, campaign_execs=500, build_exit=0,
                 binary_verified=True, overlay_matches=True, candidate_path=None,
                 coverage_build_exit=0, coverage_binary_verified=True):
        self.commands = []
        self.campaign_execs = campaign_execs
        self.coverage_stdout = coverage_stdout if coverage_stdout is not None else LLVM_COVERAGE_JSON
        self.build_exit = build_exit
        self.binary_verified = binary_verified
        self.overlay_matches = overlay_matches
        self.coverage_build_exit = coverage_build_exit
        self.coverage_binary_verified = coverage_binary_verified
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
                argv = " ".join(cmd[2:])
                if "SANITIZER=coverage" in argv:
                    return FakeResult(cmd, self.coverage_build_exit, "cov build", "")
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
                    return FakeResult(cmd, 0, "smoke ok", "HGB_TARGET_START\n")
                if phase == "campaign":
                    out = f"#{self.campaign_execs} INITED\nstat::number_of_executed_units: {self.campaign_execs}\n"
                    return FakeResult(cmd, 0, out, "")
                if phase == "coverage":
                    return FakeResult(cmd, 0, self.coverage_stdout, "")
                return FakeResult(cmd, 0, "", "")
            if sub == "cp":
                cp_src = cmd[2] if len(cmd) > 2 else ""
                cp_dst = cmd[3] if len(cmd) > 3 else ""
                if "corpus.tar" in cp_src and cp_dst:
                    import io
                    import tarfile
                    Path(cp_dst).parent.mkdir(parents=True, exist_ok=True)
                    data = b"corpus-input-1"
                    with tarfile.open(cp_dst, "w") as tf:
                        info = tarfile.TarInfo(name="corpus/seed_0000")
                        info.size = len(data)
                        tf.addfile(info, io.BytesIO(data))
                return FakeResult(cmd, 0, "", "")
            if sub == "rm":
                return FakeResult(cmd, 0, "", "")
            if sub == "run":
                shell_cmd = " ".join(cmd[3:])
                if "test -x" in shell_cmd and "sha256sum" in shell_cmd:
                    if "coverage" in str(cmd) and not self.coverage_binary_verified:
                        return FakeResult(cmd, 1, "", "not found")
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


def test_coverage_build_failure_cannot_fall_back_to_non_coverage_image(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = ZetaFakeRunner(
        candidate_path=str(candidates_dir / "cand_001.c"),
        coverage_build_exit=1,
        coverage_binary_verified=False,
    )
    result = evaluator.evaluate(
        generator="oss-fuzz-gen", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-zeta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
        build_coverage_image=True,
    )
    assert result["status"] != hgb_result.STATUS_EVALUATED
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["coverage"] == "failed"
    assert "coverage image build failed" in (cand_json.get("error") or "")


def test_final_corpus_missing_fails_strict_evaluation(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)

    class _EmptyCorpusRunner(ZetaFakeRunner):
        def __call__(self, command, timeout):
            r = super().__call__(command, timeout)
            cmd = list(command)
            if cmd[:2] == ["docker", "cp"]:
                cp_src = cmd[2] if len(cmd) > 2 else ""
                cp_dst = cmd[3] if len(cmd) > 3 else ""
                if "corpus.tar" in cp_src and cp_dst:
                    import tarfile
                    Path(cp_dst).parent.mkdir(parents=True, exist_ok=True)
                    with tarfile.open(cp_dst, "w"):
                        pass
                    return FakeResult(cmd, 0, "", "")
            return r

    runner = _EmptyCorpusRunner(candidate_path=str(candidates_dir / "cand_001.c"))
    result = evaluator.evaluate(
        generator="oss-fuzz-gen", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-zeta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
    )
    assert result["status"] != hgb_result.STATUS_EVALUATED
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["campaign"] == "failed"


def test_near_duplicate_candidate_cannot_be_selected() -> None:
    good = {
        "candidate_id": "cand_001",
        "stages": {s: "completed" for s in hgb_result.EVALUATION_STAGES},
        "copy_audit": {"exact_copy": False, "near_duplicate_reference": False, "contains_reference_canary": False},
        "sanitizer_smoke": {},
        "api_reachability": {"status": "not_requested"},
        "coverage": {"line_coverage": {"covered": 27}},
        "campaign": {"execs_done": 500, "final_corpus_file_count": 3},
        "overlaid": True,
    }
    near_dup = json.loads(json.dumps(good))
    near_dup["candidate_id"] = "cand_002"
    near_dup["copy_audit"]["near_duplicate_reference"] = True
    assert hgb_result.select_best_candidate([near_dup, good])["candidate_id"] == "cand_001"
    assert hgb_result.select_best_candidate([near_dup]) is None


def test_smoke_cannot_complete_from_missing_copied_input(tmp_path: Path) -> None:
    work_dir = tmp_path / "smoke"
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"\x01\x02\x03")

    class _BadCopyRunner(ZetaFakeRunner):
        def __call__(self, command, timeout):
            cmd = list(command)
            if cmd[:2] == ["docker", "cp"]:
                cp_src = cmd[2] if len(cmd) > 2 else ""
                cp_dst = cmd[3] if len(cmd) > 3 else ""
                if cp_src and ":" not in cp_src and cp_dst and ":" in cp_dst:
                    return FakeResult(cmd, 1, "", "copy_in failed")
            return super().__call__(command, timeout)

    runner = _BadCopyRunner()
    smoke = hgb_fuzzbench_builder.run_smoke(
        image_tag="hgb-test", binary_path="/out/fuzz_target",
        seeds=[seed], work_dir=work_dir, runner=runner,
    )
    assert smoke["any_executed"] is False


def test_full_evaluated_loop_succeeds_for_zeta(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = ZetaFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"))
    result = evaluator.evaluate(
        generator="oss-fuzz-gen", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-zeta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
        build_coverage_image=True,
    )
    assert result["status"] == hgb_result.STATUS_EVALUATED
    assert result["method_variant"] == "paper-faithful"
    sel = result["selected_candidate"]
    for field in ("copy_audit", "overlay_audit", "coverage_report_path", "campaign_log", "final_corpus_dir", "build_logs"):
        assert field in sel, f"selected_candidate missing {field}"


# ---------------------------------------------------------------------------
# Z4. Result matrix marks paper_equivalent=false when coverage diff unavailable
# ---------------------------------------------------------------------------


def test_matrix_paper_equivalent_zeta_gate() -> None:
    base = {
        "generator": "oss-fuzz-gen",
        "target": "jsoncpp_jsoncpp_fuzzer",
        "status": "evaluated",
        "applicability": "applicable",
        "profile": "reproduction-zeta",
        "method_variant": "paper-faithful",
        "excluded_from_aggregate": False,
        "stages": {n: "completed" for n in ("candidate_build", "sanitizer_smoke", "campaign", "coverage")},
        "metrics": {
            "coverage": {"line_coverage": {"covered": 27}},
            "campaign": {"execs_done": 500, "final_corpus_file_count": 3},
            "coverage_diff": {"runtime_coverage_valid": True, "status": "available"},
        },
        "build": {"overlay_audit": {"matches_candidate": True}},
        "selected_candidate": {
            "copy_audit": {"exact_copy": False},
            "build": {"overlay_audit": {"matches_candidate": True}},
        },
        "prompt_audit": {
            "exact_reference_harness_in_prompt": False,
            "selected_harness_api_metadata_used": False,
        },
        "introspector": {
            "mode": "real", "function_count": 123, "used_local_shim": False,
        },
    }
    row = collector.extract_ofg_row(base)
    assert row["paper_equivalent_zeta"] is True
    assert row["paper_equivalent_strict"] is True

    # Each condition below must flip paper_equivalent_zeta to False.
    for mutation in (
        {"profile": "alpha"},
        {"method_variant": "compat-smoke"},
        {"status": "quality_failure"},
        {"excluded_from_aggregate": True},
        {"metrics": {"coverage": {"line_coverage": {"covered": 0}},
                     "campaign": {"execs_done": 500, "final_corpus_file_count": 3},
                     "coverage_diff": {"runtime_coverage_valid": True, "status": "available"}}},
        {"metrics": {"coverage": {"line_coverage": {"covered": 27}},
                     "campaign": {"execs_done": 0, "final_corpus_file_count": 3},
                     "coverage_diff": {"runtime_coverage_valid": True, "status": "available"}}},
        {"build": {"overlay_audit": {"matches_candidate": False}},
         "selected_candidate": {"copy_audit": {"exact_copy": False}, "build": {"overlay_audit": {"matches_candidate": False}}}},
        {"prompt_audit": {"exact_reference_harness_in_prompt": True, "selected_harness_api_metadata_used": False}},
        {"introspector": {"mode": "real", "function_count": 123, "used_local_shim": True}},
        # coverage_diff.runtime_coverage_valid=False with available status flips it.
        {"metrics": {"coverage": {"line_coverage": {"covered": 27}},
                     "campaign": {"execs_done": 500, "final_corpus_file_count": 3},
                     "coverage_diff": {"runtime_coverage_valid": False, "status": "available"}}},
    ):
        mutated = json.loads(json.dumps(base))
        mutated.update(mutation)
        row = collector.extract_ofg_row(mutated)
        assert row["paper_equivalent_zeta"] is False, mutation


def test_matrix_paper_equivalent_false_when_coverage_diff_unavailable() -> None:
    # zeta plan §5: when native control coverage diff is unavailable, the row
    # may be evaluated but paper_equivalent_zeta must be false.
    base = {
        "generator": "oss-fuzz-gen",
        "target": "jsoncpp_jsoncpp_fuzzer",
        "status": "evaluated",
        "applicability": "applicable",
        "profile": "reproduction-zeta",
        "method_variant": "paper-faithful",
        "excluded_from_aggregate": False,
        "stages": {n: "completed" for n in ("candidate_build", "sanitizer_smoke", "campaign", "coverage")},
        "metrics": {
            "coverage": {"line_coverage": {"covered": 27}},
            "campaign": {"execs_done": 500, "final_corpus_file_count": 3},
            "coverage_diff": {"runtime_coverage_valid": False, "status": "unavailable"},
        },
        "build": {"overlay_audit": {"matches_candidate": True}},
        "selected_candidate": {
            "copy_audit": {"exact_copy": False},
            "build": {"overlay_audit": {"matches_candidate": True}},
        },
        "prompt_audit": {
            "exact_reference_harness_in_prompt": False,
            "selected_harness_api_metadata_used": False,
        },
        "introspector": {
            "mode": "real", "function_count": 123, "used_local_shim": False,
        },
    }
    row = collector.extract_ofg_row(base)
    assert row["paper_equivalent_zeta"] is False
    assert row["paper_equivalent_strict"] is False


def test_valuable_target_set_has_twenty_targets() -> None:
    hgb_targets = _load_module("hgb_targets_zeta", "scripts/hgb_targets.py")
    registry = hgb_targets.load_registry(REPO_ROOT)
    valuable = hgb_targets.targets_for_set(registry, "valuable")
    assert len(valuable) == 20


def test_matrix_runner_wrapper_accepts_zeta_args() -> None:
    wrapper = (REPO_ROOT / "scripts/hgb_run_baseline_matrix.sh").read_text(encoding="utf-8")
    assert "hgb_generate_matrix.sh" in wrapper
    assert "--profile" in wrapper
    assert "--campaign-seconds" in wrapper
    assert '--generators "$generators"' in wrapper
    assert '--profile "$profile"' in wrapper
