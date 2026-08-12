"""Epsilon reproduction tests for the OSS-Fuzz-Gen harness-generator pipeline.

These tests exercise the strict paper-native OSS-Fuzz-Gen reproduction contract
from ``plans/oss-fuzz-gen_reproduction_epsilon.md`` with fake Docker/CLI
fixtures so they pass without real external checkouts, Docker, Fuzz Introspector,
or model access.

OSS-Fuzz-Gen remains a ``harness_generator`` (it synthesizes ``LLVMFuzzerTestOneInput``
fuzz targets), never an input generator.

The epsilon plan shares its foundation with the other reproduction-epsilon
baselines (profile wiring, fail-closed split packages, candidate overlay/copy
audit, smoke/campaign/coverage evidence). These tests additionally cover the
OSS-Fuzz-Gen-specific tasks:

* OFG-1: enforce strict profile in every entrypoint.
* OFG-2: remove target reference leakage from prompts and ranking.
* OFG-3: restore real OSS-Fuzz-Gen context and repair loop (no local shim).
* OFG-4: build candidate against exact FuzzBench benchmark.
* OFG-5: repair result schema and matrix semantics.
* OFG-6: valuable-target matrix semantics.
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
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ofg_profile = _load_module("ofg_profile_epsilon", "docker/common/ofg_profile.py")
ofg_introspector = _load_module("ofg_introspector_adapter_epsilon", "docker/common/ofg_introspector_adapter.py")
ofg_synthesis = _load_module("ofg_benchmark_synthesis_epsilon", "docker/common/ofg_benchmark_synthesis.py")
ofg_api_rank = _load_module("ofg_api_rank_epsilon", "docker/common/ofg_api_rank.py")
ofg_run_wrapper = _load_module("ofg_run_wrapper_epsilon", "docker/common/ofg_run_wrapper.py")
hgb_harness_evaluator = _load_module("hgb_harness_evaluator_epsilon", "docker/common/hgb_harness_evaluator.py")
hgb_split_context = _load_module("hgb_split_context_epsilon", "docker/common/hgb_split_context.py")
hgb_result = _load_module("hgb_result_epsilon", "docker/common/hgb_result.py")
hgb_coverage = _load_module("hgb_coverage_epsilon", "docker/common/hgb_coverage.py")
hgb_fuzzbench_builder = _load_module("hgb_fuzzbench_builder_epsilon", "docker/common/hgb_fuzzbench_builder.py")
hgb_target_package = _load_module("hgb_target_package_epsilon", "docker/common/hgb_target_package.py")
matrix_collector = _load_module("hgb_collect_matrix_epsilon", "scripts/hgb_collect_matrix.py")


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


class EpsilonFakeRunner:
    """Configurable fake runner for the evaluator scenarios."""

    def __init__(self, *, coverage_stdout=None, campaign_execs=500, build_exit=0,
                 binary_verified=True, overlay_matches=True, candidate_path=None,
                 native_coverage_stdout=None):
        self.commands = []
        self.campaign_execs = campaign_execs
        self.coverage_stdout = coverage_stdout if coverage_stdout is not None else LLVM_COVERAGE_JSON
        self.native_coverage_stdout = native_coverage_stdout
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
                elif "native" in name:
                    phase = "native"
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
                if phase == "native":
                    cov = self.native_coverage_stdout if self.native_coverage_stdout is not None else self.coverage_stdout
                    return FakeResult(cmd, 0, cov, "")
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
                    if self.binary_verified:
                        return FakeResult(cmd, 0, f"{self.candidate_sha}  /out/jsoncpp_fuzzer\n", "")
                    return FakeResult(cmd, 1, "", "not found")
                if "sha256sum /src/" in shell_cmd:
                    if self.overlay_matches:
                        return FakeResult(cmd, 0, f"{self.candidate_sha}  /src/jsoncpp/jsoncpp_fuzzer.cc\n", "")
                    return FakeResult(cmd, 0, "referenceSHA  /src/jsoncpp/jsoncpp_fuzzer.cc\n", "")
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


def _run_env():
    env = dict(os.environ)
    env["PATH"] = str(REPO_ROOT / "scripts") + os.pathsep + env.get("PATH", "")
    return env


# ---------------------------------------------------------------------------
# E0. Profile acceptance and strictness
# ---------------------------------------------------------------------------


def test_reproduction_epsilon_is_valid_profile() -> None:
    assert "reproduction-epsilon" in ofg_profile.VALID_PROFILES
    assert ofg_profile.is_method_faithful("reproduction-epsilon")
    assert "reproduction-epsilon" in ofg_profile.STRICT_REPRODUCTION_PROFILES


def test_reproduction_delta_remains_accepted_as_alias() -> None:
    assert "reproduction-delta" in ofg_profile.VALID_PROFILES
    assert "reproduction-delta" in ofg_profile.STRICT_REPRODUCTION_PROFILES


def test_reproduction_epsilon_rejects_local_introspector_shim() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-epsilon", "blind-project",
        {"OFG_INTROSPECTOR_MODE": "local"},
    )
    assert any("OFG_INTROSPECTOR_MODE" in v for v in violations)


def test_reproduction_epsilon_rejects_coverage_skip() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-epsilon", "blind-project",
        {"OFG_SKIP_COVERAGE_GAINS": "1"},
    )
    assert any("OFG_SKIP_COVERAGE_GAINS" in v for v in violations)


def test_reproduction_epsilon_rejects_gcs_target_download() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-epsilon", "target-aware",
        {"OFG_ALLOW_GCS_TARGET_DOWNLOAD": "1"},
    )
    assert any("OFG_ALLOW_GCS_TARGET_DOWNLOAD" in v for v in violations)


def test_reproduction_epsilon_rejects_yaml_fallback_by_default() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-epsilon", "blind-project",
        {"OFG_ALLOW_PROJECT_YAML_FALLBACK": "1"},
    )
    assert any("OFG_ALLOW_PROJECT_YAML_FALLBACK" in v for v in violations)


def test_reproduction_epsilon_rejects_bad_benchmark_synthesis_by_default() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-epsilon", "blind-project",
        {"OFG_SYNTHESIZE_ON_BAD_BENCHMARK": "1"},
    )
    assert any("OFG_SYNTHESIZE_ON_BAD_BENCHMARK" in v for v in violations)


def test_reproduction_epsilon_accepts_real_introspector_mode() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-epsilon", "blind-project",
        {"OFG_INTROSPECTOR_MODE": "real", "OFG_NUM_SAMPLES": "10"},
    )
    assert violations == []


def test_reproduction_epsilon_maps_to_paper_faithful_method_variant() -> None:
    result = hgb_result.build_result(
        profile="reproduction-epsilon", protocol="blind-project", target="t",
        status="evaluated",
        stages={n: "completed" for n in hgb_result.STAGE_NAMES},
    )
    assert result["method_variant"] == "paper-faithful"
    assert result["task_family"] == "harness_generator"


def test_dry_run_canonical_command_passes_profile_validation(tmp_path: Path) -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_run_baseline.sh", "--generator", "oss-fuzz-gen",
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
    assert result["task_family"] == "harness_generator"


def test_unknown_profile_exits_with_code_2() -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_run_baseline.sh", "--generator", "oss-fuzz-gen",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-nonexistent",
         "--protocol", "blind-project", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    assert proc.returncode == 2, proc.stderr
    assert "invalid profile" in proc.stderr


def test_hgb_generate_harness_rejects_unknown_profile_with_code_2() -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_generate_harness.sh", "--generator", "oss-fuzz-gen",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-nonexistent", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    assert proc.returncode == 2, proc.stderr
    assert "unknown profile" in proc.stderr


def test_hgb_generate_harness_accepts_reproduction_epsilon() -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_generate_harness.sh", "--generator", "oss-fuzz-gen",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-epsilon", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    assert proc.returncode != 2
    assert "unknown profile" not in proc.stderr


# ---------------------------------------------------------------------------
# E1. Fail-closed split target package
# ---------------------------------------------------------------------------


def test_generator_input_has_no_reference_harnesses(tmp_path: Path) -> None:
    _pkg, generator_input, _evaluator_only = _make_split_package(tmp_path)
    assert not (generator_input / "reference_harnesses").exists()
    assert not (generator_input / "fuzzbench_selected_harness_apis.json").exists()


def test_blind_target_isolation_detects_reference_harness_dir(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "reference_harnesses").mkdir(parents=True)
    violations = ofg_run_wrapper.verify_blind_target_isolation(target)
    assert any("reference_harnesses" in v for v in violations)


def test_blind_target_isolation_detects_selected_harness_apis(tmp_path: Path) -> None:
    target = tmp_path / "target"
    (target / "source_input").mkdir(parents=True)
    (target / "source_input" / "fuzzbench_selected_harness_apis.json").write_text("[]", encoding="utf-8")
    violations = ofg_run_wrapper.verify_blind_target_isolation(target)
    assert any("fuzzbench_selected_harness_apis.json" in v for v in violations)


def test_blind_target_isolation_clean_for_split_package(tmp_path: Path) -> None:
    _pkg, generator_input, _evaluator_only = _make_split_package(tmp_path)
    violations = ofg_run_wrapper.verify_blind_target_isolation(generator_input)
    assert violations == []


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


def test_selected_harness_apis_not_in_generator_mount(tmp_path: Path) -> None:
    _pkg, generator_input, _evaluator_only = _make_split_package(tmp_path)
    assert not any("fuzzbench_selected_harness_apis" in p.name for p in generator_input.rglob("*"))


# ---------------------------------------------------------------------------
# E2. Candidate overlay and copy-audit authoritative
# ---------------------------------------------------------------------------


def test_candidate_overlay_copies_into_native_path(tmp_path: Path) -> None:
    _pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    candidates_dir = tmp_path / "candidates"
    _write_candidate(candidates_dir)
    work_dir = tmp_path / "evaluation"
    runner = EpsilonFakeRunner(candidate_path=str(candidates_dir / "cand_001.cc"))
    result = hgb_harness_evaluator.evaluate(
        generator="oss-fuzz-gen",
        target_root=generator_input,
        evaluator_root=evaluator_only,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="jsoncpp",
        fuzz_target="jsoncpp_fuzzer",
        profile="reproduction-epsilon",
        protocol="blind-project",
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
    sealed_harness = work_dir / "sealed_context" / "source_input" / "jsoncpp" / "jsoncpp_fuzzer.cc"
    assert sealed_harness.is_file()
    assert "jsoncpp_parse" in sealed_harness.read_text(encoding="utf-8")
    assert result["candidate_count"] == 1


def test_overlay_audit_detects_reference_overwrite(tmp_path: Path) -> None:
    _pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    candidates_dir = tmp_path / "candidates"
    _write_candidate(candidates_dir)
    work_dir = tmp_path / "evaluation"
    runner = EpsilonFakeRunner(
        candidate_path=str(candidates_dir / "cand_001.cc"), overlay_matches=False,
    )
    result = hgb_harness_evaluator.evaluate(
        generator="oss-fuzz-gen",
        target_root=generator_input,
        evaluator_root=evaluator_only,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="jsoncpp",
        fuzz_target="jsoncpp_fuzzer",
        profile="reproduction-epsilon",
        protocol="blind-project",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        context_provider=_fake_context_provider,
        intended_apis=[],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["build"]["overlay_audit"]["matches_candidate"] is False
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_build_success_without_binary_fails_candidate_build(tmp_path: Path) -> None:
    _pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    candidates_dir = tmp_path / "candidates"
    _write_candidate(candidates_dir)
    work_dir = tmp_path / "evaluation"
    runner = EpsilonFakeRunner(
        candidate_path=str(candidates_dir / "cand_001.cc"), binary_verified=False,
    )
    result = hgb_harness_evaluator.evaluate(
        generator="oss-fuzz-gen",
        target_root=generator_input,
        evaluator_root=evaluator_only,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="jsoncpp",
        fuzz_target="jsoncpp_fuzzer",
        profile="reproduction-epsilon",
        protocol="blind-project",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        context_provider=_fake_context_provider,
        intended_apis=[],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["candidate_build"] == "failed"
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
# OFG-1. Enforce strict profile in every entrypoint
# ---------------------------------------------------------------------------


def test_entrypoint_has_reproduction_epsilon_profile_defaults() -> None:
    entrypoint = (REPO_ROOT / "docker/oss-fuzz-gen/entrypoint.sh").read_text(encoding="utf-8")
    # The strict reproduction branch covers reproduction-delta and its epsilon alias.
    # zeta/eta have their own cases that layer additional env on top.
    assert "reproduction-delta|reproduction-epsilon)" in entrypoint
    assert 'OFG_INTROSPECTOR_MODE="${OFG_INTROSPECTOR_MODE:-real}"' in entrypoint
    assert 'OFG_ALLOW_GCS_TARGET_DOWNLOAD="${OFG_ALLOW_GCS_TARGET_DOWNLOAD:-0}"' in entrypoint


def test_entrypoint_evaluator_passes_protocol_and_build_timeout() -> None:
    entrypoint = (REPO_ROOT / "docker/oss-fuzz-gen/entrypoint.sh").read_text(encoding="utf-8")
    assert '--protocol "$hgb_protocol"' in entrypoint
    assert "--build-timeout-seconds" in entrypoint


def test_entrypoint_epsilon_routes_to_method_faithful_result() -> None:
    entrypoint = (REPO_ROOT / "docker/oss-fuzz-gen/entrypoint.sh").read_text(encoding="utf-8")
    # The method-faithful condition includes epsilon.
    assert '"$hgb_profile" == "reproduction-gamma" || "$hgb_profile" == "reproduction-delta" || "$hgb_profile" == "reproduction-epsilon"' in entrypoint


def test_run_baseline_accepts_reproduction_epsilon_for_ofg() -> None:
    script = (REPO_ROOT / "scripts/hgb_run_baseline.sh").read_text(encoding="utf-8")
    assert "alpha|paper-faithful|reproduction-gamma|reproduction-delta|reproduction-epsilon|reproduction-zeta|reproduction-eta|compat-smoke)" in script
    assert "oss-fuzz-gen/$profile: OFG_SKIP_COVERAGE_GAINS=1 is forbidden" in script
    assert "oss-fuzz-gen/$profile: OFG_ALLOW_GCS_TARGET_DOWNLOAD=1 is forbidden" in script
    assert "oss-fuzz-gen/$profile: OFG_INTROSPECTOR_MODE=local is forbidden" in script


def test_run_wrapper_is_method_faithful_includes_epsilon(monkeypatch) -> None:
    monkeypatch.setenv("HGB_BASELINE_PROFILE", "reproduction-epsilon")
    monkeypatch.setenv("HGB_BASELINE_PROTOCOL", "blind-project")
    assert ofg_run_wrapper.is_method_faithful() is True
    assert ofg_run_wrapper.is_strict_reproduction() is True


def test_run_wrapper_local_shim_disabled_in_epsilon(monkeypatch) -> None:
    monkeypatch.setenv("HGB_BASELINE_PROFILE", "reproduction-epsilon")
    ofg_run_wrapper.PATCH_REGISTRY.clear()
    ofg_run_wrapper._install_local_introspector_shim([])
    shim_patch = [p for p in ofg_run_wrapper.PATCH_REGISTRY if p["patch"] == "local_introspector_shim"]
    assert shim_patch and shim_patch[0]["enabled"] is False


def test_run_wrapper_coverage_skip_disabled_in_epsilon(monkeypatch) -> None:
    monkeypatch.setenv("HGB_BASELINE_PROFILE", "reproduction-epsilon")
    ofg_run_wrapper.PATCH_REGISTRY.clear()
    ofg_run_wrapper._patch_coverage_skip()
    ofg_run_wrapper._install_coverage_gains_noop()
    enabled = [p for p in ofg_run_wrapper.PATCH_REGISTRY if p["enabled"]]
    assert not enabled


# ---------------------------------------------------------------------------
# OFG-2. Remove target reference leakage from prompts and ranking
# ---------------------------------------------------------------------------


def test_exact_native_harness_excluded_from_examples(tmp_path: Path) -> None:
    _pkg, generator_input, _evaluator_only = _make_split_package(tmp_path)
    native_rel = "jsoncpp/jsoncpp_fuzzer.cc"
    assert not (generator_input / "source_input" / native_rel).exists()
    result = ofg_synthesis.collect_allowed_examples(
        generator_input / "source_input", allow_same_project_fuzz=False,
    )
    allowed = [e["path"] for e in result["allowed"]]
    assert any(p.endswith("json_reader.cpp") for p in allowed)
    assert all("fuzz" not in p.lower() for p in allowed)


def test_run_wrapper_has_no_reference_example_loader() -> None:
    wrapper = (REPO_ROOT / "docker/common/ofg_run_wrapper.py").read_text(encoding="utf-8")
    assert "_read_reference_targets" not in wrapper
    assert "_patch_project_examples" not in wrapper


def test_api_rank_identical_with_or_without_selected_harness_metadata(tmp_path: Path) -> None:
    records = [
        {"name": "jsoncpp_parse", "signature": "int jsoncpp_parse(const char*)",
         "return_type": "int", "path": "/src/jsoncpp/json_reader.cpp"},
        {"name": "jsoncpp_write", "signature": "int jsoncpp_write(const char*)",
         "return_type": "int", "path": "/src/jsoncpp/json_writer.cpp"},
    ]
    ranked_a = ofg_api_rank.rank_records(
        list(records), project="jsoncpp", target_name="jsoncpp_fuzzer",
        reference_dir=None,
    )
    ref_dir = tmp_path / "refs"
    ref_dir.mkdir()
    (ref_dir / "harness.cc").write_text(
        "jsoncpp_parse(arg);\njsoncpp_write(arg);\n", encoding="utf-8",
    )
    ranked_b = ofg_api_rank.rank_records(
        list(records), project="jsoncpp", target_name="jsoncpp_fuzzer",
        reference_dir=ref_dir,
    )
    scores_a = [r.get("_hgb_score") for r in ranked_a]
    scores_b = [r.get("_hgb_score") for r in ranked_b]
    assert scores_a == scores_b
    for ranked in (ranked_a, ranked_b):
        for r in ranked:
            assert "called_by_harness" not in r.get("_hgb_score_reasons", [])
            assert "mentioned_by_harness" not in r.get("_hgb_score_reasons", [])


def test_prompt_audit_clean_when_no_reference_in_prompt(tmp_path: Path) -> None:
    audit = ofg_profile.build_prompt_audit(
        examples=[{"path": "json_reader.cpp", "reason": "allowed_non_target_example"}],
        reference_canary="HGB_REF_CANARY_epsilon",
        prompt_artifacts=[],
    )
    assert audit["exact_reference_harness_in_prompt"] is False
    assert audit["selected_harness_api_metadata_used"] is False
    assert ofg_profile.validate_prompt_audit(audit, profile="reproduction-epsilon") == []


def test_prompt_audit_detects_canary_in_prompt_artifact(tmp_path: Path) -> None:
    canary = "HGB_REF_CANARY_epsilon_leak"
    artifact = tmp_path / "prompt.txt"
    artifact.write_text(f"some preamble\n// {canary}\nmore text", encoding="utf-8")
    audit = ofg_profile.build_prompt_audit(
        examples=[],
        reference_canary=canary,
        prompt_artifacts=[artifact],
    )
    assert audit["exact_reference_harness_in_prompt"] is True
    violations = ofg_profile.validate_prompt_audit(audit, profile="reproduction-epsilon")
    assert any("exact_reference_harness_in_prompt" in v for v in violations)


def test_canary_in_reference_harness_does_not_leak_into_generator_input(tmp_path: Path) -> None:
    _pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    canary = "HGB_REF_CANARY_epsilon_test"
    ref = evaluator_only / "reference_harnesses" / "selected" / "source_input" / "jsoncpp" / "jsoncpp_fuzzer.cc"
    ref.write_text(f"// {canary}\n" + ref.read_text(encoding="utf-8"), encoding="utf-8")
    audit = ofg_profile.audit_leakage(generator_input, canary)
    assert audit["leaked"] is False
    for p in generator_input.rglob("*"):
        if p.is_file():
            assert canary not in p.read_text(encoding="utf-8", errors="replace"), p


# ---------------------------------------------------------------------------
# OFG-3. Restore real OSS-Fuzz-Gen context and repair loop
# ---------------------------------------------------------------------------


def test_introspector_provenance_records_real_mode_and_counts(tmp_path: Path) -> None:
    report_dir = tmp_path / "intro"
    report_dir.mkdir()
    functions = [
        {"name": "jsoncpp_parse", "function_signature": "int jsoncpp_parse(const char*)",
         "source_file": "/src/jsoncpp/json_reader.cpp", "return-type": "int",
         "function_arguments": []},
        {"name": "jsoncpp_write", "function_signature": "int jsoncpp_write(const char*)",
         "source_file": "/src/jsoncpp/json_writer.cpp", "return-type": "int",
         "function_arguments": []},
    ]
    (report_dir / "all_functions.json").write_text(json.dumps(functions), encoding="utf-8")
    (report_dir / "calltree.json").write_text("{}", encoding="utf-8")
    (report_dir / "type_info.json").write_text("{}", encoding="utf-8")
    (report_dir / "report_manifest.json").write_text('{"project": "jsoncpp"}', encoding="utf-8")
    prov = ofg_introspector.write_introspector_provenance(
        report_dir, mode="real", oss_fuzz_commit="abc123",
        project="jsoncpp", target="jsoncpp_fuzzer",
    )
    assert prov["mode"] == "real"
    assert prov["used_local_shim"] is False
    assert prov["function_count"] == 2
    assert prov["source_files_count"] == 2
    loaded = ofg_introspector.load_introspector_provenance(report_dir)
    ok, violations = ofg_introspector.validate_introspector_provenance(loaded, strict=True)
    assert ok is True
    assert violations == []


def test_introspector_provenance_fails_on_local_shim_in_strict() -> None:
    prov = {"mode": "local", "function_count": 5, "used_local_shim": True}
    ok, violations = ofg_introspector.validate_introspector_provenance(prov, strict=True)
    assert ok is False
    assert any("mode=local" in v for v in violations)
    assert any("used_local_shim" in v for v in violations)


def test_introspector_provenance_fails_on_zero_functions() -> None:
    prov = {"mode": "real", "function_count": 0, "used_local_shim": False}
    ok, violations = ofg_introspector.validate_introspector_provenance(prov, strict=True)
    assert ok is False
    assert any("function_count" in v for v in violations)


def test_local_introspector_shim_rejected_in_reproduction_epsilon(tmp_path: Path) -> None:
    report = ofg_introspector.build_introspector_report(
        target_root=tmp_path, work_dir=tmp_path / "work",
        project="jsoncpp", fuzz_target="jsoncpp_fuzzer",
        oss_fuzz_dir=None, compat_shim=False,
    )
    assert report.valid is False
    assert "failed_stage=introspector" in report.message


def test_empty_introspector_report_fails_reproduction_epsilon(tmp_path: Path) -> None:
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
# OFG-4 / E3 / E4 / E5. Build candidate against exact FuzzBench benchmark
# ---------------------------------------------------------------------------


def test_zero_exec_campaign_fails(tmp_path: Path) -> None:
    _pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    candidates_dir = tmp_path / "candidates"
    _write_candidate(candidates_dir)
    work_dir = tmp_path / "evaluation"
    runner = EpsilonFakeRunner(
        candidate_path=str(candidates_dir / "cand_001.cc"), campaign_execs=0,
    )
    result = hgb_harness_evaluator.evaluate(
        generator="oss-fuzz-gen",
        target_root=generator_input,
        evaluator_root=evaluator_only,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="jsoncpp",
        fuzz_target="jsoncpp_fuzzer",
        profile="reproduction-epsilon",
        protocol="blind-project",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        context_provider=_fake_context_provider,
        intended_apis=[],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["campaign"] == "failed"
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_empty_coverage_fails_coverage_stage(tmp_path: Path) -> None:
    _pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    candidates_dir = tmp_path / "candidates"
    _write_candidate(candidates_dir)
    work_dir = tmp_path / "evaluation"
    runner = EpsilonFakeRunner(
        candidate_path=str(candidates_dir / "cand_001.cc"), coverage_stdout="",
    )
    result = hgb_harness_evaluator.evaluate(
        generator="oss-fuzz-gen",
        target_root=generator_input,
        evaluator_root=evaluator_only,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="jsoncpp",
        fuzz_target="jsoncpp_fuzzer",
        profile="reproduction-epsilon",
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


def test_coverage_diff_unavailable_without_native_control() -> None:
    cand = hgb_coverage.parse_llvm_coverage_json(LLVM_COVERAGE_JSON)
    diff = hgb_harness_evaluator.compute_coverage_diff(cand, None)
    assert diff["runtime_coverage_valid"] is True
    assert diff["status"] == "unavailable"
    assert diff["native_lines_covered"] is None


def test_coverage_diff_available_with_native_control() -> None:
    cand = hgb_coverage.parse_llvm_coverage_json(LLVM_COVERAGE_JSON)
    native = hgb_coverage.parse_llvm_coverage_json(json.dumps({
        "data": [{"totals": {"lines": {"count": 100, "covered": 20},
                              "functions": {"count": 10, "covered": 4},
                              "regions": {"count": 50, "covered": 10}},
                   "functions": [{"name": "jsoncpp_parse", "count": 3}]}],
        "type": "llvm.coverage.json.export", "version": "2.0.1",
    }))
    diff = hgb_harness_evaluator.compute_coverage_diff(cand, native)
    assert diff["runtime_coverage_valid"] is True
    assert diff["status"] == "available"
    assert diff["candidate_lines_covered"] == 31
    assert diff["native_lines_covered"] == 20
    assert diff["new_lines_vs_native"] == 11


def test_build_only_output_is_not_evaluated() -> None:
    stages = hgb_result.default_stages()
    stages["generation"] = "completed"
    stages["candidate_build"] = "completed"
    stages["sanitizer_smoke"] = "pending"
    stages["campaign"] = "pending"
    stages["coverage"] = "pending"
    status = hgb_result.result_status_from_stages(stages)
    assert status != hgb_result.STATUS_EVALUATED


def test_no_evaluated_status_without_campaign_or_coverage(tmp_path: Path) -> None:
    _pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    candidates_dir = tmp_path / "candidates"
    _write_candidate(candidates_dir)
    work_dir = tmp_path / "evaluation"
    runner = EpsilonFakeRunner(
        candidate_path=str(candidates_dir / "cand_001.cc"),
        campaign_execs=0, coverage_stdout="",
    )
    result = hgb_harness_evaluator.evaluate(
        generator="oss-fuzz-gen",
        target_root=generator_input,
        evaluator_root=evaluator_only,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="jsoncpp",
        fuzz_target="jsoncpp_fuzzer",
        profile="reproduction-epsilon",
        protocol="blind-project",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        context_provider=_fake_context_provider,
        intended_apis=[],
        seeds=[],
    )
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_full_evaluated_loop_succeeds_for_epsilon(tmp_path: Path) -> None:
    _pkg, generator_input, evaluator_only = _make_split_package(tmp_path)
    candidates_dir = tmp_path / "candidates"
    _write_candidate(candidates_dir)
    work_dir = tmp_path / "evaluation"
    runner = EpsilonFakeRunner(candidate_path=str(candidates_dir / "cand_001.cc"))
    result = hgb_harness_evaluator.evaluate(
        generator="oss-fuzz-gen",
        target_root=generator_input,
        evaluator_root=evaluator_only,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="jsoncpp",
        fuzz_target="jsoncpp_fuzzer",
        profile="reproduction-epsilon",
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
# OFG-5. Repair result schema and matrix semantics
# ---------------------------------------------------------------------------


def test_build_result_writes_required_schema_v2_fields() -> None:
    result = hgb_result.build_result(
        profile="reproduction-epsilon", protocol="blind-project", target="t",
        status="evaluated",
        stages={n: "completed" for n in hgb_result.STAGE_NAMES},
        metrics={"coverage": {"line_coverage": {"covered": 5}},
                 "campaign": {"execs_done": 10}},
        selected_candidate={"overlaid": True, "candidate_path": "/x"},
    )
    for field in ("task_family", "profile", "protocol", "method_variant", "status",
                   "applicability", "stages", "artifacts", "metrics", "selected_candidate",
                   "excluded_from_aggregate", "build", "campaign", "coverage"):
        assert field in result, f"missing schema field {field}"
    assert result["task_family"] == "harness_generator"
    assert result["method_variant"] == "paper-faithful"


def _ofg_epsilon_base_meta(**overrides) -> dict:
    base = {
        "generator": "oss-fuzz-gen",
        "task_family": "harness_generator",
        "target": "jsoncpp_jsoncpp_fuzzer",
        "status": "evaluated",
        "applicability": "applicable",
        "profile": "reproduction-epsilon",
        "method_variant": "paper-faithful",
        "excluded_from_aggregate": False,
        "stages": {n: "completed" for n in (
            "candidate_overlay", "candidate_build", "sanitizer_smoke",
            "campaign", "coverage",
        )},
        "metrics": {
            "coverage": {"line_coverage": {"covered": 31}},
            "campaign": {"execs_done": 500, "crashes": 0, "timeouts": 0, "final_corpus_file_count": 4},
            "coverage_diff": {"runtime_coverage_valid": True, "status": "available"},
        },
        "build": {"overlay_audit": {"matches_candidate": True}},
        "selected_candidate": {
            "build": {"overlay_audit": {"matches_candidate": True}},
        },
        "prompt_audit": {
            "exact_reference_harness_in_prompt": False,
            "selected_harness_api_metadata_used": False,
        },
        "introspector": {
            "mode": "real", "function_count": 123,
            "used_local_shim": False,
        },
    }
    base.update(overrides)
    return base


def test_matrix_paper_equivalent_epsilon_gate() -> None:
    base = _ofg_epsilon_base_meta()
    row = matrix_collector.extract_ofg_row(base)
    assert row["paper_equivalent_epsilon"] is True
    assert row["paper_equivalent_strict"] is True
    assert row["paper_equivalent_delta"] is False
    assert matrix_collector.evaluated_row_violations(base) == []


def test_matrix_paper_equivalent_epsilon_flips_on_each_condition() -> None:
    base = _ofg_epsilon_base_meta()
    mutations = (
        {"profile": "alpha"},
        {"method_variant": "compat-smoke"},
        {"status": "quality_failure"},
        {"excluded_from_aggregate": True},
        {"metrics": {"coverage": {"line_coverage": {"covered": 0}},
                     "campaign": {"execs_done": 500},
                     "coverage_diff": {"runtime_coverage_valid": True}}},
        {"metrics": {"coverage": {"line_coverage": {"covered": 31}},
                     "campaign": {"execs_done": 0},
                     "coverage_diff": {"runtime_coverage_valid": True}}},
        {"build": {"overlay_audit": {"matches_candidate": False}},
         "selected_candidate": {"build": {"overlay_audit": {"matches_candidate": False}}}},
        {"prompt_audit": {"exact_reference_harness_in_prompt": True,
                          "selected_harness_api_metadata_used": False}},
        {"prompt_audit": {"exact_reference_harness_in_prompt": False,
                          "selected_harness_api_metadata_used": True}},
        {"introspector": {"mode": "real", "function_count": 123, "used_local_shim": True}},
        {"introspector": {"mode": "real", "function_count": 0, "used_local_shim": False}},
        {"metrics": {"coverage": {"line_coverage": {"covered": 31}},
                     "campaign": {"execs_done": 500},
                     "coverage_diff": {"runtime_coverage_valid": False, "status": "available"}}},
    )
    for mut in mutations:
        mutated = json.loads(json.dumps(base))
        mutated.update(mut)
        row = matrix_collector.extract_ofg_row(mutated)
        assert row["paper_equivalent_epsilon"] is False, f"expected False for {mut}"


def test_matrix_paper_equivalent_epsilon_allows_unavailable_native_control_when_excluded() -> None:
    base = _ofg_epsilon_base_meta(
        excluded_from_aggregate=True,
        metrics={
            "coverage": {"line_coverage": {"covered": 31}},
            "campaign": {"execs_done": 500},
            "coverage_diff": {"runtime_coverage_valid": True, "status": "unavailable"},
        },
    )
    row = matrix_collector.extract_ofg_row(base)
    assert row["paper_equivalent_epsilon"] is False
    assert row["cov_diff_status"] == "unavailable"


def test_evaluated_row_violations_enforce_epsilon_prompt_and_introspector() -> None:
    meta = _ofg_epsilon_base_meta(
        prompt_audit={"exact_reference_harness_in_prompt": True,
                      "selected_harness_api_metadata_used": False},
    )
    violations = matrix_collector.evaluated_row_violations(meta)
    assert any("exact_reference_harness_in_prompt" in v for v in violations)
    meta = _ofg_epsilon_base_meta(
        introspector={"mode": "real", "function_count": 0, "used_local_shim": False},
    )
    violations = matrix_collector.evaluated_row_violations(meta)
    assert any("function_count" in v for v in violations)


def test_matrix_collect_ofg_paper_equivalent_epsilon_count(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    rows = []
    for index, (status, paper_eq) in enumerate(
        [("evaluated", True), ("evaluated", False), ("quality_failure", False)], start=1
    ):
        ws = tmp_path / f"ws{index}"
        ws.mkdir()
        meta = _ofg_epsilon_base_meta(target=f"target_{index}", status=status)
        if not paper_eq:
            meta["prompt_audit"]["exact_reference_harness_in_prompt"] = True
        meta_path = ws / "metadata.json"
        meta_path.write_text(json.dumps(meta), encoding="utf-8")
        rows.append((f"target_{index}", ws, meta_path))
    with (matrix_dir / "matrix.tsv").open("w", encoding="utf-8") as f:
        f.write("generator\ttarget\tstatus\tworkspace\tmetadata\n")
        for target, ws, meta_path in rows:
            f.write(f"oss-fuzz-gen\t{target}\t{meta_path.parent.name}\t{ws}\t{meta_path}\n")
    summary = matrix_collector.collect(matrix_dir, generator="oss-fuzz-gen", profile="reproduction-epsilon")
    assert summary["ofg_paper_equivalent_epsilon"] == 1
    assert summary["ofg_paper_equivalent_strict"] == 1
    assert len(summary["ofg_target_rows"]) == 3


def test_compat_fallback_rows_reported_separately(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    ws = tmp_path / "ws"
    ws.mkdir()
    meta = _ofg_epsilon_base_meta(
        excluded_from_aggregate=True,
        method_variant="compat_project_yaml_fallback",
    )
    meta_path = ws / "metadata.json"
    meta_path.write_text(json.dumps(meta), encoding="utf-8")
    with (matrix_dir / "matrix.tsv").open("w", encoding="utf-8") as f:
        f.write("generator\ttarget\tstatus\tworkspace\tmetadata\n")
        f.write(f"oss-fuzz-gen\ttarget_1\t{meta_path.parent.name}\t{ws}\t{meta_path}\n")
    summary = matrix_collector.collect(matrix_dir, generator="oss-fuzz-gen", profile="reproduction-epsilon")
    assert len(summary["ofg_compat_fallback_rows"]) == 1
    assert summary["ofg_paper_equivalent_epsilon"] == 0


# ---------------------------------------------------------------------------
# OFG-6. Valuable-target matrix semantics
# ---------------------------------------------------------------------------


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
    assert '--generators "$generators"' in wrapper
    assert '--profile "$profile"' in wrapper


def test_matrix_strict_no_violations_for_real_evaluated_epsilon_row(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    app_ws = matrix_dir / "app"
    app_ws.mkdir()
    (app_ws / "metadata.json").write_text(json.dumps(_ofg_epsilon_base_meta()), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\n"
        f"oss-fuzz-gen\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, strict=True, generator="oss-fuzz-gen", profile="reproduction-epsilon")
    assert summary["evaluated_row_violations"] == []


def test_matrix_strict_flags_coverage_missing_epsilon_row(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    app_ws = matrix_dir / "app"
    app_ws.mkdir()
    meta = _ofg_epsilon_base_meta(
        metrics={"coverage": {"line_coverage": {"covered": 0}},
                 "campaign": {"execs_done": 500},
                 "coverage_diff": {"runtime_coverage_valid": True, "status": "available"}},
    )
    (app_ws / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\n"
        f"oss-fuzz-gen\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, strict=True, generator="oss-fuzz-gen", profile="reproduction-epsilon")
    assert summary["evaluated_row_violations"]
