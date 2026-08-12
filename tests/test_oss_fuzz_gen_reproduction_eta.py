"""Eta reproduction tests for the OSS-Fuzz-Gen harness-generator pipeline.

These tests exercise the strictest paper-native OSS-Fuzz-Gen reproduction
contract from ``plans/oss-fuzz-gen_reproduction_eta.md``.

OSS-Fuzz-Gen is a ``harness_generator``: it uses OSS-Fuzz project context,
Fuzz Introspector, LLM generation, build repair, and coverage evaluation. The
eta plan makes ``reproduction-eta`` the canonical strict profile and keeps
``reproduction-zeta``/``reproduction-epsilon``/``reproduction-delta`` as
aliases. Eta inherits all zeta invariants and additionally requires:
* a separate coverage-instrumented build that replays the final campaign
  corpus with a copied ``coverage.json`` (no stdout fallback);
* a native coverage control that produces an available line-coverage diff;
* the matrix collector to fail when coverage diff is missing, coverage
  copy-out failed, or the selected candidate is a near-duplicate reference.
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


ofg_profile = _load_module("ofg_profile_eta", "docker/common/ofg_profile.py")
hgb_result = _load_module("hgb_result_eta", "docker/common/hgb_result.py")
hgb_fuzzbench_builder = _load_module("hgb_fuzzbench_builder_eta", "docker/common/hgb_fuzzbench_builder.py")
evaluator = _load_module("hgb_harness_evaluator_eta", "docker/common/hgb_harness_evaluator.py")
ofg_run_wrapper = _load_module("ofg_run_wrapper_eta", "docker/common/ofg_run_wrapper.py")
collector = _load_module("hgb_collect_matrix_eta", "scripts/hgb_collect_matrix.py")


VALUABLE_TARGETS = [
    "bloaty_fuzz_target", "curl_curl_fuzzer_http", "freetype2_ftfuzzer",
    "harfbuzz_hb-shape-fuzzer", "jsoncpp_jsoncpp_fuzzer", "lcms_cms_transform_fuzzer",
    "libjpeg-turbo_libjpeg_turbo_fuzzer", "libpcap_fuzz_both", "libpng_libpng_read_fuzzer",
    "libxml2_xml", "libxslt_xpath", "mbedtls_fuzz_dtlsclient", "mruby_mruby_fuzzer_8c8bbd",
    "openh264_decoder_fuzzer", "openssl_x509", "php_php-fuzz-parser_0dbedb", "re2_fuzzer",
    "sqlite3_ossfuzz", "systemd_fuzz-link-parser", "zlib_zlib_uncompress_fuzzer",
]


def _run_env():
    env = dict(os.environ)
    env["PATH"] = str(REPO_ROOT / "scripts") + os.pathsep + env.get("PATH", "")
    return env


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeResult:
    def __init__(self, command, exit_code=0, stdout="", stderr=""):
        self.command = list(command)
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


class EtaFakeRunner:
    """Configurable fake runner for the eta evaluator scenarios.

    Eta requires a copied ``coverage.json`` (no stdout fallback) and a
    ``HGB_INPUTS_REPLAYED=<n>`` marker proving the final campaign corpus was
    replayed. This runner materializes a real coverage.json on the coverage
    copy_out and emits the marker on stderr, matching the hardened shared
    builder contract (eta plan §2/§6).
    """

    def __init__(self, *, campaign_execs=500, build_exit=0, binary_verified=True,
                 overlay_matches=True, candidate_path=None,
                 coverage_build_exit=0, coverage_binary_verified=True,
                 copy_in_ok=True, smoke_marker=True,
                 coverage_copy_out_ok=True, coverage_inputs_replayed=1,
                 materialize_coverage=True):
        self.commands = []
        self.campaign_execs = campaign_execs
        self.coverage_json = json.dumps({
            "data": [{"totals": {"lines": {"count": 100, "covered": 27},
                                  "functions": {"count": 10, "covered": 5},
                                  "regions": {"count": 50, "covered": 12}},
                      "functions": [{"name": "hgb_sample_api", "count": 5}]}],
            "type": "llvm.coverage.json.export", "version": "2.0.1",
        })
        self.build_exit = build_exit
        self.binary_verified = binary_verified
        self.overlay_matches = overlay_matches
        self.coverage_build_exit = coverage_build_exit
        self.coverage_binary_verified = coverage_binary_verified
        self.copy_in_ok = copy_in_ok
        self.smoke_marker = smoke_marker
        self.coverage_copy_out_ok = coverage_copy_out_ok
        self.coverage_inputs_replayed = coverage_inputs_replayed
        self.materialize_coverage = materialize_coverage
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
                if "FUZZING_ENGINE=coverage" in argv:
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
                    stderr = "HGB_TARGET_START\n" if self.smoke_marker else ""
                    return FakeResult(cmd, 0, "smoke ok", stderr)
                if phase == "campaign":
                    out = f"#{self.campaign_execs} INITED\nstat::number_of_executed_units: {self.campaign_execs}\n"
                    return FakeResult(cmd, 0, out, "")
                if phase == "coverage":
                    # Eta: emit the replayed-inputs marker on stderr and the
                    # coverage JSON on stdout. The copied coverage.json is the
                    # authoritative report (eta plan §6).
                    stderr = f"HGB_INPUTS_REPLAYED={self.coverage_inputs_replayed}\n"
                    return FakeResult(cmd, 0, self.coverage_json, stderr)
                return FakeResult(cmd, 0, "", "")
            if sub == "cp":
                cp_src = cmd[2] if len(cmd) > 2 else ""
                cp_dst = cmd[3] if len(cmd) > 3 else ""
                # copy_in (host -> container): honor the configured copy_in_ok.
                if cp_src and ":" not in cp_src and cp_dst and ":" in cp_dst:
                    if not self.copy_in_ok:
                        return FakeResult(cmd, 1, "", "copy_in failed")
                # copy_out (container -> host).
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
                if "coverage.json" in cp_src and cp_dst:
                    if not self.coverage_copy_out_ok:
                        return FakeResult(cmd, 1, "", "coverage copy_out failed")
                    if self.materialize_coverage:
                        Path(cp_dst).parent.mkdir(parents=True, exist_ok=True)
                        Path(cp_dst).write_text(self.coverage_json, encoding="utf-8")
                    return FakeResult(cmd, 0, "", "")
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
    # The native coverage control locates the original native harness by name
    # under selected_reference_harnesses/ (eta plan §2: native control replays
    # the same final campaign corpus as the candidate).
    (evl_root / "selected_reference_harnesses" / "project").mkdir(parents=True)
    (evl_root / "selected_reference_harnesses" / "project" / "native.c").write_text(
        "// original native\nint LLVMFuzzerTestOneInput(){}\n", encoding="utf-8"
    )
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
# E0. Profile acceptance and strict env defaults
# ---------------------------------------------------------------------------


def test_reproduction_eta_is_valid_profile() -> None:
    assert "reproduction-eta" in ofg_profile.VALID_PROFILES
    assert ofg_profile.is_method_faithful("reproduction-eta")
    assert "reproduction-eta" in ofg_profile.STRICT_REPRODUCTION_PROFILES
    assert "reproduction-eta" in ofg_profile.ETA_PROFILES


def test_reproduction_eta_keeps_zeta_epsilon_delta_as_aliases() -> None:
    # eta is the canonical strict profile; zeta/epsilon/delta remain accepted.
    assert "reproduction-zeta" in ofg_profile.VALID_PROFILES
    assert "reproduction-epsilon" in ofg_profile.VALID_PROFILES
    assert "reproduction-delta" in ofg_profile.VALID_PROFILES
    assert "reproduction-zeta" in ofg_profile.STRICT_REPRODUCTION_PROFILES
    assert "reproduction-epsilon" in ofg_profile.STRICT_REPRODUCTION_PROFILES
    assert "reproduction-delta" in ofg_profile.STRICT_REPRODUCTION_PROFILES


def test_reproduction_eta_rejects_local_introspector_shim() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-eta", "blind-project",
        {"OFG_ALLOW_LOCAL_INTROSPECTOR_SHIM": "1", "HGB_TARGET_REQUIRE_SPLIT": "1"},
    )
    assert any("OFG_ALLOW_LOCAL_INTROSPECTOR_SHIM" in v for v in violations)


def test_reproduction_eta_rejects_reference_examples() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-eta", "blind-project",
        {"OFG_ALLOW_REFERENCE_EXAMPLES": "1", "HGB_TARGET_REQUIRE_SPLIT": "1"},
    )
    assert any("OFG_ALLOW_REFERENCE_EXAMPLES" in v for v in violations)


def test_reproduction_eta_rejects_selected_harness_api_ranking() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-eta", "blind-project",
        {"OFG_ALLOW_SELECTED_HARNESS_API_RANKING": "1", "HGB_TARGET_REQUIRE_SPLIT": "1"},
    )
    assert any("OFG_ALLOW_SELECTED_HARNESS_API_RANKING" in v for v in violations)


def test_reproduction_eta_rejects_repair_loop_disabled() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-eta", "blind-project",
        {"OFG_ENABLE_REPAIR_LOOP": "0", "HGB_TARGET_REQUIRE_SPLIT": "1"},
    )
    assert any("OFG_ENABLE_REPAIR_LOOP" in v for v in violations)


def test_reproduction_eta_rejects_coverage_disabled() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-eta", "blind-project",
        {"OFG_ENABLE_COVERAGE": "0", "HGB_TARGET_REQUIRE_SPLIT": "1"},
    )
    assert any("OFG_ENABLE_COVERAGE" in v for v in violations)


def test_reproduction_eta_requires_split() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-eta", "blind-project",
        {},
    )
    assert any("HGB_TARGET_REQUIRE_SPLIT" in v for v in violations)


def test_reproduction_eta_rejects_local_introspector_mode() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-eta", "blind-project",
        {"OFG_INTROSPECTOR_MODE": "local", "HGB_TARGET_REQUIRE_SPLIT": "1"},
    )
    assert any("OFG_INTROSPECTOR_MODE" in v for v in violations)


def test_reproduction_eta_rejects_coverage_skip() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-eta", "blind-project",
        {"OFG_SKIP_COVERAGE_GAINS": "1", "HGB_TARGET_REQUIRE_SPLIT": "1"},
    )
    assert any("OFG_SKIP_COVERAGE_GAINS" in v for v in violations)


def test_reproduction_eta_rejects_gcs_target_download() -> None:
    violations = ofg_profile.validate_profile(
        "reproduction-eta", "target-aware",
        {"OFG_ALLOW_GCS_TARGET_DOWNLOAD": "1", "HGB_TARGET_REQUIRE_SPLIT": "1"},
    )
    assert any("OFG_ALLOW_GCS_TARGET_DOWNLOAD" in v for v in violations)


def test_reproduction_eta_clean_with_all_required_env() -> None:
    violations = ofg_profile.validate_profile("reproduction-eta", "blind-project", {
        "OFG_INTROSPECTOR_MODE": "real",
        "HGB_TARGET_REQUIRE_SPLIT": "1",
    })
    assert violations == [], violations


def test_dry_run_canonical_command_passes_eta_profile_validation() -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_run_baseline.sh", "--generator", "oss-fuzz-gen",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-eta",
         "--protocol", "blind-project", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    workspace = proc.stdout.strip().splitlines()[-1]
    result = json.loads((Path(workspace) / "result.json").read_text(encoding="utf-8"))
    assert result["status"] == "dry_run_ok"
    assert result["profile"] == "reproduction-eta"
    assert result["method_variant"] == "paper-faithful"


def test_hgb_generate_harness_accepts_reproduction_eta() -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_generate_harness.sh", "--generator", "oss-fuzz-gen",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-eta", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    assert proc.returncode != 2
    assert "unknown profile" not in proc.stderr


def test_ofg_run_wrapper_is_method_faithful_for_eta(monkeypatch) -> None:
    monkeypatch.setenv("HGB_BASELINE_PROFILE", "reproduction-eta")
    assert ofg_run_wrapper.is_method_faithful() is True
    assert ofg_run_wrapper.is_strict_reproduction() is True


def test_entrypoint_has_reproduction_eta_profile_defaults() -> None:
    entrypoint = (REPO_ROOT / "docker/oss-fuzz-gen/entrypoint.sh").read_text(encoding="utf-8")
    assert "reproduction-eta)" in entrypoint
    assert "OFG_USE_REAL_OSS_FUZZ" in entrypoint
    assert "OFG_ALLOW_LOCAL_INTROSPECTOR_SHIM" in entrypoint
    assert "OFG_ALLOW_REFERENCE_EXAMPLES" in entrypoint
    assert "OFG_ALLOW_SELECTED_HARNESS_API_RANKING" in entrypoint
    assert "OFG_ENABLE_REPAIR_LOOP" in entrypoint
    assert "OFG_ENABLE_COVERAGE" in entrypoint
    assert "HGB_TARGET_REQUIRE_SPLIT=1" in entrypoint


def test_hgb_run_baseline_eta_section_forces_env() -> None:
    script = (REPO_ROOT / "scripts/hgb_run_baseline.sh").read_text(encoding="utf-8")
    assert "OFG_ALLOW_LOCAL_INTROSPECTOR_SHIM" in script
    assert "OFG_ALLOW_REFERENCE_EXAMPLES" in script
    assert "OFG_ALLOW_SELECTED_HARNESS_API_RANKING" in script
    assert "OFG_ENABLE_REPAIR_LOOP" in script
    assert "OFG_ENABLE_COVERAGE" in script


# ---------------------------------------------------------------------------
# E1. Entrypoint routing: build-coverage-image + run-native-control
# ---------------------------------------------------------------------------


def test_entrypoint_eta_passes_build_coverage_image_and_native_control() -> None:
    entrypoint = (REPO_ROOT / "docker/oss-fuzz-gen/entrypoint.sh").read_text(encoding="utf-8")
    # HGB8 blocker fix: strict eta must pass --build-coverage-image so coverage
    # comes from a separate coverage-instrumented FuzzBench build.
    assert "--build-coverage-image" in entrypoint
    # eta plan §5: eta must also run the native coverage control.
    assert "--run-native-control" in entrypoint
    # The build-coverage-image flag must be gated on the strict profiles.
    cov_img_lines = [ln for ln in entrypoint.splitlines() if "--build-coverage-image" in ln]
    assert cov_img_lines
    # The evaluator failure must be propagated with a specific reason code.
    assert "ofg_evaluator_failed" in entrypoint


def test_entrypoint_eta_routes_reproduction_eta_case() -> None:
    entrypoint = (REPO_ROOT / "docker/oss-fuzz-gen/entrypoint.sh").read_text(encoding="utf-8")
    assert "reproduction-eta)" in entrypoint
    eta_pos = entrypoint.index("reproduction-eta)")
    # The eta case must call the zeta/eta env helper.
    tail = entrypoint[eta_pos:eta_pos + 600]
    assert "_ofg_apply_zeta_eta_env" in tail
    assert "_ofg_apply_strict_reproduction_defaults" in tail


# ---------------------------------------------------------------------------
# E2. Generation prompt/context rejects reference leaks
# ---------------------------------------------------------------------------


def test_prompt_audit_rejects_exact_reference_harness_for_eta() -> None:
    audit = {
        "exact_reference_harness_in_prompt": True,
        "selected_harness_api_metadata_used": False,
    }
    violations = ofg_profile.validate_prompt_audit(audit, profile="reproduction-eta")
    assert any("exact_reference_harness_in_prompt" in v for v in violations)


def test_prompt_audit_rejects_selected_harness_api_metadata_for_eta() -> None:
    audit = {
        "exact_reference_harness_in_prompt": False,
        "selected_harness_api_metadata_used": True,
    }
    violations = ofg_profile.validate_prompt_audit(audit, profile="reproduction-eta")
    assert any("selected_harness_api_metadata_used" in v for v in violations)


def test_prompt_audit_clean_for_eta() -> None:
    audit = {
        "exact_reference_harness_in_prompt": False,
        "selected_harness_api_metadata_used": False,
    }
    violations = ofg_profile.validate_prompt_audit(audit, profile="reproduction-eta")
    assert violations == []


def test_prompt_audit_records_examples_and_selected_reference_visible() -> None:
    # eta plan §3: the prompt audit must list every example file shown to OFG,
    # its relation to the target, and assert the selected reference is not
    # visible to generation.
    audit = ofg_profile.build_prompt_audit(
        examples=[
            {"path": "examples/other_project_fuzzer.c", "relation": "non-target example"},
        ],
        reference_canary="HGB_REF_CANARY_xyz",
        prompt_artifacts=[],
        selected_harness_api_metadata_used=False,
    )
    assert audit["exact_reference_harness_in_prompt"] is False
    assert audit["selected_harness_api_metadata_used"] is False
    assert audit["examples"]
    assert audit["examples"][0]["relation"] == "non-target example"


# ---------------------------------------------------------------------------
# E3. Real Introspector manifest required and project/target scoped
# ---------------------------------------------------------------------------


def test_introspector_provenance_rejects_local_shim_for_eta() -> None:
    provenance = ofg_profile.build_introspector_provenance(
        mode="local", project="jsoncpp", target="jsoncpp_fuzzer", function_count=10,
    )
    violations = ofg_profile.validate_introspector_provenance(provenance, profile="reproduction-eta")
    assert any("mode=local" in v for v in violations)


def test_introspector_provenance_rejects_zero_functions_for_eta() -> None:
    provenance = ofg_profile.build_introspector_provenance(
        mode="real", project="jsoncpp", target="jsoncpp_fuzzer", function_count=0,
    )
    violations = ofg_profile.validate_introspector_provenance(provenance, profile="reproduction-eta")
    assert any("function_count" in v for v in violations)


def test_introspector_provenance_clean_for_eta() -> None:
    provenance = ofg_profile.build_introspector_provenance(
        mode="real", project="jsoncpp", target="jsoncpp_fuzzer", function_count=10,
        used_local_shim=False,
    )
    violations = ofg_profile.validate_introspector_provenance(provenance, profile="reproduction-eta")
    assert violations == []


# ---------------------------------------------------------------------------
# E4. Shared evaluator hardening: eta coverage invariants
# ---------------------------------------------------------------------------


def test_near_duplicate_candidate_cannot_be_selected() -> None:
    good = {
        "candidate_id": "cand_001",
        "stages": {s: "completed" for s in hgb_result.EVALUATION_STAGES},
        "copy_audit": {"exact_copy": False, "near_duplicate_reference": False, "contains_reference_canary": False},
        "sanitizer_smoke": {},
        "api_reachability": {"status": "not_requested"},
        "coverage": {"line_coverage": {"covered": 27}},
        "campaign": {"execs_done": 500},
        "overlaid": True,
    }
    near_dup = json.loads(json.dumps(good))
    near_dup["candidate_id"] = "cand_002"
    near_dup["copy_audit"]["near_duplicate_reference"] = True
    assert hgb_result.select_best_candidate([near_dup, good])["candidate_id"] == "cand_001"
    near_dup_only = json.loads(json.dumps(good))
    near_dup_only["copy_audit"]["near_duplicate_reference"] = True
    assert hgb_result.select_best_candidate([near_dup_only]) is None


def test_assert_evaluated_invariants_rejects_eta_coverage_gaps(tmp_path: Path) -> None:
    cov_file = tmp_path / "coverage.json"
    cov_file.write_text("{}", encoding="utf-8")
    base = {
        "profile": "reproduction-eta",
        "status": "evaluated",
        "stages": {s: "completed" for s in hgb_result.STAGE_NAMES},
        "metrics": {
            "coverage": {"line_coverage": {"covered": 27}, "report_exists": True,
                          "copy_out_ok": True, "inputs_replayed": 3,
                          "coverage_report_path": str(cov_file)},
            "campaign": {"execs_done": 500, "final_corpus_file_count": 3},
        },
        "selected_candidate": {
            "overlaid": True,
            "copy_audit": {"near_duplicate_reference": False, "exact_copy": False},
            "coverage": {"copy_out_ok": True, "inputs_replayed": 3,
                          "coverage_report_path": str(cov_file)},
        },
    }
    assert hgb_result.assert_evaluated_invariants(base) == []
    # copy_out_ok != true is a violation.
    bad = json.loads(json.dumps(base))
    bad["selected_candidate"]["coverage"]["copy_out_ok"] = False
    assert any("copy_out_ok" in v for v in hgb_result.assert_evaluated_invariants(bad))
    # missing coverage_report_path is a violation.
    bad = json.loads(json.dumps(base))
    bad["selected_candidate"]["coverage"]["coverage_report_path"] = ""
    assert any("coverage_report_path" in v for v in hgb_result.assert_evaluated_invariants(bad))
    # coverage_report_path does not exist is a violation.
    bad = json.loads(json.dumps(base))
    bad["selected_candidate"]["coverage"]["coverage_report_path"] = str(tmp_path / "missing.json")
    assert any("does not exist" in v for v in hgb_result.assert_evaluated_invariants(bad))
    # inputs_replayed <= 0 is a violation.
    bad = json.loads(json.dumps(base))
    bad["selected_candidate"]["coverage"]["inputs_replayed"] = 0
    assert any("inputs_replayed" in v for v in hgb_result.assert_evaluated_invariants(bad))


def test_coverage_build_failure_cannot_fall_back_to_non_coverage_image(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = EtaFakeRunner(
        candidate_path=str(candidates_dir / "cand_001.c"),
        coverage_build_exit=1,
        coverage_binary_verified=False,
    )
    result = evaluator.evaluate(
        generator="oss-fuzz-gen", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-eta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
        build_coverage_image=True,
    )
    assert result["status"] != hgb_result.STATUS_EVALUATED
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["coverage"] == "failed"
    assert "coverage image build failed" in (cand_json.get("error") or "")


def test_final_corpus_missing_fails_strict_evaluation(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)

    class _EmptyCorpusRunner(EtaFakeRunner):
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
        fuzz_target="fuzz_target", profile="reproduction-eta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
    )
    assert result["status"] != hgb_result.STATUS_EVALUATED
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["campaign"] == "failed"


def test_smoke_cannot_complete_from_missing_copied_input(tmp_path: Path) -> None:
    work_dir = tmp_path / "smoke"
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"\x01\x02\x03")
    runner = EtaFakeRunner(copy_in_ok=False, smoke_marker=True)
    smoke = hgb_fuzzbench_builder.run_smoke(
        image_tag="hgb-test",
        binary_path="/out/fuzz_target",
        seeds=[seed],
        work_dir=work_dir,
        runner=runner,
    )
    assert smoke["any_executed"] is False
    assert all(s["copy_in_ok"] is False for s in smoke["samples"])


def test_smoke_cannot_complete_from_missing_marker(tmp_path: Path) -> None:
    work_dir = tmp_path / "smoke"
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"\x01\x02\x03")
    runner = EtaFakeRunner(copy_in_ok=True, smoke_marker=False)
    smoke = hgb_fuzzbench_builder.run_smoke(
        image_tag="hgb-test",
        binary_path="/out/fuzz_target",
        seeds=[seed],
        work_dir=work_dir,
        runner=runner,
    )
    assert smoke["any_executed"] is False


def test_eta_coverage_requires_copied_report_not_stdout(tmp_path: Path) -> None:
    # When the coverage copy_out fails (no copied coverage.json), eta run_coverage
    # must not accept stdout alone: report_exists is False and the evaluator
    # fails coverage (eta plan §6).
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = EtaFakeRunner(
        candidate_path=str(candidates_dir / "cand_001.c"),
        coverage_copy_out_ok=False,
        materialize_coverage=False,
    )
    result = evaluator.evaluate(
        generator="oss-fuzz-gen", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-eta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
        build_coverage_image=True,
    )
    assert result["status"] != hgb_result.STATUS_EVALUATED
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["coverage"] == "failed"
    assert "copy_out_ok" in (cand_json.get("error") or "") or "coverage_report_path" in (cand_json.get("error") or "")


def test_eta_coverage_requires_nonzero_replayed_inputs(tmp_path: Path) -> None:
    # A copied coverage.json with inputs_replayed=0 must fail eta coverage:
    # the final campaign corpus was not replayed (eta plan §6).
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = EtaFakeRunner(
        candidate_path=str(candidates_dir / "cand_001.c"),
        coverage_inputs_replayed=0,
    )
    result = evaluator.evaluate(
        generator="oss-fuzz-gen", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-eta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
        build_coverage_image=True,
    )
    assert result["status"] != hgb_result.STATUS_EVALUATED
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["coverage"] == "failed"
    assert "inputs_replayed" in (cand_json.get("error") or "")


def test_full_evaluated_loop_succeeds_for_eta(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = EtaFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"))
    result = evaluator.evaluate(
        generator="oss-fuzz-gen", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-eta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
        build_coverage_image=True, run_native_control=True,
    )
    assert result["status"] == hgb_result.STATUS_EVALUATED
    assert result["method_variant"] == "paper-faithful"
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["build"]["overlay_audit"]["matches_candidate"] is True
    assert cand_json["build"]["binary_verified"] is True
    # The eta coverage invariants are recorded on the candidate.
    cov = cand_json["coverage"]
    assert cov["copy_out_ok"] is True
    assert cov["inputs_replayed"] > 0
    assert cov["coverage_report_path"]
    assert Path(cov["coverage_report_path"]).is_file()
    # Native control ran and produced a coverage summary (best-effort).
    assert cand_json.get("native_coverage") not in (None, {})
    sel = result["selected_candidate"]
    for field in ("copy_audit", "overlay_audit", "coverage_report_path", "campaign_log", "final_corpus_dir", "build_logs"):
        assert field in sel, f"selected_candidate missing {field}"


def test_sealed_context_fail_closed_for_strict_split_error(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    (gen_root / "source_repos.json").unlink()
    runner = EtaFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"))
    result = evaluator.evaluate(
        generator="oss-fuzz-gen", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-eta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=[], seeds=[],
    )
    assert result["status"] == hgb_result.STATUS_INFRA_FAILURE


# ---------------------------------------------------------------------------
# E5. Matrix semantics
# ---------------------------------------------------------------------------


def _eta_matrix_base(tmp_path: Path) -> dict:
    cov_file = tmp_path / "coverage.json"
    cov_file.write_text("{}", encoding="utf-8")
    return {
        "generator": "oss-fuzz-gen",
        "target": "jsoncpp_jsoncpp_fuzzer",
        "status": "evaluated",
        "applicability": "applicable",
        "profile": "reproduction-eta",
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
            "copy_audit": {"exact_copy": False, "near_duplicate_reference": False},
            "build": {"overlay_audit": {"matches_candidate": True}},
            "campaign": {"final_corpus_file_count": 3},
            "coverage": {"copy_out_ok": True, "coverage_report_path": str(cov_file), "inputs_replayed": 3},
        },
        "prompt_audit": {
            "exact_reference_harness_in_prompt": False,
            "selected_harness_api_metadata_used": False,
        },
        "introspector": {
            "mode": "real", "function_count": 123, "used_local_shim": False,
        },
    }


def test_matrix_paper_equivalent_eta_gate(tmp_path: Path) -> None:
    base = _eta_matrix_base(tmp_path)
    row = collector.extract_ofg_row(base)
    assert row["paper_equivalent_eta"] is True
    assert row["paper_equivalent_strict"] is True

    # Each condition below must flip paper_equivalent_eta to False.
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
        # eta-specific: empty final corpus flips the eta gate.
        {"metrics": {"coverage": {"line_coverage": {"covered": 27}},
                     "campaign": {"execs_done": 500, "final_corpus_file_count": 0},
                     "coverage_diff": {"runtime_coverage_valid": True, "status": "available"}}},
        {"build": {"overlay_audit": {"matches_candidate": False}},
         "selected_candidate": {"copy_audit": {"exact_copy": False}, "build": {"overlay_audit": {"matches_candidate": False}},
                                "campaign": {"final_corpus_file_count": 3},
                                "coverage": {"copy_out_ok": True, "coverage_report_path": str(tmp_path / "coverage.json"), "inputs_replayed": 3}}},
        {"prompt_audit": {"exact_reference_harness_in_prompt": True, "selected_harness_api_metadata_used": False}},
        {"introspector": {"mode": "real", "function_count": 123, "used_local_shim": True}},
        # eta-specific: coverage_diff.status unavailable flips the eta gate.
        {"metrics": {"coverage": {"line_coverage": {"covered": 27}},
                     "campaign": {"execs_done": 500, "final_corpus_file_count": 3},
                     "coverage_diff": {"runtime_coverage_valid": False, "status": "unavailable"}}},
        # eta-specific: copy_out_ok False flips the eta gate.
        {"selected_candidate": {"copy_audit": {"exact_copy": False, "near_duplicate_reference": False},
                                "build": {"overlay_audit": {"matches_candidate": True}},
                                "campaign": {"final_corpus_file_count": 3},
                                "coverage": {"copy_out_ok": False, "coverage_report_path": str(tmp_path / "coverage.json"), "inputs_replayed": 3}}},
        # eta-specific: missing coverage_report_path flips the eta gate.
        {"selected_candidate": {"copy_audit": {"exact_copy": False, "near_duplicate_reference": False},
                                "build": {"overlay_audit": {"matches_candidate": True}},
                                "campaign": {"final_corpus_file_count": 3},
                                "coverage": {"copy_out_ok": True, "coverage_report_path": "", "inputs_replayed": 3}}},
        # eta-specific: inputs_replayed <= 0 flips the eta gate.
        {"selected_candidate": {"copy_audit": {"exact_copy": False, "near_duplicate_reference": False},
                                "build": {"overlay_audit": {"matches_candidate": True}},
                                "campaign": {"final_corpus_file_count": 3},
                                "coverage": {"copy_out_ok": True, "coverage_report_path": str(tmp_path / "coverage.json"), "inputs_replayed": 0}}},
        # eta-specific: near-duplicate reference candidate flips the eta gate.
        {"selected_candidate": {"copy_audit": {"exact_copy": False, "near_duplicate_reference": True},
                                "build": {"overlay_audit": {"matches_candidate": True}},
                                "campaign": {"final_corpus_file_count": 3},
                                "coverage": {"copy_out_ok": True, "coverage_report_path": str(tmp_path / "coverage.json"), "inputs_replayed": 3}}},
    ):
        mutated = json.loads(json.dumps(base))
        mutated.update(mutation)
        row = collector.extract_ofg_row(mutated)
        assert row["paper_equivalent_eta"] is False, mutation


def test_matrix_paper_equivalent_false_when_coverage_diff_unavailable(tmp_path: Path) -> None:
    # eta plan §5: when native control coverage diff is unavailable, the row
    # may be evaluated but paper_equivalent_eta must be false.
    base = _eta_matrix_base(tmp_path)
    base["metrics"]["coverage_diff"] = {"runtime_coverage_valid": False, "status": "unavailable"}
    row = collector.extract_ofg_row(base)
    assert row["paper_equivalent_eta"] is False
    assert row["paper_equivalent_strict"] is False


def test_evaluated_row_violations_enforce_eta_invariants(tmp_path: Path) -> None:
    cov_file = tmp_path / "coverage.json"
    cov_file.write_text("{}", encoding="utf-8")
    meta = {
        "task_family": "harness_generator",
        "generator": "oss-fuzz-gen",
        "profile": "reproduction-eta",
        "method_variant": "paper-faithful",
        "status": "evaluated",
        "excluded_from_aggregate": False,
        "metrics": {
            "coverage": {"line_coverage": {"covered": 27}},
            "campaign": {"execs_done": 500, "final_corpus_file_count": 2},
        },
        "selected_candidate": {
            "copy_audit": {"near_duplicate_reference": True, "exact_copy": False},
            "build": {"overlay_audit": {"matches_candidate": False}},
            "campaign": {"final_corpus_file_count": 2},
            "coverage": {"copy_out_ok": False, "coverage_report_path": "", "inputs_replayed": 0},
        },
        "prompt_audit": {"exact_reference_harness_in_prompt": False, "selected_harness_api_metadata_used": False},
        "introspector": {"mode": "real", "function_count": 5, "used_local_shim": False},
    }
    violations = collector.evaluated_row_violations(meta)
    assert any("near_duplicate_reference" in v for v in violations)
    assert any("matches_candidate" in v for v in violations)
    assert any("copy_out_ok" in v for v in violations)
    assert any("coverage_report_path" in v for v in violations)
    assert any("inputs_replayed" in v for v in violations)


def test_valuable_target_set_has_twenty_targets() -> None:
    hgb_targets = _load_module("hgb_targets_eta", "scripts/hgb_targets.py")
    registry = hgb_targets.load_registry(REPO_ROOT)
    valuable = hgb_targets.targets_for_set(registry, "valuable")
    assert len(valuable) == 20
    assert sorted(valuable) == sorted(VALUABLE_TARGETS)


def test_common_sh_eta_is_strict_reproduction() -> None:
    common = (REPO_ROOT / "scripts/lib/common.sh").read_text(encoding="utf-8")
    assert "reproduction-eta" in common
    proc = subprocess.run(
        ["bash", "-c", "source scripts/lib/common.sh && hgb_profile_is_strict_reproduction reproduction-eta && echo OK"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30,
    )
    assert "OK" in proc.stdout, proc.stderr


def test_hgb_targets_infers_require_split_for_eta() -> None:
    env = dict(os.environ)
    env["HGB_BASELINE_PROFILE"] = "reproduction-eta"
    env["HGB_BASELINE_PROTOCOL"] = "blind-project"
    proc = subprocess.run(
        ["python3", "scripts/hgb_targets.py", "package", "--help"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=env, timeout=30,
    )
    assert "--require-split" in proc.stdout


def test_matrix_runner_wrapper_accepts_eta_args() -> None:
    wrapper = (REPO_ROOT / "scripts/hgb_run_baseline_matrix.sh").read_text(encoding="utf-8")
    assert "hgb_generate_matrix.sh" in wrapper
    assert "--profile" in wrapper
    assert "--campaign-seconds" in wrapper
    assert '--generators "$generators"' in wrapper
    assert '--profile "$profile"' in wrapper


def test_matrix_collector_accepts_eta_flags() -> None:
    proc = subprocess.run(
        ["python3", "scripts/hgb_collect_matrix.py", "--help"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30,
    )
    assert "--fail-on-invariant-violations" in proc.stdout
    assert "--require-evaluated" in proc.stdout
    assert "--require-coverage-diff" in proc.stdout
