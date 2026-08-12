"""Eta reproduction tests for the PromeFuzz harness-generator pipeline.

These tests exercise the strictest paper-native PromeFuzz reproduction contract
from ``plans/promefuzz_reproduction_eta.md``.

PromeFuzz is a ``harness_generator``: it uses knowledge-driven harness
generation with exact compile context, library link context, code metadata,
documentation, consumer/API usage knowledge, embedding retrieval, generation,
and then full FuzzBench evaluation. The eta plan makes ``reproduction-eta``
the canonical strict profile and keeps ``reproduction-zeta``/``epsilon``/
``delta`` as aliases. Eta inherits all zeta invariants and additionally
requires:
* a separate coverage-instrumented build that replays the final campaign
  corpus with a copied ``coverage.json`` (no stdout fallback);
* a native coverage control that produces an available line-coverage diff;
* the matrix collector to fail when coverage diff is missing, coverage
  copy-out failed, or the selected candidate is a near-duplicate reference;
* exact FuzzBench compile DB provenance, nonempty driver_build_args, real
  embedding metadata, and loaded consumer knowledge evidence.
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


profile = _load_module("promefuzz_profile_eta", "docker/common/promefuzz_profile.py")
hgb_result = _load_module("hgb_result_eta", "docker/common/hgb_result.py")
hgb_fuzzbench_builder = _load_module("hgb_fuzzbench_builder_eta", "docker/common/hgb_fuzzbench_builder.py")
evaluator = _load_module("hgb_harness_evaluator_eta", "docker/common/hgb_harness_evaluator.py")
promefuzz_build_context = _load_module("promefuzz_build_context_eta", "docker/common/promefuzz_build_context.py")
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


_REAL_EMB = {"PROME_FUZZ_EMBEDDING_LLM_TYPE": "openai", "PROME_FUZZ_EMBEDDING_MODEL": "text-embedding-3-small"}


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
    copy_out and emits the marker on stderr (eta plan §2/§6).
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
                    stderr = f"HGB_INPUTS_REPLAYED={self.coverage_inputs_replayed}\n"
                    return FakeResult(cmd, 0, self.coverage_json, stderr)
                return FakeResult(cmd, 0, "", "")
            if sub == "cp":
                cp_src = cmd[2] if len(cmd) > 2 else ""
                cp_dst = cmd[3] if len(cmd) > 3 else ""
                if cp_src and ":" not in cp_src and cp_dst and ":" in cp_dst:
                    if not self.copy_in_ok:
                        return FakeResult(cmd, 1, "", "copy_in failed")
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
    assert "reproduction-eta" in profile.VALID_PROFILES
    assert profile.is_method_faithful("reproduction-eta")
    assert "reproduction-eta" in profile.STRICT_REPRODUCTION_PROFILES
    assert "reproduction-eta" in profile.ETA_PROFILES


def test_reproduction_eta_keeps_zeta_epsilon_delta_as_aliases() -> None:
    assert "reproduction-zeta" in profile.VALID_PROFILES
    assert "reproduction-epsilon" in profile.VALID_PROFILES
    assert "reproduction-delta" in profile.VALID_PROFILES
    assert "reproduction-zeta" in profile.STRICT_REPRODUCTION_PROFILES
    assert "reproduction-epsilon" in profile.STRICT_REPRODUCTION_PROFILES
    assert "reproduction-delta" in profile.STRICT_REPRODUCTION_PROFILES


def test_reproduction_eta_rejects_hash_embedding() -> None:
    violations = profile.validate_profile(
        "reproduction-eta", "blind-project",
        {"PROMEFUZZ_ALLOW_HASH_EMBEDDING": "1", "HGB_TARGET_REQUIRE_SPLIT": "1", **_REAL_EMB},
    )
    assert any("PROMEFUZZ_ALLOW_HASH_EMBEDDING" in v for v in violations)


def test_reproduction_eta_rejects_synthetic_compile_db() -> None:
    violations = profile.validate_profile(
        "reproduction-eta", "blind-project",
        {"PROMEFUZZ_ALLOW_SYNTHETIC_COMPILE_DB": "1", "HGB_TARGET_REQUIRE_SPLIT": "1", **_REAL_EMB},
    )
    assert any("PROMEFUZZ_ALLOW_SYNTHETIC_COMPILE_DB" in v for v in violations)


def test_reproduction_eta_rejects_empty_link_args() -> None:
    violations = profile.validate_profile(
        "reproduction-eta", "blind-project",
        {"PROMEFUZZ_ALLOW_EMPTY_LINK_ARGS": "1", "HGB_TARGET_REQUIRE_SPLIT": "1", **_REAL_EMB},
    )
    assert any("PROMEFUZZ_ALLOW_EMPTY_LINK_ARGS" in v for v in violations)


def test_reproduction_eta_requires_consumer_cases() -> None:
    violations = profile.validate_profile(
        "reproduction-eta", "blind-project",
        {"PROMEFUZZ_REQUIRE_CONSUMER_CASES": "0", "HGB_TARGET_REQUIRE_SPLIT": "1", **_REAL_EMB},
    )
    assert any("PROMEFUZZ_REQUIRE_CONSUMER_CASES" in v for v in violations)


def test_reproduction_eta_requires_split() -> None:
    violations = profile.validate_profile(
        "reproduction-eta", "blind-project",
        {**_REAL_EMB},
    )
    assert any("HGB_TARGET_REQUIRE_SPLIT" in v for v in violations)


def test_reproduction_eta_rejects_cmake_export_build_context() -> None:
    violations = profile.validate_profile(
        "reproduction-eta", "blind-project",
        {"PROME_FUZZ_BUILD_CONTEXT_METHOD": "cmake_export", "HGB_TARGET_REQUIRE_SPLIT": "1", **_REAL_EMB},
    )
    assert any("PROME_FUZZ_BUILD_CONTEXT_METHOD" in v for v in violations)


def test_reproduction_eta_accepts_fuzzbench_replay_build_context() -> None:
    violations = profile.validate_profile(
        "reproduction-eta", "blind-project",
        {"PROME_FUZZ_BUILD_CONTEXT_METHOD": "fuzzbench_replay", "HGB_TARGET_REQUIRE_SPLIT": "1", **_REAL_EMB},
    )
    assert not any("PROME_FUZZ_BUILD_CONTEXT_METHOD" in v for v in violations)


def test_reproduction_eta_rejects_mock_embedding_type() -> None:
    violations = profile.validate_profile(
        "reproduction-eta", "blind-project",
        {"PROME_FUZZ_EMBEDDING_LLM_TYPE": "mock", "HGB_TARGET_REQUIRE_SPLIT": "1",
         "PROME_FUZZ_EMBEDDING_MODEL": "text-embedding-3-small"},
    )
    assert any("PROME_FUZZ_EMBEDDING_LLM_TYPE" in v for v in violations)


def test_reproduction_eta_rejects_hash_embedding_model() -> None:
    violations = profile.validate_profile(
        "reproduction-eta", "blind-project",
        {"PROME_FUZZ_EMBEDDING_LLM_TYPE": "openai", "PROME_FUZZ_EMBEDDING_MODEL": "hgb-hash-embedding",
         "HGB_TARGET_REQUIRE_SPLIT": "1"},
    )
    assert any("PROME_FUZZ_EMBEDDING_MODEL" in v for v in violations)


def test_reproduction_eta_clean_with_all_required_env() -> None:
    violations = profile.validate_profile("reproduction-eta", "blind-project", {
        **_REAL_EMB,
        "HGB_TARGET_REQUIRE_SPLIT": "1",
        "PROME_FUZZ_BUILD_CONTEXT_METHOD": "fuzzbench_replay",
    })
    assert violations == [], violations


def test_dry_run_canonical_command_passes_eta_profile_validation() -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_run_baseline.sh", "--generator", "promefuzz",
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
        ["bash", "scripts/hgb_generate_harness.sh", "--generator", "promefuzz",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-eta", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    assert proc.returncode != 2
    assert "unknown profile" not in proc.stderr


def test_entrypoint_has_reproduction_eta_profile() -> None:
    entrypoint = (REPO_ROOT / "docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")
    assert "reproduction-eta" in entrypoint
    assert "PROMEFUZZ_ALLOW_HASH_EMBEDDING" in entrypoint
    assert "PROMEFUZZ_ALLOW_SYNTHETIC_COMPILE_DB" in entrypoint
    assert "PROMEFUZZ_ALLOW_EMPTY_LINK_ARGS" in entrypoint
    assert "PROMEFUZZ_REQUIRE_CONSUMER_CASES" in entrypoint
    assert "HGB_TARGET_REQUIRE_SPLIT=1" in entrypoint
    validation_pos = entrypoint.index("promefuzz_profile.py validate")
    defaults_pos = entrypoint.index("PROME_FUZZ_EMBEDDING_LLM_TYPE=\"${PROME_FUZZ_EMBEDDING_LLM_TYPE:-openai}")
    split_pos = entrypoint.index("HGB_TARGET_REQUIRE_SPLIT=1")
    assert defaults_pos < validation_pos
    assert split_pos < validation_pos


def test_entrypoint_eta_passes_build_coverage_image_and_native_control() -> None:
    entrypoint = (REPO_ROOT / "docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")
    # HGB8 blocker fix: strict eta must pass --build-coverage-image so coverage
    # comes from a separate coverage-instrumented FuzzBench build.
    assert "--build-coverage-image" in entrypoint
    # eta plan §5: eta must also run the native coverage control.
    assert "--run-native-control" in entrypoint


def test_entrypoint_eta_routes_reproduction_eta_case() -> None:
    entrypoint = (REPO_ROOT / "docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")
    assert "reproduction-eta" in entrypoint
    # The eta case must inherit all zeta required env.
    assert 'promefuzz_profile" == "reproduction-zeta" || "$promefuzz_profile" == "reproduction-eta"' in entrypoint


def test_entrypoint_eta_records_knowledge_usage() -> None:
    entrypoint = (REPO_ROOT / "docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")
    assert "knowledge_usage" in entrypoint
    assert "write_knowledge_usage" in entrypoint


def test_hgb_run_baseline_eta_section_forces_env() -> None:
    script = (REPO_ROOT / "scripts/hgb_run_baseline.sh").read_text(encoding="utf-8")
    assert "PROMEFUZZ_ALLOW_HASH_EMBEDDING" in script
    assert "PROMEFUZZ_ALLOW_SYNTHETIC_COMPILE_DB" in script
    assert "PROMEFUZZ_ALLOW_EMPTY_LINK_ARGS" in script
    assert "PROMEFUZZ_REQUIRE_CONSUMER_CASES" in script


# ---------------------------------------------------------------------------
# E1. Shared evaluator hardening: eta coverage invariants
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
    bad = json.loads(json.dumps(base))
    bad["selected_candidate"]["coverage"]["copy_out_ok"] = False
    assert any("copy_out_ok" in v for v in hgb_result.assert_evaluated_invariants(bad))
    bad = json.loads(json.dumps(base))
    bad["selected_candidate"]["coverage"]["coverage_report_path"] = ""
    assert any("coverage_report_path" in v for v in hgb_result.assert_evaluated_invariants(bad))
    bad = json.loads(json.dumps(base))
    bad["selected_candidate"]["coverage"]["coverage_report_path"] = str(tmp_path / "missing.json")
    assert any("does not exist" in v for v in hgb_result.assert_evaluated_invariants(bad))
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
        generator="promefuzz", target_root=gen_root, evaluator_root=evl_root,
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
        generator="promefuzz", target_root=gen_root, evaluator_root=evl_root,
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
        image_tag="hgb-test", binary_path="/out/fuzz_target",
        seeds=[seed], work_dir=work_dir, runner=runner,
    )
    assert smoke["any_executed"] is False
    assert all(s["copy_in_ok"] is False for s in smoke["samples"])


def test_smoke_cannot_complete_from_missing_marker(tmp_path: Path) -> None:
    work_dir = tmp_path / "smoke"
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"\x01\x02\x03")
    runner = EtaFakeRunner(copy_in_ok=True, smoke_marker=False)
    smoke = hgb_fuzzbench_builder.run_smoke(
        image_tag="hgb-test", binary_path="/out/fuzz_target",
        seeds=[seed], work_dir=work_dir, runner=runner,
    )
    assert smoke["any_executed"] is False


def test_eta_coverage_requires_copied_report_not_stdout(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = EtaFakeRunner(
        candidate_path=str(candidates_dir / "cand_001.c"),
        coverage_copy_out_ok=False,
        materialize_coverage=False,
    )
    result = evaluator.evaluate(
        generator="promefuzz", target_root=gen_root, evaluator_root=evl_root,
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
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = EtaFakeRunner(
        candidate_path=str(candidates_dir / "cand_001.c"),
        coverage_inputs_replayed=0,
    )
    result = evaluator.evaluate(
        generator="promefuzz", target_root=gen_root, evaluator_root=evl_root,
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
        generator="promefuzz", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-eta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
        build_coverage_image=True, run_native_control=True,
    )
    assert result["status"] == hgb_result.STATUS_EVALUATED
    assert result["method_variant"] == "paper-faithful"
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["build"]["overlay_audit"]["matches_candidate"] is True
    cov = cand_json["coverage"]
    assert cov["copy_out_ok"] is True
    assert cov["inputs_replayed"] > 0
    assert cov["coverage_report_path"]
    assert Path(cov["coverage_report_path"]).is_file()
    assert cand_json.get("native_coverage") not in (None, {})
    sel = result["selected_candidate"]
    for field in ("copy_audit", "overlay_audit", "coverage_report_path", "campaign_log", "final_corpus_dir", "build_logs"):
        assert field in sel, f"selected_candidate missing {field}"


def test_sealed_context_fail_closed_for_strict_split_error(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    (gen_root / "source_repos.json").unlink()
    runner = EtaFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"))
    result = evaluator.evaluate(
        generator="promefuzz", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-eta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=[], seeds=[],
    )
    assert result["status"] == hgb_result.STATUS_INFRA_FAILURE


# ---------------------------------------------------------------------------
# E2. Build context and knowledge usage
# ---------------------------------------------------------------------------


def test_write_knowledge_usage_records_counts(tmp_path: Path) -> None:
    knowledge_dir = tmp_path / "knowledge_out" / "target"
    knowledge_dir.mkdir(parents=True)
    (knowledge_dir / "knowledge_metadata.json").write_text("{}", encoding="utf-8")
    (knowledge_dir / "correlation.json").write_text("{}", encoding="utf-8")
    (knowledge_dir / "retrieved_examples.json").write_text("[]", encoding="utf-8")
    (knowledge_dir / "api_patterns.json").write_text("[]", encoding="utf-8")
    record = promefuzz_build_context.write_knowledge_usage(
        knowledge_dir,
        consumer_cases_status="available",
        consumer_count=3,
        selected_api_count=8,
    )
    assert record["consumer_cases_status"] == "available"
    assert record["consumer_count"] == 3
    assert record["selected_api_count"] == 8
    assert record["document_count"] > 0
    assert record["call_correlation_count"] > 0
    assert record["retrieved_example_count"] > 0
    assert record["api_usage_pattern_count"] > 0
    assert record["loaded"] is True
    usage_path = tmp_path / "knowledge_out" / "knowledge_usage.json"
    assert usage_path.is_file()
    saved = json.loads(usage_path.read_text(encoding="utf-8"))
    assert saved["loaded"] is True


def test_write_knowledge_usage_empty_dir(tmp_path: Path) -> None:
    knowledge_dir = tmp_path / "empty_knowledge"
    knowledge_dir.mkdir(parents=True)
    record = promefuzz_build_context.write_knowledge_usage(
        knowledge_dir,
        consumer_cases_status="unavailable",
        consumer_count=0,
        selected_api_count=0,
    )
    assert record["loaded"] is False
    assert record["document_count"] == 0


# ---------------------------------------------------------------------------
# E3. Matrix semantics
# ---------------------------------------------------------------------------


def _eta_matrix_base(tmp_path: Path) -> dict:
    cov_file = tmp_path / "coverage.json"
    cov_file.write_text("{}", encoding="utf-8")
    return {
        "generator": "promefuzz",
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
        "method": {
            "compile_db": {"strategy": "fuzzbench_replay", "count": 42},
            "link_context": {"driver_build_args_count": 5},
            "embedding": {"provider": "openai", "model": "text-embedding-3-small"},
            "consumer_knowledge": {"enabled": True, "artifacts_nonempty": True},
        },
    }


def test_matrix_paper_equivalent_eta_gate(tmp_path: Path) -> None:
    base = _eta_matrix_base(tmp_path)
    row = collector.extract_promefuzz_row(base)
    assert row["paper_equivalent_eta"] is True
    assert row["paper_equivalent_strict"] is True

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
        {"metrics": {"coverage": {"line_coverage": {"covered": 27}},
                     "campaign": {"execs_done": 500, "final_corpus_file_count": 0},
                     "coverage_diff": {"runtime_coverage_valid": True, "status": "available"}}},
        {"build": {"overlay_audit": {"matches_candidate": False}},
         "selected_candidate": {"copy_audit": {"exact_copy": False}, "build": {"overlay_audit": {"matches_candidate": False}},
                                "campaign": {"final_corpus_file_count": 3},
                                "coverage": {"copy_out_ok": True, "coverage_report_path": str(tmp_path / "coverage.json"), "inputs_replayed": 3}}},
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
        # PromeFuzz-specific: synthetic compile DB flips the eta gate.
        {"method": {"compile_db": {"strategy": "synthetic", "count": 42},
                    "link_context": {"driver_build_args_count": 5},
                    "embedding": {"provider": "openai", "model": "text-embedding-3-small"},
                    "consumer_knowledge": {"enabled": True, "artifacts_nonempty": True}}},
        # PromeFuzz-specific: empty link args flips the eta gate.
        {"method": {"compile_db": {"strategy": "fuzzbench_replay", "count": 42},
                    "link_context": {"driver_build_args_count": 0},
                    "embedding": {"provider": "openai", "model": "text-embedding-3-small"},
                    "consumer_knowledge": {"enabled": True, "artifacts_nonempty": True}}},
        # PromeFuzz-specific: mock embedding flips the eta gate.
        {"method": {"compile_db": {"strategy": "fuzzbench_replay", "count": 42},
                    "link_context": {"driver_build_args_count": 5},
                    "embedding": {"provider": "mock", "model": "text-embedding-3-small"},
                    "consumer_knowledge": {"enabled": True, "artifacts_nonempty": True}}},
        # PromeFuzz-specific: consumer knowledge not enabled flips the eta gate.
        {"method": {"compile_db": {"strategy": "fuzzbench_replay", "count": 42},
                    "link_context": {"driver_build_args_count": 5},
                    "embedding": {"provider": "openai", "model": "text-embedding-3-small"},
                    "consumer_knowledge": {"enabled": False, "artifacts_nonempty": True}}},
    ):
        mutated = json.loads(json.dumps(base))
        mutated.update(mutation)
        row = collector.extract_promefuzz_row(mutated)
        assert row["paper_equivalent_eta"] is False, mutation


def test_matrix_paper_equivalent_false_when_coverage_diff_unavailable(tmp_path: Path) -> None:
    base = _eta_matrix_base(tmp_path)
    base["metrics"]["coverage_diff"] = {"runtime_coverage_valid": False, "status": "unavailable"}
    row = collector.extract_promefuzz_row(base)
    assert row["paper_equivalent_eta"] is False
    assert row["paper_equivalent_strict"] is False


def test_evaluated_row_violations_enforce_eta_invariants(tmp_path: Path) -> None:
    cov_file = tmp_path / "coverage.json"
    cov_file.write_text("{}", encoding="utf-8")
    meta = {
        "task_family": "harness_generator",
        "generator": "promefuzz",
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
        "method": {
            "compile_db": {"strategy": "synthetic", "count": 0},
            "link_context": {"driver_build_args_count": 0},
            "embedding": {"provider": "mock", "model": "hgb-hash-embedding"},
            "consumer_knowledge": {"enabled": False, "artifacts_nonempty": False},
        },
    }
    violations = collector.evaluated_row_violations(meta)
    assert any("near_duplicate_reference" in v for v in violations)
    assert any("matches_candidate" in v for v in violations)
    assert any("copy_out_ok" in v for v in violations)
    assert any("coverage_report_path" in v for v in violations)
    assert any("inputs_replayed" in v for v in violations)
    assert any("compile_db" in v for v in violations)
    assert any("driver_build_args_count" in v for v in violations)
    assert any("embedding" in v for v in violations)
    assert any("consumer_knowledge" in v for v in violations)


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
