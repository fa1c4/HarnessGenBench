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


hgb_target_package = _load_module("hgb_target_package_eta", "docker/common/hgb_target_package.py")
hgb_split_context = _load_module("hgb_split_context_eta", "docker/common/hgb_split_context.py")
hgb_result = _load_module("hgb_result_eta", "docker/common/hgb_result.py")
hgb_coverage = _load_module("hgb_coverage_eta", "docker/common/hgb_coverage.py")
hgb_reachability = _load_module("hgb_reachability_eta", "docker/common/hgb_reachability.py")
hgb_fuzzbench_builder = _load_module("hgb_fuzzbench_builder_eta", "docker/common/hgb_fuzzbench_builder.py")
evaluator = _load_module("hgb_harness_evaluator_eta", "docker/common/hgb_harness_evaluator.py")
profile = _load_module("ckgfuzzer_profile_eta", "docker/common/ckgfuzzer_profile.py")
collector = _load_module("hgb_collect_matrix_eta", "scripts/hgb_collect_matrix.py")


VALUABLE_TARGETS = [
    "bloaty_fuzz_target", "curl_curl_fuzzer_http", "freetype2_ftfuzzer",
    "harfbuzz_hb-shape-fuzzer", "jsoncpp_jsoncpp_fuzzer", "lcms_cms_transform_fuzzer",
    "libjpeg-turbo_libjpeg_turbo_fuzzer", "libpcap_fuzz_both", "libpng_libpng_read_fuzzer",
    "libxml2_xml", "libxslt_xpath", "mbedtls_fuzz_dtlsclient", "mruby_mruby_fuzzer_8c8bbd",
    "openh264_decoder_fuzzer", "openssl_x509", "php_php-fuzz-parser_0dbedb", "re2_fuzzer",
    "sqlite3_ossfuzz", "systemd_fuzz-link-parser", "zlib_zlib_uncompress_fuzzer",
]


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


def _run_env():
    env = dict(os.environ)
    env["PATH"] = str(REPO_ROOT / "scripts") + os.pathsep + env.get("PATH", "")
    return env


# ---------------------------------------------------------------------------
# E0. Profile acceptance and strictness
# ---------------------------------------------------------------------------


def test_reproduction_eta_is_valid_profile() -> None:
    assert "reproduction-eta" in profile.VALID_PROFILES
    assert profile.is_method_faithful("reproduction-eta")
    assert "reproduction-eta" in profile.STRICT_REPRODUCTION_PROFILES
    assert "reproduction-eta" in profile.ETA_PROFILES
    violations = profile.validate_profile("reproduction-eta", "blind-project", {
        "CKGFUZZER_EMBEDDING_MODEL": "openai-text-embedding-3-small",
        "HGB_TARGET_REQUIRE_SPLIT": "1",
    })
    assert violations == [], violations


def test_reproduction_eta_keeps_zeta_epsilon_delta_as_aliases() -> None:
    # eta is the canonical strict profile; zeta/epsilon/delta remain accepted.
    assert "reproduction-zeta" in profile.VALID_PROFILES
    assert "reproduction-epsilon" in profile.VALID_PROFILES
    assert "reproduction-delta" in profile.VALID_PROFILES
    assert "reproduction-zeta" in profile.STRICT_REPRODUCTION_PROFILES
    assert "reproduction-epsilon" in profile.STRICT_REPRODUCTION_PROFILES
    assert "reproduction-delta" in profile.STRICT_REPRODUCTION_PROFILES


def test_reproduction_eta_forbids_all_local_mock_fallbacks() -> None:
    for bad_env in (
        {"CKGFUZZER_LOCAL_API_SUMMARY": "1"},
        {"CKGFUZZER_LOCAL_API_COMBINATION": "1"},
        {"CKGFUZZER_SKIP_CHECK_COMPILATION": "1"},
        {"CKGFUZZER_EMBEDDING_MODEL": "mock"},
        {"CKGFUZZER_EMBEDDING_MODEL": "hgb-hash-embedding"},
        {"CKGFUZZER_ALLOW_SOURCE_FALLBACK": "1"},
        {"CKGFUZZER_SOURCE_GRAPH_FALLBACK": "1", "HGB_TARGET_REQUIRE_SPLIT": "1"},
        {"CKGFUZZER_ALLOW_MOCK_EMBEDDING": "1", "HGB_TARGET_REQUIRE_SPLIT": "1"},
        {"HGB_API_SELECTION_MODE": "selected_harness"},
        {"HGB_API_SELECTION_MODE": "selected_harness_fallback"},
        {"CKGFUZZER_API_SELECTION_MODE": "selected_harness_fallback"},
    ):
        env = {"CKGFUZZER_EMBEDDING_MODEL": "openai-text-embedding-3-small", "HGB_TARGET_REQUIRE_SPLIT": "1"}
        env.update(bad_env)
        violations = profile.validate_profile("reproduction-eta", "blind-project", env)
        assert violations, f"expected violation for {bad_env}"


def test_reproduction_eta_requires_split() -> None:
    violations = profile.validate_profile("reproduction-eta", "blind-project", {
        "CKGFUZZER_EMBEDDING_MODEL": "openai-text-embedding-3-small",
    })
    assert any("HGB_TARGET_REQUIRE_SPLIT" in v for v in violations)


def test_reproduction_eta_maps_to_paper_faithful_method_variant() -> None:
    result = hgb_result.build_result(
        profile="reproduction-eta", protocol="blind-project", target="t",
        status="evaluated",
        stages={n: "completed" for n in hgb_result.STAGE_NAMES},
    )
    assert result["method_variant"] == "paper-faithful"


def test_dry_run_canonical_command_passes_eta_profile_validation() -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_run_baseline.sh", "--generator", "ckgfuzzer",
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
        ["bash", "scripts/hgb_generate_harness.sh", "--generator", "ckgfuzzer",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-eta", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    assert proc.returncode != 2
    assert "unknown profile" not in proc.stderr


# ---------------------------------------------------------------------------
# E1. Entrypoint routing, method evidence, compile repair
# ---------------------------------------------------------------------------


def test_entrypoint_eta_routes_to_method_faithful_evaluator() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert "reproduction-eta" in entrypoint
    assert '"$ckg_profile" == "reproduction-eta"' in entrypoint
    cond = '"$ckg_method_faithful" == "1" ]]'
    assert cond in entrypoint
    evaluator_pos = entrypoint.index("hgb_harness_evaluator.py")
    verifier_pos = entrypoint.index("ckgfuzzer_candidate_verifier.py")
    assert evaluator_pos < verifier_pos


def test_entrypoint_eta_enforces_method_evidence_and_coverage_image() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    guard_lines = [ln for ln in entrypoint.splitlines() if "reproduction-eta" in ln]
    assert any("reproduction-delta" in ln and "reproduction-epsilon" in ln for ln in guard_lines)
    cov_img_lines = [ln for ln in entrypoint.splitlines() if "--build-coverage-image" in ln]
    assert any("reproduction-eta" in ln for ln in cov_img_lines)
    # eta additionally runs the native coverage control.
    assert any("--run-native-control" in ln and "reproduction-eta" in ln for ln in entrypoint.splitlines())


def test_codeql_graph_evidence_missing_prevents_evaluator_invocation() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert "ckg_method_evidence_missing" in entrypoint
    assert "requires nonzero CodeQL graph query results" in entrypoint
    evidence_guard_pos = entrypoint.index("ckg_method_evidence_missing")
    exit_block = entrypoint[evidence_guard_pos:evidence_guard_pos + 1200]
    assert "exit" in exit_block
    evaluator_pos = entrypoint.index("hgb_harness_evaluator.py")
    assert evaluator_pos > evidence_guard_pos
    # eta records the additional CKG evidence files under a ckg/ directory.
    assert "ckg_evidence_dir" in entrypoint
    assert "query_results.json" in entrypoint
    assert "api_plan.json" in entrypoint


def test_codeql_cache_hit_recounts_graph_before_eta_evidence_guard() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    restore_pos = entrypoint.index("ckg_codeql_cache_try_restore")
    recount_pos = entrypoint.index("PY_CKG_COMBINED_GRAPH_COUNTS_POST_CACHE")
    evidence_guard_pos = entrypoint.index("requires nonzero CodeQL graph query results")
    assert restore_pos < recount_pos < evidence_guard_pos
    recount_block = entrypoint[recount_pos - 900:recount_pos + 1800]
    assert "api_combine/combined_call_graph.csv" in recount_block
    assert 'ckg_codeql_cache_restored" == "1' in recount_block
    assert "knowledge_graph completed" in recount_block


def test_compile_repair_loop_command_does_not_skip_check_compilation() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert 'ckg_compilation_args+=(--skip_check_compilation)' in entrypoint
    skip_pos = entrypoint.index('ckg_compilation_args+=(--skip_check_compilation)')
    guard = 'if [[ "$ckg_method_faithful" != "1" ]]; then'
    assert guard in entrypoint
    guard_pos = entrypoint.index(guard)
    assert skip_pos > guard_pos
    assert "repair/attempt_" in entrypoint or "attempt_${ckg_repair_attempt}" in entrypoint


def test_entrypoint_eta_forbids_source_graph_fallback_and_mock_embedding() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert "CKGFUZZER_SOURCE_GRAPH_FALLBACK" in entrypoint
    assert "CKGFUZZER_ALLOW_MOCK_EMBEDDING" in entrypoint
    assert 'export HGB_TARGET_REQUIRE_SPLIT=1' in entrypoint


# ---------------------------------------------------------------------------
# E2. Shared evaluator hardening: eta coverage invariants
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


def test_coverage_image_build_uses_sanitizer_cache_key(tmp_path: Path) -> None:
    runner = EtaFakeRunner()
    hgb_fuzzbench_builder.build_coverage_image(
        context_dir=tmp_path,
        dockerfile=tmp_path / "Dockerfile",
        image_tag="hgb-test-coverage",
        fuzz_target="fuzz_target",
        work_dir=tmp_path / "coverage_build",
        runner=runner,
    )
    build_cmd = next(
        cmd for cmd in runner.commands
        if cmd[:2] == ["docker", "build"] and "SANITIZER=coverage" in " ".join(cmd)
    )
    assert "--no-cache" not in build_cmd
    assert "HGB_BUILD_VARIANT=coverage-libfuzzer" in build_cmd
    assert "HGB_SANITIZER=coverage" in build_cmd
    assert "HGB_FUZZING_ENGINE=libfuzzer" in build_cmd


def test_coverage_build_failure_cannot_fall_back_to_non_coverage_image(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = EtaFakeRunner(
        candidate_path=str(candidates_dir / "cand_001.c"),
        coverage_build_exit=1,
        coverage_binary_verified=False,
    )
    result = evaluator.evaluate(
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
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
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
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
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
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
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
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
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
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
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-eta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=[], seeds=[],
    )
    assert result["status"] == hgb_result.STATUS_INFRA_FAILURE


# ---------------------------------------------------------------------------
# E3. Matrix semantics
# ---------------------------------------------------------------------------


def test_matrix_paper_equivalent_eta_gate() -> None:
    base = {
        "generator": "ckgfuzzer",
        "target": "jsoncpp_jsoncpp_fuzzer",
        "status": "evaluated",
        "applicability": "applicable",
        "profile": "reproduction-eta",
        "method_variant": "paper-faithful",
        "excluded_from_aggregate": False,
        "stages": {n: "completed" for n in ("candidate_build", "sanitizer_smoke", "api_reachability", "campaign", "coverage")},
        "metrics": {
            "coverage": {"line_coverage": {"covered": 27}, "function_coverage": {"covered": 5},
                          "region_coverage": {"covered": 12}, "copy_out_ok": True,
                          "coverage_report_path": "/tmp/coverage.json", "inputs_replayed": 3},
            "campaign": {"execs_done": 500, "crashes": 0, "timeouts": 0, "final_corpus_file_count": 3},
        },
        "build": {"overlay_audit": {"matches_candidate": True}},
        "selected_candidate": {
            "copy_audit": {"exact_copy": False, "near_duplicate_reference": False},
            "build": {"overlay_audit": {"matches_candidate": True}},
            "campaign": {"final_corpus_file_count": 3},
            "coverage": {"copy_out_ok": True, "coverage_report_path": "/tmp/coverage.json", "inputs_replayed": 3},
        },
        "candidate": {"contains_reference_canary": False, "near_duplicate_reference": False},
    }
    row = collector.extract_ckgfuzzer_row(base)
    assert row["paper_equivalent_eta"] is True
    assert row["paper_equivalent_strict"] is True

    # Each condition below must flip paper_equivalent_eta to False.
    for mutation in (
        {"profile": "alpha"},
        {"method_variant": "compat-smoke"},
        {"status": "quality_failure"},
        {"excluded_from_aggregate": True},
        {"metrics": {"coverage": {"line_coverage": {"covered": 0}, "copy_out_ok": True, "coverage_report_path": "/tmp/coverage.json", "inputs_replayed": 3}, "campaign": {"execs_done": 500, "final_corpus_file_count": 3}}},
        {"metrics": {"coverage": {"line_coverage": {"covered": 27}, "copy_out_ok": True, "coverage_report_path": "/tmp/coverage.json", "inputs_replayed": 3}, "campaign": {"execs_done": 0, "final_corpus_file_count": 3}}},
        {"metrics": {"coverage": {"line_coverage": {"covered": 27}, "copy_out_ok": True, "coverage_report_path": "/tmp/coverage.json", "inputs_replayed": 3}, "campaign": {"execs_done": 500, "final_corpus_file_count": 0}}},
        # eta-specific: copy_out_ok False flips the eta gate.
        {"metrics": {"coverage": {"line_coverage": {"covered": 27}, "copy_out_ok": False, "coverage_report_path": "/tmp/coverage.json", "inputs_replayed": 3}, "campaign": {"execs_done": 500, "final_corpus_file_count": 3}}},
        # eta-specific: missing coverage_report_path flips the eta gate.
        {"metrics": {"coverage": {"line_coverage": {"covered": 27}, "copy_out_ok": True, "coverage_report_path": "", "inputs_replayed": 3}, "campaign": {"execs_done": 500, "final_corpus_file_count": 3}}},
        # eta-specific: inputs_replayed <= 0 flips the eta gate.
        {"metrics": {"coverage": {"line_coverage": {"covered": 27}, "copy_out_ok": True, "coverage_report_path": "/tmp/coverage.json", "inputs_replayed": 0}, "campaign": {"execs_done": 500, "final_corpus_file_count": 3}}},
        {"selected_candidate": {"copy_audit": {"exact_copy": True, "near_duplicate_reference": False}, "build": {"overlay_audit": {"matches_candidate": True}}, "campaign": {"final_corpus_file_count": 3}, "coverage": {"copy_out_ok": True, "coverage_report_path": "/tmp/coverage.json", "inputs_replayed": 3}}},
        {"selected_candidate": {"copy_audit": {"exact_copy": False, "near_duplicate_reference": True}, "build": {"overlay_audit": {"matches_candidate": True}}, "campaign": {"final_corpus_file_count": 3}, "coverage": {"copy_out_ok": True, "coverage_report_path": "/tmp/coverage.json", "inputs_replayed": 3}}},
        {"selected_candidate": {"copy_audit": {"exact_copy": False, "near_duplicate_reference": False}, "build": {"overlay_audit": {"matches_candidate": False}}, "campaign": {"final_corpus_file_count": 3}, "coverage": {"copy_out_ok": True, "coverage_report_path": "/tmp/coverage.json", "inputs_replayed": 3}}},
    ):
        mutated = json.loads(json.dumps(base))
        mutated.update(mutation)
        row = collector.extract_ckgfuzzer_row(mutated)
        assert row["paper_equivalent_eta"] is False, mutation


def test_evaluated_row_violations_enforce_eta_invariants() -> None:
    meta = {
        "task_family": "harness_generator",
        "generator": "ckgfuzzer",
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
    assert "--profile" in wrapper
    assert "--campaign-seconds" in wrapper
    assert '--generators "$generators"' in wrapper
    assert '--profile "$profile"' in wrapper


def test_matrix_collector_accepts_fail_on_invariant_violations_flag() -> None:
    proc = subprocess.run(
        ["python3", "scripts/hgb_collect_matrix.py", "--help"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30,
    )
    assert "--fail-on-invariant-violations" in proc.stdout
    assert "--require-evaluated" in proc.stdout
