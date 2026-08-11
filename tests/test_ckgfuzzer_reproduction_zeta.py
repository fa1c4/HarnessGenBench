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


hgb_target_package = _load_module("hgb_target_package_zeta", "docker/common/hgb_target_package.py")
hgb_split_context = _load_module("hgb_split_context_zeta", "docker/common/hgb_split_context.py")
hgb_result = _load_module("hgb_result_zeta", "docker/common/hgb_result.py")
hgb_coverage = _load_module("hgb_coverage_zeta", "docker/common/hgb_coverage.py")
hgb_reachability = _load_module("hgb_reachability_zeta", "docker/common/hgb_reachability.py")
hgb_fuzzbench_builder = _load_module("hgb_fuzzbench_builder_zeta", "docker/common/hgb_fuzzbench_builder.py")
evaluator = _load_module("hgb_harness_evaluator_zeta", "docker/common/hgb_harness_evaluator.py")
profile = _load_module("ckgfuzzer_profile_zeta", "docker/common/ckgfuzzer_profile.py")
collector = _load_module("hgb_collect_matrix_zeta", "scripts/hgb_collect_matrix.py")


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


class ZetaFakeRunner:
    """Configurable fake runner for the zeta evaluator scenarios.

    Emits the HGB_TARGET_START marker for smoke and materializes a real final
    corpus tar for the campaign copy_out, matching the hardened shared builder
    contract (zeta plan §2).
    """

    def __init__(self, *, coverage_stdout=None, campaign_execs=500, build_exit=0,
                 binary_verified=True, overlay_matches=True, candidate_path=None,
                 coverage_build_exit=0, coverage_binary_verified=True,
                 copy_in_ok=True, smoke_marker=True):
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
        self.coverage_build_exit = coverage_build_exit
        self.coverage_binary_verified = coverage_binary_verified
        self.copy_in_ok = copy_in_ok
        self.smoke_marker = smoke_marker
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
                # The coverage image build uses FUZZING_ENGINE=coverage.
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
                    return FakeResult(cmd, 0, self.coverage_stdout, "")
                return FakeResult(cmd, 0, "", "")
            if sub == "cp":
                cp_src = cmd[2] if len(cmd) > 2 else ""
                cp_dst = cmd[3] if len(cmd) > 3 else ""
                # copy_in (host -> container): honor the configured copy_in_ok.
                if cp_src and ":" not in cp_src and cp_dst and ":" in cp_dst:
                    if not self.copy_in_ok:
                        return FakeResult(cmd, 1, "", "copy_in failed")
                # copy_out (container -> host): materialize a real corpus tar.
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
                    # Coverage binary verification uses the coverage image tag.
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


def _run_env():
    env = dict(os.environ)
    env["PATH"] = str(REPO_ROOT / "scripts") + os.pathsep + env.get("PATH", "")
    return env


# ---------------------------------------------------------------------------
# Z0. Profile acceptance and strictness
# ---------------------------------------------------------------------------


def test_reproduction_zeta_is_valid_profile() -> None:
    assert "reproduction-zeta" in profile.VALID_PROFILES
    assert profile.is_method_faithful("reproduction-zeta")
    assert "reproduction-zeta" in profile.STRICT_REPRODUCTION_PROFILES
    violations = profile.validate_profile("reproduction-zeta", "blind-project", {
        "CKGFUZZER_EMBEDDING_MODEL": "openai-text-embedding-3-small",
        "HGB_TARGET_REQUIRE_SPLIT": "1",
    })
    assert violations == [], violations


def test_reproduction_zeta_preserves_epsilon_and_delta_aliases() -> None:
    # zeta is the canonical strict profile; epsilon and delta remain accepted.
    assert "reproduction-epsilon" in profile.VALID_PROFILES
    assert "reproduction-delta" in profile.VALID_PROFILES
    assert "reproduction-zeta" in profile.STRICT_REPRODUCTION_PROFILES
    assert "reproduction-epsilon" in profile.STRICT_REPRODUCTION_PROFILES
    assert "reproduction-delta" in profile.STRICT_REPRODUCTION_PROFILES


def test_reproduction_zeta_forbids_all_local_mock_fallbacks() -> None:
    # zeta forbids every local/mock fallback, including the zeta-specific ones.
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
    ):
        env = {"CKGFUZZER_EMBEDDING_MODEL": "openai-text-embedding-3-small", "HGB_TARGET_REQUIRE_SPLIT": "1"}
        env.update(bad_env)
        violations = profile.validate_profile("reproduction-zeta", "blind-project", env)
        assert violations, f"expected violation for {bad_env}"


def test_reproduction_zeta_requires_split() -> None:
    # zeta requires HGB_TARGET_REQUIRE_SPLIT=1 (stricter than epsilon).
    violations = profile.validate_profile("reproduction-zeta", "blind-project", {
        "CKGFUZZER_EMBEDDING_MODEL": "openai-text-embedding-3-small",
    })
    assert any("HGB_TARGET_REQUIRE_SPLIT" in v for v in violations)
    # epsilon does NOT require the explicit split env var (it infers it).
    eps = profile.validate_profile("reproduction-epsilon", "blind-project", {
        "CKGFUZZER_EMBEDDING_MODEL": "openai-text-embedding-3-small",
    })
    assert not any("HGB_TARGET_REQUIRE_SPLIT" in v for v in eps)


def test_reproduction_zeta_maps_to_paper_faithful_method_variant() -> None:
    result = hgb_result.build_result(
        profile="reproduction-zeta", protocol="blind-project", target="t",
        status="evaluated",
        stages={n: "completed" for n in hgb_result.STAGE_NAMES},
    )
    assert result["method_variant"] == "paper-faithful"


def test_dry_run_canonical_command_passes_zeta_profile_validation() -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_run_baseline.sh", "--generator", "ckgfuzzer",
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
        ["bash", "scripts/hgb_generate_harness.sh", "--generator", "ckgfuzzer",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-zeta", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    assert proc.returncode != 2
    assert "unknown profile" not in proc.stderr


# ---------------------------------------------------------------------------
# Z1. Entrypoint routing, method evidence, compile repair
# ---------------------------------------------------------------------------


def test_entrypoint_zeta_routes_to_method_faithful_evaluator() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert "reproduction-zeta" in entrypoint
    assert '"$ckg_profile" == "reproduction-zeta"' in entrypoint
    # The method-faithful condition includes zeta.
    cond = '"$ckg_method_faithful" == "1" ]]'
    assert cond in entrypoint
    evaluator_pos = entrypoint.index("hgb_harness_evaluator.py")
    verifier_pos = entrypoint.index("ckgfuzzer_candidate_verifier.py")
    assert evaluator_pos < verifier_pos


def test_entrypoint_zeta_enforces_method_evidence_and_coverage_image() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    # The evidence guard and coverage-image guard both cover zeta.
    guard_lines = [ln for ln in entrypoint.splitlines() if "reproduction-zeta" in ln]
    assert any("reproduction-delta" in ln and "reproduction-epsilon" in ln for ln in guard_lines)
    cov_img_lines = [ln for ln in entrypoint.splitlines() if "--build-coverage-image" in ln]
    assert any("reproduction-zeta" in ln for ln in cov_img_lines)
    # zeta additionally runs the native coverage control.
    assert any("--run-native-control" in ln and "reproduction-zeta" in ln for ln in entrypoint.splitlines())


def test_codeql_graph_evidence_missing_prevents_evaluator_invocation() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    # The zeta evidence guard requires nonzero CodeQL graph query results and
    # exits before the evaluator is invoked.
    assert "ckg_method_evidence_missing" in entrypoint
    assert "requires nonzero CodeQL graph query results" in entrypoint
    evidence_guard_pos = entrypoint.index("ckg_method_evidence_missing")
    # The evidence-missing path exits with a nonzero code before the evaluator.
    exit_block = entrypoint[evidence_guard_pos:evidence_guard_pos + 1200]
    assert "exit" in exit_block
    # The evaluator invocation must come after the evidence guard.
    evaluator_pos = entrypoint.index("hgb_harness_evaluator.py")
    assert evaluator_pos > evidence_guard_pos
    # zeta records the additional CKG evidence files under a ckg/ directory.
    assert "ckg_evidence_dir" in entrypoint
    assert "query_results.json" in entrypoint
    assert "api_plan.json" in entrypoint


def test_compile_repair_loop_command_does_not_skip_check_compilation() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    # --skip_check_compilation is only appended for compat-smoke (when
    # ckg_method_faithful != 1). For zeta (method-faithful) it must never appear
    # in the command trace.
    assert 'ckg_compilation_args+=(--skip_check_compilation)' in entrypoint
    skip_pos = entrypoint.index('ckg_compilation_args+=(--skip_check_compilation)')
    # The skip is guarded by the non-method-faithful condition.
    guard = 'if [[ "$ckg_method_faithful" != "1" ]]; then'
    assert guard in entrypoint
    guard_pos = entrypoint.index(guard)
    assert skip_pos > guard_pos
    # zeta also saves repair attempt evidence under repair/attempt_N/.
    assert "repair/attempt_" in entrypoint or "attempt_${ckg_repair_attempt}" in entrypoint


def test_entrypoint_zeta_forbids_source_graph_fallback_and_mock_embedding() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert "CKGFUZZER_SOURCE_GRAPH_FALLBACK" in entrypoint
    assert "CKGFUZZER_ALLOW_MOCK_EMBEDDING" in entrypoint
    assert 'export HGB_TARGET_REQUIRE_SPLIT=1' in entrypoint


# ---------------------------------------------------------------------------
# Z2. Shared evaluator hardening: near-duplicate, coverage, final corpus, smoke
# ---------------------------------------------------------------------------


def test_near_duplicate_candidate_cannot_be_selected() -> None:
    # A near-duplicate reference candidate is rejected by select_best_candidate
    # exactly like an exact_copy (zeta plan §3/§4).
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
    # If every candidate is a near-duplicate, none can be selected.
    near_dup_only = json.loads(json.dumps(good))
    near_dup_only["copy_audit"]["near_duplicate_reference"] = True
    assert hgb_result.select_best_candidate([near_dup_only]) is None


def test_assert_evaluated_invariants_rejects_near_duplicate_and_empty_corpus() -> None:
    base = {
        "status": "evaluated",
        "stages": {s: "completed" for s in hgb_result.STAGE_NAMES},
        "metrics": {
            "coverage": {"line_coverage": {"covered": 27}, "report_exists": True},
            "campaign": {"execs_done": 500, "final_corpus_file_count": 3},
        },
        "selected_candidate": {
            "overlaid": True,
            "copy_audit": {"near_duplicate_reference": False, "exact_copy": False},
        },
    }
    assert hgb_result.assert_evaluated_invariants(base) == []
    # near_duplicate_reference on the selected candidate is a violation.
    bad = json.loads(json.dumps(base))
    bad["selected_candidate"]["copy_audit"]["near_duplicate_reference"] = True
    assert any("near-duplicate" in v for v in hgb_result.assert_evaluated_invariants(bad))
    # empty final corpus is a violation.
    bad = json.loads(json.dumps(base))
    bad["metrics"]["campaign"]["final_corpus_file_count"] = 0
    assert any("final corpus" in v for v in hgb_result.assert_evaluated_invariants(bad))
    # coverage.report_exists=false is a violation.
    bad = json.loads(json.dumps(base))
    bad["metrics"]["coverage"]["report_exists"] = False
    assert any("report_exists" in v for v in hgb_result.assert_evaluated_invariants(bad))
    # covered <= 0 is a violation.
    bad = json.loads(json.dumps(base))
    bad["metrics"]["coverage"]["line_coverage"]["covered"] = 0
    assert any("covered <= 0" in v for v in hgb_result.assert_evaluated_invariants(bad))


def test_coverage_build_failure_cannot_fall_back_to_non_coverage_image(tmp_path: Path) -> None:
    # With --build-coverage-image set, a coverage image build failure must
    # fail the coverage stage immediately and never reuse the address image
    # (zeta plan §3). The row cannot become evaluated.
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = ZetaFakeRunner(
        candidate_path=str(candidates_dir / "cand_001.c"),
        coverage_build_exit=1,
        coverage_binary_verified=False,
    )
    result = evaluator.evaluate(
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-zeta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
        build_coverage_image=True,
    )
    assert result["status"] != hgb_result.STATUS_EVALUATED
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["coverage"] == "failed"
    # The coverage failure reason must mention the coverage image build, not a
    # silent reuse of the address image.
    assert "coverage image build failed" in (cand_json.get("error") or "")


def test_final_corpus_missing_fails_strict_evaluation(tmp_path: Path) -> None:
    # When the campaign produces an empty final corpus in a strict profile,
    # the campaign stage fails and the row never falls back to the seed corpus
    # (zeta plan §2/§3).
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)

    class _EmptyCorpusRunner(ZetaFakeRunner):
        def __call__(self, command, timeout):
            r = super().__call__(command, timeout)
            cmd = list(command)
            # Suppress the corpus.tar materialization so extraction yields no files.
            if cmd[:2] == ["docker", "cp"]:
                cp_src = cmd[2] if len(cmd) > 2 else ""
                cp_dst = cmd[3] if len(cmd) > 3 else ""
                if "corpus.tar" in cp_src and cp_dst:
                    # Write an empty tar (no entries) so final_corpus_file_count=0.
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
        fuzz_target="fuzz_target", profile="reproduction-zeta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
    )
    assert result["status"] != hgb_result.STATUS_EVALUATED
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["campaign"] == "failed"


def test_smoke_cannot_complete_from_missing_copied_input(tmp_path: Path) -> None:
    # A smoke sample whose input copy fails is not executed, even if the
    # container would have emitted the marker (zeta plan §2).
    work_dir = tmp_path / "smoke"
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"\x01\x02\x03")
    runner = ZetaFakeRunner(copy_in_ok=False, smoke_marker=True)
    smoke = hgb_fuzzbench_builder.run_smoke(
        image_tag="hgb-test",
        binary_path="/out/fuzz_target",
        seeds=[seed],
        work_dir=work_dir,
        runner=runner,
    )
    assert smoke["any_executed"] is False
    assert all(s["executed"] is False for s in smoke["samples"])
    assert all(s["copy_in_ok"] is False for s in smoke["samples"])


def test_smoke_cannot_complete_from_missing_marker(tmp_path: Path) -> None:
    # Even with a successful input copy, a missing start marker means the
    # target was not actually started (zeta plan §2).
    work_dir = tmp_path / "smoke"
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"\x01\x02\x03")
    runner = ZetaFakeRunner(copy_in_ok=True, smoke_marker=False)
    smoke = hgb_fuzzbench_builder.run_smoke(
        image_tag="hgb-test",
        binary_path="/out/fuzz_target",
        seeds=[seed],
        work_dir=work_dir,
        runner=runner,
    )
    assert smoke["any_executed"] is False


def test_full_evaluated_loop_succeeds_for_zeta(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = ZetaFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"))
    result = evaluator.evaluate(
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-zeta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
        build_coverage_image=True,
    )
    assert result["status"] == hgb_result.STATUS_EVALUATED
    assert result["method_variant"] == "paper-faithful"
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["build"]["overlay_audit"]["matches_candidate"] is True
    assert cand_json["build"]["binary_verified"] is True
    # The selected candidate carries the zeta-required provenance fields.
    sel = result["selected_candidate"]
    for field in ("copy_audit", "overlay_audit", "coverage_report_path", "campaign_log", "final_corpus_dir", "build_logs"):
        assert field in sel, f"selected_candidate missing {field}"


def test_sealed_context_fail_closed_for_strict_split_error(tmp_path: Path) -> None:
    # In a strict profile, a split-package VerificationContextError must fail
    # closed (infra_failure), never fall through to a monolithic package that
    # could contain reference harnesses (zeta plan §3).
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    # Remove the generator source_repos.json so SplitTargetContext.load fails.
    (gen_root / "source_repos.json").unlink()
    runner = ZetaFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"))
    result = evaluator.evaluate(
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-zeta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=[], seeds=[],
    )
    assert result["status"] == hgb_result.STATUS_INFRA_FAILURE


# ---------------------------------------------------------------------------
# Z3. Matrix semantics
# ---------------------------------------------------------------------------


def test_matrix_paper_equivalent_zeta_gate() -> None:
    base = {
        "generator": "ckgfuzzer",
        "target": "jsoncpp_jsoncpp_fuzzer",
        "status": "evaluated",
        "applicability": "applicable",
        "profile": "reproduction-zeta",
        "method_variant": "paper-faithful",
        "excluded_from_aggregate": False,
        "stages": {n: "completed" for n in ("candidate_build", "sanitizer_smoke", "api_reachability", "campaign", "coverage")},
        "metrics": {
            "coverage": {"line_coverage": {"covered": 27}, "function_coverage": {"covered": 5}, "region_coverage": {"covered": 12}},
            "campaign": {"execs_done": 500, "crashes": 0, "timeouts": 0, "final_corpus_file_count": 3},
        },
        "build": {"overlay_audit": {"matches_candidate": True}},
        "selected_candidate": {
            "copy_audit": {"exact_copy": False, "near_duplicate_reference": False},
            "build": {"overlay_audit": {"matches_candidate": True}},
            "campaign": {"final_corpus_file_count": 3},
        },
        "candidate": {"contains_reference_canary": False, "near_duplicate_reference": False},
    }
    row = collector.extract_ckgfuzzer_row(base)
    assert row["paper_equivalent_zeta"] is True
    assert row["paper_equivalent_strict"] is True

    # Each condition below must flip paper_equivalent_zeta to False.
    for mutation in (
        {"profile": "alpha"},
        {"method_variant": "compat-smoke"},
        {"status": "quality_failure"},
        {"excluded_from_aggregate": True},
        {"metrics": {"coverage": {"line_coverage": {"covered": 0}}, "campaign": {"execs_done": 500, "final_corpus_file_count": 3}}},
        {"metrics": {"coverage": {"line_coverage": {"covered": 27}}, "campaign": {"execs_done": 0, "final_corpus_file_count": 3}}},
        {"metrics": {"coverage": {"line_coverage": {"covered": 27}}, "campaign": {"execs_done": 500, "final_corpus_file_count": 0}}},
        {"selected_candidate": {"copy_audit": {"exact_copy": True, "near_duplicate_reference": False}, "build": {"overlay_audit": {"matches_candidate": True}}, "campaign": {"final_corpus_file_count": 3}}},
        {"selected_candidate": {"copy_audit": {"exact_copy": False, "near_duplicate_reference": True}, "build": {"overlay_audit": {"matches_candidate": True}}, "campaign": {"final_corpus_file_count": 3}}},
        {"selected_candidate": {"copy_audit": {"exact_copy": False, "near_duplicate_reference": False}, "build": {"overlay_audit": {"matches_candidate": False}}, "campaign": {"final_corpus_file_count": 3}}},
    ):
        mutated = json.loads(json.dumps(base))
        mutated.update(mutation)
        row = collector.extract_ckgfuzzer_row(mutated)
        assert row["paper_equivalent_zeta"] is False, mutation


def test_evaluated_row_violations_enforce_zeta_invariants() -> None:
    meta = {
        "task_family": "harness_generator",
        "generator": "ckgfuzzer",
        "profile": "reproduction-zeta",
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
        },
    }
    violations = collector.evaluated_row_violations(meta)
    assert any("near_duplicate_reference" in v for v in violations)
    assert any("matches_candidate" in v for v in violations)


def test_valuable_target_set_has_twenty_targets() -> None:
    hgb_targets = _load_module("hgb_targets_zeta", "scripts/hgb_targets.py")
    registry = hgb_targets.load_registry(REPO_ROOT)
    valuable = hgb_targets.targets_for_set(registry, "valuable")
    assert len(valuable) == 20
    # The valuable set must match the plan's target list.
    assert sorted(valuable) == sorted(VALUABLE_TARGETS)


def test_common_sh_zeta_is_strict_reproduction() -> None:
    common = (REPO_ROOT / "scripts/lib/common.sh").read_text(encoding="utf-8")
    assert "reproduction-zeta" in common
    # hgb_profile_is_strict_reproduction covers zeta.
    proc = subprocess.run(
        ["bash", "-c", "source scripts/lib/common.sh && hgb_profile_is_strict_reproduction reproduction-zeta && echo OK"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30,
    )
    assert "OK" in proc.stdout, proc.stderr


def test_hgb_targets_infers_require_split_for_zeta() -> None:
    env = dict(os.environ)
    env["HGB_BASELINE_PROFILE"] = "reproduction-zeta"
    env["HGB_BASELINE_PROTOCOL"] = "blind-project"
    proc = subprocess.run(
        ["python3", "scripts/hgb_targets.py", "package", "--help"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=env, timeout=30,
    )
    assert "--require-split" in proc.stdout


def test_matrix_runner_wrapper_accepts_zeta_args() -> None:
    wrapper = (REPO_ROOT / "scripts/hgb_run_baseline_matrix.sh").read_text(encoding="utf-8")
    assert "--profile" in wrapper
    assert "--campaign-seconds" in wrapper
    assert '--generators "$generators"' in wrapper
    assert '--profile "$profile"' in wrapper
