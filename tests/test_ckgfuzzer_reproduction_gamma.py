from __future__ import annotations

import importlib.util
import json
import shutil
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


hgb_target_package = _load_module("hgb_target_package_gamma", "docker/common/hgb_target_package.py")
hgb_split_context = _load_module("hgb_split_context_gamma", "docker/common/hgb_split_context.py")
SplitContextError = hgb_split_context.VerificationContextError
hgb_result = _load_module("hgb_result_gamma", "docker/common/hgb_result.py")
hgb_coverage = _load_module("hgb_coverage_gamma", "docker/common/hgb_coverage.py")
hgb_reachability = _load_module("hgb_reachability_gamma", "docker/common/hgb_reachability.py")
hgb_fuzzbench_builder = _load_module("hgb_fuzzbench_builder_gamma", "docker/common/hgb_fuzzbench_builder.py")
evaluator = _load_module("hgb_harness_evaluator_gamma", "docker/common/hgb_harness_evaluator.py")
profile = _load_module("ckgfuzzer_profile_gamma", "docker/common/ckgfuzzer_profile.py")
collector = _load_module("hgb_collect_matrix_gamma", "scripts/hgb_collect_matrix.py")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_monolithic_package(tmp_path: Path) -> Path:
    pkg = tmp_path / "target_pkg"
    (pkg / "source_input" / "project").mkdir(parents=True)
    (pkg / "seeds").mkdir(parents=True)
    (pkg / "reference_harnesses" / "selected" / "source_input" / "project").mkdir(parents=True)
    (pkg / "fuzzbench_benchmark").mkdir(parents=True)
    (pkg / "source_input" / "project" / "sample.c").write_text("int api(void){return 0;}\n", encoding="utf-8")
    (pkg / "reference_harnesses" / "selected" / "source_input" / "project" / "native.c").write_text(
        "int LLVMFuzzerTestOneInput(void){return 0;}\n", encoding="utf-8"
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


def _split_package(tmp_path: Path) -> tuple[Path, Path, Path]:
    pkg = _make_monolithic_package(tmp_path)
    halves = hgb_target_package.split_package(
        pkg,
        native_harness={
            "selected_reference": "source_input/project/native.c",
            "container_destination": "/src/project/native.c",
            "language": "c",
        },
    )
    return Path(halves["generator_input"]), Path(halves["evaluator_only"]), pkg


class FakeResult:
    def __init__(self, command, exit_code=0, stdout="", stderr=""):
        self.command = list(command)
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    def __init__(self, *, coverage_stdout=None, campaign_execs=500, build_exit=0):
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
        return FakeResult(cmd, 0, "", "")


def test_builder_preseeds_freetype_libarchive_iconv_configure(tmp_path: Path) -> None:
    context = tmp_path / "context"
    (context / "fuzzbench_benchmark").mkdir(parents=True)
    for build_sh in (context / "build.sh", context / "fuzzbench_benchmark" / "build.sh"): 
        build_sh.write_text("#!/bin/bash -ex\n./configure --disable-shared\n", encoding="utf-8")

    hgb_fuzzbench_builder._patch_single_target_build_context(context, "ftfuzzer")

    for build_sh in (context / "build.sh", context / "fuzzbench_benchmark" / "build.sh"): 
        patched = build_sh.read_text(encoding="utf-8")
        assert patched.startswith("#!/bin/bash -ex\n# HGB sealed evaluator: avoid sanitizer-built libarchive iconv conftest.")
        assert "export am_cv_func_iconv=yes" in patched
        assert "export am_cv_lib_iconv=no" in patched
        assert "export am_cv_func_iconv_works=yes" in patched

def test_evaluator_filters_comment_only_api_mentions(tmp_path: Path) -> None:
    target_root = tmp_path / "target"
    primary = target_root / "source_input" / "project"
    primary.mkdir(parents=True)
    (primary / "api.c").write_text(
        '/* CreateFont() appears only in docs. */\n'
        'const char *s = "line() is only a string";\n'
        'int real_api(void) { return 0; }\n'
        'void caller(void) { (void) real_api(); }\n',
        encoding="utf-8",
    )
    (target_root / "source_repos.json").write_text(json.dumps([
        {"package_path": "source_input/project", "is_primary_project": True},
    ]), encoding="utf-8")

    assert evaluator._filter_intended_apis_by_primary_source(
        ["CreateFont", "line", "real_api"], target_root
    ) == ["real_api"]


def test_evaluator_filters_intended_apis_to_primary_source(tmp_path: Path) -> None:
    target_root = tmp_path / "target"
    primary = target_root / "source_input" / "mbedtls"
    secondary = target_root / "source_input" / "boringssl"
    primary.mkdir(parents=True)
    secondary.mkdir(parents=True)
    (primary / "ssl.h").write_text("int mbedtls_ssl_setup(void);\n", encoding="utf-8")
    (secondary / "rand.h").write_text("void CRYPTO_sysrand(unsigned char *, size_t);\n", encoding="utf-8")
    (target_root / "source_repos.json").write_text(json.dumps([
        {"package_path": "source_input/mbedtls", "is_primary_project": True},
        {"package_path": "source_input/boringssl", "is_primary_project": False},
    ]), encoding="utf-8")

    assert evaluator._filter_intended_apis_by_primary_source(
        ["mbedtls_ssl_setup", "CRYPTO_sysrand"], target_root
    ) == ["mbedtls_ssl_setup"]


def _setup_evaluator_paths(tmp_path: Path):
    gen_root = tmp_path / "generator_input"
    evl_root = tmp_path / "evaluator_only"
    candidates_dir = tmp_path / "candidates"
    work_dir = tmp_path / "evaluation"
    (gen_root / "seeds").mkdir(parents=True)
    (gen_root / "source_input" / "project").mkdir(parents=True)
    (gen_root / "source_input" / "project" / "sample.c").write_text("int api(void){return 0;}\n", encoding="utf-8")
    (gen_root / "source_repos.json").write_text("[]", encoding="utf-8")
    (evl_root / "benchmark_copy").mkdir(parents=True)
    (evl_root / "benchmark_copy" / "Dockerfile").write_text("FROM scratch\nCOPY source_input/ /src/\n", encoding="utf-8")
    (evl_root / "benchmark_copy" / "build.sh").write_text("#!/bin/sh\ncc $SRC/project/native.c -o $OUT/fuzz_target\n", encoding="utf-8")
    (evl_root / "reference_harnesses" / "source_input" / "project").mkdir(parents=True)
    (evl_root / "reference_harnesses" / "source_input" / "project" / "native.c").write_text("// ref\n", encoding="utf-8")
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
# 1. Split manifest test
# ---------------------------------------------------------------------------


def test_split_package_writes_sanitized_target_manifest_json(tmp_path: Path) -> None:
    gen_root, evl_root, _ = _split_package(tmp_path)
    # The sanitized manifest must exist at the canonical /target path.
    manifest_path = gen_root / "target_manifest.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for field in hgb_target_package.GENERATOR_FORBIDDEN_FIELDS:
        assert field not in manifest, f"sanitized manifest leaked field {field}"
    # The generator manifest must also exist.
    assert (gen_root / "target_manifest.generator.json").is_file()
    # source_repos.json must be at the generator top level.
    assert (gen_root / "source_repos.json").is_file()
    # reference_harnesses must NOT exist in the generator half.
    assert not (gen_root / "reference_harnesses").exists()


def test_split_package_writes_evaluator_manifest(tmp_path: Path) -> None:
    gen_root, evl_root, _ = _split_package(tmp_path)
    assert (evl_root / "evaluator_manifest.json").is_file()
    assert (evl_root / "target_manifest.evaluator.json").is_file()
    ev_manifest = json.loads((evl_root / "evaluator_manifest.json").read_text(encoding="utf-8"))
    assert ev_manifest["benchmark_copy_dir"] == "benchmark_copy"


def test_common_sh_exports_explicit_env_vars() -> None:
    common = (REPO_ROOT / "scripts/lib/common.sh").read_text(encoding="utf-8")
    assert "-e HGB_TARGET_ROOT=/target" in common
    assert "-e HGB_GENERATOR_TARGET_ROOT=/target" in common
    assert "HGB_EVALUATOR_MANIFEST=/evaluator/evaluator_manifest.json" in common


# ---------------------------------------------------------------------------
# 2. Sealed evaluator context test (split-aware)
# ---------------------------------------------------------------------------


def test_split_context_load_combines_generator_and_evaluator_halves(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    ctx = hgb_split_context.SplitTargetContext.load(gen_root, evl_root)
    assert ctx.source_input == gen_root / "source_input"
    assert ctx.source_repos == gen_root / "source_repos.json"
    assert ctx.benchmark_copy == evl_root / "benchmark_copy"
    assert ctx.native_harness_path == evl_root / "native_harness_path.json"
    assert ctx.reference_harnesses == evl_root / "reference_harnesses"


def test_split_context_load_names_missing_file(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    # Remove source_repos.json from generator half.
    (gen_root / "source_repos.json").unlink()
    (gen_root / "build_metadata").mkdir(parents=True, exist_ok=True)
    with pytest.raises(SplitContextError) as exc:
        hgb_split_context.SplitTargetContext.load(gen_root, evl_root)
    assert "source_repos.json" in str(exc.value)


def test_create_sealed_build_context_assembles_both_halves(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    ctx = hgb_split_context.SplitTargetContext.load(gen_root, evl_root)
    sealed = hgb_split_context.create_sealed_build_context(ctx, work_dir / "sealed")
    sealed_dir = Path(sealed["context_dir"])
    assert (sealed_dir / "source_input" / "project" / "sample.c").is_file()
    assert (sealed_dir / "source_repos.json").is_file()
    assert (sealed_dir / "fuzzbench_benchmark" / "Dockerfile").is_file()
    assert (sealed_dir / "build.sh").is_file()
    assert sealed["benchmark_context_file_count"] >= 1
    assert (sealed_dir / "native_harness_path.json").is_file()
    assert (sealed_dir / "reference_harnesses").is_dir()
    assert sealed["mode"] == "split_sealed_source_snapshot"


def test_split_context_mirrors_benchmark_root_auxiliary_files(tmp_path: Path) -> None:
    gen_root, evl_root, _candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    (evl_root / "benchmark_copy" / "target.cc").write_text("// aux\n", encoding="utf-8")
    (evl_root / "benchmark_copy" / ".dockerignore").write_text("/build.sh\n", encoding="utf-8")
    (evl_root / "benchmark_copy" / "seeds").mkdir()
    (evl_root / "benchmark_copy" / "seeds" / "seed").write_bytes(b"seed")

    ctx = hgb_split_context.SplitTargetContext.load(gen_root, evl_root)
    sealed = hgb_split_context.create_sealed_build_context(ctx, work_dir / "sealed")
    sealed_dir = Path(sealed["context_dir"])

    assert (sealed_dir / "target.cc").is_file()
    assert (sealed_dir / ".dockerignore").read_text(encoding="utf-8") == "/build.sh\n"
    assert (sealed_dir / "seeds" / "seed").is_file()
    assert (sealed_dir / "fuzzbench_benchmark" / "target.cc").is_file()
    assert sealed["benchmark_context_file_count"] >= 4


def test_evaluator_uses_split_context_for_split_package(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = FakeRunner()
    result = evaluator.evaluate(
        generator="ckgfuzzer",
        target_root=gen_root,
        evaluator_root=evl_root,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="project",
        fuzz_target="fuzz_target",
        profile="reproduction-gamma",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        intended_apis=["hgb_sample_api"],
        seeds=[],
    )
    assert result["status"] == hgb_result.STATUS_EVALUATED
    sealed_dir = work_dir / "sealed_context"
    assert sealed_dir.is_dir()


def test_verify_overlay_path_rejects_traversal(tmp_path: Path) -> None:
    sealed_dir = tmp_path / "sealed"
    (sealed_dir / "source_input").mkdir(parents=True)
    with pytest.raises(SplitContextError):
        hgb_split_context.verify_overlay_path("/src/../../etc/passwd", sealed_dir)



def test_builder_normalizes_cpp_syntax_for_c_native_harness(tmp_path: Path) -> None:
    builder = _load_module("hgb_fuzzbench_builder_gamma_direct", "docker/common/hgb_fuzzbench_builder.py")
    cand = tmp_path / "candidate.cc"
    cand.write_text(
        '#include <stdint.h>\n#include <stddef.h>\nextern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return nullptr == NULL; }\n',
        encoding="utf-8",
    )

    staged = builder._normalize_candidate_for_native_path(cand, "/src/project/fuzz_target.c", tmp_path / "work")
    text = staged.read_text(encoding="utf-8")

    assert staged.suffix == ".c"
    assert 'extern "C"' not in text
    assert "nullptr" not in text
    assert "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);" in text


def test_builder_adds_c_linkage_for_cpp_libfuzzer_entrypoint(tmp_path: Path) -> None:
    builder = _load_module("hgb_fuzzbench_builder_gamma_cpp_linkage", "docker/common/hgb_fuzzbench_builder.py")
    cand = tmp_path / "candidate.cc"
    cand.write_text(
        '#include <stdint.h>\n#include <stddef.h>\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return 0; }\n',
        encoding="utf-8",
    )

    staged = builder._normalize_candidate_for_native_path(cand, "/src/project/fuzz_target.cc", tmp_path / "work")
    text = staged.read_text(encoding="utf-8")

    assert staged.suffix == ".cc"
    assert 'extern "C" int LLVMFuzzerTestOneInput' in text


def test_builder_restricts_curl_fuzzer_target_list(tmp_path: Path) -> None:
    builder = _load_module("hgb_fuzzbench_builder_gamma_curl", "docker/common/hgb_fuzzbench_builder.py")
    curl_root = tmp_path / "source_input" / "curl_fuzzer"
    scripts = curl_root / "scripts"
    scripts.mkdir(parents=True)
    fuzz_targets = scripts / "fuzz_targets"
    fuzz_targets.write_text('export FUZZ_TARGETS="curl_fuzzer_http curl_fuzzer_ws"\n', encoding="utf-8")
    (scripts / "compile_fuzzer.sh").write_text("#!/bin/bash\nmake || exit 4\nmake check || exit 5\n", encoding="utf-8")
    (curl_root / "ossfuzz.sh").write_text(
        "${SCRIPTDIR}/handle_x.sh zlib ${ZLIBDIR} ${INSTALLDIR} || exit 1\n"
        "# For the memory sanitizer build, turn off OpenSSL as it causes bugs we can't\n"
        "if [[ ${SANITIZER} != \"memory\" ]]\nthen\n"
        "    ${SCRIPTDIR}/handle_x.sh openssl ${OPENSSLDIR} ${INSTALLDIR} || exit 1\n"
        "fi\n"
        "${SCRIPTDIR}/handle_x.sh nghttp2 ${NGHTTPDIR} ${INSTALLDIR} || exit 1\n"
        "make zip\n",
        encoding="utf-8",
    )
    (curl_root / "Makefile.am").write_text(
        "COMMON_SOURCES = curl_fuzzer.cc curl_fuzzer_tlv.cc curl_fuzzer_callback.cc\n"
        "curl_fuzzer_http_SOURCES = $(COMMON_SOURCES)\n"
        "curl_fuzzer_ws_SOURCES = $(COMMON_SOURCES)\n",
        encoding="utf-8",
    )

    builder._patch_single_target_build_context(tmp_path, "curl_fuzzer_http")

    assert fuzz_targets.read_text(encoding="utf-8") == 'export FUZZ_TARGETS="curl_fuzzer_http"\n'
    compile_text = (scripts / "compile_fuzzer.sh").read_text(encoding="utf-8")
    assert "make ${FUZZ_TARGETS} || exit 4" in compile_text
    assert "skip broad curl make check" in compile_text
    ossfuzz_text = (curl_root / "ossfuzz.sh").read_text(encoding="utf-8")
    assert "downloaded zlib" in ossfuzz_text
    assert "avoid downloading OpenSSL" in ossfuzz_text
    assert "downloaded nghttp2" in ossfuzz_text
    assert "make ${TARGET}_seed_corpus.zip" in ossfuzz_text
    makefile_text = (curl_root / "Makefile.am").read_text(encoding="utf-8")
    assert "curl_fuzzer_http_SOURCES = curl_fuzzer.cc" in makefile_text
    assert "curl_fuzzer_ws_SOURCES = $(COMMON_SOURCES)" in makefile_text


# ---------------------------------------------------------------------------
# 3. Old verifier bypass test
# ---------------------------------------------------------------------------


def test_entrypoint_skips_old_verifier_for_method_faithful() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    # The old verifier call must only appear in the compat-smoke branch.
    assert "ckgfuzzer_candidate_verifier.py" in entrypoint
    # The method-faithful branch must route directly to the evaluator.
    cond = '"$ckg_method_faithful" == "1" ]]'
    assert cond in entrypoint
    cond_pos = entrypoint.index(cond)
    verifier_pos = entrypoint.index("ckgfuzzer_candidate_verifier.py")
    evaluator_pos = entrypoint.index("hgb_harness_evaluator.py")
    # The evaluator must appear before the old verifier (method-faithful
    # branch routes directly to the evaluator; the old verifier is only in
    # the compat-smoke else branch).
    assert evaluator_pos < verifier_pos
    # Between the method-faithful condition and the first evaluator call,
    # the old verifier must not appear.
    block = entrypoint[cond_pos:evaluator_pos]
    assert "ckgfuzzer_candidate_verifier.py" not in block


def test_entrypoint_filters_candidates_without_entry_point() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert "LLVMFuzzerTestOneInput" in entrypoint
    assert "generated_harnesses_filtered" in entrypoint


# ---------------------------------------------------------------------------
# 4. No fake reachability test
# ---------------------------------------------------------------------------


def test_reachability_fails_without_real_trace_evidence() -> None:
    intended = ["hgb_sample_api", "other_api"]
    # An empty trace must NOT mark reachability reached.
    reach = hgb_reachability.check_reachability(intended, {"executed_functions": []})
    assert reach["reached"] is False
    # A trace with unrelated functions must NOT mark reachability reached.
    reach2 = hgb_reachability.check_reachability(intended, {"executed_functions": ["unrelated"]})
    assert reach2["reached"] is False


def test_evaluator_does_not_synthesize_intended_apis_as_executed() -> None:
    source = (REPO_ROOT / "docker/common/hgb_harness_evaluator.py").read_text(encoding="utf-8")
    # The old fake pattern must be gone.
    assert 'reach_trace = {"executed_functions": intended_apis}' not in source
    # The real pattern uses coverage function data.
    assert "covered_functions" in source
    assert "not_requested" in source


def test_evaluator_not_requested_when_no_intended_apis(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = FakeRunner()
    result = evaluator.evaluate(
        generator="ckgfuzzer",
        target_root=gen_root,
        evaluator_root=evl_root,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="project",
        fuzz_target="fuzz_target",
        profile="reproduction-gamma",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        intended_apis=[],
        seeds=[],
    )
    assert result["status"] == hgb_result.STATUS_EVALUATED
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["api_reachability"]["status"] == "not_requested"
    assert cand_json["api_reachability"]["reason"] == "no_intended_api_list"


def test_evaluator_reachability_fails_when_coverage_lacks_intended_api(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    # Coverage JSON with functions that do NOT include the intended API.
    bad_cov = json.dumps({
        "data": [{"totals": {"lines": {"count": 100, "covered": 27},
                              "functions": {"count": 10, "covered": 5},
                              "regions": {"count": 50, "covered": 12}},
                  "functions": [{"name": "unrelated_func", "count": 5}]}],
        "type": "llvm.coverage.json.export", "version": "2.0.1",
    })
    runner = FakeRunner(coverage_stdout=bad_cov)
    result = evaluator.evaluate(
        generator="ckgfuzzer",
        target_root=gen_root,
        evaluator_root=evl_root,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="project",
        fuzz_target="fuzz_target",
        profile="reproduction-gamma",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        intended_apis=["hgb_sample_api"],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["api_reachability"] == "failed"
    assert result["status"] != hgb_result.STATUS_EVALUATED


# ---------------------------------------------------------------------------
# 5. Smoke mount test
# ---------------------------------------------------------------------------


def test_smoke_runner_copies_input_into_container(tmp_path: Path) -> None:
    work_dir = tmp_path / "smoke"
    seed = tmp_path / "seed.bin"
    seed.write_bytes(b"\x01\x02\x03")
    runner = FakeRunner()
    hgb_fuzzbench_builder.run_smoke(
        image_tag="hgb-test",
        binary_path="/out/fuzz_target",
        seeds=[seed],
        work_dir=work_dir,
        runner=runner,
    )
    # At least one docker cp copy_in command must have been issued.
    cp_commands = [c for c in runner.commands if c[:2] == ["docker", "cp"]]
    assert cp_commands, "smoke runner must copy input into container"
    # The copy_in source must be the host seed file.
    assert any(str(seed) in " ".join(c) for c in cp_commands)


def test_smoke_runner_fails_if_no_sample_executed(tmp_path: Path) -> None:
    source = (REPO_ROOT / "docker/common/hgb_fuzzbench_builder.py").read_text(encoding="utf-8")
    assert "any_executed" in source
    assert "copy_in" in source


def test_campaign_runner_adds_bounded_runs_to_time_budget(tmp_path: Path) -> None:
    runner = FakeRunner()
    result = hgb_fuzzbench_builder.run_campaign(
        image_tag="hgb-test",
        binary_path="/out/fuzz_target",
        corpus_dir=tmp_path / "seed_corpus",
        work_dir=tmp_path / "campaign",
        campaign_seconds=2,
        runner=runner,
    )

    create_commands = [" ".join(c) for c in runner.commands if c[:2] == ["docker", "create"]]
    assert any("timeout -s INT -k 5s 7s" in c for c in create_commands)
    assert any("-runs=512" in c and "-max_total_time=2" in c for c in create_commands)
    assert any("HGB_FUZZER_EXIT_CODE=$fuzzer_rc" in c for c in create_commands)
    assert result["execs_done"] == 500
    assert result["timeouts"] == 0


# ---------------------------------------------------------------------------
# 6. Coverage real-file test
# ---------------------------------------------------------------------------


def test_coverage_parser_extracts_covered_functions() -> None:
    text = json.dumps({
        "data": [{"totals": {"lines": {"count": 10, "covered": 5},
                              "functions": {"count": 4, "covered": 2},
                              "regions": {"count": 8, "covered": 3}},
                  "functions": [{"name": "foo", "count": 3}, {"name": "bar", "count": 0}]}],
        "type": "llvm.coverage.json.export", "version": "2.0.1",
    })
    summary = hgb_coverage.parse_llvm_coverage_json(text)
    assert summary["line_coverage"]["covered"] == 5
    assert "foo" in summary["covered_functions"]
    assert "bar" not in summary["covered_functions"]
    assert summary["region_coverage"]["covered"] == 3


def test_coverage_stage_fails_on_empty_report(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = FakeRunner(coverage_stdout="")
    result = evaluator.evaluate(
        generator="ckgfuzzer",
        target_root=gen_root,
        evaluator_root=evl_root,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="project",
        fuzz_target="fuzz_target",
        profile="reproduction-gamma",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        intended_apis=[],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["coverage"] == "failed"
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_coverage_export_includes_function_detail() -> None:
    source = (REPO_ROOT / "docker/common/hgb_fuzzbench_builder.py").read_text(encoding="utf-8")
    # The old summary-only command must be gone from the actual llvm-cov call.
    assert "llvm-cov export -format=text -summary-only" not in source
    # The new full export (without -summary-only) must be present.
    assert "llvm-cov export -format=text {binary_path}" in source


# ---------------------------------------------------------------------------
# 7. Reference canary test
# ---------------------------------------------------------------------------


def test_candidate_audit_detects_canary_leak(tmp_path: Path) -> None:
    ref_dir = tmp_path / "refs"
    ref_dir.mkdir()
    (ref_dir / "native.c").write_text("// HGB_REF_CANARY_xyz secret reference\nint LLVMFuzzerTestOneInput(){}\n", encoding="utf-8")
    candidate = tmp_path / "cand.c"
    candidate.write_text("// HGB_REF_CANARY_xyz leaked\nint LLVMFuzzerTestOneInput(){}\n", encoding="utf-8")
    result = hgb_split_context.audit_candidate_reference_copy(candidate, ref_dir, canary="HGB_REF_CANARY_xyz")
    assert result["contains_reference_canary"] is True


def test_candidate_audit_detects_near_duplicate(tmp_path: Path) -> None:
    ref_dir = tmp_path / "refs"
    ref_dir.mkdir()
    ref_text = "int LLVMFuzzerTestOneInput(const unsigned char *data, long size){ return 0; }\n"
    (ref_dir / "native.c").write_text(ref_text, encoding="utf-8")
    candidate = tmp_path / "cand.c"
    candidate.write_text(ref_text, encoding="utf-8")
    result = hgb_split_context.audit_candidate_reference_copy(candidate, ref_dir)
    assert result["near_duplicate_reference"] is True


def test_candidate_audit_passes_for_original_candidate(tmp_path: Path) -> None:
    ref_dir = tmp_path / "refs"
    ref_dir.mkdir()
    (ref_dir / "native.c").write_text("int LLVMFuzzerTestOneInput(){ return 0; }\n", encoding="utf-8")
    candidate = tmp_path / "cand.c"
    candidate.write_text(
        "// completely different driver\nint LLVMFuzzerTestOneInput(const unsigned char *d, long n){ parse(d); return 0; }\n",
        encoding="utf-8",
    )
    result = hgb_split_context.audit_candidate_reference_copy(candidate, ref_dir, canary="SECRET")
    assert result["contains_reference_canary"] is False
    assert result["near_duplicate_reference"] is False


# ---------------------------------------------------------------------------
# 8. Matrix status test
# ---------------------------------------------------------------------------


def test_build_only_result_never_evaluated() -> None:
    # A result with candidate_build completed but campaign/coverage pending
    # must not be "evaluated".
    stages = hgb_result.default_stages()
    stages["generation"] = "completed"
    stages["candidate_build"] = "completed"
    stages["sanitizer_smoke"] = "pending"
    stages["api_reachability"] = "pending"
    stages["campaign"] = "pending"
    stages["coverage"] = "pending"
    status = hgb_result.result_status_from_stages(stages)
    assert status != hgb_result.STATUS_EVALUATED


def test_matrix_extractor_includes_required_fields(tmp_path: Path) -> None:
    meta = {
        "generator": "ckgfuzzer",
        "target": "jsoncpp_jsoncpp_fuzzer",
        "status": "evaluated",
        "applicability": "applicable",
        "stages": {"candidate_build": "completed", "sanitizer_smoke": "completed",
                    "api_reachability": "completed", "campaign": "completed", "coverage": "completed"},
        "metrics": {
            "coverage": {"line_coverage": {"covered": 27}, "function_coverage": {"covered": 5},
                          "region_coverage": {"covered": 12}},
            "campaign": {"execs_done": 500, "crashes": 0, "timeouts": 0},
        },
        "api_trace_total_count": 42,
        "ckgfuzzer": {"codeql_graph_nodes": 10, "codeql_graph_edges": 20},
        "candidate": {"contains_reference_canary": False, "near_duplicate_reference": False},
        "excluded_from_aggregate": False,
    }
    row = collector.extract_ckgfuzzer_row(meta)
    for field in ("status", "applicability", "candidate_build", "sanitizer_smoke",
                   "api_reachability", "campaign", "coverage", "line_coverage",
                   "region_coverage", "function_coverage", "execs_done", "crashes",
                   "hangs", "llm_calls", "embedding_calls", "codeql_graph_nodes",
                   "codeql_graph_edges", "reference_canary_leak",
                   "near_duplicate_reference", "exclude_from_aggregate"):
        assert field in row, f"missing field {field}"
    assert row["line_coverage"] == 27
    assert row["codeql_graph_nodes"] == 10
    assert row["execs_done"] == 500


# ---------------------------------------------------------------------------
# Profile validation tests
# ---------------------------------------------------------------------------


def test_reproduction_gamma_is_method_faithful() -> None:
    assert profile.is_method_faithful("reproduction-gamma")
    violations = profile.validate_profile("reproduction-gamma", "blind-project", {
        "CKGFUZZER_LOCAL_API_SUMMARY": "1",
    })
    assert any("LOCAL_API_SUMMARY" in v for v in violations)


def test_reproduction_gamma_maps_to_paper_faithful_method_variant() -> None:
    result = hgb_result.build_result(
        profile="reproduction-gamma", protocol="blind-project", target="t",
        status="evaluated",
        stages={n: "completed" for n in hgb_result.STAGE_NAMES},
    )
    assert result["method_variant"] == "paper-faithful"
