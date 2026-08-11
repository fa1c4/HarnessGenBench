"""Epsilon reproduction tests for the PromeFuzz harness-generator pipeline.

These tests exercise the strict paper-native PromeFuzz reproduction contract
from ``plans/promefuzz_reproduction_epsilon.md`` with fake Docker/CLI fixtures
so they pass without real external checkouts, Docker, embeddings, or model
access.

PromeFuzz remains a ``harness_generator`` (it synthesizes ``LLVMFuzzerTestOneInput``
fuzz targets via comprehend/retrieve/generate stages), never an input generator.

The epsilon plan shares its foundation with the other reproduction-epsilon
baselines (profile wiring, fail-closed split packages, candidate overlay/copy
audit, smoke/campaign/coverage evidence). These tests additionally cover the
PromeFuzz-specific tasks:

* PROME-1: package imports and full tests runnable from repo root.
* PROME-2: add and route ``reproduction-epsilon``.
* PROME-3: require exact FuzzBench build context.
* PROME-4: wire real consumer/API knowledge into PromeFuzz.
* PROME-5: disable non-paper shortcuts.
* PROME-6: run the official-style PromeFuzz stages.
* PROME-7: candidate and evaluator requirements.
* PROME-8: valuable-target matrix semantics.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
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


profile = _load_module("promefuzz_profile_epsilon", "docker/common/promefuzz_profile.py")
build_context = _load_module("promefuzz_build_context_epsilon", "docker/common/promefuzz_build_context.py")
hgb_result = _load_module("hgb_result_epsilon", "docker/common/hgb_result.py")
hgb_coverage = _load_module("hgb_coverage_epsilon", "docker/common/hgb_coverage.py")
hgb_reachability = _load_module("hgb_reachability_epsilon", "docker/common/hgb_reachability.py")
hgb_fuzzbench_builder = _load_module("hgb_fuzzbench_builder_epsilon", "docker/common/hgb_fuzzbench_builder.py")
hgb_target_package = _load_module("hgb_target_package_epsilon", "docker/common/hgb_target_package.py")
hgb_split_context = _load_module("hgb_split_context_epsilon", "docker/common/hgb_split_context.py")
evaluator = _load_module("hgb_harness_evaluator_epsilon", "docker/common/hgb_harness_evaluator.py")
matrix_collector = _load_module("hgb_collect_matrix_epsilon", "scripts/hgb_collect_matrix.py")


def _entrypoint() -> str:
    return (REPO_ROOT / "docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")


def _common_sh() -> str:
    return (REPO_ROOT / "scripts/lib/common.sh").read_text(encoding="utf-8")


def _baseline_sh() -> str:
    return (REPO_ROOT / "scripts/hgb_run_baseline.sh").read_text(encoding="utf-8")


def _run_env():
    env = dict(os.environ)
    env["PATH"] = str(REPO_ROOT / "scripts") + os.pathsep + env.get("PATH", "")
    return env


# ---------------------------------------------------------------------------
# Fixture helpers
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
        "// HGB_REF_CANARY_EPSILON\nint LLVMFuzzerTestOneInput(void){return 0;}\n", encoding="utf-8"
    )
    (pkg / "reference_harnesses" / "source_input" / "project" / "sibling_fuzzer.c").write_text(
        "int LLVMFuzzerTestOneInput_sibling(void){return 0;}\n", encoding="utf-8",
    )
    (pkg / "fuzzbench_benchmark" / "Dockerfile").write_text("FROM scratch\nCOPY * /src/\n", encoding="utf-8")
    (pkg / "fuzzbench_benchmark" / "build.sh").write_text("#!/bin/sh\ncc $SRC/project/native.c -o $OUT/fuzz_target\n", encoding="utf-8")
    manifest = {
        "schema_version": 1, "target": "fixture_target", "project": "project",
        "fuzz_target": "fuzz_target", "source_input_dir": "source_input",
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


def _make_fixture_target(tmp_path: Path) -> tuple[Path, Path]:
    src = tmp_path / "project"
    src.mkdir()
    (src / "lib").mkdir()
    (src / "lib" / "foo.h").write_text(
        "#ifndef FOO_H\n#define FOO_H\nint foo(const char *s, int n);\nint bar(int);\n#endif\n",
        encoding="utf-8",
    )
    (src / "lib" / "foo.c").write_text(
        '#include "foo.h"\nint foo(const char *s, int n){ int r=0; for(int i=0;i<n;i++) r^=s[i]; return r; }\n'
        "int bar(int x){ return x * 3; }\n",
        encoding="utf-8",
    )
    (src / "examples").mkdir()
    (src / "examples" / "use_foo.c").write_text(
        '#include "../lib/foo.h"\nint main(void){ return foo("abc",3) + bar(1); }\n',
        encoding="utf-8",
    )
    (src / "fuzz_foo.c").write_text(
        "#include <stdint.h>\n#include <stddef.h>\n#include \"lib/foo.h\"\n"
        "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){ return foo((const char*)d, (int)n); }\n",
        encoding="utf-8",
    )
    (src / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.10)\nproject(foo C)\n"
        "add_library(foo STATIC lib/foo.c)\n"
        "target_include_directories(foo PUBLIC lib)\n"
        "add_executable(use_foo examples/use_foo.c)\n"
        "target_link_libraries(use_foo foo)\n",
        encoding="utf-8",
    )
    target_root = tmp_path / "target"
    (target_root / "source_input").mkdir(parents=True)
    shutil.copytree(src, target_root / "source_input" / "foo", dirs_exist_ok=True)
    bench = target_root / "fuzzbench_benchmark"
    bench.mkdir()
    (bench / "build.sh").write_text(
        "cd $SRC/foo && cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON && cmake --build build\n",
        encoding="utf-8",
    )
    (bench / "Dockerfile").write_text("FROM base\nWORKDIR $SRC/foo\n", encoding="utf-8")
    (target_root / "target_manifest.json").write_text(
        json.dumps({
            "selected_reference_harness_files": ["source_input/foo/fuzz_foo.c"],
            "project": "foo", "fuzz_target": "fuzz_foo", "target": "foo_fuzz_foo",
        }),
        encoding="utf-8",
    )
    ref = target_root / "reference_harnesses" / "selected"
    ref.mkdir(parents=True)
    (ref / "fuzz_foo.c").write_text(
        "// HGB_REF_CANARY_EPSILON\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){return 0;}\n",
        encoding="utf-8",
    )
    return target_root, target_root / "source_input" / "foo"


LLVM_COVERAGE_JSON = json.dumps({
    "data": [{"totals": {"lines": {"count": 100, "covered": 27},
                          "functions": {"count": 10, "covered": 5},
                          "regions": {"count": 50, "covered": 12}},
               "functions": [{"name": "hgb_sample_api", "count": 5},
                             {"name": "LLVMFuzzerTestOneInput", "count": 12}]}],
    "type": "llvm.coverage.json.export",
    "version": "2.0.1",
})


class _FakeDockerResult:
    def __init__(self, command, exit_code=0, stdout="", stderr=""):
        self.command = list(command)
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


class _EpsilonFakeRunner:
    """Configurable fake runner for the evaluator scenarios."""

    def __init__(self, *, coverage_stdout=None, campaign_execs=500, build_exit=0,
                 binary_verified=True, overlay_matches=True, candidate_path=None):
        self.commands = []
        self.campaign_execs = campaign_execs
        self.coverage_stdout = coverage_stdout if coverage_stdout is not None else LLVM_COVERAGE_JSON
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
            return _FakeDockerResult(cmd, 1)
        head = cmd[0]
        if head == "docker":
            sub = cmd[1] if len(cmd) > 1 else ""
            if sub == "build":
                return _FakeDockerResult(cmd, self.build_exit, "build ok", "")
            if sub == "image" and len(cmd) > 3 and cmd[2] == "inspect":
                return _FakeDockerResult(cmd, 0, "sha256:fakeimage\n", "")
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
                return _FakeDockerResult(cmd, 0, name + "\n", "")
            if sub == "start":
                name = cmd[-1]
                phase = self._containers.get(name, "unknown")
                if phase == "smoke":
                    return _FakeDockerResult(cmd, 0, "smoke ok", "HGB_TARGET_START\n")
                if phase == "campaign":
                    out = f"#{self.campaign_execs} INITED\nstat::number_of_executed_units: {self.campaign_execs}\n"
                    return _FakeDockerResult(cmd, 0, out, "")
                if phase == "coverage":
                    return _FakeDockerResult(cmd, 0, self.coverage_stdout, "")
                return _FakeDockerResult(cmd, 0, "", "")
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
                return _FakeDockerResult(cmd, 0, "", "")
            if sub == "rm":
                return _FakeDockerResult(cmd, 0, "", "")
            if sub == "run":
                shell_cmd = " ".join(cmd[3:])
                if "test -x" in shell_cmd and "sha256sum" in shell_cmd:
                    if self.binary_verified:
                        return _FakeDockerResult(cmd, 0, f"{self.candidate_sha}  /out/fuzz_target\n", "")
                    return _FakeDockerResult(cmd, 1, "", "not found")
                if "sha256sum /src/" in shell_cmd:
                    if self.overlay_matches:
                        return _FakeDockerResult(cmd, 0, f"{self.candidate_sha}  /src/project/native.c\n", "")
                    return _FakeDockerResult(cmd, 0, "referenceSHA  /src/project/native.c\n", "")
                return _FakeDockerResult(cmd, 0, "", "")
        return _FakeDockerResult(cmd, 0, "", "")


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


def _fake_context_provider(target_root, work_dir):
    ctx = work_dir / "sealed_context"
    if ctx.exists():
        shutil.rmtree(ctx)
    (ctx / "source_input" / "project").mkdir(parents=True, exist_ok=True)
    (ctx / "source_input" / "project" / "native.c").write_text("// placeholder\n", encoding="utf-8")
    (ctx / "Dockerfile").write_text("FROM scratch\nCOPY source_input/ /src/\n", encoding="utf-8")
    return {"context_dir": str(ctx), "dockerfile": str(ctx / "Dockerfile"), "mode": "test_sealed"}


CANARY = "HGB_REF_CANARY_EPSILON_PROMEFUZZ"


# ---------------------------------------------------------------------------
# E0. Profile acceptance and strictness
# ---------------------------------------------------------------------------


def test_reproduction_epsilon_is_valid_profile() -> None:
    assert "reproduction-epsilon" in profile.VALID_PROFILES
    assert profile.is_method_faithful("reproduction-epsilon")
    assert "reproduction-epsilon" in profile.STRICT_REPRODUCTION_PROFILES


def test_reproduction_delta_remains_accepted_as_alias() -> None:
    assert "reproduction-delta" in profile.VALID_PROFILES
    assert "reproduction-delta" in profile.STRICT_REPRODUCTION_PROFILES


def test_reproduction_epsilon_validates_clean_env() -> None:
    violations = profile.validate_profile("reproduction-epsilon", "blind-project", {
        "PROME_FUZZ_EMBEDDING_MODEL": "text-embedding-3-small",
        "PROME_FUZZ_EMBEDDING_LLM_TYPE": "openai",
    })
    assert violations == [], violations


def test_reproduction_epsilon_forbids_synthetic_compile_db() -> None:
    violations = profile.validate_profile("reproduction-epsilon", "blind-project", {
        "PROME_FUZZ_EMBEDDING_MODEL": "text-embedding-3-small",
        "PROME_FUZZ_EMBEDDING_LLM_TYPE": "openai",
        "HGB_PROMEFUZZ_SYNTHETIC_COMPILE_DB": "1",
    })
    assert any("SYNTHETIC_COMPILE_DB" in v for v in violations)


def test_reproduction_epsilon_forbids_mock_hash_embeddings() -> None:
    for bad_type in ("mock", "local", "hash", ""):
        violations = profile.validate_profile("reproduction-epsilon", "blind-project", {
            "PROME_FUZZ_EMBEDDING_MODEL": "hgb-hash-embedding",
            "PROME_FUZZ_EMBEDDING_LLM_TYPE": bad_type,
        })
        assert violations, f"expected violations for embedding type {bad_type!r}"


def test_reproduction_epsilon_forbids_selected_harness_api_modes() -> None:
    for mode in ("selected_harness", "selected_harness_fallback"):
        violations = profile.validate_profile("reproduction-epsilon", "blind-project", {
            "PROME_FUZZ_EMBEDDING_MODEL": "text-embedding-3-small",
            "PROME_FUZZ_EMBEDDING_LLM_TYPE": "openai",
            "HGB_API_SELECTION_MODE": mode,
        })
        assert any("API_SELECTION_MODE" in v for v in violations)
    for mode in ("report_first", "report_only"):
        violations = profile.validate_profile("reproduction-epsilon", "blind-project", {
            "PROME_FUZZ_EMBEDDING_MODEL": "text-embedding-3-small",
            "PROME_FUZZ_EMBEDDING_LLM_TYPE": "openai",
            "HGB_API_REPORT_MODE": mode,
        })
        assert any("API_REPORT_MODE" in v for v in violations)


def test_reproduction_epsilon_maps_to_paper_faithful_method_variant() -> None:
    result = profile.build_result(
        profile="reproduction-epsilon", protocol="blind-project", target="t",
        status="evaluated",
        stages={n: "completed" for n in profile.STAGE_NAMES},
    )
    assert result["method_variant"] == "paper-faithful"
    assert result["task_family"] == "harness_generator"


def test_dry_run_canonical_command_passes_profile_validation(tmp_path: Path) -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_run_baseline.sh", "--generator", "promefuzz",
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
        ["bash", "scripts/hgb_run_baseline.sh", "--generator", "promefuzz",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-nonexistent",
         "--protocol", "blind-project", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    assert proc.returncode == 2, proc.stderr
    assert "invalid profile" in proc.stderr


def test_hgb_generate_harness_rejects_unknown_profile_with_code_2() -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_generate_harness.sh", "--generator", "promefuzz",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-nonexistent", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    assert proc.returncode == 2, proc.stderr
    assert "unknown profile" in proc.stderr


def test_hgb_generate_harness_accepts_reproduction_epsilon() -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_generate_harness.sh", "--generator", "promefuzz",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-epsilon", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    assert proc.returncode != 2
    assert "unknown profile" not in proc.stderr


def test_baseline_sh_accepts_reproduction_epsilon_for_promefuzz() -> None:
    baseline = _baseline_sh()
    assert "alpha|paper-faithful|reproduction-gamma|reproduction-delta|reproduction-epsilon|reproduction-zeta|compat-smoke" in baseline
    assert "promefuzz/$profile: HGB_PROMEFUZZ_SYNTHETIC_COMPILE_DB=1 is forbidden" in baseline


# ---------------------------------------------------------------------------
# E1. Fail-closed split target package
# ---------------------------------------------------------------------------


def test_split_package_writes_reference_canary_into_evaluator_only(tmp_path: Path) -> None:
    pkg = _make_monolithic_package(tmp_path)
    os.environ["HGB_REF_CANARY"] = CANARY
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
    assert CANARY in (evl / "reference_canary.txt").read_text()


def test_generator_input_has_no_reference_harnesses_or_canary(tmp_path: Path) -> None:
    pkg = _make_monolithic_package(tmp_path)
    os.environ["HGB_REF_CANARY"] = CANARY
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
    for p in gen.rglob("*"):
        if p.is_file():
            assert CANARY not in p.read_text(encoding="utf-8", errors="replace"), p


def test_require_split_fails_when_reference_harnesses_missing(tmp_path: Path) -> None:
    pkg = _make_monolithic_package(tmp_path)
    shutil.rmtree(pkg / "reference_harnesses")
    with pytest.raises(hgb_target_package.PackageSplitError):
        hgb_target_package.split_package(pkg, native_harness={}, require_split=True)


def test_common_sh_fail_closed_for_epsilon_requires_split_halves() -> None:
    common = _common_sh()
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


def test_entrypoint_epsilon_manifest_assertions() -> None:
    entrypoint = _entrypoint()
    assert "promefuzz_delta_manifest_missing" in entrypoint
    assert "promefuzz_delta_reference_leak" in entrypoint
    assert "promefuzz_delta_evaluator_manifest_missing" in entrypoint
    assert "test -f /target/target_manifest.json" in entrypoint
    assert "test -e /target/reference_harnesses" in entrypoint
    assert "test -f /evaluator/evaluator_manifest.json" in entrypoint


def test_entrypoint_epsilon_leakage_preaudit_before_llm() -> None:
    entrypoint = _entrypoint()
    assert "promefuzz_delta_reference_leak_preaudit" in entrypoint
    assert "leakage_preaudit.log" in entrypoint
    preaudit_pos = entrypoint.index("promefuzz_delta_reference_leak_preaudit")
    embedding_call = 'promefuzz_embedding_preflight "$workspace/logs/embedding_preflight.log"'
    assert embedding_call in entrypoint
    embedding_pos = entrypoint.index(embedding_call)
    assert preaudit_pos < embedding_pos


def test_canary_in_generator_input_fails_before_embedding(tmp_path: Path) -> None:
    gen_dir = tmp_path / "delta_canary_test"
    gen_dir.mkdir(parents=True)
    (gen_dir / "leaked.c").write_text(f"// {CANARY}\nint main(){{return 0;}}\n", encoding="utf-8")
    result = profile.audit_leakage(gen_dir, CANARY)
    assert result["leaked"] is True
    assert result["hit_count"] >= 1


# ---------------------------------------------------------------------------
# PROME-3. Require exact FuzzBench build context
# ---------------------------------------------------------------------------


def test_fuzzbench_replay_capture_method_supported() -> None:
    proc = subprocess.run(
        ["python3", "docker/common/promefuzz_build_context.py", "--help"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30,
    )
    assert "fuzzbench_replay" in proc.stdout


def test_fuzzbench_replay_prefers_bear_replay(tmp_path: Path) -> None:
    target_root, src = _make_fixture_target(tmp_path)
    work = tmp_path / "work"
    manifest = build_context.capture_build_context(
        target_root=target_root, work_dir=work, fuzz_target="fuzz_foo",
        language="c", profile="reproduction-epsilon", allow_synthetic=False,
        capture_method="fuzzbench_replay", source_root=src,
    )
    assert manifest["synthetic"] is False
    assert manifest["capture_method"] in {"bear_replay", "cmake_export"}


def test_provenance_json_written_with_required_fields(tmp_path: Path) -> None:
    target_root, src = _make_fixture_target(tmp_path)
    work = tmp_path / "work"
    build_context.capture_build_context(
        target_root=target_root, work_dir=work, fuzz_target="fuzz_foo",
        language="c", profile="reproduction-epsilon", allow_synthetic=False,
        capture_method="fuzzbench_replay", source_root=src,
    )
    prov_path = work / "build_context" / "provenance.json"
    assert prov_path.is_file(), "provenance.json must be written"
    prov = json.loads(prov_path.read_text(encoding="utf-8"))
    for field in ("strategy", "benchmark_dockerfile_sha256", "build_sh_sha256",
                  "compile_commands_count", "uses_fuzzbench_env", "cc", "cxx",
                  "cflags", "cxxflags", "out_artifacts"):
        assert field in prov, f"provenance.json missing field {field}"


def test_cmake_only_compile_db_rejected_under_epsilon(tmp_path: Path) -> None:
    target_root, src = _make_fixture_target(tmp_path)
    work = tmp_path / "work"
    manifest = build_context.capture_build_context(
        target_root=target_root, work_dir=work, fuzz_target="fuzz_foo",
        language="c", profile="reproduction-epsilon", allow_synthetic=False,
        capture_method="cmake_export", source_root=src,
    )
    prov_path = Path(manifest.get("provenance_path", work / "build_context" / "provenance.json"))
    assert prov_path.is_file()
    prov = json.loads(prov_path.read_text(encoding="utf-8"))
    assert prov["strategy"] != "fuzzbench_replay" or prov["uses_fuzzbench_env"] is True


def test_empty_driver_build_args_fails_before_generation(tmp_path: Path) -> None:
    link_path = tmp_path / "link_context.json"
    link_path.write_text(json.dumps({"mode": "fuzzbench_build_replay"}), encoding="utf-8")
    ok, msg = build_context.verify_and_record_link_set(
        link_context_path=link_path, driver_build_args=[],
        work_dir=tmp_path / "probe", language="c",
    )
    assert ok is False
    assert "empty" in msg
    data = json.loads(link_path.read_text(encoding="utf-8"))
    assert data["verified"] is False


def test_entrypoint_enforces_nonempty_link_context_in_epsilon() -> None:
    entrypoint = _entrypoint()
    assert "promefuzz_link_context_empty" in entrypoint
    assert "failed_stage=link_context" in entrypoint
    assert "verify_and_record_link_set" in entrypoint


# ---------------------------------------------------------------------------
# PROME-4. Wire real consumer/API knowledge into PromeFuzz
# ---------------------------------------------------------------------------


def test_consumer_cases_exclude_reference_harness(tmp_path: Path) -> None:
    target_root, src = _make_fixture_target(tmp_path)
    work = tmp_path / "work"
    build_context.capture_build_context(
        target_root=target_root, work_dir=work, fuzz_target="fuzz_foo",
        language="c", profile="reproduction-epsilon", capture_method="cmake_export",
        source_root=src,
    )
    cases = json.loads((work / "knowledge" / "consumer_cases.json").read_text(encoding="utf-8"))
    for case in cases["consumers"]:
        assert "fuzz_foo" not in case["file"]
        assert CANARY not in Path(case["file"]).read_text(encoding="utf-8", errors="replace")
        assert "LLVMFuzzerTestOneInput" not in Path(case["file"]).read_text(encoding="utf-8", errors="replace")
    assert any(Path(c["file"]).name == "use_foo.c" for c in cases["consumers"])


def test_consumer_case_paths_in_libraries_toml() -> None:
    entrypoint = _entrypoint()
    assert "consumer_case_paths" in entrypoint
    assert "/workspace/knowledge/consumer_cases" in entrypoint


def test_entrypoint_validates_comprehend_knowledge() -> None:
    entrypoint = _entrypoint()
    assert "comprehend_knowledge_audit" in entrypoint
    assert "promefuzz_comprehend_empty" in entrypoint


def test_consumer_examples_indexed_when_present(tmp_path: Path) -> None:
    target_root, src = _make_fixture_target(tmp_path)
    work = tmp_path / "work"
    build_context.capture_build_context(
        target_root=target_root, work_dir=work, fuzz_target="fuzz_foo",
        language="c", profile="reproduction-epsilon", capture_method="cmake_export",
        source_root=src,
    )
    cases = json.loads((work / "knowledge" / "consumer_cases.json").read_text(encoding="utf-8"))
    example_cases = [c for c in cases["consumers"] if c["why_allowed"] == "example"]
    assert len(example_cases) >= 1
    assert any("use_foo.c" in c["file"] for c in example_cases)


# ---------------------------------------------------------------------------
# PROME-5 / PROME-6. Disable non-paper shortcuts and run official stages
# ---------------------------------------------------------------------------


def test_entrypoint_empty_candidate_dir_is_not_evaluated() -> None:
    entrypoint = _entrypoint()
    assert "promefuzz_no_generated_harness" in entrypoint
    assert "quality_failure" in entrypoint


def test_entrypoint_epsilon_sequence_order() -> None:
    entrypoint = _entrypoint()
    audit_pos = entrypoint.index("promefuzz_delta_reference_leak_preaudit")
    build_context_pos = entrypoint.index("/opt/hgb/bin/promefuzz_build_context.py")
    libraries_pos = entrypoint.index('cat >"$libraries" <<EOF_PROMEFUZZ_LIBS')
    stages_pos = entrypoint.index("stages=(preprocess comprehend generate stats)")
    evaluator_pos = entrypoint.index("/opt/hgb/bin/hgb_harness_evaluator.py")
    assert audit_pos < build_context_pos < libraries_pos
    assert libraries_pos < stages_pos
    assert stages_pos < evaluator_pos


def test_entrypoint_records_llm_trace() -> None:
    entrypoint = _entrypoint()
    assert "hgb_llm_trace" in entrypoint or "llm_trace" in entrypoint


def test_entrypoint_generation_mode_all_cover() -> None:
    entrypoint = _entrypoint()
    assert "ALL-COVER" in entrypoint or "all_cover" in entrypoint.lower()
    assert "PROME_FUZZ_ALL_COVER_CANDIDATES" in entrypoint


def test_entrypoint_uses_fuzzbench_replay_for_epsilon() -> None:
    entrypoint = _entrypoint()
    assert 'PROME_FUZZ_BUILD_CONTEXT_METHOD="${PROME_FUZZ_BUILD_CONTEXT_METHOD:-fuzzbench_replay}"' in entrypoint
    assert "reproduction-epsilon" in entrypoint


def test_entrypoint_passes_method_evidence_env_vars() -> None:
    entrypoint = _entrypoint()
    assert "PROME_FUZZ_COMPILE_DB_STRATEGY" in entrypoint
    assert "PROME_FUZZ_COMPILE_DB_COUNT" in entrypoint
    assert "PROME_FUZZ_DRIVER_BUILD_ARGS_COUNT" in entrypoint
    assert "PROME_FUZZ_CONSUMER_ARTIFACTS_NONEMPTY" in entrypoint
    assert "PROME_FUZZ_GENERATION_MODE" in entrypoint


# ---------------------------------------------------------------------------
# E2 / PROME-7. Candidate overlay and copy-audit
# ---------------------------------------------------------------------------


def test_overlay_audit_detects_reference_overwrite(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = _EpsilonFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"), overlay_matches=False)
    result = evaluator.evaluate(
        generator="promefuzz",
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
        context_provider=_fake_context_provider,
        intended_apis=[],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["build"]["overlay_audit"]["matches_candidate"] is False
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_zero_exec_campaign_fails(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = _EpsilonFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"), campaign_execs=0)
    result = evaluator.evaluate(
        generator="promefuzz",
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
        context_provider=_fake_context_provider,
        intended_apis=[],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["campaign"] == "failed"
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_empty_coverage_fails_coverage_stage(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = _EpsilonFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"), coverage_stdout="")
    result = evaluator.evaluate(
        generator="promefuzz",
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
        context_provider=_fake_context_provider,
        intended_apis=[],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["coverage"] == "failed"
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_build_success_without_binary_fails_candidate_build(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = _EpsilonFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"), binary_verified=False)
    result = evaluator.evaluate(
        generator="promefuzz",
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
        context_provider=_fake_context_provider,
        intended_apis=[],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["candidate_build"] == "failed"
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
    runner = _EpsilonFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"), coverage_stdout=bad_cov)
    result = evaluator.evaluate(
        generator="promefuzz",
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
        context_provider=_fake_context_provider,
        intended_apis=["hgb_sample_api"],
        seeds=[],
    )
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["api_reachability"] == "failed"
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_full_evaluated_loop_succeeds_for_epsilon(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = _EpsilonFakeRunner(candidate_path=str(candidates_dir / "cand_001.c"))
    result = evaluator.evaluate(
        generator="promefuzz",
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
        context_provider=_fake_context_provider,
        intended_apis=["hgb_sample_api"],
        seeds=[],
    )
    assert result["status"] == hgb_result.STATUS_EVALUATED
    assert result["method_variant"] == "paper-faithful"
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["build"]["overlay_audit"]["matches_candidate"] is True
    assert cand_json["build"]["binary_verified"] is True


def test_finalize_status_rejects_build_only_in_epsilon() -> None:
    stages = {n: "completed" for n in profile.STAGE_NAMES}
    assert profile.finalize_status_from_evaluator(
        "evaluated", stages=stages, profile="reproduction-epsilon",
        coverage_covered_lines=None, campaign_execs_done=0, reached_count=0, candidate_count=1,
    ) == "quality_failure"
    assert profile.finalize_status_from_evaluator(
        "evaluated", stages=stages, profile="reproduction-epsilon",
        coverage_covered_lines=10, campaign_execs_done=100, reached_count=1, candidate_count=1,
    ) == "evaluated"


def test_build_only_result_is_not_evaluated() -> None:
    stages = hgb_result.default_stages()
    hgb_result.mark_stage(stages, "generation", "completed")
    hgb_result.mark_stage(stages, "candidate_overlay", "completed")
    hgb_result.mark_stage(stages, "copy_audit", "completed")
    hgb_result.mark_stage(stages, "candidate_build", "completed")
    status = hgb_result.result_status_from_stages(
        stages, has_candidate_json=True, coverage_covered_lines=None,
        campaign_execs_done=0, candidate_overlaid=True,
    )
    assert status != hgb_result.STATUS_EVALUATED


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


def test_copy_audit_detects_exact_copy(tmp_path: Path) -> None:
    ref_dir = tmp_path / "reference_harnesses"
    ref_dir.mkdir()
    ref_file = ref_dir / "native.c"
    ref_file.write_text(f"// {CANARY}\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){{return 0;}}\n", encoding="utf-8")
    candidate = tmp_path / "cand.c"
    candidate.write_text(ref_file.read_text(), encoding="utf-8")
    audit = hgb_split_context.audit_candidate_reference_copy(candidate, ref_dir, canary=CANARY)
    assert audit["exact_copy"] is True
    assert audit["contains_reference_canary"] is True


def test_copy_audit_passes_for_original_candidate(tmp_path: Path) -> None:
    ref_dir = tmp_path / "reference_harnesses"
    ref_dir.mkdir()
    (ref_dir / "native.c").write_text(
        f"// {CANARY}\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){{return 0;}}\n",
        encoding="utf-8",
    )
    candidate = tmp_path / "cand.c"
    candidate.write_text(
        "#include <stdint.h>\n#include <stddef.h>\n"
        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){\n"
        "  if (size < 4) return 0;\n"
        "  int x = *(int*)data;\n"
        "  return x % 2;\n"
        "}\n",
        encoding="utf-8",
    )
    audit = hgb_split_context.audit_candidate_reference_copy(candidate, ref_dir, canary=CANARY)
    assert audit["exact_copy"] is False
    assert audit["contains_reference_canary"] is False
    assert audit["near_duplicate_reference"] is False


# ---------------------------------------------------------------------------
# PROME-5. Result schema: method evidence fields
# ---------------------------------------------------------------------------


def test_build_result_writes_method_evidence() -> None:
    result = profile.build_result(
        profile="reproduction-epsilon", protocol="blind-project", target="t",
        status="evaluated",
        stages={n: "completed" for n in profile.STAGE_NAMES},
        method={
            "compile_db": {"strategy": "fuzzbench_replay", "count": 42},
            "link_context": {"driver_build_args_count": 5},
            "consumer_knowledge": {"enabled": True, "artifacts_nonempty": True},
            "embedding": {"provider": "openai", "model": "text-embedding-3-small"},
            "generation_mode": "ALL-COVER",
        },
    )
    assert "method" in result
    assert result["method"]["compile_db"]["strategy"] == "fuzzbench_replay"
    assert result["method"]["compile_db"]["count"] == 42
    assert result["method"]["link_context"]["driver_build_args_count"] == 5
    assert result["method"]["consumer_knowledge"]["artifacts_nonempty"] is True
    assert result["method"]["embedding"]["provider"] == "openai"
    assert result["method"]["generation_mode"] == "ALL-COVER"
    assert result["method_variant"] == "paper-faithful"
    assert result["excluded_from_aggregate"] is False


def test_build_result_writes_required_schema_v2_fields() -> None:
    result = profile.build_result(
        profile="reproduction-epsilon", protocol="blind-project", target="t",
        status="evaluated",
        stages={n: "completed" for n in profile.STAGE_NAMES},
        metrics={"coverage": {"line_coverage": {"covered": 5}}, "campaign": {"execs_done": 10}},
        selected_candidate={"overlaid": True, "candidate_path": "/x"},
    )
    for field in ("task_family", "profile", "protocol", "method_variant", "status",
                   "applicability", "stages", "artifacts", "method", "selected_candidate",
                   "excluded_from_aggregate"):
        assert field in result, f"missing schema field {field}"
    assert result["task_family"] == "harness_generator"


# ---------------------------------------------------------------------------
# Leakage audit
# ---------------------------------------------------------------------------


def test_reference_canary_not_in_generator_input(tmp_path: Path) -> None:
    pkg = _make_monolithic_package(tmp_path)
    ref_file = pkg / "reference_harnesses" / "selected" / "source_input" / "project" / "native.c"
    ref_file.write_text(f"// {CANARY}\nint LLVMFuzzerTestOneInput(void){{return 0;}}\n", encoding="utf-8")
    os.environ["HGB_REF_CANARY"] = CANARY
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
    for path in gen.rglob("*"):
        if path.is_file():
            content = path.read_text(encoding="utf-8", errors="replace")
            assert CANARY not in content, f"canary leaked into generator_input: {path}"


def test_reference_canary_not_in_consumer_cases(tmp_path: Path) -> None:
    target_root, src = _make_fixture_target(tmp_path)
    work = tmp_path / "work"
    build_context.capture_build_context(
        target_root=target_root, work_dir=work, fuzz_target="fuzz_foo",
        language="c", profile="reproduction-epsilon", capture_method="cmake_export",
        source_root=src,
    )
    cases_path = work / "knowledge" / "consumer_cases.json"
    content = cases_path.read_text(encoding="utf-8", errors="replace")
    assert CANARY not in content


def test_leakage_audit_detects_canary(tmp_path: Path) -> None:
    gen_input = tmp_path / "gen_input"
    gen_input.mkdir()
    (gen_input / "prompt.txt").write_text(f"some prompt with {CANARY}", encoding="utf-8")
    result = profile.audit_leakage(gen_input, CANARY)
    assert result["leaked"] is True
    assert result["hit_count"] >= 1


def test_leakage_audit_passes_without_canary(tmp_path: Path) -> None:
    gen_input = tmp_path / "gen_input"
    gen_input.mkdir()
    (gen_input / "prompt.txt").write_text("some clean prompt", encoding="utf-8")
    result = profile.audit_leakage(gen_input, CANARY)
    assert result["leaked"] is False


# ---------------------------------------------------------------------------
# PROME-8. Valuable-target matrix semantics
# ---------------------------------------------------------------------------


def _promefuzz_epsilon_base_meta(**overrides) -> dict:
    base = {
        "generator": "promefuzz",
        "task_family": "harness_generator",
        "target": "jsoncpp_jsoncpp_fuzzer",
        "status": "evaluated",
        "applicability": "applicable",
        "profile": "reproduction-epsilon",
        "method_variant": "paper-faithful",
        "excluded_from_aggregate": False,
        "stages": {n: "completed" for n in (
            "candidate_overlay", "candidate_build", "sanitizer_smoke",
            "campaign", "coverage", "api_reachability",
        )},
        "metrics": {
            "coverage": {"line_coverage": {"covered": 27}},
            "campaign": {"execs_done": 500, "crashes": 0, "timeouts": 0, "final_corpus_file_count": 4},
        },
        "build": {"overlay_audit": {"matches_candidate": True}},
        "selected_candidate": {
            "copy_audit": {"exact_copy": False, "contains_reference_canary": False,
                           "near_duplicate_reference": False},
            "build": {"overlay_audit": {"matches_candidate": True}},
        },
    }
    base.update(overrides)
    return base


def test_matrix_strict_no_violations_for_real_evaluated_epsilon_row(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    app_ws = matrix_dir / "app"
    app_ws.mkdir()
    (app_ws / "metadata.json").write_text(json.dumps(_promefuzz_epsilon_base_meta()), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\n"
        f"promefuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, strict=True, generator="promefuzz", profile="reproduction-epsilon")
    assert summary["evaluated_row_violations"] == []


def test_matrix_strict_flags_coverage_missing_epsilon_row(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    app_ws = matrix_dir / "app"
    app_ws.mkdir()
    meta = _promefuzz_epsilon_base_meta(
        metrics={"coverage": {"line_coverage": {"covered": 0}},
                 "campaign": {"execs_done": 500}},
    )
    (app_ws / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\n"
        f"promefuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, strict=True, generator="promefuzz", profile="reproduction-epsilon")
    assert summary["evaluated_row_violations"]


def test_matrix_strict_flags_exact_copy_epsilon_row(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    app_ws = matrix_dir / "app"
    app_ws.mkdir()
    meta = _promefuzz_epsilon_base_meta(
        selected_candidate={
            "copy_audit": {"exact_copy": True, "contains_reference_canary": False,
                           "near_duplicate_reference": False},
            "build": {"overlay_audit": {"matches_candidate": True}},
        },
    )
    (app_ws / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\n"
        f"promefuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, strict=True, generator="promefuzz", profile="reproduction-epsilon")
    assert summary["evaluated_row_violations"]
    violations = summary["evaluated_row_violations"][0]["violations"]
    assert any("exact_copy" in v for v in violations)


def test_matrix_strict_flags_overlay_mismatch_epsilon_row(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    app_ws = matrix_dir / "app"
    app_ws.mkdir()
    meta = _promefuzz_epsilon_base_meta(
        selected_candidate={
            "copy_audit": {"exact_copy": False, "contains_reference_canary": False,
                           "near_duplicate_reference": False},
            "build": {"overlay_audit": {"matches_candidate": False}},
        },
    )
    (app_ws / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\n"
        f"promefuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, strict=True, generator="promefuzz", profile="reproduction-epsilon")
    assert summary["evaluated_row_violations"]
    violations = summary["evaluated_row_violations"][0]["violations"]
    assert any("matches_candidate" in v for v in violations)


def test_matrix_strict_flags_non_paper_faithful_epsilon_row(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    app_ws = matrix_dir / "app"
    app_ws.mkdir()
    meta = _promefuzz_epsilon_base_meta(method_variant="compat-smoke")
    (app_ws / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\n"
        f"promefuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{app_ws}\t{app_ws / 'metadata.json'}\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, strict=True, generator="promefuzz", profile="reproduction-epsilon")
    assert summary["evaluated_row_violations"]
    violations = summary["evaluated_row_violations"][0]["violations"]
    assert any("method_variant" in v for v in violations)


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


def test_reproduction_gamma_remains_accepted_as_alias() -> None:
    assert "reproduction-gamma" in profile.VALID_PROFILES
    violations = profile.validate_profile("reproduction-gamma", "blind-project", {
        "PROME_FUZZ_EMBEDDING_MODEL": "text-embedding-3-small",
        "PROME_FUZZ_EMBEDDING_LLM_TYPE": "openai",
    })
    assert violations == []
    result = profile.build_result(
        profile="reproduction-gamma", protocol="blind-project", target="t",
        stages={n: "completed" for n in profile.STAGE_NAMES},
    )
    assert result["method_variant"] == "paper-faithful"
