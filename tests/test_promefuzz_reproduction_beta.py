from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "docker/common"))


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


profile = _load_module("promefuzz_profile", "docker/common/promefuzz_profile.py")
build_context = _load_module("promefuzz_build_context", "docker/common/promefuzz_build_context.py")
hgb_result = _load_module("hgb_result", "docker/common/hgb_result.py")
hgb_coverage = _load_module("hgb_coverage", "docker/common/hgb_coverage.py")
hgb_reachability = _load_module("hgb_reachability", "docker/common/hgb_reachability.py")
hgb_fuzzbench_builder = _load_module("hgb_fuzzbench_builder", "docker/common/hgb_fuzzbench_builder.py")
hgb_target_package = _load_module("hgb_target_package", "docker/common/hgb_target_package.py")
evaluator = _load_module("hgb_harness_evaluator", "docker/common/hgb_harness_evaluator.py")


FIXTURE = REPO_ROOT / "tests" / "fixtures" / "fuzzbench_minimal"


# ---------------------------------------------------------------------------
# Fixture: a tiny C library with a CMake build, an example consumer, a static
# library, and a fuzz target. Exercises the full build-context path without
# external services.
# ---------------------------------------------------------------------------


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
        "// HGB_REF_CANARY_LEAK_TOKEN\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){return 0;}\n",
        encoding="utf-8",
    )
    return target_root, target_root / "source_input" / "foo"


def _entrypoint() -> str:
    return (REPO_ROOT / "docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. Target package isolation hides reference harnesses from PromeFuzz.
# ---------------------------------------------------------------------------


def _make_monolithic_package(tmp_path: Path) -> Path:
    pkg = tmp_path / "target_pkg"
    (pkg / "source_input" / "project").mkdir(parents=True)
    (pkg / "reference_harnesses" / "selected" / "source_input" / "project").mkdir(parents=True)
    (pkg / "fuzzbench_benchmark").mkdir(parents=True)
    (pkg / "source_input" / "project" / "sample.c").write_text("int api(void){return 0;}\n", encoding="utf-8")
    (pkg / "reference_harnesses" / "selected" / "source_input" / "project" / "native.c").write_text(
        "int LLVMFuzzerTestOneInput(void){return 0;}\n", encoding="utf-8"
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
        "selected_reference_harness_count": 1, "seed_count": 0, "dictionary_count": 0,
    }
    (pkg / "target_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (pkg / "source_repos.json").write_text("[]", encoding="utf-8")
    return pkg


def test_promefuzz_generator_input_has_no_reference_harnesses(tmp_path: Path) -> None:
    pkg = _make_monolithic_package(tmp_path)
    halves = hgb_target_package.split_package(
        pkg,
        native_harness={
            "selected_reference": "source_input/project/native.c",
            "container_destination": "/src/project/native.c",
            "language": "c",
        },
    )
    generator_input = Path(halves["generator_input"])
    assert not (generator_input / "reference_harnesses").exists()
    assert not any(p.name == "reference_harnesses" for p in generator_input.rglob("*"))
    assert not any("selected_reference" in p.name for p in generator_input.rglob("*"))
    audit = hgb_target_package.audit_generator_input(generator_input)
    assert audit["clean"], f"forbidden reference tokens in generator_input: {audit['hits']}"


def test_common_sh_mounts_generator_input_only_for_blind_promefuzz() -> None:
    common = (REPO_ROOT / "scripts/lib/common.sh").read_text(encoding="utf-8")
    assert 'target_mount_src="$target_package/generator_input"' in common
    assert "-v \"$target_mount_src:/target:ro\"" in common
    assert "-v \"$target_package/evaluator_only:/evaluator:ro\"" in common
    # PromeFuzz is registered as a blind generator.
    assert "promefuzzer" in common.replace(" ", "") or "promefuzz)" in common


# ---------------------------------------------------------------------------
# 2. alpha rejects synthetic compile DB; no synthetic path in alpha/paper.
# ---------------------------------------------------------------------------


def test_alpha_rejects_synthetic_compile_db_env() -> None:
    violations = profile.validate_profile("alpha", "blind-project", {
        "PROME_FUZZ_EMBEDDING_MODEL": "text-embedding-3-small",
        "PROME_FUZZ_EMBEDDING_LLM_TYPE": "openai",
        "HGB_PROMEFUZZ_SYNTHETIC_COMPILE_DB": "1",
    })
    assert any("SYNTHETIC_COMPILE_DB" in v for v in violations)


def test_alpha_capture_never_uses_synthetic_path(tmp_path: Path) -> None:
    target_root, src = _make_fixture_target(tmp_path)
    work = tmp_path / "work"
    # An empty source root with allow_synthetic=False must not fabricate a DB.
    empty_root = tmp_path / "empty_target"
    (empty_root / "source_input").mkdir(parents=True)
    (empty_root / "fuzzbench_benchmark").mkdir()
    (empty_root / "target_manifest.json").write_text(
        json.dumps({"project": "x", "fuzz_target": "fuzz_x", "target": "x_fuzz_x"}), encoding="utf-8"
    )
    empty_src = tmp_path / "empty_src"
    empty_src.mkdir()
    manifest = build_context.capture_build_context(
        target_root=empty_root, work_dir=work, fuzz_target="fuzz_x",
        language="c", profile="alpha", allow_synthetic=False,
        capture_method="cmake_export", source_root=empty_src,
    )
    assert manifest["synthetic"] is False
    assert manifest["valid"] is False
    assert manifest["real_capture"] is False
    # mode is never "fuzzbench_build_replay" for a non-capture in alpha.
    assert manifest["mode"] != "fuzzbench_build_replay"


# ---------------------------------------------------------------------------
# 3. alpha rejects a generic CMake DB unless it is an exact replay.
# ---------------------------------------------------------------------------


class _FakeRunner:
    """Records commands; can inject a foreign compile_commands.json for cmake."""

    def __init__(self, foreign_db: list[dict] | None = None):
        self.commands = []
        self.foreign_db = foreign_db

    def __call__(self, command, timeout=None):
        self.commands.append(list(command))
        return build_context.CommandResult(list(command), 0, "", "")


def _fake_cmake_runner(foreign_db_path: Path, foreign_db: list[dict]):
    """Return a runner that writes a foreign compile_commands.json when cmake runs."""

    class _R:
        def __init__(self):
            self.commands = []

        def __call__(self, command, timeout=None):
            self.commands.append(list(command))
            rc, out, err = 0, "", ""
            if command and command[0] == "cmake" and "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" in command:
                # cmake configure: write the foreign DB at the build dir.
                for tok in command:
                    if tok.startswith("-B"):
                        build_dir = Path(tok[2:])
                        build_dir.mkdir(parents=True, exist_ok=True)
                        (build_dir / "compile_commands.json").write_text(
                            json.dumps(foreign_db), encoding="utf-8"
                        )
                        break
                out = "configured"
            elif command and command[0] == "cmake" and "--build" in command:
                out = "built"
            elif command and command[0] in ("clang", "clang++"):
                rc = 0
            return build_context.CommandResult(list(command), rc, out, err)

    return _R()


def test_alpha_rejects_generic_cmake_db_not_covering_project(tmp_path: Path) -> None:
    target_root, src = _make_fixture_target(tmp_path)
    work = tmp_path / "work"
    # A foreign compile DB whose files do not exist under the staged source.
    foreign = [{
        "directory": str(tmp_path),
        "file": str(tmp_path / "foreign" / "unrelated.c"),
        "command": "clang -c unrelated.c",
    }]
    runner = _fake_cmake_runner(work / "build_context" / "cmake_build" / "compile_commands.json", foreign)
    manifest = build_context.capture_build_context(
        target_root=target_root, work_dir=work, fuzz_target="fuzz_foo",
        language="c", profile="alpha", capture_method="cmake_export", source_root=src,
        runner=runner,
    )
    assert manifest["valid"] is False
    assert manifest["real_capture"] is False
    assert manifest["mode"] != "fuzzbench_build_replay"


def test_alpha_accepts_exact_replay_cmake_build(tmp_path: Path) -> None:
    target_root, src = _make_fixture_target(tmp_path)
    work = tmp_path / "work"
    manifest = build_context.capture_build_context(
        target_root=target_root, work_dir=work, fuzz_target="fuzz_foo",
        language="c", profile="alpha", capture_method="cmake_export", source_root=src,
    )
    assert manifest["valid"] is True
    assert manifest["real_capture"] is True
    assert manifest["exact_replay"] is True
    assert manifest["mode"] == "fuzzbench_build_replay"
    assert manifest["compiler_wrapper"] == "cmake"


def test_capture_fuzzbench_compile_db_returns_compile_context(tmp_path: Path) -> None:
    target_root, src = _make_fixture_target(tmp_path)
    work = tmp_path / "work"
    ctx = build_context.capture_fuzzbench_compile_db(
        target_root=target_root, work_dir=work, project="foo", fuzz_target="fuzz_foo",
        language="c", profile="alpha", capture_method="cmake_export", source_root=src,
    )
    assert isinstance(ctx, build_context.CompileContext)
    assert ctx.valid is True
    assert ctx.exact_replay is True
    assert ctx.mode == "fuzzbench_build_replay"
    assert ctx.fuzz_target == "fuzz_foo"
    assert ctx.benchmark_project == "foo"
    assert ctx.compile_commands_count >= 2
    assert Path(ctx.compile_commands_path).is_file()
    assert Path(ctx.link_context_path).is_file()


# ---------------------------------------------------------------------------
# 4. alpha rejects empty driver_build_args; verify_link_set is enforced.
# ---------------------------------------------------------------------------


def test_entrypoint_enforces_nonempty_driver_build_args() -> None:
    entrypoint = _entrypoint()
    assert "promefuzz_link_context_empty" in entrypoint
    assert "failed_stage=link_context" in entrypoint
    assert "verify_and_record_link_set" in entrypoint
    assert "promefuzz_link_context_unverified" in entrypoint


def test_verify_and_record_link_set_rejects_empty_args(tmp_path: Path) -> None:
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


def test_verify_and_record_link_set_records_verified_flag(tmp_path: Path) -> None:
    target_root, src = _make_fixture_target(tmp_path)
    work = tmp_path / "work"
    manifest = build_context.capture_build_context(
        target_root=target_root, work_dir=work, fuzz_target="fuzz_foo",
        language="c", profile="alpha", capture_method="cmake_export", source_root=src,
    )
    link_path = Path(manifest["link_context_path"])
    ok, msg = build_context.verify_and_record_link_set(
        link_context_path=link_path, driver_build_args=manifest["driver_build_args"],
        work_dir=tmp_path / "probe", language="c", source_root=src,
    )
    assert ok, msg
    data = json.loads(link_path.read_text(encoding="utf-8"))
    assert data["verified"] is True


def test_link_context_includes_fuzzer_and_project_libraries(tmp_path: Path) -> None:
    target_root, src = _make_fixture_target(tmp_path)
    work = tmp_path / "work"
    manifest = build_context.capture_build_context(
        target_root=target_root, work_dir=work, fuzz_target="fuzz_foo",
        language="c", profile="alpha", capture_method="cmake_export", source_root=src,
    )
    link_ctx = json.loads(Path(manifest["link_context_path"]).read_text(encoding="utf-8"))
    assert link_ctx["mode"] == "fuzzbench_build_replay"
    assert link_ctx["fuzz_target"] == "fuzz_foo"
    assert link_ctx["benchmark_project"] == "foo"
    assert link_ctx["compile_commands_count"] >= 2
    # The recovered driver_build_args include the project static library.
    assert any("libfoo.a" in arg for arg in link_ctx["driver_build_args"]), link_ctx["driver_build_args"]


# ---------------------------------------------------------------------------
# 5. Consumer cases exclude the reference harness and are wired into config.
# ---------------------------------------------------------------------------


def test_reference_harness_not_used_as_consumer_case(tmp_path: Path) -> None:
    target_root, src = _make_fixture_target(tmp_path)
    work = tmp_path / "work"
    manifest = build_context.capture_build_context(
        target_root=target_root, work_dir=work, fuzz_target="fuzz_foo",
        language="c", profile="alpha", capture_method="cmake_export", source_root=src,
    )
    cases = json.loads((work / "knowledge" / "consumer_cases.json").read_text(encoding="utf-8"))
    for case in cases["consumers"]:
        assert "fuzz_foo" not in case["file"]
        assert "HGB_REF_CANARY_LEAK_TOKEN" not in Path(case["file"]).read_text(encoding="utf-8", errors="replace")
        assert "LLVMFuzzerTestOneInput" not in Path(case["file"]).read_text(encoding="utf-8", errors="replace")
    # The example consumer is allowed.
    assert any(Path(c["file"]).name == "use_foo.c" for c in cases["consumers"])


def test_consumer_case_paths_are_written_to_libraries_toml() -> None:
    entrypoint = _entrypoint()
    assert "consumer_case_paths" in entrypoint
    assert "/workspace/knowledge/consumer_cases" in entrypoint
    # consumer_cases status is recorded (available or unavailable).
    assert 'consumer_cases_status="available"' in entrypoint.replace(" ", "") or "consumer_cases_status" in entrypoint


def test_comprehend_output_checked_for_nonempty_knowledge() -> None:
    entrypoint = _entrypoint()
    assert "comprehend_knowledge_audit" in entrypoint
    assert "promefuzz_comprehend_empty" in entrypoint
    assert "retrieval/correlation knowledge" in entrypoint


# ---------------------------------------------------------------------------
# 6. Hash/mock embeddings are forbidden in alpha/paper-faithful.
# ---------------------------------------------------------------------------


def test_hash_embeddings_forbidden_in_alpha_and_paper() -> None:
    for prof in ("alpha", "paper-faithful"):
        violations = profile.validate_profile(prof, "blind-project", {
            "PROME_FUZZ_EMBEDDING_MODEL": "hgb-hash-embedding",
            "PROME_FUZZ_EMBEDDING_LLM_TYPE": "mock",
        })
        assert any("embedding" in v.lower() for v in violations), prof
    # compat-smoke may use hash embeddings.
    violations = profile.validate_profile("compat-smoke", "blind-project", {
        "PROME_FUZZ_EMBEDDING_MODEL": "hgb-hash-embedding",
        "PROME_FUZZ_EMBEDDING_LLM_TYPE": "mock",
    })
    assert violations == []


def test_entrypoint_alpha_defaults_real_embedding_and_forbids_hash() -> None:
    entrypoint = _entrypoint()
    assert 'PROME_FUZZ_EMBEDDING_LLM_TYPE="${PROME_FUZZ_EMBEDDING_LLM_TYPE:-openai}"' in entrypoint
    assert 'PROME_FUZZ_EMBEDDING_LLM_TYPE="${PROME_FUZZ_EMBEDDING_LLM_TYPE:-mock}"' in entrypoint


# ---------------------------------------------------------------------------
# 7. Full shared evaluator is invoked after generation.
# ---------------------------------------------------------------------------


def test_entrypoint_invokes_shared_harness_evaluator() -> None:
    entrypoint = _entrypoint()
    assert "/opt/hgb/bin/hgb_harness_evaluator.py" in entrypoint
    assert "--generator promefuzz" in entrypoint
    assert "--evaluator-root" in entrypoint
    assert "--strict" in entrypoint
    # Budget defaults are defined in one place.
    assert 'PROME_GENERATION_BUDGET_SECONDS="${PROME_GENERATION_BUDGET_SECONDS:-3600}"' in entrypoint
    assert 'PROME_MAX_CANDIDATES="${PROME_MAX_CANDIDATES:-10}"' in entrypoint
    assert 'HGB_CAMPAIGN_SECONDS="${HGB_CAMPAIGN_SECONDS:-300}"' in entrypoint


def test_entrypoint_cannot_mark_campaign_coverage_complete_without_evaluator_output() -> None:
    entrypoint = _entrypoint()
    # campaign/coverage stages are set ONLY from the evaluator result.json,
    # never right after a build-only success.
    assert 'for stage in candidate_build sanitizer_smoke api_reachability campaign coverage' in entrypoint
    # The evaluator result is read and stages derived from it.
    assert 'eval_result="$eval_dir/result.json"' in entrypoint
    assert "promefuzz_no_verified_harness" in entrypoint
    # A compile-only candidate cannot reach evaluated.
    assert "quality_failure" in entrypoint


# ---------------------------------------------------------------------------
# 8. Fake runner validates candidate overlay path and stable Docker image tag.
# ---------------------------------------------------------------------------


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


class _FakeDockerRunner:
    """A fake Docker runner for the shared harness evaluator."""

    def __init__(self, *, campaign_execs=500, campaign_stdout=None, coverage_stdout=None, build_exit=0, smoke_crash=False):
        self.commands = []
        self.campaign_execs = campaign_execs
        self.campaign_stdout = campaign_stdout
        self.coverage_stdout = coverage_stdout if coverage_stdout is not None else LLVM_COVERAGE_JSON
        self.build_exit = build_exit
        self.smoke_crash = smoke_crash
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
                    stderr = "AddressSanitizer: crash\n" if self.smoke_crash else ""
                    return _FakeDockerResult(cmd, 77 if self.smoke_crash else 0, "", stderr)
                if phase == "campaign":
                    if self.campaign_stdout is not None:
                        return _FakeDockerResult(cmd, 0, self.campaign_stdout, "")
                    out = f"#{self.campaign_execs} INITED\n#{self.campaign_execs} DONE\n"
                    out += f"stat::number_of_executed_units: {self.campaign_execs}\n"
                    out += "stat::new_units_added: 12\nstat::peak_rss_mb: 100\n"
                    return _FakeDockerResult(cmd, 0, out, "")
                if phase == "coverage":
                    return _FakeDockerResult(cmd, 0, self.coverage_stdout, "")
                return _FakeDockerResult(cmd, 0, "", "")
            if sub in ("cp", "rm"):
                return _FakeDockerResult(cmd, 0, "", "")
        return _FakeDockerResult(cmd, 0, "", "")


def _fake_context_provider(target_root, work_dir):
    ctx = work_dir / "sealed_context"
    if ctx.exists():
        shutil.rmtree(ctx)
    (ctx / "source_input" / "project").mkdir(parents=True, exist_ok=True)
    (ctx / "source_input" / "project" / "native.c").write_text(
        "// placeholder reference harness\n", encoding="utf-8"
    )
    (ctx / "Dockerfile").write_text("FROM scratch\nCOPY source_input/ /src/\n", encoding="utf-8")
    return {"context_dir": str(ctx), "dockerfile": str(ctx / "Dockerfile"), "mode": "test_sealed"}


def _setup_evaluator_paths(tmp_path: Path):
    target_root = tmp_path / "generator_input"
    evaluator_root = tmp_path / "evaluator_only"
    candidates_dir = tmp_path / "candidates"
    work_dir = tmp_path / "evaluation"
    (target_root / "seeds").mkdir(parents=True)
    (evaluator_root / "benchmark_copy").mkdir(parents=True)
    candidates_dir.mkdir(parents=True)
    (evaluator_root / "native_harness_path.json").write_text(json.dumps({
        "selected_reference": "source_input/project/native.c",
        "container_destination": "/src/project/native.c",
        "language": "c",
    }), encoding="utf-8")
    (candidates_dir / "cand_001.c").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char *d, long n){return 0;}\n",
        encoding="utf-8",
    )
    return target_root, evaluator_root, candidates_dir, work_dir


def _run_shared_evaluator(target_root, evaluator_root, candidates_dir, work_dir, runner, **kw):
    return evaluator.evaluate(
        generator="promefuzz",
        target_root=target_root,
        evaluator_root=evaluator_root,
        candidates_dir=candidates_dir,
        work_dir=work_dir,
        project="project",
        fuzz_target="fuzz_target",
        profile="alpha",
        campaign_seconds=10,
        strict=True,
        runner=runner,
        context_provider=_fake_context_provider,
        intended_apis=["hgb_sample_api"],
        seeds=[],
        **kw,
    )


def test_shared_evaluator_overlays_candidate_at_exact_native_path(tmp_path: Path) -> None:
    target_root, evaluator_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = _FakeDockerRunner()
    result = _run_shared_evaluator(target_root, evaluator_root, candidates_dir, work_dir, runner)
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["overlaid"] is True
    assert cand_json["native_destination"] == "/src/project/native.c"
    assert cand_json["candidate_sha256"] != ""
    assert result["candidate_count"] == 1


def test_shared_evaluator_uses_stable_image_tag_for_all_stages(tmp_path: Path) -> None:
    target_root, evaluator_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = _FakeDockerRunner()
    _run_shared_evaluator(target_root, evaluator_root, candidates_dir, work_dir, runner)
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    tag = cand_json["image_tag"]
    assert tag.startswith("hgb-promefuzz-")
    build_cmds = [c for c in runner.commands if c[:2] == ["docker", "build"]]
    assert build_cmds, "expected at least one docker build"
    assert any(tag in c for c in build_cmds)


def test_shared_evaluator_full_loop_yields_evaluated(tmp_path: Path) -> None:
    target_root, evaluator_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = _FakeDockerRunner()
    result = _run_shared_evaluator(target_root, evaluator_root, candidates_dir, work_dir, runner)
    assert result["status"] == hgb_result.STATUS_EVALUATED
    assert result["stages"]["campaign"] == "completed"
    assert result["stages"]["coverage"] == "completed"
    assert int(result["metrics"]["campaign"]["execs_done"]) > 0
    assert result["metrics"]["coverage"]["line_coverage"]["covered"] == 27


def test_shared_evaluator_refuses_evaluated_with_zero_execs(tmp_path: Path) -> None:
    target_root, evaluator_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = _FakeDockerRunner(campaign_stdout="done\nno execs here\n")
    result = _run_shared_evaluator(target_root, evaluator_root, candidates_dir, work_dir, runner)
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_shared_evaluator_refuses_evaluated_without_coverage(tmp_path: Path) -> None:
    target_root, evaluator_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = _FakeDockerRunner(coverage_stdout="")
    result = _run_shared_evaluator(target_root, evaluator_root, candidates_dir, work_dir, runner)
    assert result["status"] != hgb_result.STATUS_EVALUATED


# ---------------------------------------------------------------------------
# 9. Result semantics: evaluated cannot be emitted by compile-only success.
# ---------------------------------------------------------------------------


def test_finalize_status_evaluated_requires_full_loop() -> None:
    stages = {n: "completed" for n in profile.STAGE_NAMES}
    ok = profile.finalize_status_from_evaluator(
        "evaluated", stages=stages, profile="alpha",
        coverage_covered_lines=10, campaign_execs_done=100, reached_count=1, candidate_count=1,
    )
    assert ok == "evaluated"


def test_finalize_status_rejects_compile_only() -> None:
    stages = {n: "completed" for n in profile.STAGE_NAMES}
    # No coverage, no execs -> quality_failure even if stages claim completed.
    assert profile.finalize_status_from_evaluator(
        "evaluated", stages=stages, profile="alpha",
        coverage_covered_lines=None, campaign_execs_done=0, reached_count=0, candidate_count=1,
    ) == "quality_failure"
    # Missing candidate -> quality_failure.
    assert profile.finalize_status_from_evaluator(
        "evaluated", stages=stages, profile="alpha",
        coverage_covered_lines=10, campaign_execs_done=100, reached_count=1, candidate_count=0,
    ) == "quality_failure"
    # An evaluation stage not completed -> quality_failure.
    stages_fail = dict(stages)
    stages_fail["campaign"] = "pending"
    assert profile.finalize_status_from_evaluator(
        "evaluated", stages=stages_fail, profile="alpha",
        coverage_covered_lines=10, campaign_execs_done=100, reached_count=1, candidate_count=1,
    ) == "quality_failure"


def test_finalize_status_maps_infra_and_compat_smoke() -> None:
    stages = profile.default_stages()
    assert profile.finalize_status_from_evaluator(
        "infra_failure", stages=stages, profile="alpha",
    ) == "infra_failure"
    assert profile.finalize_status_from_evaluator(
        "quality_failure", stages=stages, profile="alpha",
    ) == "quality_failure"
    assert profile.finalize_status_from_evaluator(
        "evaluated", stages={n: "completed" for n in profile.STAGE_NAMES}, profile="compat-smoke",
        coverage_covered_lines=10, campaign_execs_done=100, reached_count=1, candidate_count=1,
    ) == "compat_smoke_completed"


def test_promefuzz_build_result_carries_metrics_and_selected_candidate() -> None:
    result = profile.build_result(
        profile="alpha", protocol="blind-project", target="t",
        stages={n: "completed" for n in profile.STAGE_NAMES},
        metrics={"campaign": {"execs_done": 100}, "coverage": {"line_coverage": {"covered": 27}}},
        selected_candidate={"overlaid": True, "candidate_id": "cand_001"},
        candidate_count=1,
    )
    assert result["status"] == "evaluated"
    assert result["candidate_count"] == 1
    assert result["selected_candidate"]["candidate_id"] == "cand_001"
    assert result["metrics"]["campaign"]["execs_done"] == 100


# ---------------------------------------------------------------------------
# 10. Unit tests run without artifacts/fuzzbench.
# ---------------------------------------------------------------------------


def test_unit_tests_run_without_artifacts_fuzzbench() -> None:
    # The fuzzbench_minimal fixture is present and self-contained.
    assert FIXTURE.is_dir()
    assert (FIXTURE / "build.sh").is_file()
    assert (FIXTURE / "source_input" / "project" / "sample.c").is_file()
    # The shared helpers import without any artifacts/fuzzbench checkout.
    assert hgb_result.STATUS_EVALUATED == "evaluated"
    assert hgb_fuzzbench_builder.deterministic_image_tag("run", "t", "c1", generator="promefuzz").startswith("hgb-promefuzz-")
    assert callable(hgb_coverage.summarize_coverage_report)
    assert callable(hgb_reachability.check_reachability)


def test_fuzzbench_minimal_fixture_overlay_path(tmp_path: Path) -> None:
    # The fixture's native harness overlays at /src/project/native.c.
    native = FIXTURE / "source_input" / "project" / "native.c"
    assert native.is_file()
    assert "hgb_sample_api" in native.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 11. Matrix: valuable targets emit one row each with auditable artifacts.
# ---------------------------------------------------------------------------


def _load_registry() -> dict:
    return json.loads((REPO_ROOT / "metadata/fuzzbench_targets.json").read_text(encoding="utf-8"))


def test_all_valuable_targets_have_promefuzz_override() -> None:
    registry = _load_registry()
    valuable = registry.get("target_sets", {}).get("valuable", {}).get("targets", [])
    assert len(valuable) == 20, f"expected 20 valuable targets, got {len(valuable)}"
    overrides = profile.load_target_overrides(REPO_ROOT / "metadata")
    for target in valuable:
        assert target in overrides["targets"], f"target {target} has no PromeFuzz override"
        entry = overrides["targets"][target]
        assert entry.get("candidate_destination", "").startswith("/src/")
        assert entry.get("compile_db_capture_method") in {"bear_replay", "cmake_export"}


def test_matrix_collector_counts_only_evaluated_promefuzz_alpha(tmp_path: Path) -> None:
    collector = _load_module("hgb_collect_matrix", "scripts/hgb_collect_matrix.py")
    meta_eval = tmp_path / "eval.json"
    meta_eval.write_text(json.dumps({
        "generator": "promefuzz", "task_family": "harness_generator",
        "profile": "alpha", "status": "evaluated",
        "metrics": {"campaign": {"execs_done": 100}, "coverage": {"line_coverage": {"covered": 50}}},
        "selected_candidate": {"overlaid": True},
    }))
    meta_qf = tmp_path / "qf.json"
    meta_qf.write_text(json.dumps({
        "generator": "promefuzz", "task_family": "harness_generator",
        "profile": "alpha", "status": "quality_failure",
    }))
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tmetadata\n"
        f"promefuzz\tt1\tevaluated\t{meta_eval}\n"
        f"promefuzz\tt2\tquality_failure\t{meta_qf}\n",
        encoding="utf-8",
    )
    summary = collector.collect(matrix_dir, strict=True)
    assert summary["total_pairs"] == 2
    assert summary["completed_pairs"] == 1
    assert summary["failed_pairs"] >= 1
    assert summary["evaluated_row_violations"] == []


def test_matrix_strict_rejects_promefuzz_evaluated_without_coverage_or_execs(tmp_path: Path) -> None:
    collector = _load_module("hgb_collect_matrix", "scripts/hgb_collect_matrix.py")
    meta_bad = tmp_path / "bad.json"
    meta_bad.write_text(json.dumps({
        "generator": "promefuzz", "task_family": "harness_generator",
        "profile": "alpha", "status": "evaluated",
    }))
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tmetadata\n"
        f"promefuzz\tbad\tevaluated\t{meta_bad}\n",
        encoding="utf-8",
    )
    summary = collector.collect(matrix_dir, strict=True)
    violations = summary["evaluated_row_violations"]
    assert len(violations) == 1
    assert any("coverage" in v for v in violations[0]["violations"])
    assert any("execs_done" in v for v in violations[0]["violations"])
