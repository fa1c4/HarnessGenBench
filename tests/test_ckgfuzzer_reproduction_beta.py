from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


profile = _load_module("ckgfuzzer_profile", "docker/common/ckgfuzzer_profile.py")
stage_project = _load_module("ckgfuzzer_stage_project", "docker/common/ckgfuzzer_stage_project.py")
hgb_result = _load_module("hgb_result", "docker/common/hgb_result.py")
hgb_coverage = _load_module("hgb_coverage", "docker/common/hgb_coverage.py")
hgb_reachability = _load_module("hgb_reachability", "docker/common/hgb_reachability.py")
hgb_fuzzbench_builder = _load_module("hgb_fuzzbench_builder", "docker/common/hgb_fuzzbench_builder.py")
evaluator = _load_module("hgb_harness_evaluator", "docker/common/hgb_harness_evaluator.py")


# ---------------------------------------------------------------------------
# Profile tests
# ---------------------------------------------------------------------------


def test_alpha_forbids_mock_embedding_local_summary_local_combination() -> None:
    violations = profile.validate_profile("alpha", "blind-project", {
        "CKGFUZZER_EMBEDDING_MODEL": "mock",
        "CKGFUZZER_LOCAL_API_SUMMARY": "1",
        "CKGFUZZER_LOCAL_API_COMBINATION": "1",
    })
    texts = " ".join(violations).lower()
    assert "mock" in texts or "embedding" in texts
    assert "local_api_summary" in texts or "local_api_combination" in texts
    violations2 = profile.validate_profile("alpha", "blind-project", {
        "CKGFUZZER_EMBEDDING_MODEL": "openai-text-embedding-3-small",
        "CKGFUZZER_ALLOW_SOURCE_FALLBACK": "1",
    })
    assert any("source_fallback" in v.lower() for v in violations2)


def test_alpha_fails_on_empty_codeql_graph() -> None:
    payload = stage_project.validate_codeql_context(
        codeql_database="/tmp/empty_db",
        source_file_count=0,
        function_count=0,
    )
    assert payload["valid"] is False
    assert payload["failed_stage"] == "codeql_context"
    assert "source-only fallback" in payload["reason"]

    payload_ok = stage_project.validate_codeql_context(
        codeql_database="/tmp/db",
        source_file_count=12,
        function_count=34,
        edge_count=56,
    )
    assert payload_ok["valid"] is True
    assert payload_ok["build_context"] == "fuzzbench_replay"


def test_alpha_does_not_emit_skip_check_compilation() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert "ckg_compilation_args" in entrypoint
    assert 'if [[ "$ckg_method_faithful" != "1" ]]' in entrypoint
    assert "ckg_compilation_args+=(--skip_check_compilation)" in entrypoint
    runner = (REPO_ROOT / "scripts/hgb_run_baseline.sh").read_text(encoding="utf-8")
    assert "CKGFUZZER_SKIP_CHECK_COMPILATION" in runner


# ---------------------------------------------------------------------------
# Evaluator tests (offline, fake Docker runner)
# ---------------------------------------------------------------------------


class FakeResult:
    def __init__(self, command, exit_code=0, stdout="", stderr=""):
        self.command = list(command)
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


LLVM_COVERAGE_JSON = json.dumps({
    "data": [{"totals": {"lines": {"count": 100, "covered": 27},
                          "functions": {"count": 10, "covered": 5},
                          "regions": {"count": 50, "covered": 12}},
              "functions": [
                  {"name": "hgb_sample_api", "count": 5},
                  {"name": "other_func", "count": 0},
                  {"name": "LLVMFuzzerTestOneInput", "count": 12},
              ]}],
    "type": "llvm.coverage.json.export",
    "version": "2.0.1",
})


class FakeRunner:
    """A fake Docker runner for offline evaluator tests."""

    def __init__(self, *, campaign_execs=500, campaign_stdout=None,
                 coverage_stdout=None, build_exit=0, smoke_crash=False):
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
                    stderr = "AddressSanitizer: crash\n" if self.smoke_crash else ""
                    return FakeResult(cmd, 77 if self.smoke_crash else 0, "", stderr)
                if phase == "campaign":
                    if self.campaign_stdout is not None:
                        return FakeResult(cmd, 0, self.campaign_stdout, "")
                    out = f"#{self.campaign_execs} INITED\n#{self.campaign_execs} DONE\n"
                    out += f"stat::number_of_executed_units: {self.campaign_execs}\n"
                    out += "stat::new_units_added: 12\nstat::peak_rss_mb: 100\n"
                    return FakeResult(cmd, 0, out, "")
                if phase == "coverage":
                    return FakeResult(cmd, 0, self.coverage_stdout, "")
                return FakeResult(cmd, 0, "", "")
            if sub == "cp":
                return FakeResult(cmd, 0, "", "")
            if sub == "rm":
                return FakeResult(cmd, 0, "", "")
        return FakeResult(cmd, 0, "", "")


def _fake_context_provider(target_root, work_dir):
    ctx = work_dir / "sealed_context"
    if ctx.exists():
        import shutil

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
    (candidates_dir).mkdir(parents=True)
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


def _run_evaluator(target_root, evaluator_root, candidates_dir, work_dir, runner, **kw):
    return evaluator.evaluate(
        generator="ckgfuzzer",
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


def test_evaluator_overlays_candidate_at_exact_native_path(tmp_path: Path) -> None:
    target_root, evaluator_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = FakeRunner()
    result = _run_evaluator(target_root, evaluator_root, candidates_dir, work_dir, runner)
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["overlaid"] is True
    assert cand_json["native_destination"] == "/src/project/native.c"
    assert cand_json["candidate_sha256"] != ""
    assert result["candidate_count"] == 1


def test_evaluator_uses_same_image_tag_for_build_smoke_campaign_coverage(tmp_path: Path) -> None:
    target_root, evaluator_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = FakeRunner()
    _run_evaluator(target_root, evaluator_root, candidates_dir, work_dir, runner)
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    tag = cand_json["image_tag"]
    assert tag.startswith("hgb-ckgfuzzer-")
    build_cmds = [c for c in runner.commands if c[:2] == ["docker", "build"]]
    assert build_cmds, "expected at least one docker build"
    assert any(tag in c for c in build_cmds)


def test_evaluator_refuses_to_complete_campaign_with_zero_execs(tmp_path: Path) -> None:
    target_root, evaluator_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = FakeRunner(campaign_stdout="done\nno execs here\n")
    result = _run_evaluator(target_root, evaluator_root, candidates_dir, work_dir, runner)
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["campaign"] == "failed"
    assert int(cand_json["campaign"].get("execs_done", 0)) == 0
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_evaluator_refuses_coverage_without_llvm_report(tmp_path: Path) -> None:
    target_root, evaluator_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = FakeRunner(coverage_stdout="")
    result = _run_evaluator(target_root, evaluator_root, candidates_dir, work_dir, runner)
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["stages"]["coverage"] == "failed"
    assert result["status"] != hgb_result.STATUS_EVALUATED


def test_evaluator_full_loop_yields_evaluated(tmp_path: Path) -> None:
    target_root, evaluator_root, candidates_dir, work_dir = _setup_evaluator_paths(tmp_path)
    runner = FakeRunner()
    result = _run_evaluator(target_root, evaluator_root, candidates_dir, work_dir, runner)
    assert result["status"] == hgb_result.STATUS_EVALUATED
    assert result["stages"]["campaign"] == "completed"
    assert result["stages"]["coverage"] == "completed"
    assert int(result["metrics"]["campaign"]["execs_done"]) > 0
    assert result["metrics"]["coverage"]["line_coverage"]["covered"] == 27


def test_entrypoint_does_not_mark_campaign_or_coverage_from_build_only_result() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    # The build-only block must not unconditionally mark campaign/coverage
    # completed right after candidate_build completed.
    assert "candidate_build completed" in entrypoint
    after_build = entrypoint.split("candidate_build completed", 1)[1]
    # Before the evaluator call, there must be no bare campaign/coverage completed.
    pre_eval = after_build.split("hgb_harness_evaluator.py", 1)[0]
    assert 'hgb_result_set_stage "$workspace/stages.json" campaign completed' not in pre_eval
    assert 'hgb_result_set_stage "$workspace/stages.json" coverage completed' not in pre_eval
    # The evaluator-driven stage setting must be present.
    assert "hgb_harness_evaluator.py" in entrypoint
    assert 'for stage in sanitizer_smoke api_reachability campaign coverage' in entrypoint
    assert "evaluator_status" in entrypoint
    assert "quality_failure" in entrypoint


# ---------------------------------------------------------------------------
# Matrix tests
# ---------------------------------------------------------------------------


def _load_registry() -> dict:
    return json.loads((REPO_ROOT / "metadata/fuzzbench_targets.json").read_text(encoding="utf-8"))


def test_ckgfuzzer_all_valuable_targets_have_overrides_or_project_context() -> None:
    registry = _load_registry()
    valuable = registry.get("target_sets", {}).get("valuable", {}).get("targets", [])
    assert len(valuable) == 20, f"expected 20 valuable targets, got {len(valuable)}"
    overrides = profile.load_target_overrides(REPO_ROOT / "metadata")
    targets = overrides.get("targets", {})
    for target in valuable:
        assert target in targets, f"target {target} has no override or project context"


def test_ckgfuzzer_quality_failure_not_counted_as_success(tmp_path: Path) -> None:
    collector = _load_module("hgb_collect_matrix", "scripts/hgb_collect_matrix.py")
    meta_eval = tmp_path / "eval.json"
    meta_eval.write_text(json.dumps({
        "generator": "ckgfuzzer", "task_family": "harness_generator",
        "profile": "alpha", "status": "evaluated",
        "metrics": {"campaign": {"execs_done": 100}, "coverage": {"line_coverage": {"covered": 50}}},
        "selected_candidate": {"overlaid": True},
    }))
    meta_qf = tmp_path / "qf.json"
    meta_qf.write_text(json.dumps({
        "generator": "ckgfuzzer", "task_family": "harness_generator",
        "profile": "alpha", "status": "quality_failure",
    }))
    meta_infra = tmp_path / "infra.json"
    meta_infra.write_text(json.dumps({
        "generator": "ckgfuzzer", "task_family": "harness_generator",
        "profile": "alpha", "status": "infra_failure",
    }))
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tmetadata\n"
        f"ckgfuzzer\tt1\tevaluated\t{meta_eval}\n"
        f"ckgfuzzer\tt2\tquality_failure\t{meta_qf}\n"
        f"ckgfuzzer\tt3\tinfra_failure\t{meta_infra}\n",
        encoding="utf-8",
    )
    summary = collector.collect(matrix_dir)
    assert summary["total_pairs"] == 3
    assert summary["completed_pairs"] == 1
    assert summary["failed_pairs"] >= 2


def test_matrix_strict_rejects_evaluated_row_without_coverage_or_execs(tmp_path: Path) -> None:
    collector = _load_module("hgb_collect_matrix", "scripts/hgb_collect_matrix.py")
    # An evaluated row without coverage/execs must be flagged in strict mode.
    meta_bad = tmp_path / "bad.json"
    meta_bad.write_text(json.dumps({
        "generator": "ckgfuzzer", "task_family": "harness_generator",
        "profile": "alpha", "status": "evaluated",
    }))
    meta_good = tmp_path / "good.json"
    meta_good.write_text(json.dumps({
        "generator": "ckgfuzzer", "task_family": "harness_generator",
        "profile": "alpha", "status": "evaluated",
        "metrics": {"campaign": {"execs_done": 50}, "coverage": {"line_coverage": {"covered": 10}}},
        "selected_candidate": {"overlaid": True},
    }))
    matrix_dir = tmp_path / "matrix"
    matrix_dir.mkdir()
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tmetadata\n"
        f"ckgfuzzer\tbad\tevaluated\t{meta_bad}\n"
        f"ckgfuzzer\tgood\tevaluated\t{meta_good}\n",
        encoding="utf-8",
    )
    summary = collector.collect(matrix_dir, strict=True)
    violations = summary["evaluated_row_violations"]
    assert len(violations) == 1
    assert violations[0]["target"] == "bad"
    assert any("coverage" in v for v in violations[0]["violations"])
    assert any("execs_done" in v for v in violations[0]["violations"])
    # The good row is not flagged.
    assert all(v["target"] != "good" for v in violations)


def test_evaluated_invariants_reject_build_only_success() -> None:
    bad = hgb_result.build_result(
        profile="alpha", protocol="blind-project", target="t",
        status="evaluated",
        stages={n: "completed" for n in hgb_result.STAGE_NAMES},
        candidate_count=1,
    )
    bad["selected_candidate"] = {"overlaid": True}
    violations = hgb_result.assert_evaluated_invariants(bad)
    assert any("coverage" in v for v in violations) or any("execs_done" in v for v in violations)


def test_coverage_refuses_fake_lcov_unit_counts() -> None:
    bad = "TN:hgb\nLF:0\nLH:0\nend_of_record\n"
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".lcov", delete=False) as f:
        f.write(bad)
        path = Path(f.name)
    try:
        with pytest.raises(hgb_coverage.CoverageError):
            hgb_coverage.summarize_coverage_report(path)
    finally:
        path.unlink(missing_ok=True)


def test_reachability_extracts_intended_apis_from_plan() -> None:
    plan = {"api_combination": ["hgb_sample_api", "other_api"]}
    intended = hgb_reachability.extract_intended_apis(plan)
    assert "hgb_sample_api" in intended
    reach = hgb_reachability.check_reachability(intended, {"executed_functions": ["hgb_sample_api"]})
    assert reach["reached"] is True
    reach_none = hgb_reachability.check_reachability(intended, {"executed_functions": ["unrelated"]})
    assert reach_none["reached"] is False
