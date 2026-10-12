import csv
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SPEC = importlib.util.spec_from_file_location("hgb_eval_all", Path(__file__).resolve().parents[1] / "scripts/hgb_eval_all.py")
assert SPEC and SPEC.loader
hgb_eval_all = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hgb_eval_all)

BUILDER_SPEC = importlib.util.spec_from_file_location("hgb_fuzzbench_builder_eval_all", Path(__file__).resolve().parents[1] / "docker/common/hgb_fuzzbench_builder.py")
assert BUILDER_SPEC and BUILDER_SPEC.loader
builder = importlib.util.module_from_spec(BUILDER_SPEC)
sys.modules[BUILDER_SPEC.name] = builder
BUILDER_SPEC.loader.exec_module(builder)


def test_plan_uses_committed_applicability() -> None:
    targets, scope = hgb_eval_all.plan(hgb_eval_all.ROOT)
    assert len(targets) == 20
    assert sum(value == "pending" for value in scope.values()) == 89
    assert sum(value == "N/A" for value in scope.values()) == 11
    assert sum(scope["elfuzz", target] == "N/A" for target in targets) == 11


def test_csv_contains_na_and_campaign_metrics(tmp_path: Path) -> None:
    rows = {(baseline, "example"): {"status": "N/A" if baseline == "elfuzz" else "pending"}
            for baseline in hgb_eval_all.BASELINES}
    rows["ckgfuzzer", "example"] = {"status": "evaluated", "execs_done": 42, "covered_lines": 12}
    path = tmp_path / "2026-10-10.csv"
    hgb_eval_all.save_csv(path, ["example"], rows)
    record = next(csv.DictReader(path.open(newline="", encoding="utf-8")))
    assert record["elfuzz_status"] == "N/A"
    assert record["ckgfuzzer_execs_done"] == "42"
    assert record["ckgfuzzer_covered_lines"] == "12"


def test_resume_keeps_completed_rows_and_requeues_stale_running(tmp_path: Path, monkeypatch) -> None:
    targets, scope = hgb_eval_all.plan(hgb_eval_all.ROOT)
    rows = {(b, t): {"status": scope[b, t]} for t in targets for b in hgb_eval_all.BASELINES}
    first = targets[0]
    rows["ckgfuzzer", first] = {"status": "evaluated", "execs_done": 12}
    rows["promefuzz", first] = {"status": "running"}
    output = tmp_path / "2026-10-10.csv"
    hgb_eval_all.save_csv(output, targets, rows)
    monkeypatch.setattr(sys, "argv", ["hgb_eval_all.py", "--resume", "--plan", "--output", str(output)])
    assert hgb_eval_all.main() == 0
    records = list(csv.DictReader(output.open(newline="", encoding="utf-8")))
    assert records[0]["ckgfuzzer_status"] == "evaluated"
    assert records[0]["ckgfuzzer_execs_done"] == "12"
    assert records[0]["promefuzz_status"] == "pending"


def test_eval_rejects_files_in_repository_root(monkeypatch) -> None:
    for option in ("--output", "--manifest"):
        monkeypatch.setattr(sys, "argv", ["hgb_eval_all.py", "--plan", option,
                                      str(hgb_eval_all.ROOT / "unexpected-generated.json")])
        with pytest.raises(SystemExit) as error:
            hgb_eval_all.main()
        assert error.value.code == 2


def test_short_evaluated_campaign_is_not_reported_complete(tmp_path: Path) -> None:
    run = tmp_path / "workspace/ckgfuzzer/example/r1"
    (run / "evaluation").mkdir(parents=True)
    (run / "metadata.json").write_text('{"status":"evaluated"}')
    (run / "evaluation/result.json").write_text(json.dumps({
        "status": "evaluated", "campaign": {"execs_done": 100, "campaign_wall_seconds": 10},
        "coverage": {"line_coverage": {"covered": 12}},
    }))
    row = hgb_eval_all.result_row(tmp_path, "ckgfuzzer", "example", run, 86400, 0)
    assert row["status"] == "short_campaign"
    assert row["execs_done"] == 100


def test_g2_elapsed_uses_embedded_stats_when_afl_files_are_protected(tmp_path: Path) -> None:
    run = tmp_path / "workspace/g2fuzz/example/r1"
    run.mkdir(parents=True)
    (run / "metadata.json").write_text('{"status":"evaluated"}')
    (run / "result.json").write_text(json.dumps({
        "status": "evaluated",
        "campaign": {"execs_done": 100, "crashes": 1},
        "coverage": {"line_coverage": {"covered": 21}},
        "stages": {"campaign": {"fuzzer_stats": {"start_time": 1, "last_update": 86401}}},
    }))
    row = hgb_eval_all.result_row(tmp_path, "g2fuzz", "example", run, 86400, 0)
    assert row["status"] == "evaluated"
    assert row["campaign_elapsed_seconds"] == 86400
    assert row["crashes"] == 1


def test_job_passes_one_cpu_and_24_hour_budget(tmp_path: Path, monkeypatch) -> None:
    package = tmp_path / "package"
    package.mkdir()
    logs = tmp_path / "logs"
    logs.mkdir()

    def fake_run(cmd, **kwargs):
        assert kwargs["cwd"] == logs
        assert kwargs["env"]["HGB_DOCKER_CPUS"] == "1"
        assert kwargs["env"]["HGB_DOCKER_CPUSET"] == "7"
        assert kwargs["env"]["ELFUZZ_AFL_SECONDS"] == "86400"
        assert kwargs["env"]["DOCKER_NAME"].startswith("hgb-tgi-")
        assert "--timeout" in cmd
        run = tmp_path / "workspace/elfuzz/example/r1_elfuzz_example"
        (run / "campaign").mkdir(parents=True)
        (run / "metadata.json").write_text('{"status":"evaluated"}')
        (run / "result.json").write_text(json.dumps({
            "status": "evaluated", "campaign": {"execs_done": 10},
            "coverage": {"line_coverage": {"covered": 2}},
        }))
        (run / "campaign/fuzzer_stats").write_text("start_time : 1\nlast_update : 86401\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(hgb_eval_all.subprocess, "run", fake_run)
    row = hgb_eval_all.run_job(tmp_path, "elfuzz", "example", package, "r1", 86400, 21600, logs, 7)
    assert row["status"] == "evaluated"
    assert row["campaign_elapsed_seconds"] == 86400


def test_phase_b_invokes_saved_replay_without_generation(tmp_path: Path, monkeypatch) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    source = "workspace/promefuzz/example/phase_a"

    def fake_run(cmd, **kwargs):
        assert kwargs["cwd"] == logs
        assert cmd[1].endswith("hgb_replay_saved.py")
        assert cmd[cmd.index("--source-run") + 1] == source
        assert cmd[cmd.index("--campaign-seconds") + 1] == "86400"
        assert cmd[cmd.index("--memory-gib") + 1] == "8"
        assert "hgb_generate_harness.sh" not in " ".join(cmd)
        run = tmp_path / "workspace/promefuzz/example/r1_promefuzz_example"
        (run / "evaluation").mkdir(parents=True)
        (run / "metadata.json").write_text('{"status":"evaluated"}')
        (run / "evaluation/result.json").write_text(json.dumps({
            "status": "evaluated",
            "campaign": {"campaign_wall_seconds": 86400, "execs_done": 123},
            "coverage": {"line_coverage": {"covered": 9}},
        }))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(hgb_eval_all.subprocess, "run", fake_run)
    row = hgb_eval_all.run_replay_job(tmp_path, "promefuzz", "example", source,
                                      "r1", 86400, logs, 7, 8)
    assert row["status"] == "evaluated"
    assert row["execs_done"] == 123


def test_elfuzz_binary_extraction_retries_transient_docker_failure(tmp_path: Path, monkeypatch) -> None:
    benchmark = tmp_path / "benchmark"
    benchmark.mkdir()
    (benchmark / "Dockerfile").write_text("FROM scratch\n")
    copies = []

    def runner(command, _timeout):
        cmd = list(command)
        if cmd[:2] == ["docker", "image"]:
            return builder.CommandResult(cmd, 0, "sha256:abc\n", "")
        if cmd[:2] == ["docker", "cp"]:
            copies.append(cmd)
            if len(copies) == 1:
                return builder.CommandResult(cmd, 1, "", "Docker daemon busy")
            Path(cmd[-1]).write_bytes(b"fuzzer")
        return builder.CommandResult(cmd, 0, "", "")

    monkeypatch.setattr(builder.time, "sleep", lambda _seconds: None)
    record = builder.build_elfuzz_sut(
        benchmark_dir=benchmark, image_tag="hgb-test", fuzz_target="target",
        work_dir=tmp_path / "sut", runner=runner,
    )
    assert record["binary_extracted"]
    assert len(copies) == 2
