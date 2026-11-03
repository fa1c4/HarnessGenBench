"""Small, Docker-free checks for saved Phase B recovery selection."""

from __future__ import annotations

import importlib.util
import fcntl
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "hgb_recover_phase_b_test", ROOT / "scripts/hgb_recover_phase_b.py"
)
assert SPEC and SPEC.loader
recovery = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = recovery
SPEC.loader.exec_module(recovery)


def test_recovery_command_preserves_canonical_g2_source(tmp_path: Path) -> None:
    run = tmp_path / "existing-run"
    command = recovery.recovery_command(
        {"target": "curl_curl_fuzzer_http"}, "ckgfuzzer", run,
        "/phase-a/ckg", "/phase-a/g2", 86400, 12, 8,
    )
    assert command[command.index("--canonical-source-run") + 1] == "/phase-a/g2"
    assert command[command.index("--source-run") + 1] == "/phase-a/ckg"
    assert command[command.index("--run-id") + 1] == run.name
    assert "--recover-existing" in command


def test_g2_recovery_requires_full_campaign_and_saved_corpus(tmp_path: Path) -> None:
    run = tmp_path / "g2"
    (run / "coverage/corpus").mkdir(parents=True)
    (run / "coverage/corpus/input").write_bytes(b"fuzzed input")
    result = {
        "campaign": {"campaign_wall_seconds": 86405, "execs_done": 123},
        "stages": {name: {"status": "complete"} for name in (
            "target_pair_build", "generated_input_validation", "campaign")},
    }
    (run / "result.json").write_text(json.dumps(result), encoding="utf-8")
    recovery.g2_saved_campaign_ready(run, 86400)

    result["campaign"]["campaign_wall_seconds"] = 85000
    (run / "result.json").write_text(json.dumps(result), encoding="utf-8")
    with pytest.raises(ValueError, match="full duration"):
        recovery.g2_saved_campaign_ready(run, 86400)

    result["campaign"]["campaign_wall_seconds"] = 86405
    result["campaign"]["execs_done"] = 0
    (run / "result.json").write_text(json.dumps(result), encoding="utf-8")
    with pytest.raises(ValueError, match="no recorded target executions"):
        recovery.g2_saved_campaign_ready(run, 86400)


def test_elfuzz_recovery_uses_saved_campaign_gate(tmp_path: Path, monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(recovery.hgb_fuzzbench_builder, "load_saved_campaign",
                        lambda path, budget: calls.append((path, budget)))
    recovery.saved_campaign_ready("elfuzz", tmp_path / "elfuzz-run", 86400)
    assert calls == [(tmp_path / "elfuzz-run", 86400)]


def test_verified_lcov_maps_container_path_and_rejects_missing_file(tmp_path: Path) -> None:
    run = tmp_path / "phase-b"
    report = run / "evaluation/cand_001/coverage/coverage.lcov"
    report.parent.mkdir(parents=True)
    report.write_text("SF:/src/project/file.cc\nDA:1,1\nend_of_record\n", encoding="utf-8")
    (run / "evaluation/result.json").write_text(json.dumps({
        "coverage": {"coverage_report_path": "/workspace/evaluation/cand_001/coverage/coverage.lcov"},
    }), encoding="utf-8")
    assert recovery.verified_lcov_path(run, "ckgfuzzer") == report
    report.unlink()
    with pytest.raises(ValueError, match="LCOV report is missing"):
        recovery.verified_lcov_path(run, "ckgfuzzer")


def test_dry_run_lists_eligible_without_writing_or_docker(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    workspace = tmp_path / "workspace"
    csv_path = workspace / "eval_all/2026-11-02.trials5.csv"
    csv_path.parent.mkdir(parents=True)
    run = workspace / "g2fuzz/curl_curl_fuzzer_http/existing-run"
    run.mkdir(parents=True)
    package = workspace / "target-packages/curl"
    package.mkdir(parents=True)
    (run / "phase_b_source.json").write_text(json.dumps({
        "baseline": "g2fuzz", "target": "curl_curl_fuzzer_http",
        "selected_phase_a_run": "/phase-a/g2",
        "canonical_target_package": str(package),
    }), encoding="utf-8")
    csv_path.write_text(
        "trial,target,g2fuzz_status,g2fuzz_run\n"
        "1,curl_curl_fuzzer_http,quality_failure,"
        "workspace/g2fuzz/curl_curl_fuzzer_http/existing-run\n",
        encoding="utf-8",
    )
    original = csv_path.read_bytes()
    manifest = csv_path.with_name("2026-11-02.phase_a.json")
    manifest.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(recovery, "ROOT", tmp_path)
    monkeypatch.setattr(recovery, "canonical_sources",
                        lambda _: {"curl_curl_fuzzer_http": ("/phase-a/g2", package)})
    monkeypatch.setattr(recovery.hgb_eval_all, "result_row",
                        lambda *args: {"status": "quality_failure", "coverage_contract": ""})
    monkeypatch.setattr(recovery, "saved_campaign_ready", lambda *args: None)
    monkeypatch.setattr(recovery.subprocess, "run",
                        lambda *args, **kwargs: pytest.fail("dry-run launched Docker recovery"))
    monkeypatch.setattr(sys, "argv", ["hgb_recover_phase_b.py", "--csv", str(csv_path),
                                     "--baseline", "g2fuzz", "--dry-run"])

    assert recovery.main() == 0
    assert csv_path.read_bytes() == original
    assert not csv_path.with_name(csv_path.name + ".lock").exists()
    output = capsys.readouterr().out
    assert "eligible trial 1 g2fuzz curl_curl_fuzzer_http" in output
    assert "dry-run: 1 eligible" in output


def test_recovery_rejects_csv_lock_held_by_coordinator(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    csv_path = tmp_path / "workspace/eval_all/2026-11-02.trials5.csv"
    csv_path.parent.mkdir(parents=True)
    csv_path.write_text("trial,target\n", encoding="utf-8")
    csv_path.with_name("2026-11-02.phase_a.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(recovery, "ROOT", tmp_path)
    monkeypatch.setattr(recovery, "canonical_sources", lambda _: {})
    monkeypatch.setattr(sys, "argv", ["hgb_recover_phase_b.py", "--csv", str(csv_path)])
    lock_path = csv_path.with_name(csv_path.name + ".lock")
    with lock_path.open("w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(SystemExit, match="2"):
            recovery.main()
    assert "another evaluation coordinator owns" in capsys.readouterr().err


def test_missing_lcov_keeps_recovered_csv_row_failed(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    csv_path = workspace / "eval_all/2026-11-02.trials5.csv"
    csv_path.parent.mkdir(parents=True)
    run = workspace / "g2fuzz/curl_curl_fuzzer_http/existing-run"
    run.mkdir(parents=True)
    package = workspace / "target-packages/curl"
    package.mkdir(parents=True)
    (run / "phase_b_source.json").write_text(json.dumps({
        "baseline": "g2fuzz", "target": "curl_curl_fuzzer_http",
        "selected_phase_a_run": "/phase-a/g2",
        "canonical_target_package": str(package),
    }), encoding="utf-8")
    csv_path.write_text(
        "trial,target,ckgfuzzer_status,promefuzz_status,g2fuzz_status,g2fuzz_reason,g2fuzz_run\n"
        "1,curl_curl_fuzzer_http,pending,interrupted,quality_failure,old,"
        "workspace/g2fuzz/curl_curl_fuzzer_http/existing-run\n",
        encoding="utf-8",
    )
    csv_path.with_name("2026-11-02.phase_a.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(recovery, "ROOT", tmp_path)
    monkeypatch.setattr(recovery, "canonical_sources",
                        lambda _: {"curl_curl_fuzzer_http": ("/phase-a/g2", package)})
    calls = 0

    def result_row(*_args):
        nonlocal calls
        calls += 1
        return {"status": "quality_failure" if calls == 1 else "evaluated",
                "coverage_contract": "canonical-g2-lcov-v1", "reason": "",
                "run": str(run.relative_to(tmp_path))}

    monkeypatch.setattr(recovery.hgb_eval_all, "result_row", result_row)
    monkeypatch.setattr(recovery, "saved_campaign_ready", lambda *args: None)
    monkeypatch.setattr(recovery, "recover_one",
                        lambda record, baseline, *_args: (baseline, record["target"], 0))
    monkeypatch.setattr(sys, "argv", ["hgb_recover_phase_b.py", "--csv", str(csv_path),
                                     "--baseline", "g2fuzz", "--max-jobs", "1"])
    assert recovery.main() == 1
    data = recovery.read_rows(csv_path)[1][0]
    assert data["g2fuzz_status"] == "quality_failure"
    assert "LCOV invalid" in data["g2fuzz_reason"]

    report = run / "host_coverage/coverage/coverage.lcov"
    report.parent.mkdir(parents=True)
    report.write_text("SF:/src/curl/file.c\nDA:1,1\nend_of_record\n", encoding="utf-8")
    (run / "result.json").write_text(json.dumps({
        "coverage": {"coverage_report_path": str(report)},
    }), encoding="utf-8")
    calls = 0
    assert recovery.main() == 0
    data = recovery.read_rows(csv_path)[1][0]
    assert data["g2fuzz_status"] == "evaluated"
    assert data["ckgfuzzer_status"] == "pending"
    assert data["promefuzz_status"] == "interrupted"
