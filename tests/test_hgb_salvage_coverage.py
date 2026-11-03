"""Docker-free checks for isolated zero-exec coverage salvage."""

from __future__ import annotations

import csv
import importlib.util
import io
import json
import os
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "hgb_salvage_coverage_test", ROOT / "scripts/hgb_salvage_coverage.py")
assert SPEC and SPEC.loader
salvage = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = salvage
SPEC.loader.exec_module(salvage)


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def fixture_run(tmp_path: Path, baseline: str, *, truncated: bool = False) -> tuple[dict, Path]:
    workspace = tmp_path / "workspace"
    target = "jsoncpp_jsoncpp_fuzzer"
    run = workspace / baseline / target / f"saved-{baseline}"
    phase_a = workspace / baseline / target / "phase-a"
    phase_a.mkdir(parents=True)
    g2 = workspace / "g2fuzz" / target / "phase-a"
    g2.mkdir(parents=True, exist_ok=True)
    package = workspace / "target-packages" / target
    write_json(package / "generator_input/target_manifest.json", {
        "target": target, "project": "jsoncpp", "fuzz_target": "jsoncpp_fuzzer"})
    write_json(g2 / "metadata.json", {"status": "evaluated"})
    (g2 / "host_command.txt").write_text(f"target_package={package}\n", encoding="utf-8")
    write_json(run / "phase_b_source.json", {
        "baseline": baseline, "target": target,
        "selected_phase_a_run": str(phase_a),
        "canonical_target_package": str(package),
    })
    candidate = run / "generated_harnesses/candidate.cc"
    candidate.parent.mkdir(parents=True)
    candidate.write_text("int LLVMFuzzerTestOneInput() { return 0; }\n", encoding="utf-8")
    digest = salvage.sha256_file(candidate)
    write_json(run / "replay_provenance.json", {
        "selected_phase_a_run": str(phase_a), "selected_harness_sha256": digest})
    context = run / "evaluation/sealed_context/sealed_context"
    destination = "/src/jsoncpp/jsoncpp_fuzzer.cc"
    overlay = context / "hgb_candidate_overlay/jsoncpp/jsoncpp_fuzzer.cc"
    overlay.parent.mkdir(parents=True)
    overlay.write_bytes(candidate.read_bytes())
    write_json(context / "native_harness_path.json", {"container_destination": destination})
    (context / "Dockerfile").write_text(
        "COPY hgb_candidate_overlay/jsoncpp/jsoncpp_fuzzer.cc " + destination + "\n"
        "# HGB sealed evaluator candidate build.\n", encoding="utf-8")
    write_json(run / "evaluation/result.json", {
        "status": "quality_failure", "reason": salvage.ZERO_EXEC_REASON})
    write_json(run / "result.json", {
        "status": "quality_failure", "reason": salvage.ZERO_EXEC_REASON})
    corpus = run / "evaluation/cand_001/corpus"
    corpus.mkdir(parents=True)
    (corpus / "a").write_bytes(b"input-a")
    (corpus / "b").write_bytes(b"input-b")
    archive = run / "evaluation/cand_001/campaign/corpus.tar"
    archive.parent.mkdir(parents=True)
    with tarfile.open(archive, "w") as handle:
        handle.add(corpus, arcname="corpus")
        if truncated:
            payload = b"x" * 4096
            info = tarfile.TarInfo("artifacts/incomplete")
            info.size = len(payload)
            handle.addfile(info, io.BytesIO(payload))
    if truncated:
        with tarfile.open(archive) as handle:
            member = handle.getmember("artifacts/incomplete")
        with archive.open("r+b") as handle:
            handle.truncate(member.offset_data + 1000)
    write_json(run / "evaluation/cand_001/campaign/campaign.json", {
        "execs_done": 0, "final_corpus_file_count": 2 if not truncated else 0,
        "corpus_archive_error": "unexpected end of data" if truncated else "",
    })
    row = {"trial": "1", "target": target,
           f"{baseline}_status": "quality_failure",
           f"{baseline}_reason": salvage.ZERO_EXEC_REASON,
           f"{baseline}_run": str(run.relative_to(tmp_path))}
    return row, run


def fixture_csv(tmp_path: Path, rows: list[dict]) -> Path:
    csv_path = tmp_path / "workspace/eval_all/2026-11-02.trials5.csv"
    csv_path.parent.mkdir(parents=True)
    fields = ["trial", "target"] + [f"{baseline}_{suffix}"
                                   for baseline in salvage.BASELINES
                                   for suffix in ("status", "reason", "run")]
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    records = []
    for row in rows:
        for baseline in salvage.BASELINES:
            if row.get(f"{baseline}_run"):
                run = tmp_path / row[f"{baseline}_run"]
                phase_b = salvage.read_json(run / "phase_b_source.json")
                records.append({"baseline": baseline, "target": row["target"],
                                "status": "ready",
                                "source_run": phase_b["selected_phase_a_run"]})
    target = rows[0]["target"]
    records.append({"baseline": "g2fuzz", "target": target, "status": "ready",
                    "source_run": str(tmp_path / "workspace/g2fuzz" / target / "phase-a")})
    write_json(csv_path.with_name("2026-11-02.phase_a.json"), {"records": records})
    return csv_path


def test_dry_run_reports_intact_and_truncated_without_writing_or_docker(
    tmp_path: Path, monkeypatch, capsys,
) -> None:
    intact, intact_run = fixture_run(tmp_path, "ckgfuzzer")
    partial, partial_run = fixture_run(tmp_path, "promefuzz", truncated=True)
    csv_path = fixture_csv(tmp_path, [intact, partial])
    before_csv = csv_path.read_bytes()
    before_result = (intact_run / "evaluation/result.json").read_bytes()
    before_root_result = (intact_run / "result.json").read_bytes()
    monkeypatch.setattr(salvage, "ROOT", tmp_path)
    monkeypatch.setattr(salvage.builder, "build_coverage_image",
                        lambda **kwargs: pytest.fail("dry-run started Docker"))
    assert salvage.main(["--csv", str(csv_path)]) == 0
    output = capsys.readouterr().out
    assert "eligible trial 1 ckgfuzzer jsoncpp_jsoncpp_fuzzer: 2 intact corpus files" in output
    assert "partial archive: 2 complete corpus prefix files" in output
    assert "selection: 1 eligible, 1 partial archives" in output
    assert csv_path.read_bytes() == before_csv
    assert (intact_run / "evaluation/result.json").read_bytes() == before_result
    assert (intact_run / "result.json").read_bytes() == before_root_result
    assert not (intact_run / "coverage_salvage").exists()
    assert not (partial_run / "coverage_salvage").exists()


def test_explicit_run_saves_real_lcov_separately_and_preserves_originals(
    tmp_path: Path, monkeypatch,
) -> None:
    row, run = fixture_run(tmp_path, "ckgfuzzer")
    csv_path = fixture_csv(tmp_path, [row])
    before_csv = csv_path.read_bytes()
    before_result = (run / "evaluation/result.json").read_bytes()
    before_root_result = (run / "result.json").read_bytes()
    monkeypatch.setattr(salvage, "ROOT", tmp_path)
    for key in ("HGB_DOCKER_CPUS", "HGB_DOCKER_CPUSET", "HGB_DOCKER_MEMORY",
                "HGB_PHASE_B_REPLAY"):
        monkeypatch.delenv(key, raising=False)
    calls = []

    def fake_build(**kwargs):
        calls.append("build")
        assert kwargs["context_dir"] == run / "evaluation/sealed_context/sealed_context"
        assert "staged_candidate_host" not in kwargs
        assert os.environ["HGB_DOCKER_CPUS"] == "1"
        assert os.environ["HGB_DOCKER_CPUSET"] == str(min(os.sched_getaffinity(0)))
        assert os.environ["HGB_DOCKER_MEMORY"] == "8g"
        assert os.environ["HGB_PHASE_B_REPLAY"] == "1"
        return SimpleNamespace(build_exit_code=0, binary_verified=True,
                               image_digest="sha256:coverage", binary_path="/out/jsoncpp_fuzzer")

    def fake_replay(**kwargs):
        calls.append("replay")
        assert kwargs["require_coverage_report"] is True
        assert kwargs["coverage_format"] == "lcov"
        work = kwargs["work_dir"] / "coverage"
        work.mkdir()
        report = work / "coverage.lcov"
        report.write_text("SF:/src/other/driver.cc\n"
                          "DA:1,1\nLF:1\nLH:1\nend_of_record\n", encoding="utf-8")
        (work / "coverage.log").write_text("HGB_INPUTS_REPLAYED=2\n", encoding="utf-8")
        return {"exit_code": 0, "copy_in_ok": True, "copy_out_ok": True,
                "coverage_report_path": str(report)}

    monkeypatch.setattr(salvage.builder, "build_coverage_image", fake_build)
    monkeypatch.setattr(salvage.builder, "run_coverage", fake_replay)
    assert salvage.main(["--csv", str(csv_path), "--run"]) == 0
    assert calls == ["build", "replay"]
    assert "HGB_DOCKER_CPUS" not in os.environ
    assert "HGB_DOCKER_CPUSET" not in os.environ
    assert "HGB_DOCKER_MEMORY" not in os.environ
    assert "HGB_PHASE_B_REPLAY" not in os.environ
    assert csv_path.read_bytes() == before_csv
    assert (run / "evaluation/result.json").read_bytes() == before_result
    assert (run / "result.json").read_bytes() == before_root_result
    result = salvage.read_json(run / "coverage_salvage/result.json")
    assert result["status"] == "coverage_salvaged_unverified"
    assert result["campaign_duration_verified"] is False
    assert result["campaign_execs_verified"] is False
    assert result["inputs_replayed"] == 2
    report = Path(result["coverage_report_path"])
    assert report.is_file() and report.is_relative_to(run / "coverage_salvage")
    assert result["coverage_report_sha256"] == salvage.sha256_file(report)
    assert result["coverage"]["line_coverage"]["covered"] == 1
    assert result["coverage"]["sut_line_coverage"]["covered"] == 0
    assert salvage.main(["--csv", str(csv_path), "--run"]) == 0
    assert calls == ["build", "replay"]


def test_missing_replay_marker_cannot_publish_salvage(
    tmp_path: Path, monkeypatch,
) -> None:
    row, run = fixture_run(tmp_path, "ckgfuzzer")
    csv_path = fixture_csv(tmp_path, [row])
    monkeypatch.setattr(salvage, "ROOT", tmp_path)
    monkeypatch.setenv("HGB_DOCKER_MEMORY", "12g")
    def fake_build(**kwargs):
        assert os.environ["HGB_DOCKER_MEMORY"] == "12g"
        return SimpleNamespace(build_exit_code=0, binary_verified=True,
                               image_digest="sha256:coverage", binary_path="/out/jsoncpp_fuzzer")

    monkeypatch.setattr(salvage.builder, "build_coverage_image", fake_build)

    def fake_replay(**kwargs):
        work = kwargs["work_dir"] / "coverage"
        work.mkdir()
        report = work / "coverage.lcov"
        report.write_text("SF:/src/jsoncpp/src/lib_json/json_reader.cpp\n"
                          "DA:1,1\nend_of_record\n", encoding="utf-8")
        (work / "coverage.log").write_text("no execution marker\n", encoding="utf-8")
        return {"exit_code": 0, "copy_in_ok": True, "copy_out_ok": True,
                "coverage_report_path": str(report)}

    monkeypatch.setattr(salvage.builder, "run_coverage", fake_replay)
    assert salvage.main(["--csv", str(csv_path), "--run"]) == 1
    assert os.environ["HGB_DOCKER_MEMORY"] == "12g"
    assert not (run / "coverage_salvage/result.json").exists()


def test_run_never_replays_truncated_archive(tmp_path: Path, monkeypatch, capsys) -> None:
    row, run = fixture_run(tmp_path, "promefuzz", truncated=True)
    csv_path = fixture_csv(tmp_path, [row])
    monkeypatch.setattr(salvage, "ROOT", tmp_path)
    monkeypatch.setattr(salvage.builder, "build_coverage_image",
                        lambda **kwargs: pytest.fail("truncated archive started Docker"))
    assert salvage.main(["--csv", str(csv_path), "--run"]) == 0
    assert "partial archive: 2 complete corpus prefix files" in capsys.readouterr().out
    assert not (run / "coverage_salvage").exists()
