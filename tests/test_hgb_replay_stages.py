"""Runner and measurer stages must have an explicit corpus handoff."""

from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


replay = load_module("hgb_replay_stages", ROOT / "scripts/hgb_replay_saved.py")
g2 = load_module("g2_replay_stages", ROOT / "docker/common/g2fuzz_target_pipeline.py")


def test_g2_runner_saves_deduplicated_corpus(tmp_path: Path):
    pipeline = object.__new__(g2.G2FuzzPipeline)
    pipeline.workspace = tmp_path
    pipeline.metrics = {}
    queue = tmp_path / "seeds/afl_queue"
    generated = tmp_path / "seeds/g2_generated"
    queue.mkdir(parents=True)
    generated.mkdir(parents=True)
    (queue / "queue_seed").write_bytes(b"queue")
    (generated / "duplicate").write_bytes(b"queue")
    (generated / "new_seed").write_bytes(b"generated")

    pipeline.persist_replay_corpus()

    saved = tmp_path / "coverage/corpus"
    assert sorted(p.read_bytes() for p in saved.iterdir()) == [b"generated", b"queue"]
    assert pipeline.metrics["persisted_corpus_file_count"] == 2
    assert not (tmp_path / "coverage/.corpus.runner.tmp").exists()


def test_g2_runner_preserves_prior_corpus_if_new_publish_fails(tmp_path: Path):
    pipeline = object.__new__(g2.G2FuzzPipeline)
    pipeline.workspace = tmp_path
    pipeline.metrics = {}
    old = tmp_path / "coverage/corpus"
    old.mkdir(parents=True)
    (old / "old_input").write_bytes(b"old")
    queue = tmp_path / "seeds/afl_queue"
    queue.mkdir(parents=True)
    (queue / "new_input").write_bytes(b"new")

    with pytest.raises(g2.PipelineError, match="corpus save failed"):
        pipeline.persist_replay_corpus()

    assert (old / "old_input").read_bytes() == b"old"


def test_g2_runner_skips_coverage_measurer(tmp_path: Path, monkeypatch):
    source = tmp_path / "source"
    (source / "target").mkdir(parents=True)
    (source / "target/target.afl").write_bytes(b"afl")
    (source / "target/target.cmp").write_bytes(b"cmp")
    (source / "seeds/g2_generated").mkdir(parents=True)
    (source / "metadata.json").write_text("{}\n", encoding="utf-8")
    run = tmp_path / "run"
    run.mkdir()
    commands = []

    def fake_run(cmd, **_kwargs):
        commands.append(list(cmd))
        (run / "result.json").write_text(json.dumps({"status": "corpus_ready"}))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(replay.subprocess, "run", fake_run)
    monkeypatch.setattr(replay, "finish_g2_coverage", lambda *_args: (_ for _ in ()).throw(
        AssertionError("runner must not measure coverage")))

    code = replay.run_g2(source, run, tmp_path / "package", "g2-image", "target", 86400, 0, 8,
                         measure=False)

    assert code == 0
    assert commands[0][-1] == "--runner-only"


def test_elf_runner_saves_campaign_without_coverage_build(tmp_path: Path, monkeypatch):
    import hgb_fuzzbench_builder as builder

    source = tmp_path / "source"
    (source / "target").mkdir(parents=True)
    (source / "target/build.json").write_text(json.dumps({"native_image_tag": "native"}))
    (source / "metadata.json").write_text(json.dumps({
        "fuzz_target": "target", "target": "project_target"}))
    generated = source / "generated_inputs/produced"
    generated.mkdir(parents=True)
    (generated / "input").write_bytes(b"seed")
    package = tmp_path / "package"
    package.mkdir()
    (package / "target_manifest.json").write_text(json.dumps({"project": "project"}))
    run = tmp_path / "run"
    run.mkdir()
    corpus = run / "corpus"
    corpus.mkdir()
    (corpus / "saved").write_bytes(b"seed")

    monkeypatch.setattr(replay, "docker_image_exists", lambda _tag: True)
    saved_campaign = {
        "execs_done": 100, "copy_out_ok": True,
        "final_corpus_dir": str(corpus), "final_corpus_file_count": 1,
        "campaign_active_seconds": 86400,
    }
    campaign_calls = []

    def fake_campaign(**kwargs):
        campaign_calls.append(kwargs)
        return saved_campaign

    validated = []

    def fake_load_saved(work_dir, budget):
        validated.append((work_dir, budget))
        return saved_campaign

    monkeypatch.setattr(builder, "run_campaign", fake_campaign)
    monkeypatch.setattr(builder, "load_saved_campaign", fake_load_saved)
    monkeypatch.setattr(builder, "build_elfuzz_sut", lambda **_kwargs: (_ for _ in ()).throw(
        AssertionError("runner must not build coverage target")))

    code = replay.run_elfuzz(source, run, package, 86400, 0, 8, measure=False)

    assert code == 0
    assert json.loads((run / "result.json").read_text())["status"] == "corpus_ready"
    assert campaign_calls[0]["durable"] is True
    assert campaign_calls[0]["tmpfs_workdir"] is True
    assert validated == [(run, 86400)]


def test_g2_measurer_requires_full_campaign_and_saved_corpus(tmp_path: Path):
    run = tmp_path / "run"
    (run / "campaign").mkdir(parents=True)
    corpus = run / "coverage/corpus"
    corpus.mkdir(parents=True)
    (corpus / "input").write_bytes(b"seed")
    (run / "phase_b_source.json").write_text(json.dumps({
        "baseline": "g2fuzz", "target": "project_target",
        "selected_phase_a_run": "/some/source",
    }))
    (run / "campaign/metrics.json").write_text(json.dumps({
        "duration_mode": "afl-native-V", "deadline_reached": True,
    }))
    result = {
        "status": "corpus_ready",
        "campaign": {"execs_done": 100, "queue_count": 1,
                     "campaign_wall_seconds": 86400,
                     "persisted_corpus_file_count": 1},
        "stages": {name: {"status": "complete"} for name in (
            "target_pair_build", "generated_input_validation", "campaign")},
    }

    assert replay.verify_g2_saved_corpus(run, "project_target", 86400, result, 0) == corpus

    result["campaign"]["campaign_wall_seconds"] = 3600
    with pytest.raises(ValueError, match="below"):
        replay.verify_g2_saved_corpus(run, "project_target", 86400, result, 0)
    result["campaign"]["campaign_wall_seconds"] = 86400
    (corpus / "input").unlink()
    with pytest.raises(ValueError, match="empty"):
        replay.verify_g2_saved_corpus(run, "project_target", 86400, result, 0)


def test_g2_measurer_accepts_verified_legacy_coverage_failure(tmp_path: Path):
    run = tmp_path / "run"
    corpus = run / "coverage/corpus"
    corpus.mkdir(parents=True)
    (corpus / "input").write_bytes(b"seed")
    (run / "phase_b_source.json").write_text(json.dumps({
        "baseline": "g2fuzz", "target": "project_target",
        "selected_phase_a_run": "/some/source",
    }))
    result = {
        "status": "quality_failure",
        "campaign": {"execs_done": 100, "queue_count": 1,
                     "campaign_wall_seconds": 86400},
        "stages": {**{name: {"status": "complete"} for name in (
            "target_pair_build", "generated_input_validation", "campaign")},
                   "coverage": {"status": "failed"}},
    }

    assert replay.verify_g2_saved_corpus(run, "project_target", 86400, result, 0) == corpus
