"""Campaign tmpfs checkpoints retain only useful, complete AFL artifacts."""

from __future__ import annotations

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "docker" / "common"))
from hgb_campaign_storage import AflCheckpoint, AflTreeCheckpoint  # noqa: E402


def test_afl_checkpoint_copies_findings_and_only_updates_changed_files(tmp_path: Path) -> None:
    hot = tmp_path / "hot"
    saved = tmp_path / "workspace" / "campaign" / "output"
    queue = hot / "default" / "queue"
    crashes = hot / "default" / "crashes"
    queue.mkdir(parents=True)
    crashes.mkdir(parents=True)
    (queue / "id:000001").write_bytes(b"input")
    (crashes / "id:000002").write_bytes(b"crash")
    (hot / "default" / "fuzzer_stats").write_text("execs_done : 10\n")

    checkpoint = AflCheckpoint(hot, saved, interval_seconds=300)
    assert checkpoint.sync() == 3
    assert checkpoint.sync() == 0
    assert (saved / "default/queue/id:000001").read_bytes() == b"input"
    assert (saved / "default/crashes/id:000002").read_bytes() == b"crash"
    (hot / "default" / "fuzzer_stats").write_text("execs_done : 20\n")
    assert checkpoint.sync() == 1
    assert (saved / "default/fuzzer_stats").read_text() == "execs_done : 20\n"
    assert not list(saved.rglob(".*.tmp"))


def test_elfuzz_tree_checkpoint_saves_afl_findings_but_skips_transient_files(tmp_path: Path) -> None:
    hot = tmp_path / "hot"
    queue = hot / "tmp123" / "output" / "1" / "default" / "queue"
    queue.mkdir(parents=True)
    (queue / "id:000001").write_bytes(b"finding")
    (hot / "tmp123" / "input.bin").write_bytes(b"temporary")
    saved = tmp_path / "workspace" / "campaign" / "live_checkpoint"

    assert AflTreeCheckpoint(hot, saved).sync() == 1
    assert (saved / queue.relative_to(hot) / "id:000001").read_bytes() == b"finding"
    assert not (saved / "tmp123" / "input.bin").exists()
