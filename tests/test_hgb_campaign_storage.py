"""Campaign tmpfs checkpoints retain only useful, complete AFL artifacts."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest


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
    auto_extras = queue / ".state" / "auto_extras"
    auto_extras.mkdir(parents=True)
    (auto_extras / "auto_000001").write_bytes(b"internal state")
    (crashes / "id:000002").write_bytes(b"crash")
    (hot / "default" / "fuzzer_stats").write_text("execs_done : 10\n")

    checkpoint = AflCheckpoint(hot, saved)
    assert checkpoint.interval_seconds == 86400
    assert checkpoint.sync() == 3
    assert checkpoint.sync() == 0
    assert (saved / "default/queue/id:000001").read_bytes() == b"input"
    assert (saved / "default/crashes/id:000002").read_bytes() == b"crash"
    assert not (saved / "default/queue/.state").exists()
    (hot / "default" / "fuzzer_stats").write_text("execs_done : 20\n")
    assert checkpoint.sync() == 1
    assert (saved / "default/fuzzer_stats").read_text() == "execs_done : 20\n"
    assert not list(saved.rglob(".*.tmp"))


def test_elfuzz_tree_checkpoint_saves_afl_findings_but_skips_transient_files(tmp_path: Path) -> None:
    hot = tmp_path / "hot"
    queue = hot / "tmp123" / "output" / "1" / "default" / "queue"
    queue.mkdir(parents=True)
    (queue / "id:000001").write_bytes(b"finding")
    auto_extras = queue / ".state" / "auto_extras"
    auto_extras.mkdir(parents=True)
    (auto_extras / "auto_000001").write_bytes(b"internal state")
    (hot / "tmp123" / "input.bin").write_bytes(b"temporary")
    saved = tmp_path / "workspace" / "campaign" / "live_checkpoint"

    checkpoint = AflTreeCheckpoint(hot, saved)
    assert checkpoint.interval_seconds == 86400
    assert checkpoint.sync() == 1
    assert (saved / queue.relative_to(hot) / "id:000001").read_bytes() == b"finding"
    assert not (saved / queue.relative_to(hot) / ".state").exists()
    assert not (saved / "tmp123" / "input.bin").exists()


@pytest.mark.parametrize(
    ("checkpoint_type", "queue_path"),
    [
        (AflCheckpoint, Path("default/queue")),
        (AflTreeCheckpoint, Path("upstream/output/default/queue")),
    ],
)
def test_day_long_checkpoint_saves_queue_on_normal_exit(
    tmp_path: Path, checkpoint_type, queue_path: Path,
) -> None:
    hot = tmp_path / "hot"
    saved = tmp_path / "saved"
    with checkpoint_type(hot, saved) as checkpoint:
        assert checkpoint.interval_seconds == 86400
        queue = hot / queue_path
        queue.mkdir(parents=True)
        (queue / "id:000001").write_bytes(b"finding")
        assert not saved.exists()
    assert (saved / queue_path / "id:000001").read_bytes() == b"finding"
