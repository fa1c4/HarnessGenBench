"""Bounded, incremental persistence for a campaign running on tmpfs."""

from __future__ import annotations

import os
import shutil
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path

DEFAULT_CHECKPOINT_SECONDS = 24 * 60 * 60


def iter_afl_files_without_queue_state(root: Path) -> Iterator[Path]:
    """Walk AFL findings without visiting its transient queue state."""
    for directory, subdirectories, filenames in os.walk(root):
        if Path(directory).name == "queue":
            subdirectories[:] = [name for name in subdirectories if name != ".state"]
        for filename in filenames:
            yield Path(directory) / filename


def require_tmpfs(path: Path) -> None:
    """Fail closed if a configured hot directory would write to a disk mount."""
    mountpoint = str(path.resolve())
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        before, separator, after = line.partition(" - ")
        if separator and before.split()[4] == mountpoint and after.split()[0] == "tmpfs":
            return
    raise ValueError(f"campaign hot directory is not a tmpfs mount: {mountpoint}")


def _copy_atomic(source: Path, destination: Path) -> bool:
    """Publish a complete checkpoint file only when its source changed."""
    if source.is_symlink() or not source.is_file():
        return False
    source_stat = source.stat()
    try:
        old = destination.stat()
        if old.st_size == source_stat.st_size and old.st_mtime_ns == source_stat.st_mtime_ns:
            return False
    except FileNotFoundError:
        pass
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as out, source.open("rb") as inp:
            shutil.copyfileobj(inp, out, 1024 * 1024)
            out.flush()
            os.fsync(out.fileno())
        # AFL may replace a status file while it is copied. Publish only a
        # stable snapshot; the next checkpoint will retry a changed file.
        current_stat = source.stat()
        if (current_stat.st_size, current_stat.st_mtime_ns) != (source_stat.st_size, source_stat.st_mtime_ns):
            return False
        shutil.copystat(source, temporary)
        with open(temporary, "rb") as copied:
            os.fsync(copied.fileno())
        os.replace(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


class AflCheckpoint:
    """Save AFL findings every interval; the active AFL output stays on tmpfs."""

    def __init__(self, output: Path, workspace_output: Path,
                 interval_seconds: int = DEFAULT_CHECKPOINT_SECONDS):
        if interval_seconds < 1:
            raise ValueError("checkpoint interval must be positive")
        self.output = output
        self.workspace_output = workspace_output
        self.interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="hgb-afl-checkpoint", daemon=True)
        self.last_error: OSError | None = None

    def sync(self) -> int:
        copied = 0
        default = self.output / "default"
        for name in ("queue", "crashes", "hangs"):
            source_dir = default / name
            if source_dir.is_dir():
                for source in iter_afl_files_without_queue_state(source_dir):
                    if source.is_file() and not source.is_symlink():
                        destination = self.workspace_output / "default" / name / source.relative_to(source_dir)
                        if not destination.parent.resolve().is_relative_to(self.workspace_output.resolve()):
                            raise OSError(f"checkpoint path escapes workspace: {destination}")
                        try:
                            copied += _copy_atomic(source, destination)
                        except FileNotFoundError:
                            continue
        for name in ("fuzzer_stats", "plot_data"):
            source = default / name
            if source.is_file():
                try:
                    copied += _copy_atomic(source, self.workspace_output / "default" / name)
                except FileNotFoundError:
                    continue
        self.last_error = None
        return copied

    def _loop(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            try:
                self.sync()
            except OSError as exc:
                self.last_error = exc

    def __enter__(self) -> "AflCheckpoint":
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        self._thread.join()
        self.sync()


class AflTreeCheckpoint(AflCheckpoint):
    """Checkpoint AFL findings under an upstream tool's temporary work tree."""

    def sync(self) -> int:
        copied = 0
        for source in iter_afl_files_without_queue_state(self.output):
            if source.is_symlink() or not source.is_file():
                continue
            relative = source.relative_to(self.output)
            if not ({"queue", "crashes", "hangs"} & set(relative.parts)) and source.name != "fuzzer_stats":
                continue
            destination = self.workspace_output / relative
            if not destination.parent.resolve().is_relative_to(self.workspace_output.resolve()):
                raise OSError(f"checkpoint path escapes workspace: {destination}")
            try:
                copied += _copy_atomic(source, destination)
            except FileNotFoundError:
                continue
        self.last_error = None
        return copied
