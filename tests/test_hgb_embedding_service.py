import importlib.util
import subprocess
from pathlib import Path

import pytest


SPEC = importlib.util.spec_from_file_location(
    "hgb_embedding_service", Path(__file__).resolve().parents[1] / "scripts/hgb_embedding_service.py")
assert SPEC and SPEC.loader
service = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(service)


def test_auto_started_service_stops_after_last_generator(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(service, "STATE_DIR", tmp_path)
    monkeypatch.setattr(service, "process_token", lambda pid: str(pid))
    current = None
    starts = []
    stops = []

    def inspect():
        return current

    def start(existing):
        nonlocal current
        starts.append(existing)
        current = {"id": "service-1", "running": "true"}
        return {"id": "service-1", "created": existing is None}

    def stop(managed):
        nonlocal current
        stops.append(managed)
        current = None

    monkeypatch.setattr(service, "container_info", inspect)
    monkeypatch.setattr(service, "start_service", start)
    monkeypatch.setattr(service, "stop_service", stop)
    monkeypatch.setattr(service, "wait_health", lambda: None)

    service.update("acquire", 101)
    service.update("acquire", 102)
    assert len(starts) == 1
    service.update("release", 101)
    assert not stops
    service.update("release", 102)
    assert stops == [{"id": "service-1", "created": True}]


def test_existing_running_service_is_not_stopped(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(service, "STATE_DIR", tmp_path)
    monkeypatch.setattr(service, "process_token", lambda pid: str(pid))
    monkeypatch.setattr(service, "container_info", lambda: {"id": "external", "running": "true"})
    monkeypatch.setattr(service, "wait_health", lambda: None)
    monkeypatch.setattr(service, "start_service", lambda _existing: 1 / 0)
    monkeypatch.setattr(service, "stop_service", lambda _managed: 1 / 0)
    service.update("acquire", 101)
    service.update("release", 101)
    assert service.read_state()["managed"] is None


def test_restarted_stopped_service_is_stopped_after_release(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(service, "STATE_DIR", tmp_path)
    monkeypatch.setattr(service, "process_token", lambda pid: str(pid))
    monkeypatch.setattr(service, "container_info", lambda: {"id": "existing", "running": "false"})
    monkeypatch.setattr(service, "start_service", lambda existing: {"id": existing["id"], "created": False})
    monkeypatch.setattr(service, "stop_service", lambda managed: stopped.append(managed))
    stopped = []
    service.update("acquire", 101)
    service.update("release", 101)
    assert stopped == [{"id": "existing", "created": False}]


def test_failed_service_startup_cleans_up_container(monkeypatch) -> None:
    stopped = []
    monkeypatch.setattr(service.subprocess, "run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(service, "container_info", lambda: {"id": "new", "running": "true"})
    monkeypatch.setattr(service, "wait_health", lambda: (_ for _ in ()).throw(RuntimeError("unhealthy")))
    monkeypatch.setattr(service, "stop_service", lambda managed: stopped.append(managed))
    with pytest.raises(RuntimeError, match="unhealthy"):
        service.start_service(None)
    assert stopped == [{"id": "new", "created": True}]


def test_failed_startup_script_cleans_up_created_container(monkeypatch) -> None:
    stopped = []
    def fail_start(command, **_kwargs):
        raise subprocess.CalledProcessError(1, command)
    monkeypatch.setattr(service.subprocess, "run", fail_start)
    monkeypatch.setattr(service, "container_info", lambda: {"id": "new", "running": "true"})
    monkeypatch.setattr(service, "stop_service", lambda managed: stopped.append(managed))
    with pytest.raises(subprocess.CalledProcessError):
        service.start_service(None)
    assert stopped == [{"id": "new", "created": True}]


def test_reaper_stops_service_after_killed_generator(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(service, "STATE_DIR", tmp_path)
    monkeypatch.setattr(service, "process_token", lambda _pid: None)
    monkeypatch.setattr(service, "container_info", lambda: {"id": "orphan", "running": "true"})
    stopped = []
    monkeypatch.setattr(service, "stop_service", lambda managed: stopped.append(managed))
    service.save_state({"leases": [{"pid": 101, "token": "old"}],
                        "managed": {"id": "orphan", "created": True}})
    service.update("release", 0)
    assert stopped == [{"id": "orphan", "created": True}]
    assert service.read_state() == {"leases": [], "managed": None}


def test_generator_entrypoints_release_embedding_lease_on_exit() -> None:
    root = Path(__file__).resolve().parents[1]
    single = (root / "scripts/hgb_generate_harness.sh").read_text()
    matrix = (root / "scripts/hgb_generate_matrix.sh").read_text()
    retry = (root / "scripts/hgb_retry_promefuzz.sh").read_text()
    assert "hgb_release_embedding_service" in single
    assert "trap 'hgb_release_embedding_service || true' EXIT" in matrix
    assert "trap release_embedding_on_exit EXIT" in retry
    assert "reap_embedding_service(ROOT)" in (root / "scripts/hgb_eval_all.py").read_text()
