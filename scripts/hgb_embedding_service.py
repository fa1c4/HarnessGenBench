#!/usr/bin/env python3
"""Lease the shared local embedding container to active generator processes."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / "workspace/.embedding_service"
CONTAINER = os.environ.get("HGB_EMBEDDING_CONTAINER_NAME", "hgb-local-embedding")
PORT = int(os.environ.get("HGB_EMBEDDING_PORT", "18080"))


def process_token(pid: int) -> str | None:
    try:
        # /proc/<pid>/stat field 22 identifies a process even if its PID is reused.
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return None if fields[0] == "Z" else fields[19]
    except (OSError, IndexError):
        return None


def live_leases(leases: list[dict]) -> list[dict]:
    return [lease for lease in leases
            if isinstance(lease, dict) and process_token(int(lease.get("pid") or 0)) == lease.get("token")]


def container_info() -> dict[str, str] | None:
    result = subprocess.run(
        ["docker", "inspect", "--format",
         '{{.Id}}|{{.State.Running}}|{{index .Config.Labels "hgb.service"}}', CONTAINER],
        capture_output=True, text=True, timeout=20, check=False)
    if result.returncode:
        if "No such object" in result.stderr or "No such container" in result.stderr:
            return None
        raise RuntimeError(f"docker inspect failed: {result.stderr.strip()}")
    container_id, running, label = result.stdout.strip().split("|", 2)
    if label != "hgb-local-embedding":
        raise RuntimeError(f"{CONTAINER} is not an HGB embedding service")
    return {"id": container_id, "running": running}


def health_ok() -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=5) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError):
        return False


def wait_health(seconds: int = 180) -> None:
    deadline = time.monotonic() + seconds
    while True:
        if health_ok():
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"local embedding service did not become ready within {seconds}s")
        time.sleep(3)


def start_service(existing: dict[str, str] | None) -> dict[str, str | bool]:
    created = existing is None
    try:
        if existing is not None:
            subprocess.run(["docker", "start", CONTAINER], capture_output=True,
                           text=True, timeout=60, check=True)
        else:
            subprocess.run(["bash", str(ROOT / "scripts/local_embedding_server.sh"), "start"],
                           capture_output=True, text=True, timeout=360, check=True)
        current = container_info()
        if current is None or current["running"] != "true":
            raise RuntimeError("local embedding container did not start")
        wait_health()
    except Exception:
        # The startup script can create the container and then fail its probe.
        # Do not leave that unleased service running.
        try:
            current = container_info()
            if current is not None and current["running"] == "true":
                stop_service({"id": current["id"], "created": created})
        except (OSError, RuntimeError, subprocess.SubprocessError):
            pass
        raise
    return {"id": current["id"], "created": created}


def stop_service(managed: dict) -> None:
    current = container_info()
    if current is None or current["id"] != managed.get("id"):
        return  # Never stop a replacement or an independently started service.
    command = (["docker", "rm", "-f", CONTAINER] if managed.get("created") else
               ["docker", "stop", CONTAINER])
    subprocess.run(command, capture_output=True, text=True, timeout=120, check=True)
    metadata = ROOT / "results/local_embedding_service.json"
    if metadata.is_file():
        try:
            if json.loads(metadata.read_text(encoding="utf-8")).get("container_name") == CONTAINER:
                metadata.unlink()
        except (OSError, ValueError, AttributeError):
            pass


def read_state() -> dict:
    path = STATE_DIR / "state.json"
    if not path.exists():
        return {"leases": [], "managed": None}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("leases"), list):
        raise RuntimeError("invalid embedding service lease state")
    return data


def save_state(state: dict) -> None:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=STATE_DIR,
                                     delete=False) as handle:
        temporary = Path(handle.name)
        json.dump(state, handle, sort_keys=True)
        handle.write("\n")
    temporary.replace(STATE_DIR / "state.json")


def update(action: str, pid: int) -> None:
    token = process_token(pid)
    if token is None and action == "acquire":
        raise RuntimeError(f"embedding lease owner {pid} is not running")
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with (STATE_DIR / "lifecycle.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = read_state()
        state["leases"] = live_leases(state["leases"])
        if action == "acquire":
            current = container_info()
            managed = state.get("managed")
            if not current or not isinstance(managed, dict) or managed.get("id") != current["id"]:
                state["managed"] = None
            if current is None or current["running"] != "true":
                state["managed"] = start_service(current)
            else:
                wait_health()
            if not any(lease.get("pid") == pid and lease.get("token") == token
                       for lease in state["leases"]):
                state["leases"].append({"pid": pid, "token": token})
        else:
            state["leases"] = [lease for lease in state["leases"]
                               if not (lease.get("pid") == pid and lease.get("token") == token)]
            if not state["leases"] and isinstance(state.get("managed"), dict):
                stop_service(state["managed"])
                state["managed"] = None
        save_state(state)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("acquire", "release", "reap"))
    parser.add_argument("--pid", type=int)
    args = parser.parse_args()
    if args.action != "reap" and args.pid is None:
        parser.error("--pid is required for acquire and release")
    try:
        update("release", 0) if args.action == "reap" else update(args.action, args.pid)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"embedding service {args.action} failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
