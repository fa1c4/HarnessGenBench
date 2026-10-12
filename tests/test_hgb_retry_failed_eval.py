import csv
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace


SPEC = importlib.util.spec_from_file_location(
    "hgb_retry_failed_eval", Path(__file__).resolve().parents[1] / "scripts/hgb_retry_failed_eval.py"
)
assert SPEC and SPEC.loader
retry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(retry)


def test_retry_waits_for_prior_service_and_keeps_a_csv_snapshot(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(retry, "ROOT", tmp_path)
    output = tmp_path / "results/eval_all/2026-10-11.csv"
    output.parent.mkdir(parents=True)

    def write(status: str) -> None:
        with output.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["target", *[f"{b}_status" for b in retry.BASELINES]])
            writer.writeheader()
            writer.writerow({"target": "example", **{f"{b}_status": status if b == "promefuzz" else "evaluated"
                                                     for b in retry.BASELINES}})

    write("quality_failure")
    commands = []

    def fake_run(command, **_kwargs):
        commands.append(command)
        if command[:3] == ["systemctl", "--user", "is-active"]:
            return SimpleNamespace(returncode=3, stdout="inactive\n")
        assert "--resume" in command
        assert command[command.index("--parallel-worker") + 1] == "32"
        write("evaluated")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(retry.subprocess, "run", fake_run)
    monkeypatch.setattr(sys, "argv", ["hgb_retry_failed_eval.py", "--date", "2026-10-11",
                                      "--after-unit", "original.service", "--max-attempts", "1"])
    assert retry.main() == 0
    assert commands[0][:3] == ["systemctl", "--user", "is-active"]
    snapshot = output.with_name("2026-10-11.before_retry_1.csv")
    assert snapshot.is_file()
    assert "quality_failure" in snapshot.read_text()
