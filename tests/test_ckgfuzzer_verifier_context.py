from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


context = _load_module("ckgfuzzer_verifier_context", "docker/common/ckgfuzzer_verifier_context.py")


def _target(tmp_path: Path, *, checkout_status: str = "checked_out_ref") -> Path:
    target = tmp_path / "target"
    benchmark = target / "fuzzbench_benchmark"
    source = target / "source_input" / "project"
    benchmark.mkdir(parents=True)
    source.mkdir(parents=True)
    source.joinpath("api.c").write_text("int api(void) { return 0; }\n", encoding="utf-8")
    benchmark.joinpath("Dockerfile").write_text(
        "FROM scratch\nRUN git clone https://example.invalid/project.git && cd project && ./configure\nCOPY * /src/\n",
        encoding="utf-8",
    )
    target.joinpath("source_repos.json").write_text(
        "["
        '{"kind":"git","url":"https://example.invalid/project.git","dest":"project",'
        f'"checkout_status":"{checkout_status}","copy_status":"copied_to_source_input"'
        "}]\n",
        encoding="utf-8",
    )
    return target


def test_sealed_context_uses_snapshot_and_removes_git_clone(tmp_path: Path) -> None:
    target = _target(tmp_path)

    result = context.prepare_verification_context(target, tmp_path / "work")
    dockerfile = Path(result["dockerfile"]).read_text(encoding="utf-8")

    assert result["mode"] == "sealed_source_snapshot"
    assert result["removed_acquisition_commands"] == 1
    assert "COPY source_input/ /src/" in dockerfile
    assert "git clone" not in dockerfile
    assert "cd project && ./configure" in dockerfile


def test_sealed_context_rejects_unpinned_source(tmp_path: Path) -> None:
    target = _target(tmp_path, checkout_status="commit_not_found_kept_head")

    with pytest.raises(context.VerificationContextError, match="not pinned"):
        context.prepare_verification_context(target, tmp_path / "work")


def test_sealed_context_rejects_explicitly_unresolved_revision(tmp_path: Path) -> None:
    target = _target(tmp_path)
    provenance = target / "source_repos.json"
    provenance.write_text(
        provenance.read_text(encoding="utf-8").replace(
            '"copy_status":"copied_to_source_input"',
            '"copy_status":"copied_to_source_input","revision_status":"unresolved"',
        ),
        encoding="utf-8",
    )

    with pytest.raises(context.VerificationContextError, match="revision is unresolved"):
        context.prepare_verification_context(target, tmp_path / "work")


def test_ckgfuzzer_image_installs_sealed_context_helper() -> None:
    dockerfile = Path("docker/ckgfuzzer/Dockerfile").read_text(encoding="utf-8")

    assert "docker/common/ckgfuzzer_verifier_context.py" in dockerfile
