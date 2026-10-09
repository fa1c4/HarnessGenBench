from __future__ import annotations

import shutil
import sys
import py_compile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker/common"))
import ckgfuzzer_prompt_patch as patcher  # noqa: E402


def test_patch_real_upstream_prompts_is_idempotent(tmp_path: Path) -> None:
    for rel in (patcher.GENERATOR_REL, patcher.FIXER_REL):
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "artifacts/ckgfuzzer" / rel, target)

    first = patcher.patch_artifact(tmp_path)
    assert all(first.values())
    assert patcher.patch_artifact(tmp_path) == {key: False for key in first}
    generator = (tmp_path / patcher.GENERATOR_REL).read_text()
    fixer = (tmp_path / patcher.FIXER_REL).read_text()
    assert generator.count("Do not define, stub, mock, or reimplement") == 2
    assert generator.count("Include only project headers that exist") == 2
    assert generator.count("#ifdef __cplusplus / #endif guard") == 2
    assert fixer.count("Do not add project API stubs") == 2
    py_compile.compile(str(tmp_path / patcher.GENERATOR_REL), doraise=True)


def test_patch_fails_if_upstream_prompts_change(tmp_path: Path) -> None:
    for rel in (patcher.GENERATOR_REL, patcher.FIXER_REL):
        target = tmp_path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("different upstream prompt\n")
    with pytest.raises(ValueError, match="upstream prompt shape changed"):
        patcher.patch_artifact(tmp_path)
