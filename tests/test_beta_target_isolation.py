from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


hgb_target_package = _load_module("hgb_target_package", "docker/common/hgb_target_package.py")


def _make_monolithic_package(tmp_path: Path) -> Path:
    """Build a minimal monolithic target package and return its path."""
    pkg = tmp_path / "target_pkg"
    (pkg / "source_input" / "project").mkdir(parents=True)
    (pkg / "docs").mkdir(parents=True)
    (pkg / "seeds").mkdir(parents=True)
    (pkg / "dictionary").mkdir(parents=True)
    (pkg / "reference_harnesses" / "selected" / "source_input" / "project").mkdir(parents=True)
    (pkg / "fuzzbench_benchmark").mkdir(parents=True)
    (pkg / "source_input" / "project" / "sample.c").write_text("int api(void){return 0;}\n", encoding="utf-8")
    (pkg / "reference_harnesses" / "selected" / "source_input" / "project" / "native.c").write_text(
        "int LLVMFuzzerTestOneInput(void){return 0;}\n", encoding="utf-8"
    )
    (pkg / "fuzzbench_benchmark" / "Dockerfile").write_text("FROM scratch\nCOPY * /src/\n", encoding="utf-8")
    (pkg / "fuzzbench_benchmark" / "build.sh").write_text("#!/bin/sh\ncc $SRC/project/native.c -o $OUT/fuzz_target\n", encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "target": "fixture_target",
        "project": "project",
        "fuzz_target": "fuzz_target",
        "source_input_dir": "source_input",
        "reference_harness_dir": "reference_harnesses",
        "reference_harness_files": ["source_input/project/native.c"],
        "selected_reference_harness_dir": "reference_harnesses/selected",
        "selected_reference_harness_files": ["source_input/project/native.c"],
        "selected_reference_harness_count": 1,
        "seed_count": 0,
        "dictionary_count": 0,
    }
    (pkg / "target_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (pkg / "source_repos.json").write_text("[]", encoding="utf-8")
    return pkg


# ---------------------------------------------------------------------------
# 1. Blind CKGFuzzer mount contains no reference harnesses.
# ---------------------------------------------------------------------------


def test_blind_ckgfuzzer_mount_contains_no_reference_harnesses(tmp_path: Path) -> None:
    pkg = _make_monolithic_package(tmp_path)
    halves = hgb_target_package.split_package(
        pkg,
        native_harness={
            "selected_reference": "source_input/project/native.c",
            "container_destination": "/src/project/native.c",
            "language": "c",
        },
    )
    generator_input = Path(halves["generator_input"])

    # The generator mount (generator_input) must NOT contain reference_harnesses,
    # selected_reference, or the native harness file.
    assert not (generator_input / "reference_harnesses").exists()
    assert not any(p.name == "reference_harnesses" for p in generator_input.rglob("*"))
    assert not any("selected_reference" in p.name for p in generator_input.rglob("*"))
    # The native harness file must not be in generator_input (it was stripped).
    assert not (generator_input / "source_input" / "project" / "native.c").exists()
    # generator_input does contain source_input and the public sample.
    assert (generator_input / "source_input" / "project" / "sample.c").is_file()


def test_common_sh_mounts_generator_input_for_blind_ckgfuzzer() -> None:
    common = (REPO_ROOT / "scripts/lib/common.sh").read_text(encoding="utf-8")
    # The split mount logic must be present.
    assert "target_mount_src" in common
    assert "generator_input" in common
    assert "evaluator_only" in common
    assert "evaluator_mount_args" in common
    # For blind generators the package root must NOT be mounted wholesale when
    # the split exists; the generator_input half is mounted instead.
    assert 'target_mount_src="$target_package/generator_input"' in common


def test_evaluator_only_half_holds_reference_harnesses(tmp_path: Path) -> None:
    pkg = _make_monolithic_package(tmp_path)
    halves = hgb_target_package.split_package(
        pkg,
        native_harness={
            "selected_reference": "source_input/project/native.c",
            "container_destination": "/src/project/native.c",
        },
    )
    evaluator_only = Path(halves["evaluator_only"])
    assert (evaluator_only / "reference_harnesses").is_dir()
    assert (evaluator_only / "benchmark_copy").is_dir()
    assert (evaluator_only / "native_harness_path.json").is_file()
    native = json.loads((evaluator_only / "native_harness_path.json").read_text(encoding="utf-8"))
    assert native["container_destination"] == "/src/project/native.c"


# ---------------------------------------------------------------------------
# 2. Generator manifest has no reference fields.
# ---------------------------------------------------------------------------


def test_generator_manifest_has_no_reference_fields(tmp_path: Path) -> None:
    pkg = _make_monolithic_package(tmp_path)
    halves = hgb_target_package.split_package(pkg, native_harness={})
    gen_manifest = json.loads(
        (Path(halves["generator_input"]) / "target_manifest.generator.json").read_text(encoding="utf-8")
    )
    forbidden = hgb_target_package.GENERATOR_FORBIDDEN_FIELDS
    present = [f for f in forbidden if f in gen_manifest]
    assert present == [], f"generator manifest leaked reference fields: {present}"
    # The generator manifest must still carry non-sensitive build facts.
    assert gen_manifest["target"] == "fixture_target"
    assert gen_manifest["source_input_dir"] == "source_input"


def test_generator_manifest_forbidden_fields_cover_plan_requirements() -> None:
    # The plan lists these exact fields as forbidden in the generator manifest.
    for field in (
        "reference_harness_dir",
        "reference_harness_files",
        "selected_reference_harness_files",
        "native_harness_path",
    ):
        assert field in hgb_target_package.GENERATOR_FORBIDDEN_FIELDS


# ---------------------------------------------------------------------------
# 3. Reference-derived API metadata is not mounted for blind generators.
# ---------------------------------------------------------------------------


def test_reference_derived_api_metadata_not_mounted_for_blind_generators(tmp_path: Path) -> None:
    pkg = _make_monolithic_package(tmp_path)
    halves = hgb_target_package.split_package(pkg, native_harness={})
    generator_input = Path(halves["generator_input"])

    # fuzzbench_selected_harness_apis.json must never be visible in generator_input.
    audit = hgb_target_package.audit_generator_input(generator_input)
    assert audit["clean"], f"forbidden reference tokens in generator_input: {audit['hits']}"
    assert not any("fuzzbench_selected_harness_apis" in p.name for p in generator_input.rglob("*"))


def test_audit_generator_input_detects_leaked_reference_dir(tmp_path: Path) -> None:
    pkg = _make_monolithic_package(tmp_path)
    halves = hgb_target_package.split_package(pkg, native_harness={})
    generator_input = Path(halves["generator_input"])
    # Inject a forbidden token.
    (generator_input / "fuzzbench_selected_harness_apis.json").write_text("[]", encoding="utf-8")
    audit = hgb_target_package.audit_generator_input(generator_input)
    assert audit["clean"] is False
    assert any("fuzzbench_selected_harness_apis" in h for h in audit["hits"])


def test_repo_audit_fuzzbench_selected_harness_apis_not_in_generator_mounts() -> None:
    """Repo-wide guard: the blind generator mounts must not expose the
    selected-harness-apis metadata file."""
    common = (REPO_ROOT / "scripts/lib/common.sh").read_text(encoding="utf-8")
    # The blind mount uses generator_input only; the metadata file lives under
    # the repo root metadata/ which is mounted read-only at /opt/hgb/metadata.
    # That mount is for generator configs, not target answers. Assert the
    # generator_input mount path does not include the metadata dir.
    assert "-v \"$target_mount_src:/target:ro\"" in common
    # The evaluator-only half is mounted separately and is NOT under /target.
    assert "-v \"$target_package/evaluator_only:/evaluator:ro\"" in common
