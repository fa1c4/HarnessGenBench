from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


harness = _load_module("ckgfuzzer_target_harness", "docker/common/ckgfuzzer_target_harness.py")


def _target(tmp_path: Path, selected: list[str], build_script: str) -> Path:
    target = tmp_path / "target"
    benchmark = target / "fuzzbench_benchmark"
    benchmark.mkdir(parents=True)
    (benchmark / "build.sh").write_text(build_script, encoding="utf-8")
    (target / "target_manifest.json").write_text(
        json.dumps({"selected_reference_harness_files": selected}), encoding="utf-8"
    )
    return target


def test_source_snapshot_harness_uses_exact_manifest_path(tmp_path: Path) -> None:
    target = _target(
        tmp_path,
        ["source_input/bloaty/tests/fuzz_target.cc"],
        "cmake -G Ninja $SRC/bloaty\n",
    )

    selected = harness.select_native_harness(target, "fuzz_target")

    assert selected.container_destination == "/src/bloaty/tests/fuzz_target.cc"
    assert selected.language == "c++"


def test_native_build_path_beats_same_name_source_copy(tmp_path: Path) -> None:
    target = _target(
        tmp_path,
        [
            "fuzzbench_benchmark/mruby_fuzzer.c",
            "source_input/mruby/oss-fuzz/mruby_fuzzer.c",
        ],
        "FUZZ_TARGET=$SRC/mruby_fuzzer.c\n$CC $FUZZ_TARGET -o $OUT/mruby_fuzzer\n",
    )

    selected = harness.select_native_harness(target, "mruby_fuzzer_8c8bbd")

    assert selected.selected_reference == "fuzzbench_benchmark/mruby_fuzzer.c"
    assert selected.container_destination == "/src/mruby_fuzzer.c"
    assert selected.language == "c"


def test_build_script_selects_benchmark_target_over_other_reference(tmp_path: Path) -> None:
    target = _target(
        tmp_path,
        ["fuzzbench_benchmark/target.cc", "source_input/re2/re2/fuzzing/re2_fuzzer.cc"],
        "$CXX $CXXFLAGS $SRC/target.cc -o $OUT/fuzzer\n",
    )

    selected = harness.select_native_harness(target, "fuzzer")

    assert selected.selected_reference == "fuzzbench_benchmark/target.cc"
    assert selected.container_destination == "/src/target.cc"
