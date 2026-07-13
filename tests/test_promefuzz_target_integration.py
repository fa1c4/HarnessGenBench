from __future__ import annotations

import importlib.util
import json
import os
import py_compile
import subprocess
import sys
from pathlib import Path


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


compile_db = _load_module("hgb_compile_db", "docker/common/hgb_compile_db.py")
harness = _load_module("hgb_target_harness", "docker/common/hgb_target_harness.py")


def test_compile_db_filter_drops_cmake_probes_and_keeps_target_source(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "library.cc"
    source.write_text("int library() { return 0; }\n", encoding="utf-8")
    cmake_dir = tmp_path / "build" / "CMakeFiles" / "3.28.0" / "CompilerIdCXX"
    cmake_dir.mkdir(parents=True)
    probe = cmake_dir / "CMakeCXXCompilerId.cpp"
    probe.write_text("int main() {}\n", encoding="utf-8")
    database = tmp_path / "compile_commands.json"
    database.write_text(
        json.dumps(
            [
                {"directory": str(source_root), "file": str(source), "command": "clang++ -c library.cc"},
                {"directory": str(cmake_dir), "file": str(probe), "command": "clang++ -c CMakeCXXCompilerId.cpp"},
                {"directory": str(source_root), "file": "missing.cc", "command": "clang++ -c missing.cc"},
            ]
        ),
        encoding="utf-8",
    )

    total, retained = compile_db.filter_file(database, database, [source_root])

    assert (total, retained) == (3, 1)
    result = json.loads(database.read_text(encoding="utf-8"))
    assert [entry["file"] for entry in result] == [str(source)]


def test_native_harness_resolver_prefers_fuzzbench_build_destination(tmp_path: Path) -> None:
    target = tmp_path / "target"
    benchmark = target / "fuzzbench_benchmark"
    benchmark.mkdir(parents=True)
    (benchmark / "build.sh").write_text("$CXX $SRC/fuzz_target.cc -o $OUT/fuzz_target\n", encoding="utf-8")
    (target / "target_manifest.json").write_text(
        json.dumps(
            {"selected_reference_harness_files": ["fuzzbench_benchmark/fuzz_target.cc"]}
        ),
        encoding="utf-8",
    )

    selected = harness.select_native_harness(target, "fuzz_target")

    assert selected.container_destination == "/src/fuzz_target.cc"
    assert selected.language == "c++"


def test_native_target_build_wrapper_overlays_candidate_and_requires_target(tmp_path: Path) -> None:
    template = tmp_path / "template"
    template.mkdir()
    (template / "build.sh").write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\ngrep -q HGB_CANDIDATE_MARKER \"$SRC/fuzz_target.cc\"\nprintf '%s\\n' '#!/bin/sh' 'exit 0' >\"$OUT/fuzz_target\"\nchmod +x \"$OUT/fuzz_target\"\n",
        encoding="utf-8",
    )
    candidate = tmp_path / "candidate.cc"
    candidate.write_text("// HGB_CANDIDATE_MARKER\n", encoding="utf-8")
    binary = tmp_path / "candidate_binary"
    env = os.environ | {
        "PROME_FUZZ_NATIVE_SOURCE_TEMPLATE": str(template),
        "PROME_FUZZ_NATIVE_BUILD_ROOT": str(tmp_path / "native"),
        "PROME_FUZZ_NATIVE_HARNESS_DESTINATION": "/src/fuzz_target.cc",
        "PROME_FUZZ_NATIVE_FUZZ_TARGET": "fuzz_target",
    }

    result = subprocess.run(
        ["bash", "docker/common/promefuzz_target_build.sh", str(candidate), str(binary)],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert binary.is_file() and os.access(binary, os.X_OK)
    assert (tmp_path / "native" / "src" / "fuzz_target.cc").read_text(encoding="utf-8") == candidate.read_text(encoding="utf-8")


def test_promefuzz_integration_uses_final_native_validated_artifacts(tmp_path: Path) -> None:
    entrypoint = Path("docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")
    dockerfile = Path("docker/promefuzz/Dockerfile").read_text(encoding="utf-8")
    runtime = tmp_path / "runtime"
    driver = runtime / "src" / "generator" / "driver.py"
    driver.parent.mkdir(parents=True)
    driver.write_text(
        """import threading
import subprocess

class Driver:
    def build(self, src_path, bin_path, build_cmd):
        logger.debug(f"Building fuzz driver {self.id} with command: {build_cmd}")

        # build fuzz driver
        try:
            output = subprocess.check_output(
                build_cmd, stderr=subprocess.STDOUT, shell=True, text=True
            )
        except Exception:
            return False

    def check(self, func, calling):
        if f"{func.name.split("::")[-1]}(":
            return
        logger.warning(
            f"Function in fuzz driver does not exist in API collection: {calling["calleeName"]} at {calling["calleeDeclLoc"]}"
        )
""",
        encoding="utf-8",
    )


    assert "hgb_compile_db.py" in dockerfile
    assert "hgb_target_harness.py" in dockerfile
    assert "promefuzz_target_build.sh" in dockerfile
    assert "filter_compile_db \"$compile_db\" cmake" in entrypoint
    assert "PROME_FUZZ_DRIVER_BUILD_WRAPPER" in entrypoint
    assert "final_driver_dir" in entrypoint
    assert "temporary retry sources were not retained as results" in entrypoint
    assert "src/lib_json" not in entrypoint
    assert "include/json/json.h" not in entrypoint
    patch_start = entrypoint.index('driver_py = root / "src/generator/driver.py"')
    patch_end = entrypoint.index('preprocess_py = root / "cli/preprocess.py"', patch_start)
    exec(entrypoint[patch_start:patch_end], {"root": runtime})
    py_compile.compile(str(driver), doraise=True)
    assert "PROME_FUZZ_DRIVER_BUILD_WRAPPER" in driver.read_text(encoding="utf-8")
