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
    assert selected.selected_reference == "fuzzbench_benchmark/fuzz_target.cc"
    reference = subprocess.run(
        [
            sys.executable,
            "docker/common/hgb_target_harness.py",
            "--target-root", str(target), "--fuzz-target", "fuzz_target", "--field", "reference",
        ],
        text=True, capture_output=True, check=False,
    )
    assert reference.returncode == 0, reference.stderr
    assert reference.stdout.strip() == "fuzzbench_benchmark/fuzz_target.cc"



def test_fuzzbench_workdir_resolver_handles_relative_workdir(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM base\nWORKDIR $SRC\nWORKDIR zlib\n", encoding="utf-8")
    entrypoint = Path("docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")
    start = entrypoint.index("fuzzbench_build_workdir() {")
    end = entrypoint.index("is_positive_integer() {", start)
    command = entrypoint[start:end] + '\nfuzzbench_build_workdir "$1"\n'
    result = subprocess.run(
        ["bash", "-c", command, "bash", str(dockerfile)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "zlib"
    dockerfile.write_text("FROM base\nWORKDIR $SRC/curl_fuzzer\n", encoding="utf-8")
    src_workdir = subprocess.run(
        ["bash", "-c", command, "bash", str(dockerfile)],
        text=True,
        capture_output=True,
        check=False,
    )
    assert src_workdir.returncode == 0, src_workdir.stderr
    assert src_workdir.stdout.strip() == "curl_fuzzer"


def test_native_target_build_wrapper_overlays_candidate_and_requires_target(tmp_path: Path) -> None:
    template = tmp_path / "template"
    template.mkdir()
    (template / "project").mkdir()
    (template / "seeds").mkdir()
    (template / "seeds" / "seed").write_text("seed", encoding="utf-8")
    (template / "package-1.0").mkdir()
    (template / "build.sh").write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\ntest \"$PWD\" = \"$SRC/project\"\ntest -f \"$SRC/package-1.0.tar.xz\"\ngrep -q HGB_CANDIDATE_MARKER \"$SRC/fuzz_target.cc\"\nprintf '%s\\n' '#!/bin/sh' 'exit 0' >\"$OUT/fuzz_target\"\nchmod +x \"$OUT/fuzz_target\"\n",
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
        "PROME_FUZZ_NATIVE_BUILD_WORKDIR_RELATIVE": "project",
        "PROME_FUZZ_NATIVE_BUILD_LOG_DIR": str(tmp_path / "native-build-logs"),
        "PROME_FUZZ_NATIVE_RUN_LOG_DIR": str(tmp_path / "native-run-logs"),
        "PROME_FUZZ_NATIVE_CONTAINER_SRC_ROOT": str(tmp_path / "container-src"),
        "PROME_FUZZ_NATIVE_CONTAINER_SEED_ROOT": str(tmp_path / "container-seeds"),
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
    assert (tmp_path / "container-src").is_symlink()
    assert (tmp_path / "container-src").resolve() == tmp_path / "native" / "src"
    assert (tmp_path / "container-seeds").is_symlink()
    assert (tmp_path / "container-seeds").resolve() == tmp_path / "native" / "src" / "seeds"
    assert (tmp_path / "native-build-logs" / "candidate.log").is_file()
    assert (tmp_path / "native-run-logs" / "candidate.log").is_file()


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
    assert "libclang-rt-18-dev" in dockerfile
    assert "zlib1g-dev" in dockerfile
    assert "autoconf automake libtool" in dockerfile
    assert "-Wno-register" in Path("docker/common/promefuzz_target_build.sh").read_text(encoding="utf-8")
    assert "nasm" in dockerfile
    assert "/usr/local/bin/python3.8" in dockerfile
    assert os.access(Path("docker/common/promefuzz_target_build.sh"), os.X_OK)
    assert "filter_compile_db \"$compile_db\" cmake" in entrypoint
    assert "PROME_FUZZ_DRIVER_BUILD_WRAPPER" in entrypoint
    assert 'bash /opt/hgb/bin/promefuzz_target_build.sh "$baseline_source" "$baseline_binary"' in entrypoint
    assert '["bash", build_wrapper, str(src_path), str(bin_path)]' in entrypoint
    assert "fuzzbench_build_workdir" in entrypoint
    assert "fuzzbench_target_build_available" in entrypoint
    assert 'FUZZER="${FUZZER:-libfuzzer}"' in entrypoint
    assert "PROME_FUZZ_NATIVE_BUILD_WORKDIR_RELATIVE" in entrypoint
    assert "HGB_PROMEFUZZ_VALIDATE_TARGET_BASELINE" in entrypoint
    assert "PROME_FUZZ_POOL_SIZE" in entrypoint
    assert "--pool-size" in entrypoint
    assert "ExceededBudget" in entrypoint
    assert "final_driver_dir" in entrypoint
    assert "temporary retry sources were not retained as results" in entrypoint
    assert "src/lib_json" not in entrypoint
    assert "include/json/json.h" not in entrypoint
    patch_start = entrypoint.index('driver_py = root / "src/generator/driver.py"')
    patch_end = entrypoint.index('preprocess_py = root / "cli/preprocess.py"', patch_start)
    exec(entrypoint[patch_start:patch_end], {"root": runtime})
    py_compile.compile(str(driver), doraise=True)
    assert "PROME_FUZZ_DRIVER_BUILD_WRAPPER" in driver.read_text(encoding="utf-8")


def test_matrix_retains_generator_preflight_failures() -> None:
    matrix = Path("scripts/hgb_generate_matrix.sh").read_text(encoding="utf-8")
    single = Path("scripts/hgb_generate_harness.sh").read_text(encoding="utf-8")

    assert "record_preflight_failure" in matrix
    assert "generator_preflight_failed" in matrix
    assert 'if preflight_generator "$generator"; then' in matrix
    assert "rebuilding stale PromeFuzz image" in matrix
    assert "rebuilding stale PromeFuzz image" in single


def test_image_build_failure_returns_to_matrix_preflight_handler(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    command = """
source scripts/lib/common.sh
docker() {
  case "$1" in
    info) return 0 ;;
    build) return 37 ;;
    image) return 1 ;;
  esac
  return 0
}
code=0
hgb_build_image promefuzz promefuzz "$PWD" >/dev/null || code=$?
[[ "$code" == "37" ]]
"""
    result = subprocess.run(
        ["bash", "-c", command],
        cwd=repo_root,
        env=os.environ | {"HGB_WORKSPACE_DIR": str(tmp_path / "workspace")},
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_native_target_build_wrapper_preserves_build_script_errexit(tmp_path: Path) -> None:
    template = tmp_path / "template"
    template.mkdir()
    (template / "build.sh").write_text(
        "#!/usr/bin/env bash -eu\nfalse\nprintf '%s\\n' '#!/bin/sh' 'exit 0' >\"$OUT/fuzz_target\"\nchmod +x \"$OUT/fuzz_target\"\n",
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
        "PROME_FUZZ_NATIVE_CONTAINER_SRC_ROOT": str(tmp_path / "container-src"),
    }

    result = subprocess.run(
        ["bash", "docker/common/promefuzz_target_build.sh", str(candidate), str(binary)],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 68
