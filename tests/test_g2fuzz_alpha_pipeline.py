from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


g2 = load_module("g2fuzz_target_pipeline", ROOT / "docker/common/g2fuzz_target_pipeline.py")
matrix_collector = load_module("hgb_collect_matrix_g2", ROOT / "scripts/hgb_collect_matrix.py")


def make_executable(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)
    return path


def make_target_package(base: Path, target: str = "libpng_libpng_read_fuzzer") -> Path:
    package = base / "target"
    bench = package / "fuzzbench_benchmark"
    bench.mkdir(parents=True)
    (package / "target_manifest.json").write_text(
        json.dumps(
            {
                "target": target,
                "project": target.split("_", 1)[0],
                "fuzz_target": target,
                "fuzzbench_commit": "fixture",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (bench / "benchmark.yaml").write_text(f"project: {target}\nfuzz_target: {target}\n", encoding="utf-8")
    (bench / "build.sh").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    (bench / "build.sh").chmod(0o755)
    return package


def fake_pair(pair_dir: Path, program: str = "libpng_libpng_read_fuzzer") -> None:
    pair_dir.mkdir(parents=True)
    script = "#!/usr/bin/env bash\nif [[ \"${1:-}\" == \"--fail\" ]]; then exit 1; fi\nexit 0\n"
    make_executable(pair_dir / f"{program}.afl", script)
    make_executable(pair_dir / f"{program}.cmp", script)


def fake_program_gen(path: Path) -> Path:
    return make_executable(
        path,
        """#!/usr/bin/env python3
import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--output", required=True)
parser.add_argument("--program", required=True)
args = parser.parse_args()
root = Path(args.output) / "default"
(root / "generators").mkdir(parents=True, exist_ok=True)
(root / "gen_seeds").mkdir(parents=True, exist_ok=True)
(root / "generators" / f"{args.program}_generator.py").write_text("print('seed')\\n", encoding="utf-8")
(root / "gen_seeds" / "id_000000").write_bytes(b"fixture-seed")
(root / "gen_seeds" / "config.json").write_text("not python, but generated seed-like data\\n", encoding="utf-8")
""",
    )


def fake_afl_fuzz(path: Path) -> Path:
    return make_executable(
        path,
        """#!/usr/bin/env python3
import sys
from pathlib import Path

out = None
for index, arg in enumerate(sys.argv):
    if arg == "-o" and index + 1 < len(sys.argv):
        out = Path(sys.argv[index + 1])
if out is None:
    raise SystemExit(2)
queue = out / "default" / "queue"
crashes = out / "default" / "crashes"
hangs = out / "default" / "hangs"
queue.mkdir(parents=True, exist_ok=True)
crashes.mkdir(parents=True, exist_ok=True)
hangs.mkdir(parents=True, exist_ok=True)
(queue / "id:000000,orig:seed").write_bytes(b"queued")
(out / "default" / "fuzzer_stats").write_text("execs_done : 7\\npaths_total : 3\\n", encoding="utf-8")
raise SystemExit(0)
""",
    )


def fake_coverage_report(path: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "data": [
                    {
                        "totals": {
                            "lines": {"count": 12, "covered": 9},
                            "functions": {"count": 5, "covered": 4},
                            "regions": {"count": 10, "covered": 7},
                        }
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


def run_helper(tmp_path: Path, env: dict[str, str], target: str = "libpng_libpng_read_fuzzer") -> subprocess.CompletedProcess[str]:
    workspace = tmp_path / "workspace"
    package = make_target_package(tmp_path, target)
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "docker/common/g2fuzz_target_pipeline.py"),
            "full",
            "--workspace",
            str(workspace),
            "--target",
            target,
            "--target-package",
            str(package),
            "--artifact-dir",
            str(tmp_path / "artifact"),
            "--metadata-root",
            str(ROOT / "metadata"),
            "--profile",
            "alpha",
            "--protocol",
            "paper-native",
        ],
        cwd=ROOT,
        env=os.environ | env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_g2fuzz_contract_is_input_generator_and_runner_needs_no_allow_flag() -> None:
    contracts = g2.parse_simple_yaml(ROOT / "metadata/baseline_contracts.yaml")
    g2_contract = next(item for item in contracts["baselines"] if item["name"] == "g2fuzz")
    runner = (ROOT / "scripts/hgb_run_baseline.sh").read_text(encoding="utf-8")

    assert g2_contract["task_family"] == "input_generator"
    assert g2_contract["default_profile"] == "alpha"
    assert g2_contract["default_protocol"] == "paper-native"
    assert "--allow-input-generator" not in runner


def test_all_valuable_targets_have_g2fuzz_adapters_and_profile_labels() -> None:
    valuable = g2.valuable_targets(ROOT / "metadata")
    adapters = g2.load_adapters(ROOT / "metadata")
    paper = [target for target in valuable if adapters[target]["method_profile"] == "paper-faithful"]
    extension = [target for target in valuable if adapters[target]["method_profile"] == "extension"]

    assert len(valuable) == 20
    assert set(valuable) == set(adapters)
    assert len(paper) == 9
    assert len(extension) == 11
    for adapter in adapters.values():
        assert (ROOT / adapter["format_spec"]).is_file()
        assert adapter["applicability"] == "applicable"


def test_alpha_retains_all_formats_and_compat_smoke_is_the_only_truncated_profile() -> None:
    adapters = g2.load_adapters(ROOT / "metadata")
    bloaty = adapters["bloaty_fuzz_target"]

    assert g2.formats_for_profile(bloaty, "alpha", {"G2FUZZ_MAX_FORMATS": "1"}) == [
        "ELF",
        "Mach-O",
        "WebAssembly",
    ]
    assert g2.formats_for_profile(bloaty, "paper-faithful") == ["ELF", "Mach-O", "WebAssembly"]
    assert g2.formats_for_profile(bloaty, "compat-smoke") == ["ELF"]
    assert g2.try_num_for_profile("alpha", {}) == "3"
    assert g2.try_num_for_profile("compat-smoke", {}) == "1"


def test_invocation_resolution_supports_file_stdin_and_extra_argv() -> None:
    file_adapter = {
        "target": "t",
        "program_id": "p",
        "formats": ["JSON"],
        "input_mode": "file",
        "argv": ["--mode", "parse", "@@", "--strict"],
    }
    invocation = g2.resolved_invocation(file_adapter, "/bin/target")
    assert invocation["argv"] == ["/bin/target", "--mode", "parse", "@@", "--strict"]
    assert g2.argv_for_input(invocation, Path("/tmp/input")) == [
        "/bin/target",
        "--mode",
        "parse",
        "/tmp/input",
        "--strict",
    ]

    stdin_adapter = file_adapter | {"input_mode": "stdin", "argv": ["--stdin"]}
    stdin = g2.resolved_invocation(stdin_adapter, "/bin/target")
    assert stdin["uses_at_at"] is False
    assert g2.argv_for_input(stdin, Path("/tmp/input")) == ["/bin/target", "--stdin"]

    with pytest.raises(g2.PipelineError):
        g2.resolved_invocation(file_adapter | {"argv": []}, "/bin/target")


def test_missing_target_pair_is_infra_missing_and_nonzero(tmp_path: Path) -> None:
    result = run_helper(tmp_path, env={"G2FUZZ_PROGRAM_GEN": str(fake_program_gen(tmp_path / "program_gen.py"))})
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))

    assert result.returncode == 127
    assert metadata["status"] == "infra_missing"
    assert metadata["stages"]["target_pair_built"]["status"] == "infra_missing"


def test_fake_modified_afl_fixture_reaches_evaluated_with_separate_seed_counts(tmp_path: Path) -> None:
    pair = tmp_path / "pair"
    fake_pair(pair)
    program_gen = fake_program_gen(tmp_path / "program_gen.py")
    afl = fake_afl_fuzz(tmp_path / "afl-fuzz")
    coverage = fake_coverage_report(tmp_path / "coverage.json")

    result = run_helper(
        tmp_path,
        env={
            "G2FUZZ_TARGET_DIR": str(pair),
            "G2FUZZ_PROGRAM_GEN": str(program_gen),
            "G2FUZZ_AFL_FUZZ": str(afl),
            "G2FUZZ_AFL_TIMEOUT_SECONDS": "5",
            "G2FUZZ_COVERAGE_REPORT": str(coverage),
        },
    )

    assert result.returncode == 0, result.stderr
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    provenance = [
        json.loads(line)
        for line in (tmp_path / "workspace" / "seeds" / "provenance.jsonl").read_text(encoding="utf-8").splitlines()
    ]

    assert metadata["status"] == "evaluated"
    assert metadata["task_family"] == "input_generator"
    assert metadata["method_profile"] == "paper-faithful"
    assert metadata["generated_harness_count"] == 0
    assert metadata["generated_input_count"] == 1
    assert metadata["generator_count"] == 1
    assert metadata["queue_count"] == 1
    assert metadata["stages"]["coverage"]["status"] == "complete"
    assert (tmp_path / "workspace" / "generators" / "source" / "manifest.json").is_file()
    assert not any("generators/source" in item["original_path"] for item in provenance)
    assert {item["source_class"] for item in provenance} >= {"bootstrap", "g2_generated", "afl_queue"}


def test_build_command_pair_differs_only_by_instrumentation_and_output() -> None:
    adapter = g2.load_adapters(ROOT / "metadata")["libpng_libpng_read_fuzzer"]
    commands = g2.build_command_pair(adapter)

    assert commands["afl"]["argv"] == commands["cmp"]["argv"]
    afl_env = commands["afl"]["env"] | {"AFL_LLVM_CMPLOG": "X", "HGB_G2FUZZ_OUTPUT": "X"}
    cmp_env = commands["cmp"]["env"] | {"AFL_LLVM_CMPLOG": "X", "HGB_G2FUZZ_OUTPUT": "X"}
    assert afl_env == cmp_env
    assert commands["afl"]["env"]["AFL_LLVM_CMPLOG"] == "0"
    assert commands["cmp"]["env"]["AFL_LLVM_CMPLOG"] == "1"


def test_host_target_dir_is_mounted_to_container_visible_path_and_optional_data_is_not_copied() -> None:
    common = (ROOT / "scripts/lib/common.sh").read_text(encoding="utf-8")
    dockerfile = (ROOT / "docker/g2fuzz/Dockerfile").read_text(encoding="utf-8")
    entrypoint = (ROOT / "docker/g2fuzz/entrypoint.sh").read_text(encoding="utf-8")
    setup = (ROOT / "scripts/g2fuzz_setup.sh").read_text(encoding="utf-8")
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

    assert "/g2fuzz-target-pair" in common
    assert "-e G2FUZZ_TARGET_DIR=/g2fuzz-target-pair" in common
    assert '-v "$root/artifacts/g2fuzz:/opt/hgb/artifacts/g2fuzz:ro"' in common
    assert "prepare_g2fuzz_runtime_artifact" in entrypoint
    assert 'cp -a "$source_artifact"/. "$runtime_artifact"/' in entrypoint
    assert 'export HGB_GENERATOR_ARTIFACT_DIR="$artifact"' in entrypoint
    assert "COPY artifacts/g2fuzz-data" not in dockerfile
    assert "ensure_artifacts_present \"$root\" \"g2fuzz\" \"g2fuzz-data\"" not in setup
    assert "smoke-g2fuzz:\n\tbash scripts/g2fuzz_smoke_afl.sh\n" in makefile
    assert "smoke-g2fuzz:\n\tbash scripts/g2fuzz_generate_seeds.sh || true" not in makefile


def test_matrix_summary_separates_input_and_harness_families(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    g2_ws = tmp_path / "g2"
    h_ws = tmp_path / "harness"
    matrix_dir.mkdir(parents=True)
    g2_ws.mkdir()
    h_ws.mkdir()
    (g2_ws / "metadata.json").write_text(
        json.dumps({"generator": "g2fuzz", "status": "evaluated", "task_family": "input_generator", "generated_input_count": 3}),
        encoding="utf-8",
    )
    (h_ws / "metadata.json").write_text(
        json.dumps({"generator": "ckgfuzzer", "status": "evaluated", "task_family": "harness_generator", "profile": "alpha", "generated_harness_count": 1}),
        encoding="utf-8",
    )
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"g2fuzz\tlibpng_libpng_read_fuzzer\tevaluated\t{g2_ws}\t{g2_ws / 'metadata.json'}\t{g2_ws / 'HGB_SUMMARY.md'}\n"
        f"ckgfuzzer\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{h_ws}\t{h_ws / 'metadata.json'}\t{h_ws / 'HGB_SUMMARY.md'}\n",
        encoding="utf-8",
    )

    summary = matrix_collector.collect(matrix_dir)
    matrix_collector.write_outputs(matrix_dir, summary)

    # g2fuzz (input_generator) "evaluated" counts as completed;
    # ckgfuzzer (harness_generator alpha) only "evaluated" counts as completed.
    assert summary["completed_pairs"] == 2
    assert summary["task_family_counts"] == {"input_generator": 1, "harness_generator": 1}
    assert summary["status_counts_by_task_family"]["input_generator"]["evaluated"] == 1
    md = (matrix_dir / "HGB_MATRIX_SUMMARY.md").read_text(encoding="utf-8")
    assert "## Task Families" in md
    assert "`input_generator`: 1 pairs" in md
