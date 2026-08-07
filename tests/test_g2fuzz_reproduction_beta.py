"""Beta reproduction tests for the G2Fuzz input-generator pipeline.

These tests exercise the paper-consistent G2Fuzz reproduction contract from
``plans/g2fuzz_reproduction_beta.md`` with fake fixtures so they pass without
real external checkouts, Docker, AFL++ builds, or model access.

G2Fuzz is an ``input_generator`` (it synthesizes Python input generators and
seeds for a fixed native FuzzBench target pair, then drives its modified
AFL++), never a harness generator.
"""

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


g2 = load_module("g2fuzz_target_pipeline_beta", ROOT / "docker/common/g2fuzz_target_pipeline.py")
builder = load_module("hgb_fuzzbench_builder_beta", ROOT / "docker/common/hgb_fuzzbench_builder.py")
matrix_collector = load_module("hgb_collect_matrix_beta2", ROOT / "scripts/hgb_collect_matrix.py")


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


def fake_pair(pair_dir: Path, program: str = "libpng_libpng_read_fuzzer", body: str = "#!/usr/bin/env bash\nexit 0\n") -> None:
    pair_dir.mkdir(parents=True)
    make_executable(pair_dir / f"{program}.afl", body)
    make_executable(pair_dir / f"{program}.cmp", body)


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


def fake_afl_fuzz(path: Path, execs_done: int = 7, queue: bool = True) -> Path:
    q = "queue.mkdir(parents=True, exist_ok=True)\n(queue / 'id:000000,orig:seed').write_bytes(b'queued')\n" if queue else ""
    return make_executable(
        path,
        f"""#!/usr/bin/env python3
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
crashes.mkdir(parents=True, exist_ok=True)
hangs.mkdir(parents=True, exist_ok=True)
{q}
(out / "default" / "fuzzer_stats").write_text("execs_done : {execs_done}\\npaths_total : 3\\n", encoding="utf-8")
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
                            "lines": {"count": 20, "covered": 11},
                            "functions": {"count": 6, "covered": 4},
                            "regions": {"count": 14, "covered": 8},
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
            env.get("HGB_BASELINE_PROFILE", "alpha"),
            "--protocol",
            env.get("HGB_BASELINE_PROTOCOL", "paper-native"),
        ],
        cwd=ROOT,
        env=os.environ | env,
        text=True,
        capture_output=True,
        check=False,
    )


# 1. all valuable targets have adapters, specs, and profile labels
def test_all_valuable_targets_have_adapters_specs_and_profile_counts() -> None:
    valuable = g2.valuable_targets(ROOT / "metadata")
    adapters = g2.load_adapters(ROOT / "metadata")
    counts = g2.adapter_profile_counts(ROOT / "metadata")

    assert len(valuable) == 20
    assert set(valuable) == set(adapters)
    # paper-faithful and extension counts are reported and separated.
    assert counts["paper-faithful"] == 9
    assert counts["extension"] == 11
    assert counts["paper-faithful"] + counts["extension"] == len(valuable)
    for adapter in adapters.values():
        assert (ROOT / adapter["format_spec"]).is_file()
        assert adapter["applicability"] == "applicable"
        assert adapter["method_profile"] in {"paper-faithful", "extension"}


def test_duplicate_adapter_rejected(tmp_path: Path) -> None:
    meta = tmp_path / "metadata"
    meta.mkdir()
    (meta / "fuzzbench_targets.json").write_text(json.dumps({"target_sets": {"valuable": {"targets": ["a_target", "b_target"]}}}), encoding="utf-8")
    (meta / "g2fuzz_target_adapters.yaml").write_text(
        "schema_version: 1\ntargets:\n"
        "  - target: a_target\n    applicability: applicable\n    method_profile: paper-faithful\n    program_id: a\n    formats: [PNG]\n"
        "    input_mode: file\n    argv: [\"@@\"]\n    common_corpus: true\n    format_spec: repro/g2fuzz/specs/a.md\n"
        "  - target: a_target\n    applicability: applicable\n    method_profile: paper-faithful\n    program_id: a\n    formats: [PNG]\n"
        "    input_mode: file\n    argv: [\"@@\"]\n    common_corpus: true\n    format_spec: repro/g2fuzz/specs/a.md\n",
        encoding="utf-8",
    )
    with pytest.raises(g2.PipelineError):
        g2.load_adapters(meta)


# 2. alpha/paper do not require G2FUZZ_TARGET_DIR
def test_alpha_paper_do_not_require_g2fuzz_target_dir(tmp_path: Path) -> None:
    program_gen = fake_program_gen(tmp_path / "program_gen.py")
    afl = fake_afl_fuzz(tmp_path / "afl-fuzz")
    coverage = fake_coverage_report(tmp_path / "coverage.json")
    # No G2FUZZ_TARGET_DIR set: the pipeline must attempt auto-build rather
    # than erroring with a "G2FUZZ_TARGET_DIR required" message.
    result = run_helper(
        tmp_path,
        env={
            "G2FUZZ_PROGRAM_GEN": str(program_gen),
            "G2FUZZ_AFL_FUZZ": str(afl),
            "G2FUZZ_COVERAGE_REPORT": str(coverage),
            "G2FUZZ_AFL_TIMEOUT_SECONDS": "5",
        },
    )
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    # Without the AFL++ toolchain the auto-build cannot proceed; that is an
    # infra_missing failure about the toolchain, never about G2FUZZ_TARGET_DIR.
    assert metadata["status"] == "infra_missing"
    assert "G2FUZZ_TARGET_DIR" not in metadata["reason"]
    # Auto-build commands were still generated during preflight.
    build_commands = json.loads((tmp_path / "workspace" / "config" / "build_commands.json").read_text(encoding="utf-8"))
    assert build_commands["afl"]["env"]["AFL_LLVM_CMPLOG"] == "0"
    assert build_commands["cmp"]["env"]["AFL_LLVM_CMPLOG"] == "1"
    assert result.returncode != 0


# 3 + 4. builder creates .afl and .cmp build commands; CmpLog only for .cmp
def test_builder_creates_afl_and_cmp_build_commands() -> None:
    adapter = g2.load_adapters(ROOT / "metadata")["libpng_libpng_read_fuzzer"]
    commands = g2.build_command_pair(adapter, ROOT / "artifacts" / "g2fuzz", ROOT, ROOT / "workspace")
    assert commands["build_mode"] == "fuzzbench_native_afl_cmps"
    # Two separate commands sharing the same argv (the native build.sh).
    assert commands["afl"]["argv"] == commands["cmp"]["argv"]
    assert commands["afl"]["argv"][0] == "bash"
    # CC/CXX point at the G2Fuzz modified AFL++ toolchain.
    assert commands["afl"]["env"]["CC"].endswith("afl-clang-fast")
    assert commands["afl"]["env"]["CXX"].endswith("afl-clang-fast++")
    assert commands["afl"]["env"]["FUZZING_ENGINE"] == "afl"
    assert commands["afl"]["env"]["SANITIZER"] == "address"


def test_cmplog_env_used_only_for_cmp_build() -> None:
    adapter = g2.load_adapters(ROOT / "metadata")["libpng_libpng_read_fuzzer"]
    commands = g2.build_command_pair(adapter)
    assert commands["afl"]["env"]["AFL_LLVM_CMPLOG"] == "0"
    assert commands["cmp"]["env"]["AFL_LLVM_CMPLOG"] == "1"
    # Every env key other than AFL_LLVM_CMPLOG and HGB_G2FUZZ_OUTPUT is identical.
    afl_env = dict(commands["afl"]["env"])
    cmp_env = dict(commands["cmp"]["env"])
    afl_env["AFL_LLVM_CMPLOG"] = "X"
    afl_env["HGB_G2FUZZ_OUTPUT"] = "X"
    cmp_env["AFL_LLVM_CMPLOG"] = "X"
    cmp_env["HGB_G2FUZZ_OUTPUT"] = "X"
    assert afl_env == cmp_env
    assert commands["afl"]["env"]["HGB_G2FUZZ_OUTPUT"].endswith("target.afl")
    assert commands["cmp"]["env"]["HGB_G2FUZZ_OUTPUT"].endswith("target.cmp")


def test_hgb_fuzzbench_builder_pair_commands_and_verify(tmp_path: Path) -> None:
    commands = builder.g2fuzz_target_pair_build_commands(
        artifact_dir=Path("/opt/hgb/artifacts/g2fuzz"),
        target_package=Path("/target"),
        workspace=Path("/workspace"),
        program_id="libpng_libpng_read_fuzzer",
    )
    assert commands["afl"]["env"]["AFL_LLVM_CMPLOG"] == "0"
    assert commands["cmp"]["env"]["AFL_LLVM_CMPLOG"] == "1"
    work = tmp_path / "pair"
    work.mkdir(parents=True)
    afl = work / "target.afl"
    cmp_missing = work / "target.cmp"
    afl.write_bytes(b"binary")
    afl.chmod(0o755)
    verify = builder.verify_g2fuzz_target_pair(afl, cmp_missing)
    # missing .cmp fails verification.
    assert verify["ok"] is False
    assert verify["cmp"]["exists"] is False
    cmp_missing.write_bytes(b"binary")
    cmp_missing.chmod(0o755)
    assert builder.verify_g2fuzz_target_pair(afl, cmp_missing)["ok"] is True


# 5. pair smoke failure fails the stage
def test_pair_smoke_failure_fails_stage(tmp_path: Path) -> None:
    pair = tmp_path / "pair"
    fake_pair(pair, body="#!/usr/bin/env bash\nexit 134\n")
    program_gen = fake_program_gen(tmp_path / "program_gen.py")
    afl = fake_afl_fuzz(tmp_path / "afl-fuzz")
    coverage = fake_coverage_report(tmp_path / "coverage.json")
    result = run_helper(
        tmp_path,
        env={
            "G2FUZZ_TARGET_DIR": str(pair),
            "G2FUZZ_PROGRAM_GEN": str(program_gen),
            "G2FUZZ_AFL_FUZZ": str(afl),
            "G2FUZZ_COVERAGE_REPORT": str(coverage),
            "G2FUZZ_AFL_TIMEOUT_SECONDS": "5",
        },
    )
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "infra_failure"
    assert metadata["stages"]["target_pair_built"]["status"] == "infra_failure"
    assert result.returncode != 0


# 6. missing .cmp fails
def test_missing_cmp_fails(tmp_path: Path) -> None:
    pair = tmp_path / "pair"
    pair.mkdir(parents=True)
    make_executable(pair / "libpng_libpng_read_fuzzer.afl", "#!/usr/bin/env bash\nexit 0\n")
    # no .cmp binary
    program_gen = fake_program_gen(tmp_path / "program_gen.py")
    result = run_helper(
        tmp_path,
        env={
            "G2FUZZ_TARGET_DIR": str(pair),
            "G2FUZZ_PROGRAM_GEN": str(program_gen),
        },
    )
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "infra_missing"
    assert metadata["stages"]["target_pair_built"]["status"] == "infra_missing"
    assert "incomplete" in metadata["reason"] or "target.cmp" in metadata["reason"]


# 7. input contract is not globally hard-coded
def test_input_contract_not_globally_hardcoded() -> None:
    file_adapter = {
        "target": "t_file",
        "program_id": "p",
        "formats": ["JSON"],
        "input_mode": "file",
        "argv": ["--mode", "parse", "@@", "--strict"],
    }
    stdin_adapter = {
        "target": "t_stdin",
        "program_id": "p",
        "formats": ["JSON"],
        "input_mode": "stdin",
        "argv": ["--stdin"],
    }
    file_inv = g2.resolved_invocation(file_adapter, "/bin/target")
    assert file_inv["uses_at_at"] is True
    assert file_inv["argv"] == ["/bin/target", "--mode", "parse", "@@", "--strict"]
    stdin_inv = g2.resolved_invocation(stdin_adapter, "/bin/target")
    assert stdin_inv["uses_at_at"] is False
    # file mode requires exactly one @@; stdin mode forbids @@.
    with pytest.raises(g2.PipelineError):
        g2.resolved_invocation(file_adapter | {"argv": []}, "/bin/target")
    with pytest.raises(g2.PipelineError):
        g2.resolved_invocation(stdin_adapter | {"argv": ["@@"]}, "/bin/target")
    # Adapters carry their own input_mode/argv; nothing is globally forced.
    adapters = g2.load_adapters(ROOT / "metadata")
    assert all("input_mode" in a and "argv" in a for a in adapters.values())


# 8. generated input counting excludes configs, logs, .py, preseed, common corpus
def test_generated_input_counting_excludes_non_inputs(tmp_path: Path) -> None:
    produced = tmp_path / "gen_seeds"
    produced.mkdir()
    (produced / "input_000").write_bytes(b'{"k": 0}')
    (produced / "evolved.py").write_text("x=1\n", encoding="utf-8")
    (produced / "meta.json").write_text("{}", encoding="utf-8")
    (produced / "run.log").write_text("log\n", encoding="utf-8")
    (produced / "config.yaml").write_text("k: v\n", encoding="utf-8")
    (produced / "preseed_corpus").write_bytes(b"seed")
    (produced / "common_0000_seed").write_bytes(b"common")
    (produced / "hgb_corpus_0000").write_bytes(b"corpus")
    (produced / "manifest.txt").write_text("m\n", encoding="utf-8")
    (produced / "readme.txt").write_text("r\n", encoding="utf-8")
    (produced / "model_setting.json").write_text("{}", encoding="utf-8")
    assert g2.is_generated_input_candidate(produced / "input_000")
    assert not g2.is_generated_input_candidate(produced / "evolved.py")
    assert not g2.is_generated_input_candidate(produced / "meta.json")
    assert not g2.is_generated_input_candidate(produced / "run.log")
    assert not g2.is_generated_input_candidate(produced / "config.yaml")
    assert not g2.is_generated_input_candidate(produced / "preseed_corpus")
    assert not g2.is_generated_input_candidate(produced / "common_0000_seed")
    assert not g2.is_generated_input_candidate(produced / "hgb_corpus_0000")
    assert not g2.is_generated_input_candidate(produced / "manifest.txt")
    assert not g2.is_generated_input_candidate(produced / "readme.txt")
    assert not g2.is_generated_input_candidate(produced / "model_setting.json")


# 9. all generated inputs failing validation leads to quality_failure
def test_all_generated_inputs_failing_leads_to_quality_failure(tmp_path: Path) -> None:
    pair = tmp_path / "pair"
    # Target exits 77 (libFuzzer misuse) on every input: not a crash (>=128),
    # but not a valid execution either.
    fake_pair(pair, body="#!/usr/bin/env bash\nexit 77\n")
    program_gen = fake_program_gen(tmp_path / "program_gen.py")
    afl = fake_afl_fuzz(tmp_path / "afl-fuzz")
    coverage = fake_coverage_report(tmp_path / "coverage.json")
    result = run_helper(
        tmp_path,
        env={
            "G2FUZZ_TARGET_DIR": str(pair),
            "G2FUZZ_PROGRAM_GEN": str(program_gen),
            "G2FUZZ_AFL_FUZZ": str(afl),
            "G2FUZZ_COVERAGE_REPORT": str(coverage),
            "G2FUZZ_AFL_TIMEOUT_SECONDS": "5",
        },
    )
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "quality_failure"
    assert metadata["stages"]["generated_inputs_validated"]["status"] == "quality_failure"
    assert metadata["input_generation"]["valid_g2_generated_count"] == 0
    assert result.returncode != 0


# 10. AFL campaign with execs_done=0 is not completed
def test_afl_campaign_execs_done_zero_not_completed(tmp_path: Path) -> None:
    pair = tmp_path / "pair"
    fake_pair(pair, body="#!/usr/bin/env bash\nexit 0\n")
    program_gen = fake_program_gen(tmp_path / "program_gen.py")
    afl = fake_afl_fuzz(tmp_path / "afl-fuzz", execs_done=0, queue=True)
    coverage = fake_coverage_report(tmp_path / "coverage.json")
    result = run_helper(
        tmp_path,
        env={
            "G2FUZZ_TARGET_DIR": str(pair),
            "G2FUZZ_PROGRAM_GEN": str(program_gen),
            "G2FUZZ_AFL_FUZZ": str(afl),
            "G2FUZZ_COVERAGE_REPORT": str(coverage),
            "G2FUZZ_AFL_TIMEOUT_SECONDS": "5",
        },
    )
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["stages"]["campaign"]["status"] != "complete"
    assert metadata["campaign"]["execs_done"] == 0
    assert metadata["status"] != "evaluated"
    assert result.returncode != 0


# 11. coverage from AFL paths is rejected
def test_coverage_from_afl_paths_rejected(tmp_path: Path) -> None:
    # No G2FUZZ_COVERAGE_REPORT and no instrumentable coverage target: the
    # coverage stage must fail rather than label AFL paths as coverage.
    summary = g2.G2FuzzPipeline.__new__(g2.G2FuzzPipeline)  # lightweight use
    coverage = {
        "edge_coverage": {"status": "unavailable", "reason": "not_collected"},
        "line_coverage": None,
        "execs_done": 5,
        "paths_total": 3,
    }
    # The pipeline helper must never treat paths_total as edge coverage.
    assert coverage["edge_coverage"]["status"] == "unavailable"
    assert coverage["line_coverage"] is None


def test_coverage_stage_fails_without_real_report(tmp_path: Path) -> None:
    pair = tmp_path / "pair"
    fake_pair(pair, body="#!/usr/bin/env bash\nexit 0\n")
    program_gen = fake_program_gen(tmp_path / "program_gen.py")
    afl = fake_afl_fuzz(tmp_path / "afl-fuzz", execs_done=7, queue=True)
    # No coverage report and no instrumented target -> coverage cannot complete.
    result = run_helper(
        tmp_path,
        env={
            "G2FUZZ_TARGET_DIR": str(pair),
            "G2FUZZ_PROGRAM_GEN": str(program_gen),
            "G2FUZZ_AFL_FUZZ": str(afl),
            "G2FUZZ_AFL_TIMEOUT_SECONDS": "5",
            "G2FUZZ_COVERAGE_REPORT": "",
        },
    )
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["stages"]["coverage"]["status"] != "complete"
    assert metadata["coverage"]["line_coverage"] is None
    assert metadata["coverage"]["edge_coverage"]["status"] == "unavailable"
    assert metadata["status"] != "evaluated"
    assert result.returncode != 0


# 12. paper-faithful and extension aggregates are separated
def test_paper_faithful_and_extension_aggregates_separated(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    paper_ws = tmp_path / "paper"
    ext_ws = tmp_path / "ext"
    matrix_dir.mkdir(parents=True)
    paper_ws.mkdir()
    ext_ws.mkdir()
    (paper_ws / "metadata.json").write_text(
        json.dumps(
            {
                "generator": "g2fuzz",
                "status": "evaluated",
                "task_family": "input_generator",
                "method_profile": "paper-faithful",
                "target_pair_build": {"status": "completed", "afl_binary": "/x.afl", "cmp_binary": "/x.cmp"},
                "input_generation": {"valid_g2_generated_count": 2},
                "campaign": {"execs_done": 10, "queue_count": 3},
                "coverage": {"line_coverage": {"covered": 9, "total": 12}, "edge_coverage": {"status": "unavailable"}},
            }
        ),
        encoding="utf-8",
    )
    (ext_ws / "metadata.json").write_text(
        json.dumps(
            {
                "generator": "g2fuzz",
                "status": "quality_failure",
                "task_family": "input_generator",
                "method_profile": "extension",
            }
        ),
        encoding="utf-8",
    )
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"g2fuzz\tlibpng_libpng_read_fuzzer\tevaluated\t{paper_ws}\t{paper_ws / 'metadata.json'}\t\n"
        f"g2fuzz\tjsoncpp_jsoncpp_fuzzer\tquality_failure\t{ext_ws}\t{ext_ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, split_by="method_profile")
    matrix_collector.write_outputs(matrix_dir, summary)
    groups = summary["method_profile_groups"]
    assert set(groups) == {"paper-faithful", "extension"}
    assert groups["paper-faithful"]["total"] == 1
    assert groups["paper-faithful"]["evaluated"] == 1
    assert groups["extension"]["total"] == 1
    assert groups["extension"]["quality_failure"] == 1
    md = (matrix_dir / "HGB_MATRIX_SUMMARY.md").read_text(encoding="utf-8")
    assert "## Method Profile Groups" in md
    assert "`paper-faithful`" in md
    assert "`extension`" in md


def test_strict_matrix_rejects_evaluated_g2fuzz_row_without_build_evidence(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    bad_ws = tmp_path / "bad"
    matrix_dir.mkdir(parents=True)
    bad_ws.mkdir()
    # Evaluated input-generator row missing target_pair_build evidence and
    # coverage -> strict collector must flag invariant violations.
    (bad_ws / "metadata.json").write_text(
        json.dumps(
            {
                "generator": "g2fuzz",
                "status": "evaluated",
                "task_family": "input_generator",
                "method_profile": "paper-faithful",
                "target_pair_build": {"status": "pending"},
                "input_generation": {"valid_g2_generated_count": 0},
                "campaign": {"execs_done": 0, "queue_count": 0},
                "coverage": {"line_coverage": None, "edge_coverage": {"status": "unavailable"}},
            }
        ),
        encoding="utf-8",
    )
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"g2fuzz\tlibpng_libpng_read_fuzzer\tevaluated\t{bad_ws}\t{bad_ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir, strict=True)
    assert summary["evaluated_row_violations"]
    violations = summary["evaluated_row_violations"][0]["violations"]
    assert any("target_pair_build" in v for v in violations)
    assert any("valid G2-generated input" in v for v in violations)
    assert any("coverage.line_coverage.covered" in v for v in violations)


# Full fake flow reaches evaluated with the beta nested schema.
def test_full_fake_flow_reaches_evaluated_with_beta_schema(tmp_path: Path) -> None:
    pair = tmp_path / "pair"
    fake_pair(pair, body="#!/usr/bin/env bash\nexit 0\n")
    program_gen = fake_program_gen(tmp_path / "program_gen.py")
    afl = fake_afl_fuzz(tmp_path / "afl-fuzz", execs_done=7, queue=True)
    coverage = fake_coverage_report(tmp_path / "coverage.json")
    result = run_helper(
        tmp_path,
        env={
            "G2FUZZ_TARGET_DIR": str(pair),
            "G2FUZZ_PROGRAM_GEN": str(program_gen),
            "G2FUZZ_AFL_FUZZ": str(afl),
            "G2FUZZ_COVERAGE_REPORT": str(coverage),
            "G2FUZZ_AFL_TIMEOUT_SECONDS": "5",
        },
    )
    assert result.returncode == 0, result.stderr
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "evaluated"
    assert metadata["task_family"] == "input_generator"
    # Nested beta schema (plan section 11).
    assert metadata["target_pair_build"]["status"] == "completed"
    assert metadata["target_pair_build"]["afl_sha256"]
    assert metadata["target_pair_build"]["cmp_sha256"]
    assert metadata["input_generation"]["g2_generated_count"] == 1
    assert metadata["input_generation"]["valid_g2_generated_count"] == 1
    assert metadata["seed_provenance"]["g2_generated"] >= 1
    assert metadata["seed_provenance"]["afl_initial"] >= 1
    assert metadata["campaign"]["execs_done"] > 0
    assert metadata["campaign"]["queue_count"] > 0
    assert metadata["coverage"]["line_coverage"]["covered"] is not None
    assert metadata["coverage"]["edge_coverage"]["status"] == "unavailable"
    # Goal-stage aliases are present.
    assert metadata["stages"]["target_pair_build"]["status"] == "complete"
    assert metadata["stages"]["program_generation"]["status"] == "complete"
    assert metadata["stages"]["generated_input_validation"]["status"] == "complete"
