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


elf = load_module("elfuzz_target_pipeline", ROOT / "docker/common/elfuzz_target_pipeline.py")
matrix_collector = load_module("hgb_collect_matrix_elfuzz", ROOT / "scripts/hgb_collect_matrix.py")


def make_executable(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)
    return path


def make_target_package(base: Path, target: str = "jsoncpp_jsoncpp_fuzzer") -> Path:
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


APPLICABLE = {
    "curl_curl_fuzzer_http",
    "jsoncpp_jsoncpp_fuzzer",
    "libxml2_xml",
    "libxslt_xpath",
    "mruby_mruby_fuzzer_8c8bbd",
    "php_php-fuzz-parser_0dbedb",
    "re2_fuzzer",
    "sqlite3_ossfuzz",
    "systemd_fuzz-link-parser",
}
INVALID = {
    "bloaty_fuzz_target",
    "freetype2_ftfuzzer",
    "harfbuzz_hb-shape-fuzzer",
    "lcms_cms_transform_fuzzer",
    "libjpeg-turbo_libjpeg_turbo_fuzzer",
    "libpcap_fuzz_both",
    "libpng_libpng_read_fuzzer",
    "mbedtls_fuzz_dtlsclient",
    "openh264_decoder_fuzzer",
    "openssl_x509",
    "zlib_zlib_uncompress_fuzzer",
}


def fake_elfuzz_cli(path: Path, project_root: Path) -> Path:
    script = """#!/usr/bin/env python3
import os, sys, time, json
from pathlib import Path

root = Path(os.environ.get("ELFUZZ_PROJECT_ROOT", ""))
fuzzer_dir = Path(os.environ.get("ELFUZZ_FUZZER_PROGRAMS_DIR", root / "evaluation" / "elmfuzzers"))
produced_dir = Path(os.environ.get("ELFUZZ_PRODUCED_INPUTS_DIR", root / "extradata" / "seeds" / "raw" / "elm"))
campaign_dir = Path(os.environ.get("ELFUZZ_CAMPAIGN_OUTPUT_DIR", root / "extradata" / "rq1" / "afl_results"))
cmd = sys.argv[1] if len(sys.argv) > 1 else ""
benchmark = sys.argv[-1] if sys.argv else ""

if cmd == "setup":
    sys.exit(0)
if cmd == "download":
    sys.exit(0)
if cmd == "synth":
    fuzzer_dir.mkdir(parents=True, exist_ok=True)
    (fuzzer_dir / "evolved_fuzzer.py").write_text("def gen():\\n    return b'{}'\\n", encoding="utf-8")
    rec = Path(os.environ.get("ELFUZZ_LINEAGE_DIR", root / "extradata" / "evolution_record" / "Jsoncpp"))
    rec.mkdir(parents=True, exist_ok=True)
    with (rec / "lineage.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps({"iteration": 1, "parent": "seed", "child": "evolved_fuzzer.py"}) + "\\n")
    sys.exit(0)
if cmd == "produce":
    produced_dir.mkdir(parents=True, exist_ok=True)
    for i in range(3):
        (produced_dir / f"input_{i:03d}").write_bytes(b'{"k": %d}' % i)
    sys.exit(0)
if cmd == "run":
    out = campaign_dir / f"{benchmark}_elfuzz_1"
    (out / "default" / "queue").mkdir(parents=True, exist_ok=True)
    (out / "default" / "crashes").mkdir(parents=True, exist_ok=True)
    (out / "default" / "hangs").mkdir(parents=True, exist_ok=True)
    (out / "default" / "queue" / "id:000000,orig:seed").write_bytes(b'{"k": 0}')
    (out / "default" / "queue" / "id:000001,orig:seed").write_bytes(b'{"k": 1}')
    (out / "default" / "fuzzer_stats").write_text("execs_done : 100\\npaths_total : 2\\n", encoding="utf-8")
    sys.exit(0)
sys.exit(0)
"""
    return make_executable(path, script)


def fake_target_binary(path: Path) -> Path:
    return make_executable(path, "#!/usr/bin/env bash\nexit 0\n")


def base_env(tmp_path: Path, cli: Path, binary: Path, project_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "ELFUZZ_CLI": str(cli),
            "ELFUZZ_TARGET_BINARY": str(binary),
            "ELFUZZ_PROJECT_ROOT": str(project_root),
            "ELFUZZ_FUZZER_PROGRAMS_DIR": str(project_root / "evaluation" / "elmfuzzers"),
            "ELFUZZ_PRODUCED_INPUTS_DIR": str(project_root / "extradata" / "seeds" / "raw" / "jsoncpp" / "elm"),
            "ELFUZZ_CAMPAIGN_OUTPUT_DIR": str(project_root / "extradata" / "rq1" / "afl_results"),
            "ELFUZZ_REQUIRE_HF_TOKEN": "0",
            "ELFUZZ_REQUIRE_GPU": "0",
            "ELFUZZ_SKIP_DOWNLOAD": "1",
            "ELFUZZ_STAGE_TIMEOUT_SECONDS": "60",
            "HGB_BASELINE_PROFILE": "alpha",
            "HGB_BASELINE_PROTOCOL": "paper-native",
            "HGB_METADATA_DIR": str(ROOT / "metadata"),
            "HGB_GENERATOR_ARTIFACT_DIR": str(ROOT / "artifacts" / "elfuzz"),
        }
    )
    return env


def run_full(tmp_path: Path, env: dict[str, str], target: str = "jsoncpp_jsoncpp_fuzzer") -> subprocess.CompletedProcess[str]:
    workspace = tmp_path / "workspace"
    package = make_target_package(tmp_path, target)
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "docker/common/elfuzz_target_pipeline.py"),
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
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


# 1. all current valuable targets are explicitly classified
def test_all_valuable_targets_are_explicitly_classified() -> None:
    valuable = elf.valuable_targets(ROOT / "metadata")
    adapters = elf.load_adapters(ROOT / "metadata")
    assert len(valuable) == 20
    assert set(valuable) == set(adapters)
    elf.validate_adapter_coverage(ROOT / "metadata")


# 2. exactly the nine listed text targets are applicable and eleven are Invalid
def test_exactly_nine_applicable_and_eleven_invalid() -> None:
    adapters = elf.load_adapters(ROOT / "metadata")
    applicable = {t for t, a in adapters.items() if a.get("applicability") == "applicable"}
    invalid = {t for t, a in adapters.items() if a.get("applicability") == "Invalid"}
    assert applicable == APPLICABLE
    assert invalid == INVALID
    for t in APPLICABLE:
        cls = elf.classify_target(t, ROOT / "metadata")
        assert cls["applicability"] == "applicable"
        assert cls["input_kind"] == "text"
        assert (ROOT / adapters[t]["format_spec"]).is_file()
    for t in INVALID:
        cls = elf.classify_target(t, ROOT / "metadata")
        assert cls["applicability"] == "Invalid"
        assert cls["reason_code"] == "elfuzz_non_text_target"


# 3. Invalid classification happens before Docker/model/credential checks
def test_invalid_classification_needs_no_docker_or_credentials(tmp_path: Path) -> None:
    out = tmp_path / "result.json"
    env = {
        "HGB_BASELINE_PROFILE": "alpha",
        "HGB_BASELINE_PROTOCOL": "paper-native",
        "HGB_METADATA_DIR": str(ROOT / "metadata"),
    }
    # No HF_TOKEN, no Docker socket, no ELFUZZ_CLI, no artifact checkout.
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "docker/common/elfuzz_target_pipeline.py"),
            "write-invalid",
            "--target",
            "libpng_libpng_read_fuzzer",
            "--metadata-root",
            str(ROOT / "metadata"),
            "--out",
            str(out),
        ],
        cwd=ROOT,
        env=os.environ | env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["status"] == "not_applicable"
    assert data["applicability"] == "Invalid"
    harness = (ROOT / "scripts/hgb_generate_harness.sh").read_text(encoding="utf-8")
    assert harness.index("ELFuzz supports text-input targets only") < harness.index("ensure_artifacts_present")


# 4. Invalid output text begins with the required message
def test_invalid_output_text_begins_with_required_message() -> None:
    assert elf.INVALID_MESSAGE == "Invalid: ELFuzz supports text-input targets only"
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "docker/common/elfuzz_target_pipeline.py"),
            "write-invalid",
            "--target",
            "zlib_zlib_uncompress_fuzzer",
            "--metadata-root",
            str(ROOT / "metadata"),
            "--out",
            "/tmp/elfuzz_invalid_test.json",
        ],
        cwd=ROOT,
        env=os.environ,
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.stdout.startswith("Invalid: ELFuzz supports text-input targets only")


# 5. Invalid rows are not counted as evaluated
def test_invalid_rows_are_not_counted_as_evaluated() -> None:
    payload = elf.invalid_payload("libpng_libpng_read_fuzzer", ROOT / "metadata")
    assert payload["status"] == "not_applicable"
    assert payload["status"] != "evaluated"
    assert payload["status"] not in matrix_collector.COMPLETED_STATUSES
    assert payload["status"] in matrix_collector.NOT_APPLICABLE_STATUSES


# 6. missing adapter for a text target is infra_missing, not Invalid
def test_missing_adapter_for_text_target_is_infra_missing(tmp_path: Path) -> None:
    meta = tmp_path / "metadata"
    meta.mkdir()
    (meta / "fuzzbench_targets.json").write_text(
        json.dumps({"target_sets": {"valuable": {"targets": ["ghost_text_target"]}}}), encoding="utf-8"
    )
    (meta / "elfuzz_target_adapters.yaml").write_text(
        "schema_version: 1\n"
        "generator: elfuzz\n"
        "task_family: input_generator\n"
        "targets:\n"
        "  - target: ghost_text_target\n"
        "    applicability: applicable\n"
        "    input_kind: text\n"
        "    upstream_benchmark: jsoncpp\n"
        "    adapter_class: extension\n"
        "    adapter_id: ghost\n"
        "    build_mode: fuzzbench_native\n"
        "    input_mode: file\n"
        "    argv: [\"@@\"]\n"
        "    format: JSON\n"
        "    format_spec: repro/elfuzz/targets/ghost/format.md\n"
        "    adapter_dir: repro/elfuzz/targets/ghost\n"
        "    seed_template: repro/elfuzz/targets/ghost/seed_fuzzer.py\n"
        "    validity_check: json\n"
        "    timeout_seconds: 5\n",
        encoding="utf-8",
    )
    package = make_target_package(tmp_path, "ghost_text_target")
    workspace = tmp_path / "workspace"
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "docker/common/elfuzz_target_pipeline.py"),
            "full",
            "--workspace",
            str(workspace),
            "--target",
            "ghost_text_target",
            "--target-package",
            str(package),
            "--artifact-dir",
            str(tmp_path / "artifact"),
            "--metadata-root",
            str(meta),
            "--profile",
            "alpha",
            "--protocol",
            "paper-native",
        ],
        cwd=ROOT,
        env=os.environ
        | {
            "ELFUZZ_TARGET_BINARY": str(fake_target_binary(tmp_path / "bin")),
            "ELFUZZ_REQUIRE_HF_TOKEN": "0",
            "ELFUZZ_REQUIRE_GPU": "0",
            "ELFUZZ_SKIP_DOWNLOAD": "1",
            "HGB_METADATA_DIR": str(meta),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 127
    data = json.loads((workspace / "metadata.json").read_text(encoding="utf-8"))
    assert data["status"] == "infra_missing"
    assert data["stages"]["target_build"]["status"] == "infra_missing"


# 7. --allow-input-generator is unnecessary in the canonical runner
def test_allow_input_generator_unnecessary_for_elfuzz() -> None:
    runner = (ROOT / "scripts/hgb_run_baseline.sh").read_text(encoding="utf-8")
    harness = (ROOT / "scripts/hgb_generate_harness.sh").read_text(encoding="utf-8")
    matrix = (ROOT / "scripts/hgb_generate_matrix.sh").read_text(encoding="utf-8")
    # The canonical elfuzz case in the runner resolves the task family itself;
    # the canonical runner command in the plan needs no --allow-input-generator.
    assert "g2fuzz|elfuzz" in runner
    assert "--allow-input-generator" not in runner
    # The harness auto-allows input generators for elfuzz without the legacy flag.
    assert '"$generator" == "g2fuzz" || "$generator" == "elfuzz"' in harness
    # The legacy flag is kept only as a deprecated no-op alias in the harness/matrix scripts.
    assert "deprecated no-op" in harness
    assert "deprecated no-op" in matrix


# 8. alpha command includes final elfuzz run/equivalent
def test_alpha_command_includes_final_elfuzz_run() -> None:
    pipe = elf.ELFuzzPipeline(
        workspace=Path("/tmp/elfuzz-alpha-test"),
        target="jsoncpp_jsoncpp_fuzzer",
        target_package=Path("/target"),
        artifact_dir=Path("/opt/hgb/artifacts/elfuzz"),
        metadata_root=ROOT / "metadata",
        profile="alpha",
        protocol="paper-native",
    )
    run_cmd = pipe.run_command()
    assert "run" in run_cmd
    assert "rq1.afl" in run_cmd
    assert "--fuzzers" in run_cmd and "elfuzz" in run_cmd
    entrypoint = (ROOT / "docker/elfuzz/entrypoint.sh").read_text(encoding="utf-8")
    assert "elfuzz_target_pipeline.py full" in entrypoint


# 9. alpha cannot use 1-iteration/60-second smoke defaults
def test_alpha_cannot_use_smoke_defaults() -> None:
    alpha = elf.budget_for_profile("alpha", {})
    assert alpha["evolution_iterations"] >= 2
    assert alpha["produce_seconds"] >= 61
    assert alpha["excluded_from_aggregate"] is False
    with pytest.raises(elf.PipelineError):
        elf.budget_for_profile("alpha", {"ELFUZZ_EVOLUTION_ITERATIONS": "1", "ELFUZZ_PRODUCE_SECONDS": "60"})
    smoke = elf.budget_for_profile("compat-smoke", {})
    assert smoke["evolution_iterations"] == 1
    assert smoke["produce_seconds"] == 60
    assert smoke["excluded_from_aggregate"] is True


# 10. fuzzer programs are not counted as generated inputs
def test_fuzzer_programs_not_counted_as_generated_inputs(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    cli = fake_elfuzz_cli(tmp_path / "elfuzz", project_root)
    binary = fake_target_binary(tmp_path / "bin")
    env = base_env(tmp_path, cli, binary, project_root)
    result = run_full(tmp_path, env)
    assert result.returncode == 0, result.stderr
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "evaluated"
    assert metadata["fuzzer_program_count"] >= 1
    assert metadata["generated_input_count"] >= 1
    # fuzzer programs live under synthesis/, produced inputs under generated_inputs/
    fuzzer_programs = list((tmp_path / "workspace" / "synthesis" / "fuzzer_programs").glob("*"))
    produced = list((tmp_path / "workspace" / "generated_inputs" / "produced").glob("*"))
    assert fuzzer_programs
    assert produced
    # A .py fuzzer program is not a produced input candidate.
    py_prog = tmp_path / "evolved_fuzzer.py"
    py_prog.write_text("x=1\n", encoding="utf-8")
    inp = tmp_path / "input_000"
    inp.write_bytes(b"{}")
    assert not elf.is_produced_input(py_prog)
    assert elf.is_produced_input(inp)
    assert metadata["generated_input_count"] == len([p for p in produced if elf.is_produced_input(p)])


# 11. campaign deadline handling differs from synthesis timeout
def test_campaign_deadline_differs_from_synthesis_timeout(tmp_path: Path) -> None:
    # Synthesis timeout -> failed.
    project_root = tmp_path / "project"
    project_root.mkdir()
    slow_cli = make_executable(
        tmp_path / "slow_elfuzz",
        "#!/usr/bin/env python3\nimport sys, time\ncmd=sys.argv[1] if len(sys.argv)>1 else ''\n"
        "if cmd=='synth':\n    time.sleep(5)\nsys.exit(0)\n",
    )
    binary = fake_target_binary(tmp_path / "bin")
    env = base_env(tmp_path, slow_cli, binary, project_root)
    env["ELFUZZ_STAGE_TIMEOUT_SECONDS"] = "1"
    result = run_full(tmp_path, env)
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "failed"
    assert metadata["stages"]["synthesis"]["status"] == "failed"
    assert result.returncode != 0

    # Campaign deadline reached -> evaluated (completion, not failure).
    project_root2 = tmp_path / "project2"
    project_root2.mkdir()
    deadline_cli = fake_elfuzz_cli(tmp_path / "deadline_elfuzz", project_root2)
    # Make the campaign command sleep past the short deadline but write outputs first.
    real_cli = tmp_path / "deadline_elfuzz"
    make_executable(
        real_cli,
        "#!/usr/bin/env python3\nimport os, sys, json, time\nfrom pathlib import Path\n"
        "root=Path(os.environ.get('ELFUZZ_PROJECT_ROOT',''))\n"
        "cmd=sys.argv[1] if len(sys.argv)>1 else ''\nbenchmark=sys.argv[-1] if sys.argv else ''\n"
        "if cmd=='synth':\n"
        "  d=Path(os.environ['ELFUZZ_FUZZER_PROGRAMS_DIR']); d.mkdir(parents=True,exist_ok=True)\n"
        "  (d/'f.py').write_text('x=1\\n')\n  sys.exit(0)\n"
        "if cmd=='produce':\n"
        "  d=Path(os.environ['ELFUZZ_PRODUCED_INPUTS_DIR']); d.mkdir(parents=True,exist_ok=True)\n"
        "  (d/'in_0').write_bytes(b'{}')\n  sys.exit(0)\n"
        "if cmd=='run':\n"
        "  d=Path(os.environ['ELFUZZ_CAMPAIGN_OUTPUT_DIR'])/(benchmark+'_elfuzz_1')\n"
        "  (d/'default'/'queue').mkdir(parents=True,exist_ok=True)\n"
        "  (d/'default'/'fuzzer_stats').write_text('execs_done : 5\\npaths_total : 1\\n')\n"
        "  (d/'default'/'queue'/'id:0').write_bytes(b'{}')\n  time.sleep(5)\n  sys.exit(0)\n"
        "sys.exit(0)\n",
    )
    env2 = base_env(tmp_path / "second", real_cli, binary, project_root2)
    env2["HGB_BASELINE_PROFILE"] = "compat-smoke"
    env2["ELFUZZ_AFL_SECONDS"] = "2"
    env2["ELFUZZ_STAGE_TIMEOUT_SECONDS"] = "0"
    result2 = run_full(tmp_path / "second", env2)
    metadata2 = json.loads((tmp_path / "second" / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata2["status"] == "evaluated", (metadata2, result2.stderr)
    assert metadata2["stages"]["campaign"]["deadline_reached"] is True


# 12. a tiny fake text target completes the full state machine and reaches evaluated
def test_fake_text_target_reaches_evaluated(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    cli = fake_elfuzz_cli(tmp_path / "elfuzz", project_root)
    binary = fake_target_binary(tmp_path / "bin")
    env = base_env(tmp_path, cli, binary, project_root)
    result = run_full(tmp_path, env)
    assert result.returncode == 0, result.stderr
    metadata = json.loads((tmp_path / "workspace" / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["status"] == "evaluated"
    assert metadata["task_family"] == "input_generator"
    assert metadata["schema_version"] == 2
    assert metadata["generated_harness_count"] == 0
    for stage in elf.STAGE_NAMES:
        assert metadata["stages"][stage]["status"] == "complete", stage
    assert (tmp_path / "workspace" / "result.json").is_file()
    assert (tmp_path / "workspace" / "synthesis" / "fuzzer_programs").is_dir()
    assert (tmp_path / "workspace" / "generated_inputs" / "produced").is_dir()
    assert (tmp_path / "workspace" / "campaign" / "queue").is_dir()
    provenance = (tmp_path / "workspace" / "generated_inputs" / "provenance.jsonl").read_text(encoding="utf-8").splitlines()
    assert provenance
    rec = json.loads(provenance[0])
    assert "sha256" in rec and "valid" in rec and "in_campaign_queue" in rec


# 13. matrix summaries separate input_generator from harness_generator
def test_matrix_summary_separates_input_and_harness_families(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    e_ws = tmp_path / "elfuzz"
    h_ws = tmp_path / "harness"
    matrix_dir.mkdir(parents=True)
    e_ws.mkdir()
    h_ws.mkdir()
    (e_ws / "metadata.json").write_text(
        json.dumps({"generator": "elfuzz", "status": "evaluated", "task_family": "input_generator", "generated_input_count": 3}),
        encoding="utf-8",
    )
    (h_ws / "metadata.json").write_text(
        json.dumps({"generator": "ckgfuzzer", "status": "completed", "task_family": "harness_generator", "generated_harness_count": 1}),
        encoding="utf-8",
    )
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"elfuzz\tjsoncpp_jsoncpp_fuzzer\tevaluated\t{e_ws}\t{e_ws / 'metadata.json'}\t{e_ws / 'HGB_SUMMARY.md'}\n"
        f"ckgfuzzer\tjsoncpp_jsoncpp_fuzzer\tcompleted\t{h_ws}\t{h_ws / 'metadata.json'}\t{h_ws / 'HGB_SUMMARY.md'}\n",
        encoding="utf-8",
    )
    summary = matrix_collector.collect(matrix_dir)
    matrix_collector.write_outputs(matrix_dir, summary)
    assert summary["task_family_counts"] == {"input_generator": 1, "harness_generator": 1}
    assert summary["status_counts_by_task_family"]["input_generator"]["evaluated"] == 1
    md = (matrix_dir / "HGB_MATRIX_SUMMARY.md").read_text(encoding="utf-8")
    assert "## Task Families" in md
    assert "`input_generator`: 1 pairs" in md
    # An Invalid non-text row must not be counted as completed/evaluated.
    inv_ws = tmp_path / "invalid"
    inv_ws.mkdir()
    (inv_ws / "metadata.json").write_text(
        json.dumps({"generator": "elfuzz", "status": "not_applicable", "task_family": "input_generator", "applicability": "Invalid"}),
        encoding="utf-8",
    )
    (matrix_dir / "matrix.tsv").write_text(
        "generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n"
        f"elfuzz\tlibpng_libpng_read_fuzzer\tnot_applicable\t{inv_ws}\t{inv_ws / 'metadata.json'}\t\n",
        encoding="utf-8",
    )
    summary2 = matrix_collector.collect(matrix_dir)
    assert summary2["completed_pairs"] == 0
    assert summary2["not_applicable_pairs"] == 1
    assert summary2["status_counts_by_task_family"]["input_generator"].get("evaluated", 0) == 0
