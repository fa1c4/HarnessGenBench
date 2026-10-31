import csv
import importlib.util
import json
import signal
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

SPEC = importlib.util.spec_from_file_location("hgb_eval_all", Path(__file__).resolve().parents[1] / "scripts/hgb_eval_all.py")
assert SPEC and SPEC.loader
hgb_eval_all = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hgb_eval_all)

BUILDER_SPEC = importlib.util.spec_from_file_location("hgb_fuzzbench_builder_eval_all", Path(__file__).resolve().parents[1] / "docker/common/hgb_fuzzbench_builder.py")
assert BUILDER_SPEC and BUILDER_SPEC.loader
builder = importlib.util.module_from_spec(BUILDER_SPEC)
sys.modules[BUILDER_SPEC.name] = builder
BUILDER_SPEC.loader.exec_module(builder)


def test_plan_uses_committed_applicability() -> None:
    targets, scope = hgb_eval_all.plan(hgb_eval_all.ROOT)
    assert len(targets) == 20
    assert sum(value == "pending" for value in scope.values()) == 89
    assert sum(value == "N/A" for value in scope.values()) == 11
    assert sum(scope["elfuzz", target] == "N/A" for target in targets) == 11


def test_csv_contains_na_and_campaign_metrics(tmp_path: Path) -> None:
    rows = {(baseline, "example"): {"status": "N/A" if baseline == "elfuzz" else "pending"}
            for baseline in hgb_eval_all.BASELINES}
    rows["ckgfuzzer", "example"] = {"status": "evaluated", "execs_done": 42, "covered_lines": 12}
    path = tmp_path / "2026-10-10.csv"
    hgb_eval_all.save_csv(path, ["example"], rows)
    record = next(csv.DictReader(path.open(newline="", encoding="utf-8")))
    assert record["elfuzz_status"] == "N/A"
    assert record["ckgfuzzer_execs_done"] == "42"
    assert record["ckgfuzzer_covered_lines"] == "12"


def test_default_run_id_uses_phase_date_and_campaign_duration() -> None:
    assert hgb_eval_all.default_run_id("generate", "2026-10-16", 86400, 300) == (
        "eval_all_phase_a_20261016_300s")
    assert hgb_eval_all.default_run_id("fuzz", "2026-10-16", 86400, 300) == (
        "eval_all_phase_b_20261016_86400s")


def test_trials_for_each_pair_are_scheduled_together() -> None:
    targets, scope = hgb_eval_all.plan(hgb_eval_all.ROOT)
    jobs = hgb_eval_all.scheduled_jobs(targets, scope, 5)
    assert len(jobs) == 445
    for start in range(0, len(jobs), 5):
        group = jobs[start:start + 5]
        assert [trial for trial, _, _ in group] == [1, 2, 3, 4, 5]
        assert len({(baseline, target) for _, baseline, target in group}) == 1


def test_adaptive_capacity_uses_measured_memory_instead_of_docker_cap() -> None:
    capacity, estimate = hgb_eval_all.adaptive_worker_capacity(
        requested=128, cpus=256, active=38, memory_budget_gib=305,
        container_cap_gib=8, eval_usage_gib=45, available_gib=366,
        host_total_gib=436)
    assert capacity == 128
    assert 2 < estimate < 3

    capacity, _ = hgb_eval_all.adaptive_worker_capacity(
        requested=128, cpus=256, active=38, memory_budget_gib=305,
        container_cap_gib=8, eval_usage_gib=180, available_gib=366,
        host_total_gib=436)
    assert capacity < 38  # Existing jobs keep running; no more are admitted.

    capacity, _ = hgb_eval_all.adaptive_worker_capacity(
        requested=128, cpus=256, active=38, memory_budget_gib=305,
        container_cap_gib=8, eval_usage_gib=45, available_gib=80,
        host_total_gib=436)
    assert capacity == 38  # Host reserve blocks new jobs.


def test_eval_memory_sums_outer_and_nested_campaign_cgroups(monkeypatch) -> None:
    commands = []
    outer = "a" * 64
    campaign = "b" * 64
    exited = "c" * 64

    def fake_check_output(cmd, **_kwargs):
        commands.append(cmd)
        return f"{outer}\n{campaign}\n{exited}\n"

    files = {
        f"/sys/fs/cgroup/system.slice/docker-{outer}.scope/memory.current": str(2 * 1024 ** 3),
        f"/sys/fs/cgroup/system.slice/docker-{campaign}.scope/memory.current": str(1024 ** 3),
    }
    original_read_text = Path.read_text

    def fake_read_text(path, *args, **kwargs):
        if str(path) in files:
            return files[str(path)]
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(hgb_eval_all.subprocess, "check_output", fake_check_output)
    monkeypatch.setattr(Path, "read_text", fake_read_text)
    assert hgb_eval_all.eval_container_memory_gib("test_run") == 3
    assert commands[0][-1] == "label=hgb.eval_all_run=test_run"
    assert "--no-trunc" in commands[0]
    assert len(commands) == 1


def test_default_plan_uses_today_workspace_paths_and_saved_manifest(tmp_path: Path, monkeypatch) -> None:
    class Today:
        @staticmethod
        def now():
            return datetime(2026, 10, 16)

    targets = ["example"]
    scope = {(baseline, "example"): "pending" for baseline in hgb_eval_all.BASELINES}
    saved = tmp_path / "results/eval_all/2026-10-12.phase_a.json"
    saved.parent.mkdir(parents=True)
    saved.write_text(json.dumps({"records": [
        {"baseline": baseline, "target": "example", "status": "ready", "source_run": "saved-source"}
        for baseline in hgb_eval_all.BASELINES
    ]}), encoding="utf-8")
    monkeypatch.setattr(hgb_eval_all, "ROOT", tmp_path)
    monkeypatch.setattr(hgb_eval_all, "datetime", Today)
    monkeypatch.setattr(hgb_eval_all, "plan", lambda _root: (targets, scope))
    monkeypatch.setattr(hgb_eval_all, "source_ready", lambda _b, _t, raw: (True, raw))
    monkeypatch.setattr(sys, "argv", ["hgb_eval_all.py", "--phase", "fuzz", "--plan"])
    assert hgb_eval_all.main() == 0
    manifest = tmp_path / "workspace/eval_all/2026-10-16.phase_a.json"
    output = tmp_path / "workspace/eval_all/2026-10-16.csv"
    assert manifest.read_bytes() == saved.read_bytes()
    assert output.is_file()
    assert all(row[f"{baseline}_status"] == "pending" for baseline in hgb_eval_all.BASELINES
               for row in csv.DictReader(output.open(newline="", encoding="utf-8")))


def test_latest_manifest_skips_incomplete_newer_selection(tmp_path: Path) -> None:
    scope = {("ckgfuzzer", "example"): "pending", ("promefuzz", "example"): "pending"}
    directory = tmp_path / "results/eval_all"
    directory.mkdir(parents=True)
    complete = directory / "2026-10-12.phase_a.json"
    incomplete = directory / "2026-10-16.phase_a.json"
    complete.write_text(json.dumps({"records": [
        {"baseline": baseline, "target": "example", "status": "ready", "source_run": "saved-source"}
        for baseline in ("ckgfuzzer", "promefuzz")
    ]}), encoding="utf-8")
    incomplete.write_text(json.dumps({"records": [
        {"baseline": "ckgfuzzer", "target": "example", "status": "ready", "source_run": "new-source"}
    ]}), encoding="utf-8")
    assert hgb_eval_all.latest_complete_manifest(tmp_path, "2026-10-16", scope) == complete


def test_resume_keeps_completed_rows_and_requeues_stale_running(tmp_path: Path, monkeypatch) -> None:
    targets, scope = hgb_eval_all.plan(hgb_eval_all.ROOT)
    rows = {(b, t): {"status": scope[b, t]} for t in targets for b in hgb_eval_all.BASELINES}
    first = targets[0]
    rows["ckgfuzzer", first] = {"status": "evaluated", "execs_done": 12,
                                 "campaign_seconds": 86400, "campaign_elapsed_seconds": 86400,
                                 "coverage_contract": "canonical-g2-lcov-v1"}
    rows["promefuzz", first] = {"status": "running"}
    rows["oss-fuzz-gen", first] = {"status": "evaluated", "campaign_seconds": 86400,
                                    "campaign_elapsed_seconds": 100}
    output = tmp_path / "2026-10-10.csv"
    hgb_eval_all.save_csv(output, targets, rows)
    manifest = tmp_path / "phase_a.json"
    manifest.write_text(json.dumps({"records": [
        {"baseline": baseline, "target": target, "status": "ready", "source_run": "saved-source"}
        for (baseline, target), status in scope.items() if status == "pending"
    ]}), encoding="utf-8")
    monkeypatch.setattr(hgb_eval_all, "source_ready", lambda _b, _t, raw: (True, raw))
    monkeypatch.setattr(sys, "argv", ["hgb_eval_all.py", "--resume", "--plan",
                                      "--output", str(output), "--manifest", str(manifest)])
    assert hgb_eval_all.main() == 0
    records = list(csv.DictReader(output.open(newline="", encoding="utf-8")))
    assert records[0]["ckgfuzzer_status"] == "evaluated"
    assert records[0]["ckgfuzzer_execs_done"] == "12"
    assert records[0]["promefuzz_status"] == "pending"
    assert records[0]["oss-fuzz-gen_status"] == "pending"


def test_eval_rejects_files_in_repository_root(monkeypatch) -> None:
    for option in ("--output", "--manifest"):
        monkeypatch.setattr(sys, "argv", ["hgb_eval_all.py", "--plan", option,
                                      str(hgb_eval_all.ROOT / "unexpected-generated.json")])
        with pytest.raises(SystemExit) as error:
            hgb_eval_all.main()
        assert error.value.code == 2


def test_short_evaluated_campaign_is_not_reported_complete(tmp_path: Path) -> None:
    run = tmp_path / "workspace/ckgfuzzer/example/r1"
    (run / "evaluation").mkdir(parents=True)
    (run / "metadata.json").write_text('{"status":"evaluated"}')
    (run / "evaluation/result.json").write_text(json.dumps({
        "status": "evaluated", "campaign": {"execs_done": 100, "campaign_wall_seconds": 10},
        "coverage": {"line_coverage": {"covered": 12}},
    }))
    row = hgb_eval_all.result_row(tmp_path, "ckgfuzzer", "example", run, 86400, 0)
    assert row["status"] == "short_campaign"
    assert row["execs_done"] == 100


def test_g2_elapsed_uses_embedded_stats_when_afl_files_are_protected(tmp_path: Path) -> None:
    run = tmp_path / "workspace/g2fuzz/example/r1"
    run.mkdir(parents=True)
    (run / "metadata.json").write_text('{"status":"evaluated"}')
    (run / "result.json").write_text(json.dumps({
        "status": "evaluated",
        "campaign": {"execs_done": 100, "crashes": 1},
        "coverage": {"line_coverage": {"covered": 21}},
        "stages": {"campaign": {"fuzzer_stats": {"start_time": 1, "last_update": 86401}}},
    }))
    row = hgb_eval_all.result_row(tmp_path, "g2fuzz", "example", run, 86400, 0)
    assert row["status"] == "evaluated"
    assert row["campaign_elapsed_seconds"] == 86400
    assert row["crashes"] == 1


def test_eval_csv_uses_target_source_lines_and_preserves_raw_count(tmp_path: Path) -> None:
    run = tmp_path / "workspace/g2fuzz/bloaty_fuzz_target/r1"
    run.mkdir(parents=True)
    (run / "metadata.json").write_text('{"status":"evaluated"}')
    (run / "result.json").write_text(json.dumps({
        "status": "evaluated", "campaign": {"execs_done": 100,
                                             "campaign_wall_seconds": 86400},
        "coverage": {"line_coverage": {"covered": 30743},
                     "sut_line_coverage": {"covered": 3847, "total": 5842,
                                           "source_files": 22}},
    }))
    row = hgb_eval_all.result_row(tmp_path, "g2fuzz", "bloaty_fuzz_target", run, 86400, 0)
    assert row["status"] == "evaluated"
    assert row["covered_lines"] == 3847
    assert row["raw_covered_lines"] == 30743
    assert row["sut_total_lines"] == 5842


def test_job_passes_one_cpu_and_24_hour_budget(tmp_path: Path, monkeypatch) -> None:
    package = tmp_path / "package"
    package.mkdir()
    logs = tmp_path / "logs"
    logs.mkdir()

    def fake_run(cmd, **kwargs):
        assert kwargs["cwd"] == logs
        assert kwargs["env"]["HGB_DOCKER_CPUS"] == "1"
        assert kwargs["env"]["HGB_DOCKER_CPUSET"] == "7"
        assert kwargs["env"]["ELFUZZ_AFL_SECONDS"] == "86400"
        assert kwargs["env"]["DOCKER_NAME"].startswith("hgb-tgi-")
        assert "--timeout" in cmd
        run = tmp_path / "workspace/elfuzz/example/r1_elfuzz_example"
        (run / "campaign").mkdir(parents=True)
        (run / "metadata.json").write_text('{"status":"evaluated"}')
        (run / "result.json").write_text(json.dumps({
            "status": "evaluated", "campaign": {"execs_done": 10},
            "coverage": {"line_coverage": {"covered": 2}},
        }))
        (run / "campaign/fuzzer_stats").write_text("start_time : 1\nlast_update : 86401\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(hgb_eval_all.subprocess, "run", fake_run)
    row = hgb_eval_all.run_job(tmp_path, "elfuzz", "example", package, "r1", 86400, 21600, logs, 7)
    assert row["status"] == "evaluated"
    assert row["campaign_elapsed_seconds"] == 86400


def test_phase_b_invokes_saved_replay_without_generation(tmp_path: Path, monkeypatch) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    source = "workspace/promefuzz/example/phase_a"

    def fake_run(cmd, **kwargs):
        assert kwargs["cwd"] == logs
        assert cmd[1].endswith("hgb_replay_saved.py")
        assert cmd[cmd.index("--source-run") + 1] == source
        assert cmd[cmd.index("--campaign-seconds") + 1] == "86400"
        assert cmd[cmd.index("--memory-gib") + 1] == "8"
        assert "hgb_generate_harness.sh" not in " ".join(cmd)
        run = tmp_path / "workspace/promefuzz/example/r1_promefuzz_example"
        (run / "evaluation").mkdir(parents=True)
        (run / "metadata.json").write_text('{"status":"evaluated"}')
        (run / "evaluation/result.json").write_text(json.dumps({
            "status": "evaluated",
            "campaign": {"campaign_wall_seconds": 86400, "execs_done": 123},
            "coverage": {"line_coverage": {"covered": 9}},
        }))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(hgb_eval_all.subprocess, "run", fake_run)
    row = hgb_eval_all.run_replay_job(tmp_path, "promefuzz", "example", source,
                                      "r1", 86400, logs, 7, 8)
    assert row["status"] == "evaluated"
    assert row["execs_done"] == 123


def test_job_processes_stop_entire_replay_process_group() -> None:
    processes = hgb_eval_all.JobProcesses()
    process = subprocess.Popen(
        [sys.executable, "-c", "import subprocess,time; subprocess.Popen(['sleep','30']); time.sleep(30)"],
        start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        processes.add(process)
        processes.stop(signal.SIGTERM)
        assert process.wait(timeout=5) != 0
        assert processes.interrupted.is_set()
    finally:
        processes.stop(signal.SIGKILL)
        processes.discard(process)


def test_interrupt_cleanup_filters_containers_by_run_id(monkeypatch) -> None:
    commands = []
    remaining = {"container_one", "container_two"}
    def fake_run(cmd, **_kwargs):
        commands.append(cmd)
        if cmd[1] == "ps":
            return SimpleNamespace(returncode=0, stdout="\n".join(sorted(remaining)), stderr="")
        remaining.difference_update(cmd[3:])
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(hgb_eval_all.subprocess, "run", fake_run)
    hgb_eval_all.stop_eval_containers("eval_all_phase_b_test")
    assert commands[0][-1] == "label=hgb.eval_all_run=eval_all_phase_b_test"
    assert commands[1][:3] == ["docker", "rm", "-f"]
    assert commands[1][3:] == ["container_one", "container_two"]
    assert not remaining


def test_interrupt_cleanup_continues_after_one_batch_times_out(monkeypatch) -> None:
    remaining = {f"container_{index:02d}" for index in range(25)}
    batches = []
    timed_out = False

    def fake_run(cmd, **_kwargs):
        nonlocal timed_out
        if cmd[1] == "ps":
            return SimpleNamespace(returncode=0, stdout="\n".join(sorted(remaining)), stderr="")
        batches.append(cmd[3:])
        if not timed_out:
            timed_out = True
            raise subprocess.TimeoutExpired(cmd, 45)
        remaining.difference_update(cmd[3:])
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(hgb_eval_all.subprocess, "run", fake_run)
    hgb_eval_all.stop_eval_containers("eval_all_phase_b_test")
    assert len(batches) == 4
    assert max(map(len, batches)) == 12
    assert not remaining


def test_ten_minute_campaign_requires_nearly_full_elapsed_time() -> None:
    assert hgb_eval_all.minimum_campaign_elapsed(600) == 594
    assert hgb_eval_all.minimum_campaign_elapsed(86400) == 86340


def test_resume_reuses_in_place_coverage_recovery_without_restarting_fuzzing(tmp_path: Path) -> None:
    selected = str(tmp_path / "workspace/g2fuzz/zlib_zlib_uncompress_fuzzer/phase_a")
    run = tmp_path / "workspace/g2fuzz/zlib_zlib_uncompress_fuzzer/phase_b"
    run.mkdir(parents=True)
    (run / "metadata.json").write_text('{"status":"evaluated"}')
    (run / "result.json").write_text(json.dumps({
        "status": "evaluated",
        "campaign": {"configured_duration_seconds": 600, "campaign_wall_seconds": 600,
                     "execs_done": 5000},
        "coverage": {"line_coverage": {"covered": 100},
                     "sut_line_coverage": {"covered": 90, "total": 500},
                     "coverage_report_path": "/workspace/host_coverage/coverage.lcov"},
    }))
    (run / "phase_b_source.json").write_text(json.dumps({
        "baseline": "g2fuzz", "target": "zlib_zlib_uncompress_fuzzer",
        "selected_phase_a_run": selected,
        "canonical_target_package": str(tmp_path / "workspace/target-packages/zlib"),
    }))
    record = {"g2fuzz_run": str(run.relative_to(tmp_path)), "g2fuzz_status": "quality_failure"}
    recovered = hgb_eval_all.recovered_csv_trial(
        tmp_path, record, "g2fuzz", "zlib_zlib_uncompress_fuzzer", 600, selected)
    assert recovered is not None
    assert recovered["status"] == "evaluated"
    assert recovered["covered_lines"] == 90
    assert hgb_eval_all.recovered_csv_trial(
        tmp_path, record, "g2fuzz", "zlib_zlib_uncompress_fuzzer", 600, "different source") is None


def test_benchmark_context_pins_libpng_and_defaults_openssl_fuzzer(tmp_path: Path) -> None:
    libpng = tmp_path / "libpng"
    libpng.mkdir()
    (libpng / "Dockerfile").write_text("RUN git clone https://github.com/glennrp/libpng.git\n")
    (libpng / "benchmark.yaml").write_text("commit: cd0ea2a7f53b603d3d9b5b891c779c430047b39a\n")
    builder._patch_single_target_build_context(libpng, "libpng_read_fuzzer")
    assert "git -C libpng checkout cd0ea2a7f53b603d3d9b5b891c779c430047b39a" in (
        libpng / "Dockerfile").read_text()

    openssl = tmp_path / "openssl"
    openssl.mkdir()
    (openssl / "build.sh").write_text('#!/bin/bash -eu\nif [ "$FUZZER" = "centipede" ]; then\n  :\nfi\n')
    builder._patch_single_target_build_context(openssl, "x509")
    assert 'export FUZZER="${FUZZER:-libfuzzer}"' in (openssl / "build.sh").read_text()


@pytest.mark.parametrize("fuzz_target,url,dest", [
    ("jsoncpp_fuzzer", "https://github.com/open-source-parsers/jsoncpp", "jsoncpp"),
    ("cms_transform_fuzzer", "https://github.com/mm2/Little-CMS.git", "Little-CMS"),
    ("fuzz_both", "https://github.com/the-tcpdump-group/libpcap.git", "libpcap"),
    ("xml", "https://gitlab.gnome.org/GNOME/libxml2.git", "libxml2"),
    ("decoder_fuzzer", "https://github.com/cisco/openh264.git", "openh264"),
])
def test_coverage_build_uses_benchmark_source_revision(
        tmp_path: Path, fuzz_target: str, url: str, dest: str) -> None:
    (tmp_path / "Dockerfile").write_text(f"RUN git clone {url}\n")
    (tmp_path / "benchmark.yaml").write_text("commit: abc123\n")
    builder._patch_single_target_build_context(tmp_path, fuzz_target)
    assert f"git -C {dest} checkout abc123" in (tmp_path / "Dockerfile").read_text()


def test_libjpeg_coverage_build_uses_only_pinned_main_branch(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "RUN git clone https://github.com/libjpeg-turbo/fuzz && \\\n"
        "    cat fuzz/branches.txt | while read branch; do \\\n"
        "      git clone https://github.com/libjpeg-turbo/libjpeg-turbo \\\n"
        "          -b $branch libjpeg-turbo.$branch; \\\n"
        "    done\n")
    (tmp_path / "benchmark.yaml").write_text("commit: abc123\n")
    (tmp_path / "build.sh").write_text("cat fuzz/branches.txt | while read branch; do\n  :\ndone\n")
    builder._patch_single_target_build_context(tmp_path, "libjpeg_turbo_fuzzer")
    dockerfile = (tmp_path / "Dockerfile").read_text()
    assert "printf 'main\\n' | while read branch" in dockerfile
    assert "git -C libjpeg-turbo.$branch checkout abc123" in dockerfile
    assert '[ "$branch" = "main" ] || continue' in (tmp_path / "build.sh").read_text()


def test_openh264_coverage_links_the_same_library_object_set(tmp_path: Path) -> None:
    build = tmp_path / "build.sh"
    build.write_text("$CXX $CXXFLAGS -o $OUT/decoder_fuzzer "
                     "$LIB_FUZZING_ENGINE $SRC/decoder_fuzzer.cpp libopenh264.a\n")
    builder._patch_single_target_build_context(tmp_path, "decoder_fuzzer")
    patched = build.read_text()
    assert 'if [ "${SANITIZER:-}" = coverage ]; then' in patched
    assert "-Wl,--whole-archive libopenh264.a -Wl,--no-whole-archive" in patched
    assert "$SRC/decoder_fuzzer.cpp $HGB_OPENH264_ARCHIVE" in patched


def test_finished_evaluation_audits_common_lines_under_workspace(
        tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(hgb_eval_all, "ROOT", tmp_path)
    calls = []
    def fake_run(cmd, **_kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(hgb_eval_all.subprocess, "run", fake_run)
    output = tmp_path / "results/eval_all/2026-10-24.csv"
    assert hgb_eval_all.write_coverage_products(output)
    cmd = calls[0]
    assert cmd[cmd.index("--input") + 1] == str(output)
    common = Path(cmd[cmd.index("--common-source-output") + 1])
    assert common == tmp_path / "workspace/eval_all/2026-10-24.coverage_common.csv"


def test_zlib_coverage_link_includes_all_sut_archive_objects(tmp_path: Path) -> None:
    build = tmp_path / "build.sh"
    build.write_text("$CXX $CXXFLAGS -std=c++11 driver.cc -o $OUT/zlib_uncompress_fuzzer "
                     "$LIB_FUZZING_ENGINE ./libz.a\n")
    builder._patch_single_target_build_context(tmp_path, "zlib_uncompress_fuzzer")
    patched = build.read_text()
    assert 'if [ "${SANITIZER:-}" = coverage ]; then' in patched
    assert "-Wl,--whole-archive ./libz.a -Wl,--no-whole-archive" in patched
    assert "$LIB_FUZZING_ENGINE $HGB_ZLIB_ARCHIVE" in patched


def test_mbedtls_coverage_link_includes_all_sut_archives(tmp_path: Path) -> None:
    build = tmp_path / "build.sh"
    build.write_text("pip3 install -r $SRC/mbedtls/scripts/basic.requirements.txt\n"
                     "perl scripts/config.pl set MBEDTLS_PLATFORM_TIME_ALT\nmkdir build\n")
    builder._patch_single_target_build_context(tmp_path, "fuzz_dtlsclient")
    patched = build.read_text()
    assert "set(libs \"-Wl,--whole-archive\"" in patched
    assert "${mbedtls_target} ${mbedx509_target} ${mbedcrypto_target}" in patched
    assert "-Wl,--whole-archive" in patched
    assert "pip3 install -r" not in patched
    assert "jsonschema==4.17.3" in patched


def test_trials_plan_has_independent_rows_and_default_paths(tmp_path: Path, monkeypatch) -> None:
    targets = ["example"]
    scope = {(baseline, "example"): "N/A" if baseline == "elfuzz" else "pending"
             for baseline in hgb_eval_all.BASELINES}
    manifest = tmp_path / "workspace/eval_all/2026-10-20.phase_a.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({"records": [
        {"baseline": baseline, "target": "example", "status": "ready", "source_run": "saved"}
        for baseline in hgb_eval_all.BASELINES if baseline != "elfuzz"
    ]}), encoding="utf-8")
    monkeypatch.setattr(hgb_eval_all, "ROOT", tmp_path)
    monkeypatch.setattr(hgb_eval_all, "plan", lambda _root: (targets, scope))
    monkeypatch.setattr(hgb_eval_all, "source_ready", lambda _b, _t, raw: (True, raw))
    monkeypatch.setattr(sys, "argv", ["hgb_eval_all.py", "--phase", "fuzz",
                                      "--date", "2026-10-20", "--trials", "5", "--plan"])
    assert hgb_eval_all.main() == 0
    output = tmp_path / "workspace/eval_all/2026-10-20.trials5.csv"
    records = list(csv.DictReader(output.open(newline="", encoding="utf-8")))
    assert len(records) == 5
    assert [row["trial"] for row in records] == ["1", "2", "3", "4", "5"]
    assert all(row["elfuzz_status"] == "N/A" for row in records)


def test_resume_rejects_single_trial_csv_for_multi_trial_run(tmp_path: Path, monkeypatch) -> None:
    targets = ["example"]
    scope = {(baseline, "example"): "pending" for baseline in hgb_eval_all.BASELINES}
    rows = {(baseline, "example"): {"status": "evaluated", "campaign_seconds": 60}
            for baseline in hgb_eval_all.BASELINES}
    output = tmp_path / "single.csv"
    hgb_eval_all.save_csv(output, targets, rows)
    manifest = tmp_path / "phase_a.json"
    manifest.write_text(json.dumps({"records": [
        {"baseline": baseline, "target": "example", "status": "ready", "source_run": "saved"}
        for baseline in hgb_eval_all.BASELINES
    ]}), encoding="utf-8")
    monkeypatch.setattr(hgb_eval_all, "plan", lambda _root: (targets, scope))
    monkeypatch.setattr(hgb_eval_all, "source_ready", lambda _b, _t, raw: (True, raw))
    monkeypatch.setattr(sys, "argv", ["hgb_eval_all.py", "--phase", "fuzz", "--trials", "5",
                                      "--resume", "--plan", "--output", str(output),
                                      "--manifest", str(manifest)])
    with pytest.raises(SystemExit) as error:
        hgb_eval_all.main()
    assert error.value.code == 2


def test_trial_summary_uses_only_evaluated_coverage_and_exposes_failure(tmp_path: Path) -> None:
    rows = {(trial, baseline, "example"): {"status": "N/A" if baseline == "elfuzz" else "pending"}
            for trial in (1, 2) for baseline in hgb_eval_all.BASELINES}
    rows[1, "ckgfuzzer", "example"] = {"status": "evaluated", "covered_lines": 10}
    rows[2, "ckgfuzzer", "example"] = {"status": "evaluated", "covered_lines": 14}
    rows[1, "promefuzz", "example"] = {"status": "evaluated", "covered_lines": 6}
    rows[2, "promefuzz", "example"] = {"status": "failed", "reason": "SIGKILL"}
    path = tmp_path / "summary.csv"
    hgb_eval_all.save_trial_summary(path, ["example"], rows, 2)
    records = {row["baseline"]: row for row in csv.DictReader(path.open(newline="", encoding="utf-8"))}
    assert records["ckgfuzzer"]["status"] == "evaluated"
    assert records["ckgfuzzer"]["mean_covered_lines"] == "12"
    assert records["ckgfuzzer"]["stdev_covered_lines"] == "2.828"
    assert records["promefuzz"]["status"] == "partial"
    assert records["promefuzz"]["evaluated_trials"] == "1"
    assert records["elfuzz"]["status"] == "N/A"


def test_replay_trials_use_distinct_run_ids_and_logs(tmp_path: Path, monkeypatch) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    seen = []

    def fake_run(cmd, **_kwargs):
        run_id = cmd[cmd.index("--run-id") + 1]
        seen.append(run_id)
        run = tmp_path / "workspace/promefuzz/example" / run_id
        (run / "evaluation").mkdir(parents=True)
        (run / "metadata.json").write_text('{"status":"evaluated"}')
        (run / "evaluation/result.json").write_text(json.dumps({
            "status": "evaluated", "campaign": {"campaign_wall_seconds": 60, "execs_done": 1},
            "coverage": {"line_coverage": {"covered": 2}},
        }))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(hgb_eval_all.subprocess, "run", fake_run)
    for trial in (1, 2):
        hgb_eval_all.run_replay_job(tmp_path, "promefuzz", "example", "saved",
                                    "batch", 60, logs, 1, 8, trial, 2)
    assert seen == ["batch_trial_001_promefuzz_example", "batch_trial_002_promefuzz_example"]
    assert (logs / "promefuzz_example.trial_001.log").is_file()
    assert (logs / "promefuzz_example.trial_002.log").is_file()


def test_phase_b_dispatches_trials_of_one_pair_together(tmp_path: Path, monkeypatch) -> None:
    target = "example"
    scope = {(baseline, target): "pending" if baseline in {"ckgfuzzer", "g2fuzz"} else "N/A"
             for baseline in hgb_eval_all.BASELINES}
    manifest = tmp_path / "inputs/manifest.json"
    manifest.parent.mkdir()
    manifest.write_text(json.dumps({"records": [
        {"baseline": baseline, "target": target, "status": "ready", "source_run": "saved-source"}
        for baseline in ("ckgfuzzer", "g2fuzz")
    ]}), encoding="utf-8")
    output = tmp_path / "outputs/trials.csv"
    seen_active = []

    def fake_wait(active, **_kwargs):
        seen_active.append({(trial, baseline, name) for trial, baseline, name, _cpu in active.values()})
        return set(active), set()

    monkeypatch.setattr(hgb_eval_all, "ROOT", tmp_path)
    monkeypatch.setattr(hgb_eval_all, "plan", lambda _root: ([target], scope))
    monkeypatch.setattr(hgb_eval_all, "source_ready", lambda _b, _t, source: (True, source))
    monkeypatch.setattr(hgb_eval_all, "eval_container_memory_gib", lambda _run_id: 0.0)
    monkeypatch.setattr(hgb_eval_all, "host_available_memory_gib", lambda: 90.0)
    monkeypatch.setattr(hgb_eval_all, "host_memory_gib", lambda: 100)
    monkeypatch.setattr(hgb_eval_all, "run_replay_job", lambda *_args: {"status": "evaluated"})
    monkeypatch.setattr(hgb_eval_all, "wait", fake_wait)
    monkeypatch.setattr(hgb_eval_all, "write_coverage_products", lambda _output: True)
    monkeypatch.setattr(hgb_eval_all.subprocess, "run", lambda *_args, **_kwargs: SimpleNamespace(returncode=0))
    monkeypatch.setattr(sys, "argv", ["hgb_eval_all.py", "--phase", "fuzz", "--trials", "2",
                                      "--parallel-worker", "4", "--campaign-seconds", "60",
                                      "--run-id", "concurrent_trials", "--manifest", str(manifest),
                                      "--output", str(output)])
    original_cwd = Path.cwd()
    try:
        assert hgb_eval_all.main() == 0
    finally:
        monkeypatch.chdir(original_cwd)
    assert any({(1, "ckgfuzzer", target), (2, "ckgfuzzer", target)} <= active
               for active in seen_active)


def test_elfuzz_binary_extraction_retries_transient_docker_failure(tmp_path: Path, monkeypatch) -> None:
    benchmark = tmp_path / "benchmark"
    benchmark.mkdir()
    (benchmark / "Dockerfile").write_text("FROM scratch\n")
    copies = []

    def runner(command, _timeout):
        cmd = list(command)
        if cmd[:2] == ["docker", "image"]:
            return builder.CommandResult(cmd, 0, "sha256:abc\n", "")
        if cmd[:2] == ["docker", "cp"]:
            copies.append(cmd)
            if len(copies) == 1:
                return builder.CommandResult(cmd, 1, "", "Docker daemon busy")
            Path(cmd[-1]).write_bytes(b"fuzzer")
        return builder.CommandResult(cmd, 0, "", "")

    monkeypatch.setattr(builder.time, "sleep", lambda _seconds: None)
    record = builder.build_elfuzz_sut(
        benchmark_dir=benchmark, image_tag="hgb-test", fuzz_target="target",
        work_dir=tmp_path / "sut", runner=runner,
    )
    assert record["binary_extracted"]
    assert len(copies) == 2
