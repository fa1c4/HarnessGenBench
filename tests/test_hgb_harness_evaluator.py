from __future__ import annotations

import importlib.util
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
_DOCKER_COMMON = REPO_ROOT / "docker" / "common"
if str(_DOCKER_COMMON) not in sys.path:
    sys.path.insert(0, str(_DOCKER_COMMON))


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


hgb_result = _load_module("hgb_result_harness_eval", "docker/common/hgb_result.py")
hgb_fuzzbench_builder = _load_module("hgb_fuzzbench_builder_harness_eval", "docker/common/hgb_fuzzbench_builder.py")
evaluator = _load_module("hgb_harness_evaluator_shared", "docker/common/hgb_harness_evaluator.py")


def test_freetype_fallback_seed_contains_valid_font_and_consumable_length(tmp_path: Path) -> None:
    target = tmp_path / "target"
    font = target / "source_input/TRT/fonts/TestGLYFOne.ttf"
    font.parent.mkdir(parents=True)
    font.write_bytes(b"F" * 1516)
    seed = evaluator._fallback_seed(target, tmp_path / "work", "freetype2", "ftfuzzer")
    assert seed.read_bytes() == font.read_bytes() + len(font.read_bytes()).to_bytes(2, "little")
    fallback = evaluator._fallback_seed(target, tmp_path / "other", "zlib", "zlib_uncompress_fuzzer")
    assert fallback.read_bytes() == b"hgb"


class FakeResult:
    def __init__(self, command, exit_code=0, stdout="", stderr=""):
        self.command = list(command)
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


@pytest.mark.parametrize("phase_b", [False, True])
@pytest.mark.parametrize("start_exit", [0, 124])
def test_smoke_docker_waits_are_unbounded_only_for_phase_b(
    tmp_path: Path, monkeypatch, phase_b: bool, start_exit: int,
) -> None:
    if phase_b:
        monkeypatch.setenv("HGB_PHASE_B_REPLAY", "1")
    else:
        monkeypatch.delenv("HGB_PHASE_B_REPLAY", raising=False)
    calls = []

    def runner(command, timeout):
        calls.append((command[1], timeout))
        if command[1] == "start":
            return FakeResult(command, start_exit, "HGB_TARGET_START\n" if not start_exit else "")
        return FakeResult(command)

    evaluator.hgb_fuzzbench_builder.run_smoke(
        image_tag="smoke-image", binary_path="/out/fuzzer", seeds=[],
        work_dir=tmp_path, runner=runner)
    timeout = None if phase_b else 600
    assert calls == ([('create', timeout), ('cp', timeout), ('start', timeout)]
                     + ([('kill', timeout)] if start_exit and not phase_b else [])
                     + [('rm', timeout)])


def test_phase_b_binary_verification_docker_wait_has_no_timeout(monkeypatch) -> None:
    calls = []

    def runner(command, timeout):
        calls.append((list(command), timeout))
        return FakeResult(command)

    command = ["docker", "run", "--rm", "test-image", "sh", "-lc", "test -x /out/fuzzer"]
    monkeypatch.setenv("HGB_PHASE_B_REPLAY", "1")
    evaluator.hgb_fuzzbench_builder._run_phase(runner, command, 300, "verify candidate binary")
    assert calls == [(command, None)]

    monkeypatch.delenv("HGB_PHASE_B_REPLAY")
    evaluator.hgb_fuzzbench_builder._run_phase(runner, command, 300, "verify candidate binary")
    assert calls[-1] == (command, 300)


def test_phase_b_failed_attach_waits_for_container_before_copy_out(
    tmp_path: Path, monkeypatch,
) -> None:
    monkeypatch.setenv("HGB_PHASE_B_REPLAY", "1")
    commands = []
    output = tmp_path / "saved-corpus.tar"

    def runner(command, timeout):
        command = list(command)
        commands.append((command, timeout))
        action = command[1]
        if action == "start":
            return FakeResult(command, 125, "", "Docker attach failed")
        if action == "inspect":
            return FakeResult(command, 0, "true\n")
        if action == "wait":
            return FakeResult(command, 0, "0\n")
        if action == "cp":
            with tarfile.open(command[-1], "w") as archive:
                payload = b"saved after container exit"
                member = tarfile.TarInfo("corpus/sample")
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        return FakeResult(command)

    result = evaluator.hgb_fuzzbench_builder._container_run(
        image_tag="test-image", work_dir=tmp_path / "container",
        runner=runner, timeout_seconds=123,
        command=["sh", "-lc", "true"], phase="campaign",
        copy_out=("/tmp/corpus.tar", output),
    )

    assert [command[1] for command, _ in commands] == [
        "create", "start", "inspect", "wait", "cp", "rm",
    ]
    assert all(timeout is None for _, timeout in commands)
    assert all(command[:2] != ["docker", "kill"] for command, _ in commands)
    assert commands[-1][0][:3] == ["docker", "rm", commands[1][0][-1]]
    with tarfile.open(output) as archive:
        assert archive.extractfile("corpus/sample").read() == b"saved after container exit"
    assert result.copy_out_ok is True
    assert result.exit_code == 0


class _Runner:
    """Fake runner that materializes a copied coverage.json for eta and a
    corpus.tar for the campaign, and emits the HGB_INPUTS_REPLAYED marker.
    """

    def __init__(self, *, candidate_sha=None, candidate_path=None, campaign_execs=500,
                 coverage_inputs_replayed=1, coverage_copy_out_ok=True,
                 materialize_coverage=True, coverage_stdout=None):
        import hashlib
        if candidate_sha is None:
            if candidate_path is not None and Path(candidate_path).is_file():
                candidate_sha = hashlib.sha256(Path(candidate_path).read_bytes()).hexdigest()
            else:
                candidate_sha = "candsha"
        self.candidate_sha = candidate_sha
        self.campaign_execs = campaign_execs
        self.coverage_inputs_replayed = coverage_inputs_replayed
        self.coverage_copy_out_ok = coverage_copy_out_ok
        self.materialize_coverage = materialize_coverage
        self.coverage_json = coverage_stdout if coverage_stdout is not None else json.dumps({
            "data": [{"totals": {"lines": {"count": 100, "covered": 27},
                                  "functions": {"count": 10, "covered": 5},
                                  "regions": {"count": 50, "covered": 12}},
                        "functions": [{"name": "hgb_sample_api", "count": 5}]}],
            "type": "llvm.coverage.json.export", "version": "2.0.1",
        })
        self._containers = {}

    def __call__(self, command, timeout):
        cmd = list(command)
        if not cmd:
            return FakeResult(cmd, 1)
        head = cmd[0]
        if head == "docker":
            sub = cmd[1] if len(cmd) > 1 else ""
            if sub == "build":
                return FakeResult(cmd, 0, "build ok", "")
            if sub == "image" and len(cmd) > 3 and cmd[2] == "inspect":
                return FakeResult(cmd, 0, "sha256:fakeimage\n", "")
            if sub == "create":
                name = ""
                for i, tok in enumerate(cmd):
                    if tok == "--name" and i + 1 < len(cmd):
                        name = cmd[i + 1]
                phase = "coverage" if "coverage" in name else ("campaign" if "campaign" in name else ("smoke" if "smoke" in name else "unknown"))
                self._containers[name] = phase
                return FakeResult(cmd, 0, name + "\n", "")
            if sub == "start":
                name = cmd[-1]
                phase = self._containers.get(name, "unknown")
                if phase == "smoke":
                    return FakeResult(cmd, 0, "smoke ok", "HGB_TARGET_START\n")
                if phase == "campaign":
                    return FakeResult(cmd, 0, f"#{self.campaign_execs} INITED\nstat::number_of_executed_units: {self.campaign_execs}\n", "")
                if phase == "coverage":
                    return FakeResult(cmd, 0, self.coverage_json, f"HGB_INPUTS_REPLAYED={self.coverage_inputs_replayed}\n")
                return FakeResult(cmd, 0, "", "")
            if sub == "cp":
                cp_src = cmd[2] if len(cmd) > 2 else ""
                cp_dst = cmd[3] if len(cmd) > 3 else ""
                if "corpus.tar" in cp_src and cp_dst:
                    import io
                    import tarfile
                    Path(cp_dst).parent.mkdir(parents=True, exist_ok=True)
                    data = b"corpus-input-1"
                    with tarfile.open(cp_dst, "w") as tf:
                        info = tarfile.TarInfo(name="corpus/seed_0000")
                        info.size = len(data)
                        tf.addfile(info, io.BytesIO(data))
                    return FakeResult(cmd, 0, "", "")
                if "coverage.json" in cp_src and cp_dst:
                    if not self.coverage_copy_out_ok:
                        return FakeResult(cmd, 1, "", "coverage copy_out failed")
                    if self.materialize_coverage:
                        Path(cp_dst).parent.mkdir(parents=True, exist_ok=True)
                        Path(cp_dst).write_text(self.coverage_json, encoding="utf-8")
                    return FakeResult(cmd, 0, "", "")
                return FakeResult(cmd, 0, "", "")
            if sub == "rm":
                return FakeResult(cmd, 0, "", "")
            if sub == "run":
                shell_cmd = " ".join(cmd[3:])
                if "test -x" in shell_cmd and "sha256sum" in shell_cmd:
                    return FakeResult(cmd, 0, f"{self.candidate_sha}  /out/fuzz_target\n", "")
                if "sha256sum /src/" in shell_cmd:
                    return FakeResult(cmd, 0, f"{self.candidate_sha}  /src/project/native.c\n", "")
                return FakeResult(cmd, 0, "", "")
        return FakeResult(cmd, 0, "", "")


def _setup(tmp_path: Path):
    gen_root = tmp_path / "generator_input"
    evl_root = tmp_path / "evaluator_only"
    candidates_dir = tmp_path / "candidates"
    work_dir = tmp_path / "evaluation"
    (gen_root / "seeds").mkdir(parents=True)
    (gen_root / "source_input" / "project").mkdir(parents=True)
    (gen_root / "source_input" / "project" / "sample.c").write_text("int api(void){return 0;}\n", encoding="utf-8")
    (gen_root / "source_input" / "project" / "native.c").write_text("// original native\nint LLVMFuzzerTestOneInput(){}\n", encoding="utf-8")
    (gen_root / "source_repos.json").write_text("[]", encoding="utf-8")
    (evl_root / "benchmark_copy").mkdir(parents=True)
    (evl_root / "benchmark_copy" / "Dockerfile").write_text("FROM scratch\nCOPY source_input/ /src/\n", encoding="utf-8")
    (evl_root / "benchmark_copy" / "build.sh").write_text("#!/bin/sh\ncc $SRC/project/native.c -o $OUT/fuzz_target\n", encoding="utf-8")
    (evl_root / "reference_harnesses" / "source_input" / "project").mkdir(parents=True)
    (evl_root / "reference_harnesses" / "source_input" / "project" / "native.c").write_text("// ref\n", encoding="utf-8")
    (evl_root / "selected_reference_harnesses" / "project").mkdir(parents=True)
    (evl_root / "selected_reference_harnesses" / "project" / "native.c").write_text("// original native\nint LLVMFuzzerTestOneInput(){}\n", encoding="utf-8")
    (evl_root / "native_harness_path.json").write_text(json.dumps({
        "selected_reference": "source_input/project/native.c",
        "container_destination": "/src/project/native.c",
        "language": "c",
    }), encoding="utf-8")
    (evl_root / "evaluator_manifest.json").write_text(json.dumps({"benchmark_copy_dir": "benchmark_copy"}), encoding="utf-8")
    (evl_root / "target_manifest.evaluator.json").write_text(json.dumps({"target": "t"}), encoding="utf-8")
    candidates_dir.mkdir(parents=True)
    (candidates_dir / "cand_001.c").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char *d, long n){return 0;}\n", encoding="utf-8"
    )
    return gen_root, evl_root, candidates_dir, work_dir


def test_eta_evaluator_requires_copied_coverage_report(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup(tmp_path)
    runner = _Runner(candidate_path=str(candidates_dir / "cand_001.c"), coverage_copy_out_ok=False, materialize_coverage=False)
    result = evaluator.evaluate(
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-eta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
        build_coverage_image=True,
    )
    assert result["status"] != hgb_result.STATUS_EVALUATED
    cand = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand["stages"]["coverage"] == "failed"


def test_valuable_target_rejects_harness_only_coverage(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup(tmp_path)
    runner = _Runner(candidate_path=str(candidates_dir / "cand_001.c"))
    result = evaluator.evaluate(
        generator="oss-fuzz-gen", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="re2",
        fuzz_target="fuzz_target", profile="alpha", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
        build_coverage_image=True,
    )
    assert result["status"] != hgb_result.STATUS_EVALUATED
    candidate = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert "no covered re2 project source lines" in candidate["error"]


def test_eta_evaluator_requires_nonzero_inputs_replayed(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup(tmp_path)
    runner = _Runner(candidate_path=str(candidates_dir / "cand_001.c"), coverage_inputs_replayed=0)
    result = evaluator.evaluate(
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-eta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
        build_coverage_image=True,
    )
    assert result["status"] != hgb_result.STATUS_EVALUATED
    cand = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand["stages"]["coverage"] == "failed"
    assert "inputs_replayed" in (cand.get("error") or "")


def test_eta_evaluator_full_loop_with_native_control(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup(tmp_path)
    runner = _Runner(candidate_path=str(candidates_dir / "cand_001.c"))
    result = evaluator.evaluate(
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-eta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
        build_coverage_image=True, run_native_control=True,
    )
    assert result["status"] == hgb_result.STATUS_EVALUATED
    cand_json = json.loads((work_dir / "candidates" / "cand_001.json").read_text(encoding="utf-8"))
    assert cand_json["coverage"]["copy_out_ok"] is True
    assert cand_json["coverage"]["inputs_replayed"] > 0
    assert Path(cand_json["coverage"]["coverage_report_path"]).is_file()


def test_elfuzz_evaluator_uses_tmpfs_campaign_workdir(tmp_path: Path) -> None:
    class RecordingRunner(_Runner):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.commands = []

        def __call__(self, command, timeout):
            self.commands.append(list(command))
            return super().__call__(command, timeout)

    gen_root, evl_root, candidates_dir, work_dir = _setup(tmp_path)
    runner = RecordingRunner(candidate_path=str(candidates_dir / "cand_001.c"))
    evaluator.evaluate(
        generator="elfuzz", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-zeta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
    )
    campaign_shells = [command[-1] for command in runner.commands
                       if command[:2] == ["docker", "create"]
                       and "hgb-campaign/corpus" in command[-1]]
    assert len(campaign_shells) == 1
    assert 'cd /tmp/hgb-campaign/workdir || exit 1' in campaign_shells[0]


def test_evaluator_can_stop_after_first_fully_verified_candidate(tmp_path: Path) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup(tmp_path)
    (candidates_dir / "cand_002.c").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char *d, long n){return 1;}\n",
        encoding="utf-8",
    )
    runner = _Runner(candidate_path=str(candidates_dir / "cand_001.c"))
    result = evaluator.evaluate(
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-eta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
        build_coverage_image=True, stop_on_first_success=True,
    )
    assert result["status"] == hgb_result.STATUS_EVALUATED
    assert result["candidate_count"] == 2
    assert result["artifacts"]["evaluated_candidate_count"] == 1
    assert (work_dir / "candidates/cand_001.json").is_file()
    assert not (work_dir / "candidates/cand_002.json").exists()


def test_zeta_evaluator_still_accepts_stdout_coverage(tmp_path: Path) -> None:
    # zeta is an alias of the strict family but does not enforce the eta-only
    # copied-coverage-report requirement; stdout coverage is still accepted.
    gen_root, evl_root, candidates_dir, work_dir = _setup(tmp_path)
    runner = _Runner(candidate_path=str(candidates_dir / "cand_001.c"), coverage_copy_out_ok=False, materialize_coverage=False)
    result = evaluator.evaluate(
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="reproduction-zeta", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
    )
    assert result["status"] == hgb_result.STATUS_EVALUATED


def test_run_coverage_eta_requires_copied_report(tmp_path: Path) -> None:
    work_dir = tmp_path / "cov"
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "seed_0000").write_bytes(b"\x01\x02")
    runner = _Runner(coverage_copy_out_ok=False, materialize_coverage=False)
    cov = hgb_fuzzbench_builder.run_coverage(
        image_tag="hgb-test", binary_path="/out/fuzz_target", corpus_dir=corpus,
        work_dir=work_dir, runner=runner, require_coverage_report=True,
    )
    assert cov["report_exists"] is False
    assert cov["coverage_report_path"] == ""
    assert cov["copy_out_ok"] is False


def test_run_coverage_eta_parses_inputs_replayed_marker(tmp_path: Path) -> None:
    work_dir = tmp_path / "cov"
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "seed_0000").write_bytes(b"\x01\x02")
    (corpus / "seed_0001").write_bytes(b"\x03\x04")
    runner = _Runner(coverage_inputs_replayed=2)
    cov = hgb_fuzzbench_builder.run_coverage(
        image_tag="hgb-test", binary_path="/out/fuzz_target", corpus_dir=corpus,
        work_dir=work_dir, runner=runner, require_coverage_report=True,
    )
    assert cov["inputs_replayed"] == 2
    assert cov["report_exists"] is True
    assert cov["copy_out_ok"] is True
    assert cov["coverage_report_path"]
    assert Path(cov["coverage_report_path"]).is_file()


def test_coverage_replay_limits_each_input_to_one_run(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "seed").write_bytes(b"input")

    class RecordingRunner(_Runner):
        def __init__(self):
            super().__init__()
            self.commands = []

        def __call__(self, command, timeout):
            self.commands.append(list(command))
            return super().__call__(command, timeout)

    for strict in (False, True):
        runner = RecordingRunner()
        hgb_fuzzbench_builder.run_coverage(
            image_tag="hgb-test", binary_path="/out/fuzz_target", corpus_dir=corpus,
            work_dir=tmp_path / f"coverage_{strict}", runner=runner,
            require_coverage_report=strict,
        )
        create = next(cmd for cmd in runner.commands if cmd[:2] == ["docker", "create"])
        assert '-runs=1 "$f"' in create[-1]


def test_phase_b_reuses_verified_candidate_image_and_smoke(tmp_path: Path, monkeypatch) -> None:
    import hashlib

    gen_root, evl_root, candidates_dir, work_dir = _setup(tmp_path)
    candidate = candidates_dir / "cand_001.c"
    candidate_sha = hashlib.sha256(candidate.read_bytes()).hexdigest()
    runner = _Runner(candidate_sha=candidate_sha)
    saved = {
        "candidate_sha256": candidate_sha,
        "native_destination": "/src/project/native.c",
        "sanitizer_smoke": {"any_executed": True, "misuse_crash": False, "timed_out": False},
        "build": {
            "image_tag": "phase-a-verified-image", "image_digest": "sha256:fakeimage",
            "binary_path": "/out/fuzz_target", "binary_sha256": candidate_sha,
            "binary_verified": True, "overlay_audit": {"matches_candidate": True},
        },
    }

    original_build = evaluator.hgb_fuzzbench_builder.build_candidate_image

    def coverage_only_build(*args, **kwargs):
        assert kwargs.get("sanitizer") == "coverage", "Phase B rebuilt the saved address image"
        return original_build(*args, **kwargs)

    def forbidden_smoke(*_args, **_kwargs):
        raise AssertionError("Phase B repeated verified Phase A smoke")

    monkeypatch.setattr(evaluator.hgb_fuzzbench_builder, "build_candidate_image", coverage_only_build)
    monkeypatch.setattr(evaluator.hgb_fuzzbench_builder, "run_smoke", forbidden_smoke)
    result = evaluator.evaluate(
        generator="promefuzz", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="alpha", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
        build_coverage_image=True, preverified_candidate=saved,
        keep_going_campaign=True,
    )
    assert result["status"] == hgb_result.STATUS_EVALUATED
    assert result["selected_candidate"]["build"]["phase_a_reused"] is True
    assert result["campaign"]["keep_going"] is True


def test_phase_b_coverage_build_adds_candidate_compile_stage(tmp_path: Path) -> None:
    import hashlib

    gen_root, evl_root, candidates_dir, work_dir = _setup(tmp_path)
    candidate = candidates_dir / "cand_001.c"
    runner = _Runner(candidate_path=str(candidate))
    candidate_sha = hashlib.sha256(candidate.read_bytes()).hexdigest()
    saved = {
        "candidate_sha256": candidate_sha,
        "native_destination": "/src/project/native.c",
        "sanitizer_smoke": {"any_executed": True, "misuse_crash": False, "timed_out": False},
        "build": {"image_tag": "phase-a-address", "image_digest": "sha256:fakeimage",
                  "binary_path": "/out/fuzz_target", "binary_verified": True},
    }
    result = evaluator.evaluate(
        generator="promefuzz", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="alpha", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
        build_coverage_image=True, preverified_candidate=saved,
    )
    assert result["status"] == hgb_result.STATUS_EVALUATED
    dockerfile = work_dir / "sealed_context/sealed_context/Dockerfile"
    text = dockerfile.read_text(encoding="utf-8")
    assert "COPY hgb_candidate_overlay/project/native.c /src/project/native.c" in text
    assert "# HGB sealed evaluator candidate build." in text
    assert "SANITIZER=\"$HGB_SANITIZER\"" in text


def test_saved_campaign_recovery_requires_full_log_and_matching_corpus(tmp_path: Path) -> None:
    import io
    import tarfile

    work = tmp_path / "cand_001"
    (work / "campaign").mkdir(parents=True)
    (work / "corpus").mkdir()
    (work / "corpus/seed").write_bytes(b"input")
    with tarfile.open(work / "campaign/corpus.tar", "w") as archive:
        info = tarfile.TarInfo("corpus/seed")
        info.size = 5
        archive.addfile(info, io.BytesIO(b"input"))
    log = work / "campaign/campaign.log"
    log.write_text("#123: cov: 10 time: 86405s\nINFO: fuzzed for 86405 seconds\n", encoding="utf-8")
    saved = hgb_fuzzbench_builder.load_saved_campaign(work, 86400)
    assert saved["reused_saved_campaign"] is True
    assert saved["campaign_wall_seconds"] >= 86400
    assert saved["final_corpus_file_count"] == 1
    (work / "campaign/fuzzer.log").write_text(
        "HGB_CAMPAIGN_START_EPOCH=1000\nHGB_CAMPAIGN_END_EPOCH=1100\n")
    with pytest.raises(ValueError, match="active duration"):
        hgb_fuzzbench_builder.load_saved_campaign(work, 86400)
    (work / "campaign/fuzzer.log").unlink()
    log.write_text("#123: cov: 10 time: 85155s\nKilled\n", encoding="utf-8")
    with pytest.raises(ValueError, match="duration"):
        hgb_fuzzbench_builder.load_saved_campaign(work, 86400)


def test_campaign_reports_truncated_corpus_archive(tmp_path: Path) -> None:
    class TruncatedCorpusRunner(_Runner):
        def __call__(self, command, timeout):
            result = super().__call__(command, timeout)
            if len(command) > 3 and command[:2] == ["docker", "cp"] and "corpus.tar" in command[2]:
                path = Path(command[3])
                path.write_bytes(path.read_bytes()[:600])
            return result

    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "seed").write_bytes(b"input")
    work = tmp_path / "work"
    campaign = hgb_fuzzbench_builder.run_campaign(
        image_tag="test-image", binary_path="/out/php-fuzz-parser",
        corpus_dir=seeds, work_dir=work, campaign_seconds=10,
        runner=TruncatedCorpusRunner(), keep_going=True,
    )
    assert campaign["corpus_archive_error"]
    assert campaign["final_corpus_file_count"] == 0
    assert (work / "campaign/container.log").is_file()


def test_phase_b_reuses_saved_coverage_image(tmp_path: Path, monkeypatch) -> None:
    import hashlib

    gen_root, evl_root, candidates_dir, work_dir = _setup(tmp_path)
    candidate_sha = hashlib.sha256((candidates_dir / "cand_001.c").read_bytes()).hexdigest()
    saved = {
        "candidate_sha256": candidate_sha,
        "native_destination": "/src/project/native.c",
        "sanitizer_smoke": {"any_executed": True, "misuse_crash": False, "timed_out": False},
        "build": {"image_tag": "phase-a-address", "image_digest": "sha256:fakeimage",
                  "binary_path": "/out/fuzz_target", "binary_verified": True},
    }

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Phase B rebuilt a saved coverage image")

    monkeypatch.setattr(evaluator.hgb_fuzzbench_builder, "build_coverage_image", forbidden)
    result = evaluator.evaluate(
        generator="promefuzz", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="alpha", campaign_seconds=10,
        strict=True, runner=_Runner(candidate_sha=candidate_sha),
        intended_apis=["hgb_sample_api"], seeds=[], build_coverage_image=True,
        preverified_candidate=saved, keep_going_campaign=True,
        prebuilt_coverage_image="phase-a-coverage",
    )
    assert result["status"] == hgb_result.STATUS_EVALUATED
    assert result["selected_candidate"]["coverage"]["line_coverage"]["covered"] == 27


def test_phase_b_rebuilds_stale_coverage_image(tmp_path: Path) -> None:
    import hashlib

    gen_root, evl_root, candidates_dir, work_dir = _setup(tmp_path)
    candidate_sha = hashlib.sha256((candidates_dir / "cand_001.c").read_bytes()).hexdigest()

    class StaleImageRunner(_Runner):
        def __init__(self):
            super().__init__(candidate_sha=candidate_sha)
            self.commands = []

        def __call__(self, command, timeout):
            self.commands.append(list(command))
            if command[:2] == ["docker", "run"] and "phase-a-coverage" in command:
                return FakeResult(command, 0, "0" * 64 + "  /src/project/native.c\n")
            return super().__call__(command, timeout)

    runner = StaleImageRunner()
    saved = {
        "candidate_sha256": candidate_sha,
        "native_destination": "/src/project/native.c",
        "sanitizer_smoke": {"any_executed": True, "misuse_crash": False, "timed_out": False},
        "build": {"image_tag": "phase-a-address", "image_digest": "sha256:fakeimage",
                  "binary_path": "/out/fuzz_target", "binary_verified": True},
    }
    result = evaluator.evaluate(
        generator="promefuzz", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="alpha", campaign_seconds=10,
        strict=True, runner=runner, intended_apis=["hgb_sample_api"], seeds=[],
        build_coverage_image=True, preverified_candidate=saved,
        prebuilt_coverage_image="phase-a-coverage",
    )
    assert result["status"] == hgb_result.STATUS_EVALUATED
    assert result["selected_candidate"]["coverage"]["phase_a_image_reused"] is False
    assert any(cmd[:2] == ["docker", "build"] for cmd in runner.commands)


def test_fork_campaign_parses_progress_even_when_worker_stats_are_zero() -> None:
    log = (
        "INFO: -fork=1: fuzzing in separate process(s)\n"
        "#629: cov: 219 ft: 219 corp: 1 exec/s 314 oom/timeout/crash: 0/0/0 time: 2s\n"
        "stat::number_of_executed_units: 0\n"
    )
    assert evaluator.hgb_fuzzbench_builder._parse_execs_done(log) == 629


def test_runner_then_measurer_replays_saved_harness_corpus_only(
    tmp_path: Path, monkeypatch,
) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup(tmp_path)
    calls = {"campaign": 0, "coverage": 0}
    real_coverage = evaluator.hgb_fuzzbench_builder.run_coverage
    real_build_candidate = evaluator.hgb_fuzzbench_builder.build_candidate_image

    def saved_campaign(**kwargs):
        calls["campaign"] += 1
        assert kwargs["durable"] is True
        work = kwargs["work_dir"]
        campaign_dir = work / "campaign"
        corpus_dir = work / "corpus"
        campaign_dir.mkdir(parents=True, exist_ok=True)
        corpus_dir.mkdir(parents=True, exist_ok=True)
        for staged in corpus_dir.iterdir():
            if staged.is_file():
                staged.unlink()
        payload = b"saved final corpus input"
        (corpus_dir / "final_input").write_bytes(payload)
        fuzzer_log = (
            "HGB_CAMPAIGN_START_EPOCH=1000\n"
            "#500: cov: 8 time: 120s\n"
            "INFO: fuzzed for 120 seconds\n"
            "HGB_CAMPAIGN_END_EPOCH=1120\n"
        )
        (campaign_dir / "fuzzer.log").write_text(fuzzer_log)
        (campaign_dir / "campaign.log").write_text(fuzzer_log)
        with tarfile.open(campaign_dir / "corpus.tar", "w") as archive:
            item = tarfile.TarInfo("corpus/final_input")
            item.size = len(payload)
            archive.addfile(item, io.BytesIO(payload))
        record = {
            "configured_duration_seconds": 120,
            "campaign_wall_seconds": 120,
            "campaign_active_seconds": 120,
            "execs_done": 500,
            "copy_out_ok": True,
            "final_corpus_file_count": 1,
            "final_corpus_dir": str(corpus_dir),
            "corpus_dir": str(corpus_dir),
            "log": str(campaign_dir / "campaign.log"),
            "corpus_archive_error": "",
        }
        (campaign_dir / "campaign.json").write_text(json.dumps(record))
        return record

    def forbidden_coverage(**kwargs):
        raise AssertionError("runner must not measure coverage")

    monkeypatch.setattr(evaluator.hgb_fuzzbench_builder, "run_campaign", saved_campaign)
    monkeypatch.setattr(evaluator.hgb_fuzzbench_builder, "run_coverage", forbidden_coverage)
    runner_result = evaluator.evaluate(
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="alpha", campaign_seconds=120,
        strict=True, runner=_Runner(candidate_path=str(candidates_dir / "cand_001.c")),
        intended_apis=["hgb_sample_api"], seeds=[], build_coverage_image=True,
        keep_going_campaign=True, coverage_format="json", stage="runner",
    )
    assert runner_result["status"] == "corpus_ready"
    assert (work_dir / "runner_result.json").is_file()
    assert not (work_dir / "result.json").exists()
    assert runner_result["campaign"]["saved_campaign_verified"] is True
    assert calls["campaign"] == 1

    def forbidden_campaign(**kwargs):
        raise AssertionError("measurer must not fuzz again")

    def counted_coverage(**kwargs):
        calls["coverage"] += 1
        return real_coverage(**kwargs)

    monkeypatch.setattr(evaluator.hgb_fuzzbench_builder, "run_campaign", forbidden_campaign)
    monkeypatch.setattr(evaluator.hgb_fuzzbench_builder, "run_coverage", counted_coverage)
    monkeypatch.setattr(evaluator.hgb_fuzzbench_builder, "run_smoke", forbidden_campaign)
    def coverage_build_only(**kwargs):
        assert kwargs.get("sanitizer") == "coverage"
        return real_build_candidate(**kwargs)

    monkeypatch.setattr(evaluator.hgb_fuzzbench_builder, "build_candidate_image", coverage_build_only)
    measured = evaluator.evaluate(
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="alpha", campaign_seconds=120,
        strict=True, runner=_Runner(candidate_path=str(candidates_dir / "cand_001.c")),
        intended_apis=["hgb_sample_api"], seeds=[], build_coverage_image=True,
        keep_going_campaign=True, coverage_format="json", stage="measurer",
    )
    assert measured["status"] == "evaluated"
    assert calls == {"campaign": 1, "coverage": 1}
    assert measured["campaign"]["reused_saved_campaign"] is True
    assert (work_dir / "result.json").is_file()

    # Pre-split saved campaigns have a candidate report but no runner marker.
    (work_dir / "runner_result.json").unlink()
    legacy_measured = evaluator.evaluate(
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="alpha", campaign_seconds=120,
        strict=True, runner=_Runner(candidate_path=str(candidates_dir / "cand_001.c")),
        intended_apis=["hgb_sample_api"], seeds=[], build_coverage_image=True,
        keep_going_campaign=True, coverage_format="json", stage="measurer",
        reuse_saved_campaign=True,
    )
    assert legacy_measured["status"] == "evaluated"
    assert calls == {"campaign": 1, "coverage": 2}


def test_measurer_rejects_changed_candidate_without_fuzzing(tmp_path: Path, monkeypatch) -> None:
    gen_root, evl_root, candidates_dir, work_dir = _setup(tmp_path)
    work_dir.mkdir()
    candidate = candidates_dir / "cand_001.c"
    marker = {
        "status": "corpus_ready", "generator": "ckgfuzzer", "profile": "alpha",
        "target": "fuzz_target", "candidate_count": 1,
        "artifacts": {"target_manifest_sha256": ""},
        "campaign": {"configured_duration_seconds": 120, "saved_campaign_verified": True},
        "selected_candidate": {"candidate_id": "cand_001", "candidate_sha256": "wrong"},
    }
    (work_dir / "runner_result.json").write_text(json.dumps(marker))
    monkeypatch.setattr(evaluator.hgb_fuzzbench_builder, "run_campaign",
                        lambda **kwargs: pytest.fail("measurer must not fuzz"))
    result = evaluator.evaluate(
        generator="ckgfuzzer", target_root=gen_root, evaluator_root=evl_root,
        candidates_dir=candidates_dir, work_dir=work_dir, project="project",
        fuzz_target="fuzz_target", profile="alpha", campaign_seconds=120,
        stage="measurer",
    )
    assert result["status"] == "quality_failure"
    assert "saved runner evidence invalid" in result["reason"]


def test_phase_b_live_corpus_maps_outer_and_host_workspaces(tmp_path: Path) -> None:
    builder = evaluator.hgb_fuzzbench_builder
    outer = Path("/workspace/evaluation/cand_001/campaign/live_corpus")
    assert builder._phase_b_live_host_path(outer, str(tmp_path / "host-run")) == (
        tmp_path / "host-run/evaluation/cand_001/campaign/live_corpus")
    host_workspace = tmp_path / "repo/workspace"
    host_live = host_workspace / "phase_b/try_001/campaign/live_corpus"
    assert builder._phase_b_live_host_path(
        host_live, repo_workspace=host_workspace) == host_live
    with pytest.raises(ValueError, match="workspace"):
        builder._phase_b_live_host_path(tmp_path / "unrelated/live_corpus",
                                        repo_workspace=host_workspace)


def test_inner_campaign_docker_create_binds_live_corpus(tmp_path: Path) -> None:
    calls = []

    def runner(command, timeout):
        calls.append(list(command))
        return FakeResult(command)

    host_live = tmp_path / "run/evaluation/cand_001/campaign/live_corpus"
    host_live.mkdir(parents=True)
    evaluator.hgb_fuzzbench_builder._container_run(
        image_tag="address-image", work_dir=tmp_path / "container",
        runner=runner, timeout_seconds=100,
        command=["sh", "-lc", "true"], phase="campaign",
        mounts=[(host_live, "/tmp/corpus")],
    )
    create = calls[0]
    assert create[:2] == ["docker", "create"]
    assert create[create.index("-v") + 1] == f"{host_live}:/tmp/corpus"
