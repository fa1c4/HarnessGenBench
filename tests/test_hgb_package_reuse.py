from __future__ import annotations

import importlib.util
import json
import multiprocessing
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


targets = load("hgb_io_test_targets", "scripts/hgb_targets.py")
cache = load("hgb_io_test_cache", "docker/common/hgb_package_cache.py")
split = load("hgb_io_test_split", "docker/common/hgb_target_package.py")


@pytest.fixture
def project(tmp_path, monkeypatch):
    for key in ("HGB_TARGET_PACKAGE_CACHE_DIR", "HGB_TARGET_DISABLE_SPLIT", "HGB_TARGET_STRIP_REFERENCE_HARNESS",
                "HGB_REF_CANARY", "HGB_BASELINE_PROFILE", "HGB_BASELINE_PROTOCOL"):
        monkeypatch.delenv(key, raising=False)
    benchmark = tmp_path / "benchmark"
    source = tmp_path / "artifact"
    benchmark.mkdir()
    source.mkdir()
    (benchmark / "Dockerfile").write_text("FROM scratch\nRUN git clone https://example.invalid/project.git /src/project\n")
    (benchmark / "build.sh").write_text("cc $SRC/project/fuzz/fuzzer.c -o $OUT/fuzzer\n")
    (source / "api.c").write_text("int api(void) { return 1; }\n" * 100)
    (source / "api_link.c").symlink_to("api.c")
    (source / "CMakeLists.txt").write_text("project(fixture)\n")
    (source / "compile_commands.json").write_text("[]\n")
    (source / "fuzz").mkdir()
    (source / "fuzz/fuzzer.c").write_text("int LLVMFuzzerTestOneInput(void) { return 0; }\n")
    resolved = {"benchmark_dir": str(benchmark), "project": "project", "commit": "a" * 40,
                "fuzz_target": "fuzzer", "fuzzbench_commit": "b" * 40}
    calls = []
    monkeypatch.setattr(targets, "resolve_target", lambda root, target: dict(resolved))

    def materialize(recipe, target, commit, root, **kwargs):
        calls.append(kwargs)
        return {**recipe, "artifact_path": str(source), "materialize_status": "fetched",
                "revision_status": "resolved", "checked_out_commit": recipe["revision"]}

    monkeypatch.setattr(targets, "materialize_source", materialize)
    return tmp_path, benchmark, source, resolved, calls


def test_warm_and_cross_run_reuse_do_not_fetch_or_copy(project, monkeypatch):
    root, _, _, _, calls = project
    first = targets.package_target(root, "fixture", root / "run-one/target")
    assert len(calls) == 1
    monkeypatch.setattr(targets, "materialize_source", lambda *a, **kw: pytest.fail("warm package fetched sources"))
    monkeypatch.setattr(targets, "copy_tree", lambda *a, **kw: pytest.fail("warm package copied sources"))
    assert targets.package_target(root, "fixture", root / "run-one/target") == first
    assert targets.package_target(root, "fixture", root / "run-two/target") == first
    assert (root / "run-two/target").resolve() == first


def test_force_publishes_new_version_and_preserves_old_readers(project):
    root, _, source, _, calls = project
    output = root / "target"
    first = targets.package_target(root, "fixture", output)
    old_data = (first / "source_input/project/api.c").read_text()
    (source / "api.c").write_text("new source\n")
    second = targets.package_target(root, "fixture", output, force=True)
    assert second != first
    assert output.resolve() == second
    assert (first / "source_input/project/api.c").read_text() == old_data
    assert (second / "source_input/project/api.c").read_text() == "new source\n"
    assert calls == [{}, {"refresh": True}]


@pytest.mark.parametrize("change", ["recipe", "revision", "layout", "strip", "canary", "incomplete"])
def test_changed_or_incomplete_inputs_rebuild(project, monkeypatch, change):
    root, benchmark, _, resolved, calls = project
    first = targets.package_target(root, "fixture", root / "target")
    kwargs = {}
    if change == "recipe":
        (benchmark / "build.sh").write_text("changed recipe\n")
    elif change == "revision":
        resolved["commit"] = "c" * 40
    elif change == "layout":
        kwargs["layout"] = "full"
    elif change == "strip":
        monkeypatch.setenv("HGB_TARGET_STRIP_REFERENCE_HARNESS", "0")
    elif change == "canary":
        monkeypatch.setenv("HGB_REF_CANARY", "HGB_REF_CANARY_fixture")
    else:
        (first / "generator_input/target_manifest.json").unlink()
    second = targets.package_target(root, "fixture", root / "target", **kwargs)
    assert second != first
    assert len(calls) == 2


def test_failed_build_preserves_published_package_and_cleans_stage(project, monkeypatch):
    root, _, _, _, _ = project
    output = root / "target"
    first = targets.package_target(root, "fixture", output)

    def interrupted(*args, **kwargs):
        raise RuntimeError("interrupted fixture")

    monkeypatch.setattr(targets, "_build_package_target", interrupted)
    with pytest.raises(RuntimeError, match="interrupted"):
        targets.package_target(root, "fixture", output, force=True)
    assert output.resolve() == first
    assert (first / "target_manifest.json").is_file()
    assert not list((root / "workspace/target-package-cache").glob("*/.building-*"))


def test_partial_rebuild_preserves_previous_valid_version(project, monkeypatch):
    root, _, _, _, _ = project
    output = root / "target"
    first = targets.package_target(root, "fixture", output)
    monkeypatch.setattr(targets, "materialize_source", lambda *args, **kwargs: {"revision_status": "unavailable"})
    with pytest.raises(RuntimeError, match="previous package preserved"):
        targets.package_target(root, "fixture", output, force=True)
    assert output.resolve() == first


def test_compact_has_one_source_tree_and_preserves_internal_symlinks(project):
    root, _, source, _, _ = project
    package = targets.package_target(root, "fixture", root / "target")
    alias = package / "source_input"
    assert alias.is_symlink()
    assert os.readlink(alias) == "generator_input/source_input"
    public_file = package / "generator_input/source_input/project/api.c"
    assert public_file.stat().st_ino == (alias / "project/api.c").stat().st_ino
    assert public_file.stat().st_ino != (source / "api.c").stat().st_ino
    assert os.readlink(alias / "project/api_link.c") == "api.c"
    assert not (alias / "project/fuzz/fuzzer.c").exists()
    assert split.audit_generator_input(package / "generator_input")["clean"]
    assert (package / "evaluator_only/reference_harnesses/project/fuzz/fuzzer.c").is_file()


def test_compact_split_can_be_repeated_without_losing_data(tmp_path):
    package = tmp_path / "package"
    (package / "source_input/project").mkdir(parents=True)
    (package / "source_input/project/api.c").write_text("source")
    (package / "reference_harnesses").mkdir()
    (package / "fuzzbench_benchmark").mkdir()
    (package / "target_manifest.json").write_text(json.dumps({"target": "fixture", "source_layout": "compact"}))
    original = (package / "source_input/project/api.c").stat().st_ino
    for _ in range(2):
        split.split_package(package)
        assert (package / "source_input/project/api.c").read_text() == "source"
        assert (package / "generator_input/source_input/project/api.c").stat().st_ino == original


def test_concurrent_preparation_builds_once(tmp_path):
    ctx = multiprocessing.get_context("fork")
    start = ctx.Event()
    results = ctx.Queue()
    count = tmp_path / "build-count"
    inputs = {"split_enabled": False, "require_split": False, "fixture": True}

    def worker(name):
        try:
            start.wait(5)

            def build(stage):
                with count.open("a") as stream:
                    stream.write("build\n")
                for directory in ("source_input", "reference_harnesses", "docs", "seeds", "dictionary", "fuzzbench_benchmark"):
                    (stage / directory).mkdir()
                (stage / "target_manifest.json").write_text(json.dumps({"source_status": "benchmark_only", "source_repos": []}))

            version = cache.prepare_package(tmp_path, "fixture", tmp_path / name, inputs, build)
            results.put(str(version))
        except BaseException as exc:
            results.put(repr(exc))
            raise

    processes = [ctx.Process(target=worker, args=(name,)) for name in ("one", "two")]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(10)
        if process.is_alive():
            process.terminate()
            process.join()
            pytest.fail("concurrent package preparation deadlocked")
        assert process.exitcode == 0
    assert results.get(timeout=2) == results.get(timeout=2)
    assert count.read_text().splitlines() == ["build"]


def test_legacy_output_publication_failure_rolls_back(tmp_path, monkeypatch):
    destination = tmp_path / "old-package"
    destination.mkdir()
    (destination / "still-mounted").write_text("old")
    new = tmp_path / "new-package"
    new.mkdir()
    real_replace = os.replace

    def fail_alias(source, dest):
        if ".link-" in str(source):
            raise OSError("publish failure")
        real_replace(source, dest)

    monkeypatch.setattr(cache.os, "replace", fail_alias)
    with pytest.raises(OSError, match="publish failure"):
        cache._publish_alias(destination, new)
    assert (destination / "still-mounted").read_text() == "old"


def test_python_cli_passes_force(monkeypatch, tmp_path):
    calls = []

    def prepare(root, target, output, **kwargs):
        calls.append(kwargs)
        return output

    monkeypatch.setattr(targets, "package_target", prepare)
    assert targets.main(["package", "fixture", "--output", str(tmp_path / "out"), "--force"]) == 0
    assert calls[0]["force"] is True


def test_source_counts_need_one_traversal(project, monkeypatch):
    _, _, source, _, _ = project
    original = Path.rglob
    calls = []

    def counted(path, pattern):
        if path == source:
            calls.append(pattern)
        return original(path, pattern)

    monkeypatch.setattr(Path, "rglob", counted)
    assert targets.source_tree_counts(source) == (3, 1, 1)
    assert calls == ["*"]


def test_reference_selection_counts_benchmark_sources_once(project, monkeypatch):
    root, benchmark, source, _, _ = project
    (benchmark / "first.c").write_text("first")
    (benchmark / "second.c").write_text("second")
    original = Path.rglob
    calls = []

    def counted(path, pattern):
        if path == benchmark:
            calls.append(pattern)
        return original(path, pattern)

    monkeypatch.setattr(Path, "rglob", counted)
    targets.copy_selected_reference_harnesses(benchmark, source, root / "references", "fixture", "fuzzer", "project", "source_input")
    assert calls == ["*"]


@pytest.fixture
def matrix_fixture(tmp_path):
    """Run the real shell launcher with tiny preparer/Docker/generator stubs."""
    import shutil

    scripts = tmp_path / "scripts"
    (scripts / "lib").mkdir(parents=True)
    (tmp_path / "artifacts/fuzzbench/.git").mkdir(parents=True)
    (scripts / "lib/common.sh").write_text('''
repo_root() { printf '%s\\n' "$FIXTURE_ROOT"; }
load_hgb_config() { :; }
hgb_workspace_dir() { printf '%s/workspace\\n' "$1"; }
ensure_dir() { mkdir -p "$1"; }
log() { printf '%s\\n' "$*" >&2; }
die() { printf '%s\\n' "$*" >&2; exit 1; }
make_timestamp() { printf fixture; }
valid_hgb_generator() { return 0; }
generator_artifact_name() { printf '%s\\n' "$1"; }
ensure_artifacts_present() { :; }
artifact_dir() { printf '%s/artifacts/%s\\n' "$2" "$1"; }
hgb_image_name() { printf 'fixture-image'; }
workspace_generator_target_run_dir() { printf '%s/workspace/%s/%s/%s\\n' "$4" "$1" "$2" "$3"; }
extract_json_string() { printf completed; }
''')
    shutil.copy2(ROOT / "scripts/hgb_generate_matrix.sh", scripts / "hgb_generate_matrix.sh")
    (scripts / "hgb_prepare_target.sh").write_text(f'''#!{sys.executable}
import json, os, pathlib, sys
root = pathlib.Path(os.environ["FIXTURE_ROOT"])
log = root / "prepare.jsonl"
with log.open("a") as stream: stream.write(json.dumps(sys.argv[1:]) + "\\n")
number = len(log.read_text().splitlines())
package = root / "versions" / str(number)
package.mkdir(parents=True)
print(package)
''')
    # The launcher invokes the preparer with bash, so keep its interpreter explicit.
    prepare_python = scripts / "prepare_fixture.py"
    (scripts / "hgb_prepare_target.sh").rename(prepare_python)
    (scripts / "hgb_prepare_target.sh").write_text(f'#!/bin/bash\nexec "{sys.executable}" "{prepare_python}" "$@"\n')
    (scripts / "hgb_generate_harness.sh").write_text(f'#!/bin/bash\nexec "{sys.executable}" "{scripts / "harness_fixture.py"}" "$@"\n')
    (scripts / "harness_fixture.py").write_text('''
import json, os, pathlib, sys
root = pathlib.Path(os.environ["FIXTURE_ROOT"])
with (root / "harness.jsonl").open("a") as stream: stream.write(json.dumps(sys.argv[1:]) + "\\n")
''')
    (scripts / "hgb_collect_matrix.py").write_text("pass\n")
    binary = tmp_path / "bin"
    binary.mkdir()
    docker = binary / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n")
    docker.chmod(0o755)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("HGB_")}
    environment.update(FIXTURE_ROOT=str(tmp_path), PATH=str(binary) + os.pathsep + environment["PATH"])

    def run_matrix(*options):
        result = subprocess.run(["bash", str(scripts / "hgb_generate_matrix.sh"), "--targets", "fixture,fixture",
                                 "--run-id", "test", *options], env=environment, cwd=tmp_path,
                                text=True, capture_output=True, timeout=15)
        assert result.returncode == 0, result.stderr
        prepare_calls = [json.loads(line) for line in (tmp_path / "prepare.jsonl").read_text().splitlines()] if (tmp_path / "prepare.jsonl").exists() else []
        harness_calls = [json.loads(line) for line in (tmp_path / "harness.jsonl").read_text().splitlines()]
        return prepare_calls, harness_calls

    return tmp_path, scripts, environment, run_matrix


def test_matrix_reuses_compatible_targets_and_pins_version_paths(matrix_fixture):
    root, _, _, run_matrix = matrix_fixture
    prepared, harnesses = run_matrix("--generators", "promefuzz,oss-fuzz-gen", "--force-target-packages")
    assert len(prepared) == 1
    assert "--force" in prepared[0]
    assert len(harnesses) == 4
    for args in harnesses:
        assert args[args.index("--target-package") + 1] == str(root / "versions/1")


def test_matrix_reprepares_for_different_protocol(matrix_fixture):
    root, _, _, run_matrix = matrix_fixture
    prepared, harnesses = run_matrix("--generators", "promefuzz,g2fuzz")
    assert len(prepared) == 2
    packages = [args[args.index("--target-package") + 1] for args in harnesses]
    assert packages == [str(root / "versions/1")] * 2 + [str(root / "versions/2")] * 2


def test_matrix_forwards_force_in_per_pair_mode(matrix_fixture):
    _, _, _, run_matrix = matrix_fixture
    prepared, harnesses = run_matrix("--generators", "promefuzz", "--target-package-mode", "per-pair", "--force-target-packages")
    assert not prepared
    assert all("--force" in args and "--target-package" not in args for args in harnesses)


def test_prepare_shell_forwards_force(matrix_fixture):
    root, scripts, environment, _ = matrix_fixture
    import shutil

    shutil.copy2(ROOT / "scripts/hgb_prepare_target.sh", scripts / "hgb_prepare_target.sh")
    executable = root / "bin/python3"
    executable.write_text(f'''#!{sys.executable}
import json, os, pathlib, sys
with (pathlib.Path(os.environ["FIXTURE_ROOT"]) / "python.jsonl").open("a") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\\n")
print("/fixture/package-version")
''')
    executable.chmod(0o755)
    for flags in ([], ["--force"]):
        result = subprocess.run(["bash", str(scripts / "hgb_prepare_target.sh"), "--target", "fixture", *flags],
                                env=environment, text=True, capture_output=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "/fixture/package-version"
    calls = [json.loads(line) for line in (root / "python.jsonl").read_text().splitlines()]
    assert "--force" not in calls[0]
    assert calls[1][-1] == "--force"


def test_force_refreshes_unpinned_git_head_from_local_upstream(tmp_path):
    upstream = tmp_path / "upstream"
    upstream.mkdir()

    def git(*args):
        return subprocess.run(["git", "-C", str(upstream), *args], text=True, capture_output=True, check=True)

    git("init", "-q", "-b", "main")
    (upstream / "api.c").write_text("old")
    git("add", ".")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "old")
    recipe = {"kind": "git", "url": str(upstream), "dest": "project"}
    first = targets.materialize_repo(recipe, "fixture", "", tmp_path)
    (upstream / "api.c").write_text("new")
    git("add", ".")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "new")
    frozen = targets.materialize_repo(recipe, "fixture", "", tmp_path)
    assert frozen["captured_revision"] == first["captured_revision"]
    refreshed = targets.materialize_repo(recipe, "fixture", "", tmp_path, refresh=True)
    assert refreshed["captured_revision"] == git("rev-parse", "HEAD").stdout.strip()
    assert refreshed["captured_revision"] != first["captured_revision"]
    assert (Path(refreshed["artifact_path"]) / "api.c").read_text() == "new"


def test_force_refreshes_archive_without_network(tmp_path, monkeypatch):
    import shutil
    import zipfile

    archive = tmp_path / "fixture.zip"
    calls = []

    def download(url, destination):
        calls.append(url)
        shutil.copyfile(archive, destination)

    def write_archive(content):
        with zipfile.ZipFile(archive, "w") as stream:
            stream.writestr("project/api.c", content)

    monkeypatch.setattr(targets.urllib.request, "urlretrieve", download)
    recipe = {"kind": "archive", "url": "https://example.invalid/source-v1.zip", "dest": "project"}
    write_archive("old")
    first = targets.materialize_archive(recipe, "fixture", tmp_path)
    write_archive("new")
    targets.materialize_archive(recipe, "fixture", tmp_path)
    assert (Path(first["artifact_path"]) / "api.c").read_text() == "old"
    refreshed = targets.materialize_archive(recipe, "fixture", tmp_path, refresh=True)
    assert (Path(refreshed["artifact_path"]) / "api.c").read_text() == "new"
    assert len(calls) == 2


def test_inputs_changed_during_build_are_not_published(project, monkeypatch):
    root, benchmark, _, _, _ = project
    output = root / "target"
    first = targets.package_target(root, "fixture", output)
    original = targets._build_package_target

    def changed(*args, **kwargs):
        original(*args, **kwargs)
        (benchmark / "build.sh").write_text("recipe changed during preparation")

    monkeypatch.setattr(targets, "_build_package_target", changed)
    with pytest.raises(RuntimeError, match="inputs changed"):
        targets.package_target(root, "fixture", output, force=True)
    assert output.resolve() == first


def test_cli_split_failure_does_not_mutate_published_package(project, monkeypatch):
    root, _, _, _, _ = project
    output = root / "target"
    first = targets.package_target(root, "fixture", output)

    def fail(*args, **kwargs):
        raise targets.PackageSplitError("fixture split failure")

    monkeypatch.setattr(targets, "package_target", fail)
    assert targets.main(["package", "fixture", "--output", str(output), "--force"]) == 3
    assert not (first / "result.json").exists()
    failure = json.loads((root / ".target.preparation-failure.json").read_text())
    assert failure["status"] == "infra_failure"


def test_compact_alias_works_for_build_context_and_shell_copy(project):
    root, _, _, _, _ = project
    package = targets.package_target(root, "fixture", root / "target")
    build_context = load("hgb_io_test_build_context", "docker/common/promefuzz_build_context.py")
    staged = root / "staged"
    build_context._stage_source(package, staged)
    assert (staged / "project/api.c").is_file()
    assert (staged / "project/api_link.c").is_symlink()
    shell_copy = root / "shell-copy"
    shell_copy.mkdir()
    subprocess.run(["cp", "-a", str(package / "source_input") + "/.", str(shell_copy)], check=True)
    assert (shell_copy / "project/api.c").is_file()
    assert (shell_copy / "project/api_link.c").is_symlink()


def test_source_lock_is_shared_across_custom_cache_locations(tmp_path):
    ctx = multiprocessing.get_context("fork")
    start = ctx.Event()
    active = tmp_path / "active-acquisition"
    inputs = {"split_enabled": False, "require_split": False}

    def worker(name):
        import time

        os.environ["HGB_TARGET_PACKAGE_CACHE_DIR"] = str(tmp_path / name / "cache")
        start.wait(5)

        def build(stage):
            # Exclusive creation fails if another cache is mutating the same
            # target's artifact checkout at the same time.
            with active.open("x"):
                time.sleep(0.05)
                for directory in ("source_input", "reference_harnesses", "docs", "seeds", "dictionary", "fuzzbench_benchmark"):
                    (stage / directory).mkdir()
                (stage / "target_manifest.json").write_text(json.dumps({"source_status": "benchmark_only", "source_repos": []}))
            active.unlink()

        cache.prepare_package(tmp_path, "fixture", tmp_path / name / "target", inputs, build)

    processes = [ctx.Process(target=worker, args=(name,)) for name in ("first", "second")]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(10)
        if process.is_alive():
            process.terminate()
            process.join()
            pytest.fail("custom-cache acquisition deadlocked")
        assert process.exitcode == 0
