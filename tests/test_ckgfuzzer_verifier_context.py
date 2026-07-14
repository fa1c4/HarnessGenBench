from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


context = _load_module("ckgfuzzer_verifier_context", "docker/common/ckgfuzzer_verifier_context.py")


def _target(tmp_path: Path, *, checkout_status: str = "checked_out_ref") -> Path:
    target = tmp_path / "target"
    benchmark = target / "fuzzbench_benchmark"
    source = target / "source_input" / "project"
    benchmark.mkdir(parents=True)
    source.mkdir(parents=True)
    source.joinpath("api.c").write_text("int api(void) { return 0; }\n", encoding="utf-8")
    benchmark.joinpath("Dockerfile").write_text(
        "FROM scratch\nRUN git clone https://example.invalid/project.git && cd project && ./configure\nCOPY * /src/\n",
        encoding="utf-8",
    )
    target.joinpath("source_repos.json").write_text(
        "["
        '{"kind":"git","url":"https://example.invalid/project.git","dest":"project",'
        f'"checkout_status":"{checkout_status}","copy_status":"copied_to_source_input"'
        "}]\n",
        encoding="utf-8",
    )
    return target


def test_sealed_context_uses_snapshot_and_removes_git_clone(tmp_path: Path) -> None:
    target = _target(tmp_path)

    result = context.prepare_verification_context(target, tmp_path / "work")
    dockerfile = Path(result["dockerfile"]).read_text(encoding="utf-8")

    assert result["mode"] == "sealed_source_snapshot"
    assert result["removed_acquisition_commands"] == 1
    assert "COPY source_input/ /src/" in dockerfile
    assert "COPY hgb_reference_harnesses/ /src/" in dockerfile
    assert "apt-get install -y meson ninja-build python3-jinja2 python3-jsonschema" in dockerfile
    assert "git clone" not in dockerfile
    assert "cd project && ./configure" in dockerfile


def test_sealed_context_restores_selected_source_harness_only_for_verification(tmp_path: Path) -> None:
    target = _target(tmp_path)
    selected = target / "reference_harnesses" / "selected" / "source_input" / "project"
    selected.mkdir(parents=True)
    (selected / "native_fuzzer.c").write_text("int LLVMFuzzerTestOneInput(void);\n", encoding="utf-8")

    result = context.prepare_verification_context(target, tmp_path / "work")

    restored = Path(result["context_dir"]) / "hgb_reference_harnesses" / "project" / "native_fuzzer.c"
    assert restored.is_file()


def test_sealed_context_restores_all_stripped_reference_sources(tmp_path: Path) -> None:
    target = _target(tmp_path)
    references = target / "reference_harnesses" / "project" / "fuzz"
    references.mkdir(parents=True)
    (references / "support_fuzzer.c").write_text("int support(void);\n", encoding="utf-8")

    result = context.prepare_verification_context(target, tmp_path / "work")

    restored = Path(result["context_dir"]) / "hgb_reference_harnesses" / "project" / "fuzz" / "support_fuzzer.c"
    assert restored.is_file()


def test_rewrite_preserves_quoted_sed_after_continuation_comment(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM scratch\n"
        "RUN git clone https://example.invalid/systemd.git && \\\n"
        "    # retain the command after this comment\n"
        "    sed -i '119d;126d' $SRC/build.sh\n",
        encoding="utf-8",
    )

    rewritten, removed = context._rewrite_dockerfile(dockerfile)

    assert removed == 1
    assert "git clone" not in rewritten
    assert "sed -i '119d;126d' $SRC/build.sh" in rewritten


def test_rewrite_uses_snapshot_for_archive_and_preexisting_directory(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM scratch\n"
        "RUN mkdir $SRC/sqlite3 && cd $SRC/sqlite3 && \\\n"
        "    curl 'https://sqlite.org/sqlite.tar.gz' -o sqlite3.tar.gz && \\\n"
        "    tar xzf sqlite3.tar.gz --strip-components 1\n",
        encoding="utf-8",
    )

    rewritten, removed = context._rewrite_dockerfile(dockerfile)

    assert removed == 2
    assert "mkdir -p $SRC/sqlite3" in rewritten
    assert "curl " not in rewritten
    assert "tar xzf" not in rewritten


def test_rewrite_removes_source_only_branch_clone_loop(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM scratch\n"
        "RUN git clone https://example.invalid/fuzz && cat fuzz/branches.txt | while read branch; do \\\n"
        "  git clone https://example.invalid/project -b $branch project.$branch; \\\n"
        "done\n",
        encoding="utf-8",
    )

    rewritten, removed = context._rewrite_dockerfile(dockerfile)

    assert removed == 2
    assert "RUN true" in rewritten
    assert "git clone" not in rewritten


def test_sealed_context_replaces_legacy_harfbuzz_pip_bootstrap(tmp_path: Path) -> None:
    target = _target(tmp_path)
    (target / "fuzzbench_benchmark" / "build.sh").write_text(
        "#!/bin/sh\npython3.8 -m pip install ninja meson==0.56.0\n",
        encoding="utf-8",
    )

    result = context.prepare_verification_context(target, tmp_path / "work")
    build = Path(result["context_dir"]) / "build.sh"

    assert result["build_tool_fallbacks"] == 1
    assert "python3.8 -m pip install" not in build.read_text(encoding="utf-8")
    assert "command -v meson" in build.read_text(encoding="utf-8")


def test_sealed_context_replaces_legacy_mbedtls_pip_bootstrap(tmp_path: Path) -> None:
    target = _target(tmp_path)
    (target / "fuzzbench_benchmark" / "build.sh").write_text(
        "#!/bin/sh\npip3 install -r $SRC/mbedtls/scripts/basic.requirements.txt\n",
        encoding="utf-8",
    )

    result = context.prepare_verification_context(target, tmp_path / "work")
    build = Path(result["context_dir"]) / "build.sh"

    assert result["build_tool_fallbacks"] == 1
    assert "pip3 install" not in build.read_text(encoding="utf-8")
    assert "/usr/lib/python3/dist-packages" in build.read_text(encoding="utf-8")
    assert "import jsonschema" in build.read_text(encoding="utf-8")


def test_sealed_context_accepts_explicit_captured_unpinned_commit(tmp_path: Path) -> None:
    target = _target(tmp_path, checkout_status="captured_unpinned_commit")
    provenance = target / "source_repos.json"
    provenance.write_text(
        provenance.read_text(encoding="utf-8").replace(
            '"copy_status":"copied_to_source_input"',
            '"copy_status":"copied_to_source_input","revision_status":"captured_unpinned"',
        ),
        encoding="utf-8",
    )

    result = context.prepare_verification_context(target, tmp_path / "work")

    assert result["captured_unpinned_source_count"] == 1


def test_sealed_context_rejects_unpinned_source(tmp_path: Path) -> None:
    target = _target(tmp_path, checkout_status="commit_not_found_kept_head")

    with pytest.raises(context.VerificationContextError, match="not pinned"):
        context.prepare_verification_context(target, tmp_path / "work")


def test_sealed_context_rejects_explicitly_unresolved_revision(tmp_path: Path) -> None:
    target = _target(tmp_path)
    provenance = target / "source_repos.json"
    provenance.write_text(
        provenance.read_text(encoding="utf-8").replace(
            '"copy_status":"copied_to_source_input"',
            '"copy_status":"copied_to_source_input","revision_status":"unresolved"',
        ),
        encoding="utf-8",
    )

    with pytest.raises(context.VerificationContextError, match="revision is unresolved"):
        context.prepare_verification_context(target, tmp_path / "work")


def test_ckgfuzzer_image_installs_sealed_context_helper() -> None:
    dockerfile = Path("docker/ckgfuzzer/Dockerfile").read_text(encoding="utf-8")

    assert "docker/common/ckgfuzzer_verifier_context.py" in dockerfile
    assert "docker/common/ckgfuzzer_target_harness.py" in dockerfile
