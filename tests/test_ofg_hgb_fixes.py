from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path


def load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


selector = load_module("ofg_select_benchmark", "docker/common/ofg_select_benchmark.py")
extractor = load_module("extract_api_list", "docker/common/extract_api_list.py")
hgb_targets = load_module("hgb_targets", "scripts/hgb_targets.py")


def write_yaml(path: Path, project: str, target_name: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'"functions": []\n"project": "{project}"\n"target_name": "{target_name}"\n',
        encoding="utf-8",
    )


def test_selector_requires_exact_project_for_generic_target_names(tmp_path: Path) -> None:
    root = tmp_path / "benchmark-sets"
    write_yaml(root / "all" / "apache-logging-log4cxx.yaml", "apache-logging-log4cxx", "xml_fuzzer")
    write_yaml(root / "all" / "libxml2.yaml", "libxml2", "xml")

    result = selector.select_benchmark(
        root,
        "libxml2",
        fuzz_target="xml",
        target_name="libxml2_xml",
        allow_project_fallback=True,
    )

    assert result["path"].endswith("libxml2.yaml")
    assert result["selected_yaml_project"] == "libxml2"
    assert result["benchmark_match_kind"] == "exact_project_target"


def test_selector_prefers_exact_target_then_project_fallback(tmp_path: Path) -> None:
    root = tmp_path / "benchmark-sets"
    write_yaml(root / "all" / "sqlite3.yaml", "sqlite3", "other_target")
    write_yaml(root / "from-test-large" / "sqlite3.yaml", "sqlite3", "ossfuzz")

    exact = selector.select_benchmark(root, "sqlite3", fuzz_target="ossfuzz", allow_project_fallback=True)
    assert exact["path"].endswith("from-test-large/sqlite3.yaml")
    assert exact["benchmark_match_kind"] == "exact_project_target"

    fallback = selector.select_benchmark(root, "sqlite3", fuzz_target="missing", allow_project_fallback=True)
    assert fallback["path"].endswith("all/sqlite3.yaml")
    assert fallback["benchmark_match_kind"] == "exact_project"

    none = selector.select_benchmark(root, "sqlite3", fuzz_target="missing", allow_project_fallback=False)
    assert none["path"] == ""
    assert none["benchmark_match_kind"] == "none"


def test_extractor_details_filter_macro_like_names(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(extractor.shutil, "which", lambda _name: None)
    source = tmp_path / "source"
    source.mkdir()
    (source / "api.h").write_text(
        """
#define LOCAL static
LOCAL(void) macro_style_declaration(int value);
int useful_api(const uint8_t *data, size_t size);
void helper(void);
""",
        encoding="utf-8",
    )

    details = extractor.extract_details(source, 10)
    names = [record["name"] for record in details]

    assert "useful_api" in names
    assert "LOCAL" not in names
    assert "void" not in names
    useful = next(record for record in details if record["name"] == "useful_api")
    assert useful["return_type"] == "int"
    assert useful["params"][0] == {"name": "data", "type": "const uint8_t *"}


def test_default_extractor_output_remains_name_list(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(extractor.shutil, "which", lambda _name: None)
    source = tmp_path / "source"
    source.mkdir()
    (source / "api.c").write_text("int alpha(void);\nint beta(int value);\n", encoding="utf-8")

    assert extractor.extract(source, 10) == ["alpha", "beta"]


def test_materialize_repo_uses_cached_checkout_when_fetch_fails(monkeypatch, tmp_path: Path) -> None:
    root = tmp_path
    local = root / "artifacts" / "fuzzbench-target-sources" / "target" / "src"
    (local / ".git").mkdir(parents=True)
    (local / "api.c").write_text("int cached_api(void);\n", encoding="utf-8")

    def fake_run(cmd, cwd=None, check=False):
        del cwd, check
        if "fetch" in cmd:
            return subprocess.CompletedProcess(cmd, 1, "", "fetch failed")
        if "checkout" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if "rev-parse" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "abc123\n", "")
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(hgb_targets, "run", fake_run)

    result = hgb_targets.materialize_repo(
        {"kind": "git", "url": "https://example.invalid/src.git", "dest": "src"},
        "target",
        "abc123",
        root,
    )

    assert result["clone_status"] == "fetch_failed"
    assert result["materialize_status"] == "fetch_failed_using_cached_checkout"
    assert result["cache_fallback"] is True
    assert result["checkout_status"] == "checked_out_commit"
