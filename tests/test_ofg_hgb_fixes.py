from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace


sys.path.insert(0, str(Path("docker/common").resolve()))


def load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


api_report = load_module("hgb_api_report", "docker/common/hgb_api_report.py")
selector = load_module("ofg_select_benchmark", "docker/common/ofg_select_benchmark.py")
extractor = load_module("extract_api_list", "docker/common/extract_api_list.py")
ofg_trim = load_module("ofg_trim_benchmark", "docker/common/ofg_trim_benchmark.py")
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


def _make_reference_selection_fixture(tmp_path: Path, build_script: str) -> tuple[Path, Path, Path]:
    benchmark = tmp_path / "benchmark"
    source = tmp_path / "source"
    reference = tmp_path / "reference"
    benchmark.mkdir()
    source.mkdir()
    reference.mkdir()
    (benchmark / "build.sh").write_text(build_script, encoding="utf-8")
    return benchmark, source, reference


def test_selected_harness_prefers_project_dtlsclient_over_dependency(tmp_path: Path) -> None:
    benchmark, source, reference = _make_reference_selection_fixture(tmp_path, "cp programs/fuzz/fuzz_* $OUT/\n")
    (source / "mbedtls" / "programs" / "fuzz").mkdir(parents=True)
    (source / "mbedtls" / "programs" / "fuzz" / "fuzz_dtlsclient.c").write_text("int LLVMFuzzerTestOneInput(void);\n", encoding="utf-8")
    (source / "openssl" / "fuzz").mkdir(parents=True)
    (source / "openssl" / "fuzz" / "dtlsclient.c").write_text("int LLVMFuzzerTestOneInput(void);\n", encoding="utf-8")

    selected = hgb_targets.copy_selected_reference_harnesses(
        benchmark,
        source,
        reference,
        "mbedtls_fuzz_dtlsclient",
        "fuzz_dtlsclient",
        "mbedtls",
        "source_input",
    )

    assert selected == ["source_input/mbedtls/programs/fuzz/fuzz_dtlsclient.c"]


def test_selected_harness_maps_php_generated_binary_to_parser_source(tmp_path: Path) -> None:
    benchmark, source, reference = _make_reference_selection_fixture(
        tmp_path,
        'FUZZERS="php-fuzz-json\nphp-fuzz-parser"\nfor fuzzerName in $FUZZERS; do cp sapi/fuzzer/$fuzzerName $OUT/; done\n',
    )
    (source / "php-src" / "sapi" / "fuzzer").mkdir(parents=True)
    (source / "php-src" / "sapi" / "fuzzer" / "fuzzer-parser.c").write_text("int LLVMFuzzerTestOneInput(void);\n", encoding="utf-8")
    (source / "php-src" / "ext" / "date").mkdir(parents=True)
    (source / "php-src" / "ext" / "date" / "php_date.c").write_text("void php_date(void);\n", encoding="utf-8")

    selected = hgb_targets.copy_selected_reference_harnesses(
        benchmark,
        source,
        reference,
        "php_php-fuzz-parser_0dbedb",
        "php-fuzz-parser",
        "php",
        "source_input",
    )

    assert selected == ["source_input/php-src/sapi/fuzzer/fuzzer-parser.c"]


def test_selected_harness_maps_openthread_binary_to_ip6_send_source(tmp_path: Path) -> None:
    benchmark, source, reference = _make_reference_selection_fixture(tmp_path, "bash tests/fuzz/oss-fuzz-build\n")
    (source / "openthread" / "tests" / "fuzz").mkdir(parents=True)
    (source / "openthread" / "tests" / "fuzz" / "ip6_send.cpp").write_text("int LLVMFuzzerTestOneInput();\n", encoding="utf-8")
    (source / "openthread" / "src" / "core" / "net").mkdir(parents=True)
    (source / "openthread" / "src" / "core" / "net" / "ip6.cpp").write_text("void ip6();\n", encoding="utf-8")

    selected = hgb_targets.copy_selected_reference_harnesses(
        benchmark,
        source,
        reference,
        "openthread_ot-ip6-send-fuzzer",
        "ot-ip6-send-fuzzer",
        "openthread",
        "source_input",
    )

    assert selected == ["source_input/openthread/tests/fuzz/ip6_send.cpp"]



def write_api_report(path: Path, rows: list[dict]) -> None:
    path.write_text(json_dumps({"rows": rows}), encoding="utf-8")


def json_dumps(value) -> str:
    import json
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def test_api_report_selects_exact_target(tmp_path: Path) -> None:
    report = tmp_path / "apis.json"
    write_api_report(
        report,
        [
            {"target": "other", "project": "proj", "fuzz_target": "same", "candidate_api_names": ["wrong"]},
            {"target": "exact_target", "project": "proj", "fuzz_target": "same", "candidate_api_names": ["right_api"]},
        ],
    )

    names, metadata = api_report.select_report_api_names(
        report_path=report,
        target_name="exact_target",
        project="proj",
        fuzz_target="same",
        max_records=8,
    )

    assert names == ["right_api"]
    assert metadata["api_report_row_found"] is True
    assert metadata["api_report_source_field"] == "candidate_api_names"


def test_api_report_falls_back_to_project_and_fuzz_target(tmp_path: Path) -> None:
    report = tmp_path / "apis.json"
    write_api_report(
        report,
        [
            {"target": "stored_target", "project": "proj", "fuzz_target": "fuzzer", "candidate_api_names": ["api_a"]},
        ],
    )

    names, metadata = api_report.select_report_api_names(
        report_path=report,
        target_name="missing_target",
        project="proj",
        fuzz_target="fuzzer",
        max_records=8,
    )

    assert names == ["api_a"]
    assert metadata["api_report_target"] == "stored_target"


def test_api_report_candidate_names_win_over_direct_names(tmp_path: Path) -> None:
    report = tmp_path / "apis.json"
    write_api_report(
        report,
        [
            {
                "target": "target",
                "project": "proj",
                "fuzz_target": "fuzzer",
                "candidate_api_names": ["curated_api"],
                "direct_api_names": ["direct_api"],
            },
        ],
    )

    names, metadata = api_report.select_report_api_names(
        report_path=report,
        target_name="target",
        project="proj",
        fuzz_target="fuzzer",
        max_records=8,
    )

    assert names == ["curated_api"]
    assert metadata["api_report_source_field"] == "candidate_api_names"


def test_report_first_missing_row_triggers_dynamic_fallback(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(extractor.shutil, "which", lambda _name: None)
    source = tmp_path / "source"
    source.mkdir()
    (source / "api.h").write_text("int dynamic_api(void);\n", encoding="utf-8")
    report = tmp_path / "apis.json"
    write_api_report(report, [{"target": "other", "candidate_api_names": ["reported_api"]}])

    selected, metadata = extractor.select_records(
        extractor.extract_details(source, 100),
        max_records=1,
        fallback_max=1,
        selection_mode="ranked",
        project="proj",
        target_name="missing",
        fuzz_target="fuzzer",
        reference_dir="",
        keep_rejected=False,
        api_report=str(report),
        report_mode="report_first",
    )

    assert [record["name"] for record in selected] == ["dynamic_api"]
    assert metadata["api_selection_source"] == "dynamic"
    assert metadata["api_report_row_found"] is False
    assert metadata["fallback_used"] is True


def test_report_only_missing_row_returns_empty(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(extractor.shutil, "which", lambda _name: None)
    source = tmp_path / "source"
    source.mkdir()
    (source / "api.h").write_text("int dynamic_api(void);\n", encoding="utf-8")
    report = tmp_path / "apis.json"
    write_api_report(report, [{"target": "other", "candidate_api_names": ["reported_api"]}])

    selected, metadata = extractor.select_records(
        extractor.extract_details(source, 100),
        max_records=1,
        fallback_max=1,
        selection_mode="ranked",
        project="proj",
        target_name="missing",
        fuzz_target="fuzzer",
        reference_dir="",
        keep_rejected=False,
        api_report=str(report),
        report_mode="report_only",
    )

    assert selected == []
    assert metadata["api_selection_source"] == "report"
    assert metadata["api_report_row_found"] is False


def test_ofg_trim_report_first_name_mismatch_uses_dynamic_fallback(tmp_path: Path) -> None:
    report = tmp_path / "apis.json"
    write_api_report(report, [{"target": "target", "candidate_api_names": ["missing_report_api"]}])
    args = SimpleNamespace(
        report_mode="report_first",
        api_report=str(report),
        target_name="target",
        project="proj",
        fuzz_target="fuzzer",
        max_functions=1,
        reference_dir="",
        allow_test_files=False,
        selection_mode="ranked",
    )

    ranked, rejected, metadata = ofg_trim._rank_functions(
        [{"name": "dynamic_api", "signature": "int dynamic_api(void)"}],
        args,
    )

    assert [item["name"] for item in ranked] == ["dynamic_api"]
    assert rejected == []
    assert metadata["api_report_row_found"] is True


def test_api_report_caps_candidates(tmp_path: Path) -> None:
    report = tmp_path / "apis.json"
    write_api_report(
        report,
        [{"target": "target", "candidate_api_names": ["a", "b", "c", "d"]}],
    )

    names, metadata = api_report.select_report_api_names(
        report_path=report,
        target_name="target",
        max_records=2,
    )

    assert names == ["a", "b"]
    assert metadata["api_candidate_count"] == 2
