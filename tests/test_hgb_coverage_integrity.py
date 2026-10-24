from __future__ import annotations

import json
import csv
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "docker/common"))
import hgb_coverage  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import hgb_audit_coverage_integrity as audit  # noqa: E402


def test_project_coverage_rejects_a_driver_that_only_exercises_itself(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    report.write_text(json.dumps({"data": [{
        "totals": {"lines": {"count": 25, "covered": 25}},
        "files": [{"filename": "/src/target.cc",
                   "summary": {"lines": {"count": 25, "covered": 25}}}],
    }]}))
    with pytest.raises(hgb_coverage.CoverageError, match="no covered re2 project source lines"):
        hgb_coverage.summarize_coverage_report(report, project="re2")


def test_project_coverage_excludes_dependencies_and_driver_and_accepts_g2_paths(tmp_path: Path) -> None:
    report = tmp_path / "coverage.json"
    files = [
        ("/workspace/target/src_cov/bloaty/src/bloaty.cc", 100, 42),
        ("/workspace/target/src_cov/bloaty/third_party/protobuf/a.cc", 400, 200),
        ("/workspace/target/src_cov/bloaty/tests/fuzz_target.cc", 20, 20),
    ]
    report.write_text(json.dumps({"data": [{
        "totals": {"lines": {"count": 520, "covered": 262}},
        "files": [{"filename": filename,
                   "summary": {"lines": {"count": total, "covered": covered}}}
                  for filename, total, covered in files],
    }]}))
    summary = hgb_coverage.summarize_coverage_report(report, project="bloaty")
    assert summary["line_coverage"]["covered"] == 262
    assert summary["sut_line_coverage"] == {
        "covered": 42, "total": 100, "percent": 42.0, "source_files": 1}


@pytest.mark.parametrize("project,driver,library", [
    ("freetype2", "/src/freetype2/src/tools/ftfuzzer/ftfuzzer.cc",
     "/src/freetype2/src/base/ftbase.c"),
    ("jsoncpp", "/src/jsoncpp/build/../src/test_lib_json/fuzz.cpp",
     "/src/jsoncpp/src/lib_json/json_reader.cpp"),
    ("systemd", "/src/systemd/src/udev/net/fuzz-link-parser.c",
     "/src/systemd/src/udev/net/link-config.c"),
])
def test_project_coverage_excludes_in_tree_fuzz_drivers(
        tmp_path: Path, project: str, driver: str, library: str) -> None:
    report = tmp_path / "coverage.lcov"
    report.write_text(
        f"SF:{driver}\nDA:1,1\nLF:1\nLH:1\nend_of_record\n"
        f"SF:{library}\nDA:2,1\nLF:1\nLH:1\nend_of_record\n")
    summary = hgb_coverage.summarize_coverage_report(report, project=project)
    assert summary["sut_line_coverage"]["covered"] == 1
    assert set(hgb_coverage.lcov_project_lines(report, project)) == {(library, 2)}


def test_lcov_project_coverage_normalizes_compiler_relative_paths(tmp_path: Path) -> None:
    report = tmp_path / "coverage.lcov"
    report.write_text(
        "SF:/work/build/../../src/systemd/src/basic/fileio.c\nLF:100\nLH:17\nend_of_record\n"
        "SF:/src/fuzz-link-parser.c\nLF:10\nLH:10\nend_of_record\n")
    summary = hgb_coverage.summarize_coverage_report(report, project="systemd")
    assert summary["sut_line_coverage"]["covered"] == 17
    assert summary["sut_line_coverage"]["total"] == 100


def test_lcov_source_set_fingerprint_uses_target_executable_line_ids(tmp_path: Path) -> None:
    first = tmp_path / "first.lcov"
    second = tmp_path / "second.lcov"
    first.write_text("SF:/src/zlib/inflate.c\nDA:10,1\nDA:11,0\nLF:2\nLH:1\nend_of_record\n"
                     "SF:/src/zlib/zlib.h\nDA:170,0\nLF:0\nLH:0\nend_of_record\n"
                     "SF:/src/fuzzer.cc\nDA:1,1\nLF:1\nLH:1\nend_of_record\n")
    second.write_text("SF:/workspace/target/src_cov/zlib/inflate.c\n"
                      "DA:10,0\nDA:11,8\nLF:2\nLH:1\nend_of_record\n")
    a = hgb_coverage.lcov_project_source_set(first, "zlib")
    b = hgb_coverage.lcov_project_source_set(second, "zlib")
    assert a["source_set_sha256"] == b["source_set_sha256"]
    assert a["instrumented_source_lines"] == 2
    second.write_text(second.read_text().replace("DA:11,8", "DA:12,8"))
    assert hgb_coverage.lcov_project_source_set(second, "zlib")["source_set_sha256"] != a["source_set_sha256"]


def test_common_source_projection_counts_only_shared_instrumented_target_lines(tmp_path: Path) -> None:
    first = tmp_path / "first.lcov"
    second = tmp_path / "second.lcov"
    first.write_text("SF:/src/zlib/inflate.c\nDA:10,2\nDA:11,0\nLF:2\nLH:1\nend_of_record\n")
    second.write_text("SF:/src/zlib/inflate.c\nDA:10,0\nDA:11,3\nDA:12,1\n"
                      "LF:3\nLH:2\nend_of_record\n")
    source = tmp_path / "source.csv"
    audit_csv = tmp_path / "audit.csv"
    projected = tmp_path / "common.csv"
    statuses = {b: "evaluated" if b in ("ckgfuzzer", "g2fuzz") else "N/A"
                for b in audit.BASELINES}
    fields = ["target", *[f"{b}_{name}" for b in audit.BASELINES
                         for name in ("status", "covered_lines", "coverage_contract")]]
    record = {"target": "zlib_zlib_uncompress_fuzzer"}
    for baseline, status in statuses.items():
        record[f"{baseline}_status"] = status
        record[f"{baseline}_covered_lines"] = "1" if status == "evaluated" else "N/A"
        record[f"{baseline}_coverage_contract"] = "old" if status == "evaluated" else "N/A"
    with source.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow(record)
    with audit_csv.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["trial", "target", "baseline", "status", "integrity", "report_path"])
        writer.writeheader()
        for baseline, status in statuses.items():
            writer.writerow({"trial": "", "target": record["target"], "baseline": baseline,
                             "status": status, "integrity": "sut_covered" if status == "evaluated" else "N/A",
                             "report_path": str(first if baseline == "ckgfuzzer" else second)})
    assert audit.write_common_source_csv(source, audit_csv, projected) == []
    with projected.open(newline="") as handle:
        row = next(csv.DictReader(handle))
    assert row["common_source_status"] == "projected"
    assert row["common_source_lines"] == "2"
    assert row["common_source_retention_min"] == "0.6667"
    assert row["ckgfuzzer_covered_lines"] == "1"
    assert row["g2fuzz_covered_lines"] == "1"
    assert row["ckgfuzzer_coverage_contract"] == "common-target-lcov-v1"


def test_libxslt_xpath_counts_xpath_engine_and_excludes_driver(tmp_path: Path) -> None:
    report = tmp_path / "coverage.lcov"
    report.write_text(
        "SF:/src/libxslt/tests/fuzz/xpath.c\nLF:55\nLH:45\nend_of_record\n"
        "SF:/src/libxml2/xpath.c\nLF:200\nLH:70\nend_of_record\n")
    summary = hgb_coverage.summarize_coverage_report(report, project="libxslt")
    assert summary["sut_line_coverage"]["covered"] == 70


def test_corrected_csv_marks_zero_project_coverage_without_changing_raw_csv(tmp_path: Path) -> None:
    source = tmp_path / "original.csv"
    audit_csv = tmp_path / "audit.csv"
    corrected = tmp_path / "corrected.csv"
    source.write_text("target,oss-fuzz-gen_status,oss-fuzz-gen_covered_lines,oss-fuzz-gen_reason\n"
                      "re2_fuzzer,evaluated,25,\n")
    audit_csv.write_text("target,baseline,status,raw_covered_lines,sut_covered_lines,"
                         "sut_total_lines,sut_source_files,integrity\n"
                         "re2_fuzzer,oss-fuzz-gen,evaluated,25,0,0,0,no_sut_coverage\n")
    # Fill the other baseline rows that are N/A in this minimal fixture.
    with audit_csv.open("a") as handle:
        for baseline in audit.BASELINES:
            if baseline != "oss-fuzz-gen":
                handle.write(f"re2_fuzzer,{baseline},N/A,,,,,N/A\n")
    audit.write_corrected_csv(source, audit_csv, corrected)
    with corrected.open(newline="") as handle:
        row = next(csv.DictReader(handle))
    assert row["oss-fuzz-gen_status"] == "quality_failure"
    assert row["oss-fuzz-gen_covered_lines"] == "0"
    assert row["oss-fuzz-gen_raw_covered_lines"] == "25"
    assert "evaluated,25" in source.read_text()


def test_source_set_table_flags_large_denominator_difference(tmp_path: Path) -> None:
    audit_csv = tmp_path / "audit.csv"
    output = tmp_path / "sets.csv"
    audit_csv.write_text(
        "target,baseline,integrity,sut_total_lines\n"
        "zlib_zlib_uncompress_fuzzer,ckgfuzzer,sut_covered,1800\n"
        "zlib_zlib_uncompress_fuzzer,promefuzz,sut_covered,4395\n")
    audit.write_source_set_csv(audit_csv, output)
    with output.open(newline="") as handle:
        row = next(csv.DictReader(handle))
    assert row["mismatch_over_20_percent"] == "True"
    assert float(row["max_to_min_ratio"]) > 2.4


def test_source_set_table_requires_every_applicable_baseline_and_matching_hashes(tmp_path: Path) -> None:
    audit_csv = tmp_path / "audit.csv"
    output = tmp_path / "sets.csv"
    audit_csv.write_text(
        "trial,target,baseline,status,integrity,sut_total_lines,source_set_sha256\n"
        "1,re2_fuzzer,ckgfuzzer,evaluated,sut_covered,100,abc\n"
        "1,re2_fuzzer,promefuzz,quality_failure,not_evaluated,,\n"
        "2,re2_fuzzer,ckgfuzzer,evaluated,sut_covered,100,abc\n"
        "2,re2_fuzzer,promefuzz,evaluated,sut_covered,100,def\n")
    audit.write_source_set_csv(audit_csv, output)
    with output.open(newline="") as handle:
        rows = {r["trial"]: r for r in csv.DictReader(handle)}
    assert rows["1"]["source_set_status"] == "incomplete"
    assert rows["2"]["source_set_status"] == "mismatch"


def test_corrected_trial_summary_uses_target_lines_and_excludes_failed_runs(tmp_path: Path) -> None:
    corrected = tmp_path / "trials.coverage_corrected.csv"
    summary = tmp_path / "trials.coverage_corrected.summary.csv"
    fields = ["trial", "target", *[f"{b}_{metric}" for b in audit.BASELINES
                                   for metric in ("status", "covered_lines")]]
    with corrected.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for trial, status, lines in ((1, "evaluated", "100"), (2, "quality_failure", "0")):
            row = {"trial": trial, "target": "re2_fuzzer"}
            for baseline in audit.BASELINES:
                row[f"{baseline}_status"] = status if baseline == "ckgfuzzer" else "N/A"
                row[f"{baseline}_covered_lines"] = lines if baseline == "ckgfuzzer" else "N/A"
            writer.writerow(row)
    assert audit.write_corrected_trial_summary(corrected, summary)
    with summary.open(newline="") as handle:
        row = next(r for r in csv.DictReader(handle) if r["baseline"] == "ckgfuzzer")
    assert row["evaluated_trials"] == "1"
    assert row["mean_covered_lines"] == "100"
    assert row["status"] == "partial"
