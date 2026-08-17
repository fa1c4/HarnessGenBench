from __future__ import annotations

import importlib.util
import json
import os
import py_compile
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace


sys.path.insert(0, str(Path("docker/common").resolve()))


def load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


api_report = load_module("hgb_api_report", "docker/common/hgb_api_report.py")
selector = load_module("ofg_select_benchmark", "docker/common/ofg_select_benchmark.py")
extractor = load_module("extract_api_list", "docker/common/extract_api_list.py")
ofg_trim = load_module("ofg_trim_benchmark", "docker/common/ofg_trim_benchmark.py")
matrix_collector = load_module("hgb_collect_matrix", "scripts/hgb_collect_matrix.py")
hgb_targets = load_module("hgb_targets", "scripts/hgb_targets.py")
ckg_stage = load_module("ckgfuzzer_stage_project", "docker/common/ckgfuzzer_stage_project.py")
llm_trace = load_module("hgb_llm_trace", "docker/common/hgb_llm_trace.py")
ckg_runtime_patch = load_module("ckgfuzzer_runtime_patch", "docker/common/ckgfuzzer_runtime_patch.py")
ckg_api_recovery = load_module("ckgfuzzer_api_recovery", "docker/common/ckgfuzzer_api_recovery.py")
ckg_candidate_verifier = load_module("ckgfuzzer_candidate_verifier", "docker/common/ckgfuzzer_candidate_verifier.py")



def _configure_trace(monkeypatch, tmp_path: Path, sample_rate: str = "10") -> Path:
    trace_dir = tmp_path / "api_traces"
    llm_trace._SEQUENCE = 0
    monkeypatch.setenv("HGB_LLM_TRACE_ENABLED", "1")
    monkeypatch.setenv("HGB_LLM_TRACE_DIR", str(trace_dir))
    monkeypatch.setenv("HGB_LLM_TRACE_SAMPLE_RATE", sample_rate)
    monkeypatch.setenv("HGB_LLM_TRACE_FIRST", "1")
    return trace_dir


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_hgb_llm_trace_samples_first_and_every_tenth(monkeypatch, tmp_path: Path) -> None:
    trace_dir = _configure_trace(monkeypatch, tmp_path, "10")

    for index in range(20):
        llm_trace.record(
            stage="unit",
            provider="openai-compatible",
            operation="chat.completions.create",
            model="test-model",
            request={"index": index},
            response={"ok": index},
        )

    samples = _load_jsonl(trace_dir / "llm_api_samples.jsonl")
    summary = json.loads((trace_dir / "summary.json").read_text(encoding="utf-8"))

    assert [sample["sequence"] for sample in samples] == [1, 10, 20]
    assert [sample["sample_reason"] for sample in samples] == ["first", "every_10", "every_10"]
    assert summary["total_count"] == 20
    assert summary["sample_count"] == 3
    assert summary["sample_rate"] == "10"


def test_hgb_llm_trace_defaults_to_every_tenth_when_unset(monkeypatch, tmp_path: Path) -> None:
    trace_dir = tmp_path / "api_traces"
    llm_trace._SEQUENCE = 0
    monkeypatch.setenv("HGB_LLM_TRACE_ENABLED", "1")
    monkeypatch.setenv("HGB_LLM_TRACE_DIR", str(trace_dir))
    monkeypatch.delenv("HGB_LLM_TRACE_SAMPLE_RATE", raising=False)
    monkeypatch.setenv("HGB_LLM_TRACE_FIRST", "1")

    for index in range(10):
        llm_trace.record(
            stage="unit",
            provider="openai-compatible",
            operation="chat.completions.create",
            request={"index": index},
            response={"ok": index},
        )

    samples = _load_jsonl(trace_dir / "llm_api_samples.jsonl")
    summary = json.loads((trace_dir / "summary.json").read_text(encoding="utf-8"))

    assert [sample["sequence"] for sample in samples] == [1, 10]
    assert [sample["sample_reason"] for sample in samples] == ["first", "every_10"]
    assert summary["sample_rate"] == "10"


def test_hgb_llm_trace_redacts_nested_secret_payloads(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-secret")
    monkeypatch.setenv("HF_TOKEN", "hf-test-secret")

    payload = {
        "api_key": "plain-field-secret",
        "headers": {"Authorization": "Bearer header-secret"},
        "nested": [
            "prefix sk-test-secret suffix",
            {"text": "authorization: bearer inline-secret"},
            {"token": "hf-test-secret"},
        ],
    }

    serialized = llm_trace.safe_serialize(payload)
    blob = json.dumps(serialized, sort_keys=True)

    assert "sk-test-secret" not in blob
    assert "hf-test-secret" not in blob
    assert "plain-field-secret" not in blob
    assert "header-secret" not in blob
    assert "inline-secret" not in blob
    assert "[REDACTED]" in blob


def test_hgb_llm_trace_serializes_openai_like_response_objects(monkeypatch, tmp_path: Path) -> None:
    trace_dir = _configure_trace(monkeypatch, tmp_path, "1")
    response = SimpleNamespace(
        id="chatcmpl-test",
        choices=[SimpleNamespace(message=SimpleNamespace(content="hello"))],
        usage=SimpleNamespace(prompt_tokens=3, completion_tokens=2, total_tokens=5),
    )

    llm_trace.record(
        stage="unit",
        provider="openai-compatible",
        operation="chat.completions.create",
        model="test-model",
        request={"messages": [{"role": "user", "content": "hi"}]},
        response=response,
    )

    sample = _load_jsonl(trace_dir / "llm_api_samples.jsonl")[0]

    assert sample["response"]["id"] == "chatcmpl-test"
    assert sample["response"]["choices"][0]["message"]["content"] == "hello"
    assert sample["usage"] == {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}


def test_hgb_llm_trace_write_failure_does_not_raise(monkeypatch, tmp_path: Path) -> None:
    bad_trace_dir = tmp_path / "not_a_dir"
    bad_trace_dir.write_text("occupied", encoding="utf-8")
    llm_trace._SEQUENCE = 0
    monkeypatch.setenv("HGB_LLM_TRACE_ENABLED", "1")
    monkeypatch.setenv("HGB_LLM_TRACE_DIR", str(bad_trace_dir))
    monkeypatch.setenv("HGB_LLM_TRACE_SAMPLE_RATE", "1")

    llm_trace.record(
        stage="unit",
        provider="openai-compatible",
        operation="chat.completions.create",
        request={"ok": True},
        response={"ok": True},
    )


def test_matrix_collector_aggregates_api_trace_counts(tmp_path: Path) -> None:
    matrix_dir = tmp_path / "matrix" / "run"
    matrix_dir.mkdir(parents=True)
    workspaces = [tmp_path / "ws1", tmp_path / "ws2"]
    rows = []
    for index, (workspace, total, sampled) in enumerate(zip(workspaces, (12, 3), (2, 1)), start=1):
        workspace.mkdir()
        metadata = workspace / "metadata.json"
        metadata.write_text(
            json.dumps(
                {
                    "generator": "ckgfuzzer",
                    "target": f"target_{index}",
                    "status": "failed",
                    "reason": "unit failure",
                    "api_trace_total_count": total,
                    "api_trace_sample_count": sampled,
                }
            ),
            encoding="utf-8",
        )
        rows.append((f"target_{index}", workspace, metadata))
    with (matrix_dir / "matrix.tsv").open("w", encoding="utf-8") as f:
        f.write("generator\ttarget\tstatus\tworkspace\tmetadata\tsummary\n")
        for target, workspace, metadata in rows:
            f.write(f"ckgfuzzer\t{target}\tfailed\t{workspace}\t{metadata}\t{workspace / 'HGB_SUMMARY.md'}\n")

    summary = matrix_collector.collect(matrix_dir)
    matrix_collector.write_outputs(matrix_dir, summary)

    assert summary["api_trace_total_count"] == 15
    assert summary["api_trace_sample_count"] == 3
    written_summary = json.loads((matrix_dir / "summary.json").read_text(encoding="utf-8"))
    assert written_summary["api_trace_total_count"] == 15
    assert "api_trace_total_count\t15" in (matrix_dir / "summary.tsv").read_text(encoding="utf-8")
    matrix_md = (matrix_dir / "HGB_MATRIX_SUMMARY.md").read_text(encoding="utf-8")
    assert "## API Traces" in matrix_md
    assert "- Total calls: `15`" in matrix_md
    assert "- Sampled calls: `3`" in matrix_md


def test_hgb_llm_trace_helper_is_installed_in_every_generator_image() -> None:
    for generator in ("oss-fuzz-gen", "ckgfuzzer", "promefuzz", "g2fuzz", "elfuzz"):
        dockerfile = Path(f"docker/{generator}/Dockerfile").read_text(encoding="utf-8")
        assert "docker/common/hgb_llm_trace.py" in dockerfile
        assert "/opt/hgb/bin/" in dockerfile


def test_hgb_llm_trace_hooks_are_wired_for_all_generators() -> None:
    common_sh = Path("scripts/lib/common.sh").read_text(encoding="utf-8")
    target_contract = Path("docker/common/target_contract.sh").read_text(encoding="utf-8")
    ofg_wrapper = Path("docker/common/ofg_run_wrapper.py").read_text(encoding="utf-8")
    ofg_entrypoint = Path("docker/oss-fuzz-gen/entrypoint.sh").read_text(encoding="utf-8")
    ckg_entrypoint = Path("docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    prome_entrypoint = Path("docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")
    g2_entrypoint = Path("docker/g2fuzz/entrypoint.sh").read_text(encoding="utf-8")
    elfuzz_entrypoint = Path("docker/elfuzz/entrypoint.sh").read_text(encoding="utf-8")

    for name in ("HGB_LLM_TRACE_ENABLED", "HGB_LLM_TRACE_DIR", "HGB_LLM_TRACE_SAMPLE_RATE", "HGB_LLM_TRACE_FIRST"):
        assert name in common_sh
    for name in (
        "api_trace_dir",
        "api_trace_file",
        "api_trace_sample_rate",
        "api_trace_total_count",
        "api_trace_sample_count",
    ):
        assert name in target_contract
    assert "API trace file" in target_contract
    assert "API trace sample rate" in target_contract

    assert "_install_hgb_llm_trace" in ofg_wrapper
    assert "chat.completions.create" in ofg_wrapper
    assert "oss-fuzz-gen-preflight" in ofg_entrypoint
    assert "PY_CKG_LLM_TRACE_PATCH" in ckg_entrypoint
    assert "class HGBOpenAILike(OpenAILike)" in ckg_entrypoint
    assert "llm.complete =" not in ckg_entrypoint
    assert "self.client.chat.completions.create" in ckg_entrypoint
    assert "PY_PROMEFUZZ_LLM_TRACE_PATCH" in prome_entrypoint
    assert "promefuzz_llm.log" in prome_entrypoint
    assert "HGB_LLM_TRACE: G2FUZZ" in g2_entrypoint
    assert "patch_elfuzz_trace" in elfuzz_entrypoint
    assert "stage='elfuzz'" in elfuzz_entrypoint


def write_yaml(path: Path, project: str, target_name: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f'"functions": []\n"project": "{project}"\n"target_name": "{target_name}"\n',
        encoding="utf-8",
    )


def test_ckgfuzzer_stage_maps_relative_workdir_and_keeps_analysis_clean(tmp_path: Path) -> None:
    target = tmp_path / "target"
    source_input = target / "source_input"
    benchmark = target / "fuzzbench_benchmark"
    project_dir = tmp_path / "project"
    analysis_dir = tmp_path / "analysis"
    (source_input / "openh264").mkdir(parents=True)
    benchmark.mkdir(parents=True)
    (source_input / "openh264" / "codec.c").write_text("int codec(void);\n", encoding="utf-8")
    (benchmark / "Dockerfile").write_text(
        "FROM gcr.io/fuzzbench/base-builder\n"
        "COPY build.sh decoder_fuzzer.cpp $SRC/\n"
        "WORKDIR openh264\n",
        encoding="utf-8",
    )
    (benchmark / "benchmark.yaml").write_text("project: openh264\n", encoding="utf-8")
    (benchmark / "build.sh").write_text("#!/bin/bash\n", encoding="utf-8")
    (benchmark / "decoder_fuzzer.cpp").write_text("int LLVMFuzzerTestOneInput();\n", encoding="utf-8")

    metadata = ckg_stage.stage_project(
        target,
        project_dir,
        analysis_dir,
        "hgb_openh264_decoder_fuzzer",
    )

    assert metadata["build_dir"] == "/src/hgb_openh264_decoder_fuzzer/openh264"
    assert (project_dir / "openh264" / "codec.c").is_file()
    assert (project_dir / "build.sh").is_file()
    assert (project_dir / "decoder_fuzzer.cpp").is_file()
    assert (analysis_dir / "openh264" / "codec.c").is_file()
    assert not (analysis_dir / "decoder_fuzzer.cpp").exists()
    assert not (analysis_dir / "build.sh").exists()


def test_ckgfuzzer_stage_maps_src_and_absolute_workdirs() -> None:
    assert ckg_stage.map_workdir("$SRC/curl_fuzzer", "hgb_curl") == "/src/hgb_curl/curl_fuzzer"
    assert ckg_stage.map_workdir("${SRC}/curl_fuzzer", "hgb_curl") == "/src/hgb_curl/curl_fuzzer"
    assert ckg_stage.map_workdir("/src/libxslt", "hgb_libxslt") == "/src/hgb_libxslt/libxslt"
    assert ckg_stage.map_workdir("", "hgb_freetype") == "/src/hgb_freetype"


def test_ckgfuzzer_dockerfile_installs_stage_helper() -> None:
    dockerfile = Path("docker/ckgfuzzer/Dockerfile").read_text(encoding="utf-8")

    assert "docker/common/ckgfuzzer_stage_project.py" in dockerfile
    assert "/opt/hgb/bin/ckgfuzzer_stage_project.py" in dockerfile


def test_ckgfuzzer_repo_patch_accepts_codeql_success_on_stderr() -> None:
    entrypoint = Path("docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")

    assert 'combined_output = (result.stdout or "") + "\\\\n" + (result.stderr or "")' in entrypoint
    assert "database_created = result.returncode == 0" in entrypoint
    assert "success_message in combined_output" in entrypoint
    assert "os.path.isdir(database_dir)" in entrypoint



def test_ckgfuzzer_runtime_patch_uses_literal_replacements_and_syntax_guard() -> None:
    entrypoint = Path("docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")

    assert "lambda _match: replacement" in entrypoint
    assert "runtime_patch_py_compile.log" in entrypoint
    assert "python3 -m py_compile" in entrypoint


def test_ckgfuzzer_runtime_patch_scopes_string_checks_away_from_boolean_docker_start(tmp_path: Path) -> None:
    upstream = tmp_path / "check_gen_fuzzer.py"
    upstream.write_text(
        "\n".join(
            [
                "import os, sys, subprocess",
                "class Logger:",
                "    def error(self, *args): pass",
                "logger = Logger()",
                "def docker_exec_command(run_args, project_name, print_output=True):",
                "    return ''",
                "def _check_fuzzer_exists(project, fuzzer_name, architecture='x86_64'):",
                "    return True",
                "def docker_run(run_args, print_output=True, architecture='x86_64'):",
                "    return ''",
                "def docker_build(build_args):",
                "    return True",
                "def start_docker_check_compilation_impl():",
                "  result = True",
                "  if not result:",
                "    logger.error('Building fuzzers failed.')",
                "  return result",
                "def build_fuzzers_impl():",
                "  result = 'ERROR: failed'",
                "  if not result:",
                "    logger.error('Building fuzzers failed.')",
                "  return result",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    ckg_runtime_patch.patch_check_gen_fuzzer(upstream)
    patched = upstream.read_text(encoding="utf-8")
    start = patched.index("def start_docker_check_compilation_impl")
    build = patched.index("def build_fuzzers_impl")

    assert "if not result:" in patched[start:build]
    assert ".startswith" not in patched[start:build]
    assert "result.startswith(('ERROR:', 'INFRA_ERROR:'))" in patched[build:]
    assert "HGB_EXTERNAL_VERIFIER_DEFERRED" in patched
    assert "project_name + '_check'" in patched
    py_compile.compile(str(upstream), doraise=True)


def test_ckgfuzzer_runtime_patch_defers_upstream_run_under_external_verifier(tmp_path: Path) -> None:
    upstream = tmp_path / "run_fuzzer.py"
    upstream.write_text(
        "\n".join(
            [
                "import os",
                "class Logger:",
                "    def info(self, *args): pass",
                "    def error(self, *args): pass",
                "logger = Logger()",
                "class Runner:",
                "    def build_and_fuzz_one_file(self, fuzz_driver_file):",
                "        self.failed_builds = []",
                "        build_fuzzer_result = 'HGB_EXTERNAL_VERIFIER_DEFERRED'",
                "        if \"ERROR\" in build_fuzzer_result or \"error\" in build_fuzzer_result.lower():",
                "            self.failed_builds.append(fuzz_driver_file)",
                "            return",
                "        else:",
                "            logger.info(f\"Successfully built fuzzer {fuzz_driver_file}\")",
                "            run_fuzzer_result = 'HGB_COMMAND_OK'",
                "            if \"ERROR\" in run_fuzzer_result:",
                "                logger.info(\"Crash detected. Analyzing...\")",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    ckg_runtime_patch.patch_run_fuzzer(upstream)
    patched = upstream.read_text(encoding="utf-8")

    assert "self.successful_builds = []" in patched
    assert "HGB_CKG_EXTERNAL_VERIFIER" in patched
    assert "Deferring upstream run/coverage" in patched
    py_compile.compile(str(upstream), doraise=True)


def test_ckgfuzzer_call_graph_query_uses_distinct_variable_and_column_names() -> None:
    query = ckg_runtime_patch._DIRECT_CALL_GRAPH_QUERY

    assert "from Function start, Function end" in query
    assert "start as caller" in query
    assert "end as callee" in query
    assert "from Function caller" not in query
    assert "predicate selectedEvidence(Function caller, Function callee)" in query
    assert "selectedFunction(caller) and directCall(caller, callee)" in query
    assert "selectedFunction(callee) and directCall(caller, callee)" in query
    assert "selectedFunction(caller) and caller = callee" in query


def test_ckgfuzzer_api_recovery_handles_knr_c_and_cpp_templates() -> None:
    knr = """int uncompress (dest, destLen, source, sourceLen)
    Bytef *dest;
    uLongf *destLen;
    const Bytef *source;
    uLong sourceLen;
{
    return 0;
}
"""
    re2_template = """template <typename... A>
static bool RE2::Consume(StringPiece* input, const RE2& re, A&&... a) {
  return Apply(ConsumeN, input, re, Arg(a)...);
}
"""
    jsoncpp = """CharReader* CharReaderBuilder::newCharReader() const {
  return new OurCharReader();
}
"""
    openssl_macro = """IMPLEMENT_ASN1_FUNCTIONS(X509)
"""

    knr_snippet = ckg_api_recovery.function_snippet(knr, "uncompress")
    re2_snippet = ckg_api_recovery.function_snippet(re2_template, "Consume")
    jsoncpp_snippet = ckg_api_recovery.function_snippet(jsoncpp, "newCharReader")
    openssl_snippet = ckg_api_recovery.macro_generated_snippet(openssl_macro, "X509_free")

    assert "Bytef *dest;" in knr_snippet
    assert "return 0;" in knr_snippet
    assert "RE2::Consume" in re2_snippet
    assert "Json::CharReaderBuilder" not in jsoncpp_snippet
    assert "CharReaderBuilder::newCharReader" in jsoncpp_snippet
    assert "IMPLEMENT_ASN1_FUNCTIONS(X509)" in openssl_snippet


def test_ckgfuzzer_recovery_prefers_definition_over_early_header_declaration(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "api.h").write_text("int uncompress(void);\n", encoding="utf-8")
    (source / "uncompr.c").write_text(
        "int uncompress (arg)\nint arg;\n{ return arg; }\n",
        encoding="utf-8",
    )

    recovered, missing = ckg_api_recovery.recover_selected_api_code(
        {"src": {}}, ["uncompress"], str(source), 10
    )

    assert missing == []
    assert "return arg;" in recovered["uncompress"]


def test_ckgfuzzer_report_private_helper_falls_back_to_ranked_library_api(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps({"rows": [{"target": "target", "candidate_api_names": ["helper"]}]}),
        encoding="utf-8",
    )
    raw = [
        {"name": "helper", "path": "fuzzbench_benchmark/helper.cc", "signature": "int helper()"},
        {"name": "library_api", "path": "library/api.cc", "signature": "int library_api()"},
    ]

    selected, metadata = extractor.select_records(
        raw,
        max_records=1,
        fallback_max=1,
        selection_mode="ranked",
        project="library",
        target_name="target",
        fuzz_target="fuzz_target",
        reference_dir="",
        keep_rejected=False,
        api_report=str(report),
        report_mode="report_first",
    )

    assert [record["name"] for record in selected] == ["library_api"]
    assert metadata["api_selection_source"] == "dynamic"


def _prepare_verifier_snapshot(target: Path) -> None:
    source = target / "source_input" / "project"
    source.mkdir(parents=True)
    (source / "api.cc").write_text("int api() { return 0; }\n", encoding="utf-8")
    selected = target / "reference_harnesses" / "selected" / "source_input" / "project"
    selected.mkdir(parents=True)
    (selected / "native_fuzzer.cc").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char*, unsigned long) { return 0; }\n",
        encoding="utf-8",
    )
    (target / "target_manifest.json").write_text(
        json.dumps(
            {"selected_reference_harness_files": ["source_input/project/native_fuzzer.cc"]}
        ),
        encoding="utf-8",
    )
    (target / "source_repos.json").write_text(
        json.dumps(
            [
                {
                    "kind": "git",
                    "url": "https://example.invalid/project.git",
                    "dest": "project",
                    "checkout_status": "checked_out_revision",
                    "revision_status": "resolved",
                    "copy_status": "copied_to_source_input",
                }
            ]
        ),
        encoding="utf-8",
    )


def test_ckgfuzzer_candidate_verifier_stages_and_records_candidate_builds(tmp_path: Path) -> None:
    target = tmp_path / "target"
    benchmark = target / "fuzzbench_benchmark"
    candidates = tmp_path / "candidates"
    benchmark.mkdir(parents=True)
    candidates.mkdir()
    _prepare_verifier_snapshot(target)
    (benchmark / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    candidate = candidates / "candidate.cc"
    candidate.write_text("int LLVMFuzzerTestOneInput(const unsigned char*, unsigned long) { return 0; }\n", encoding="utf-8")
    calls: list[list[str]] = []

    def runner(command, _timeout):
        calls.append(list(command))
        stderr = ckg_candidate_verifier.COMPILE_MARKER if command[1] == "start" else ""
        return ckg_candidate_verifier.CommandResult(list(command), 0, "ok", stderr)

    result = ckg_candidate_verifier.verify_candidates(
        target_root=target,
        candidates_dir=candidates,
        work_dir=tmp_path / "verification",
        fuzz_target="native_fuzzer",
        runner=runner,
    )

    assert result["verification_ran"] is True
    assert result["verified_candidates"] == [str(candidate)]
    assert (tmp_path / "verification" / "results.json").is_file()
    lifecycle = [command for command in calls if command[0] == "docker"]
    assert [command[1] for command in lifecycle] == ["build", "create", "cp", "start", "cp", "cp", "rm"]
    assert "--file" in lifecycle[0]
    assert "sealed_context" in lifecycle[0][lifecycle[0].index("--file") + 1]
    create_command = lifecycle[1]
    start_command = lifecycle[3]
    assert any("HGB_CANDIDATE_FILE=native_fuzzer.cc" == part for part in create_command)
    assert any("HGB_FUZZ_TARGET=native_fuzzer" == part for part in create_command)
    assert all("-v" not in command for command in lifecycle)
    assert "HGB_CANDIDATE_DEST" in create_command[-1]
    assert "selected native candidate destination is absent" in create_command[-1]
    assert any("HGB_CANDIDATE_DEST=/src/project/native_fuzzer.cc" == part for part in create_command)
    assert any("FUZZER_LIB=-fsanitize=fuzzer" == part for part in create_command)
    assert any("FUZZER=libfuzzer" == part for part in create_command)
    assert "libFuzzingEngine.a" in create_command[-1]
    assert "/usr/lib/libFuzzingEngine.a" in create_command[-1]
    assert "LIBRARY_PATH" in create_command[-1]
    assert "CXXFLAGS" in create_command[-1]
    assert lifecycle[2][-1].endswith(":/tmp/native_fuzzer.cc")
    assert lifecycle[2][2] == str(result["records"][0]["staged_candidate"])
    assert "ninja -C" in create_command[-1]
    assert start_command == ["docker", "start", "-a", create_command[create_command.index("--name") + 1]]
    assert result["records"][0]["exit_code"] == 0
    assert result["records"][0]["compile_attempted"] is True
    assert "stderr" in result["records"][0]
    log = Path(result["records"][0]["log"]).read_text(encoding="utf-8")
    assert "## create" in log and "## cleanup" in log


def test_ckgfuzzer_candidate_verifier_removes_container_after_staging_failure(tmp_path: Path) -> None:
    target = tmp_path / "target"
    benchmark = target / "fuzzbench_benchmark"
    candidates = tmp_path / "candidates"
    benchmark.mkdir(parents=True)
    candidates.mkdir()
    _prepare_verifier_snapshot(target)
    (benchmark / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (candidates / "candidate.cc").write_text("int main() {}\n", encoding="utf-8")
    calls: list[list[str]] = []

    def runner(command, _timeout):
        calls.append(list(command))
        if command[:2] == ["docker", "cp"] and command[-1].startswith("hgb-ckgverify-"):
            return ckg_candidate_verifier.CommandResult(list(command), 1, "", "staging failed")
        return ckg_candidate_verifier.CommandResult(list(command), 0, "ok", "")

    result = ckg_candidate_verifier.verify_candidates(
        target_root=target,
        candidates_dir=candidates,
        work_dir=tmp_path / "verification",
        fuzz_target="native_fuzzer",
        runner=runner,
    )

    assert result["verification_ran"] is False
    assert result["records"][0]["exit_code"] == 1
    lifecycle = [command[1] for command in calls if command[0] == "docker"]
    assert lifecycle == ["build", "create", "cp", "rm"]

def test_ckgfuzzer_candidate_verifier_reports_pre_candidate_build_failure_as_infra(tmp_path: Path) -> None:
    target = tmp_path / "target"
    benchmark = target / "fuzzbench_benchmark"
    candidates = tmp_path / "candidates"
    benchmark.mkdir(parents=True)
    candidates.mkdir()
    _prepare_verifier_snapshot(target)
    (benchmark / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (candidates / "candidate.cc").write_text("int main() {}\n", encoding="utf-8")

    def runner(command, _timeout):
        if command[:2] == ["docker", "start"]:
            return ckg_candidate_verifier.CommandResult(list(command), 1, "", "dependency build failed")
        return ckg_candidate_verifier.CommandResult(list(command), 0, "ok", "")

    result = ckg_candidate_verifier.verify_candidates(
        target_root=target,
        candidates_dir=candidates,
        work_dir=tmp_path / "verification",
        fuzz_target="native_fuzzer",
        runner=runner,
    )

    assert result["verification_ran"] is False
    assert result["records"][0]["compile_attempted"] is False
    assert "before compiling any staged candidate" in result["infrastructure_error"]


def test_ckgfuzzer_candidate_verifier_reports_image_setup_as_infrastructure_failure(tmp_path: Path) -> None:
    target = tmp_path / "target"
    benchmark = target / "fuzzbench_benchmark"
    candidates = tmp_path / "candidates"
    benchmark.mkdir(parents=True)
    candidates.mkdir()
    _prepare_verifier_snapshot(target)
    (benchmark / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (candidates / "candidate.cc").write_text("int main() {}\n", encoding="utf-8")

    def runner(command, _timeout):
        return ckg_candidate_verifier.CommandResult(list(command), 1, "", "image failure")

    result = ckg_candidate_verifier.verify_candidates(
        target_root=target,
        candidates_dir=candidates,
        work_dir=tmp_path / "verification",
        fuzz_target="native_fuzzer",
        runner=runner,
    )

    assert result["verification_ran"] is False
    assert "image build exited" in result["infrastructure_error"]


def test_ckgfuzzer_candidate_verifier_rejects_unreproducible_source_context(tmp_path: Path) -> None:
    target = tmp_path / "target"
    benchmark = target / "fuzzbench_benchmark"
    candidates = tmp_path / "candidates"
    benchmark.mkdir(parents=True)
    candidates.mkdir()
    (benchmark / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (candidates / "candidate.cc").write_text("int main() {}\n", encoding="utf-8")
    calls: list[list[str]] = []

    def runner(command, _timeout):
        calls.append(list(command))
        return ckg_candidate_verifier.CommandResult(list(command), 0, "", "")

    result = ckg_candidate_verifier.verify_candidates(
        target_root=target,
        candidates_dir=candidates,
        work_dir=tmp_path / "verification",
        fuzz_target="native_fuzzer",
        runner=runner,
    )

    assert result["verification_ran"] is False
    assert result["verification_context"]["mode"] == "verification_context_unreproducible"
    assert "verification_context_unreproducible" in result["infrastructure_error"]
    assert calls == []


def test_ckgfuzzer_runtime_patch_preserves_check_compilation_newline_escape(tmp_path: Path) -> None:
    source = "\n".join(
        [
            "def check(file, run_args, logger, run):",
            "    if True:",
            "        if True:",
            "            if True:",
            "                result =  run(run_args)",
            r'            logger.info(f"check_compilation {file}, result:\n {result}")',
            '            if "error:" not in result:',
            "                return True",
            "    return False",
        ]
    ) + "\n"
    pattern = (
        r"                result =  run\(run_args\)[ \t]*" + "\n"
        + r'            logger\.info\(f"check_compilation \{file\}, result:\\n \{result\}"\)' + "\n"
        + r'            if "error:" not in result:' + "\n"
    )
    replacement = "\n".join(
        [
            "                result =  run(run_args)",
            "            if not isinstance(result, str):",
            '                result = f"ERROR: non-string result from check_compilation: {result!r}"',
            r'            logger.info(f"check_compilation {file}, result:\n {result}")',
            "            lowered_result = result.lower()",
            '            if "error:" not in lowered_result and "input device is not a tty" not in lowered_result and "error" not in lowered_result:',
        ]
    ) + "\n"

    patched = re.sub(pattern, lambda _match: replacement, source, count=1)
    patched_path = tmp_path / "compilation_fix_agent.py"
    patched_path.write_text(patched, encoding="utf-8")

    assert patched != source
    assert "result:\\n {result}" in patched
    assert "result:\n {result}" not in patched
    py_compile.compile(str(patched_path), doraise=True)


def test_ckgfuzzer_wrapper_allows_link_failure_after_compile_trace() -> None:
    entrypoint = Path("docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")

    assert "build replay produced compiled artifact" in entrypoint
    assert "-name '*.o'" in entrypoint
    assert "-name '*.a'" in entrypoint
    assert '[[ "$count" -gt 0 || "$run_build" -eq 0 || -n "$build_artifact" ]]' in entrypoint


def test_ckgfuzzer_does_not_count_bundled_drivers_before_fuzzing() -> None:
    entrypoint = Path("docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")

    assert 'if [[ "$fuzzing_code" != "not_run" ]]; then' in entrypoint
    assert 'done < <(find "$ckg_db" -type f' in entrypoint
    assert "ckgfuzzer_candidate_verifier.py" in entrypoint
    assert "--skip_check_compilation" in entrypoint
    assert 'done < <(find "$ckg_proj" "$ckg_db" "$ckg_shared"' not in entrypoint
    assert '"$failed_stage" == "fuzzing" && "${generated_harness_count:-0}" -gt 0' in entrypoint


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
    assert result["checkout_status"] == "checked_out_revision"
    assert result["revision_status"] == "resolved"


def test_materialize_repo_initializes_pinned_submodules(monkeypatch, tmp_path: Path) -> None:
    local = tmp_path / "artifacts" / "fuzzbench-target-sources" / "target" / "project"
    (local / ".git").mkdir(parents=True)
    (local / ".gitmodules").write_text("[submodule \"dep\"]\n", encoding="utf-8")
    calls: list[list[str]] = []

    def fake_run(cmd, cwd=None, check=False):
        del cwd, check
        calls.append(cmd)
        if "fetch" in cmd or "checkout" in cmd or "submodule" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if "rev-parse" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "pinned-commit\n", "")
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(hgb_targets, "run", fake_run)
    result = hgb_targets.materialize_repo(
        {
            "kind": "git",
            "url": "https://example.invalid/project.git",
            "dest": "project",
            "revision": "pinned-commit",
        },
        "target",
        "",
        tmp_path,
    )

    assert result["submodule_status"] == "initialized_recursive"
    assert any("submodule" in command for command in calls)


def test_materialize_submodules_rewrites_legacy_git_transport(monkeypatch, tmp_path: Path) -> None:
    local = tmp_path / "project"
    local.mkdir()
    gitmodules = local / ".gitmodules"
    gitmodules.write_text(
        '[submodule "freetype"]\n'
        '  path = third_party/freetype\n'
        '  url = git://git.sv.nongnu.org/freetype/freetype2.git\n',
        encoding="utf-8",
    )
    calls: list[list[str]] = []

    def fake_run(cmd, cwd=None, check=False):
        del cwd, check
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(hgb_targets, "run", fake_run)
    result: dict = {}

    assert hgb_targets.materialize_submodules(local, result) is True
    assert "https://github.com/freetype/freetype.git" in gitmodules.read_text(encoding="utf-8")
    assert result["submodule_url_rewrites"] == [
        {
            "original": "git://git.sv.nongnu.org/freetype/freetype2.git",
            "replacement": "https://github.com/freetype/freetype.git",
        }
    ]
    assert result["submodule_url_sync_status"] == "synchronized"
    assert calls[0][-3:] == ["submodule", "sync", "--recursive"]
    assert calls[1][-3:] == ["submodule", "update", "--init", "--recursive"][-3:]


def test_source_parser_expands_docker_variables_and_attributes_each_repo_revision(tmp_path: Path) -> None:
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "ARG ARCHIVE_VERSION=1.2.3\n"
        "ENV ARCHIVE_ROOT=https://example.invalid/releases\n"
        "RUN git clone --branch dependency-v1 https://example.invalid/dependency.git dependency && \\\n+"
        "    git -C dependency checkout dependency-commit\n"
        "RUN git clone https://example.invalid/primary.git primary\n"
        "RUN wget ${ARCHIVE_ROOT}/archive-${ARCHIVE_VERSION}.tar.gz\n",
        encoding="utf-8",
    )

    repos = hgb_targets.parse_clone_repos(dockerfile)
    hgb_targets.attribute_source_revisions(repos, "primary", "primary-commit")
    by_dest = {repo["dest"]: repo for repo in repos}

    assert by_dest["dependency"]["revision"] == "dependency-commit"
    assert by_dest["dependency"]["revision_source"] == "dockerfile_git_checkout"
    assert by_dest["dependency"]["is_primary_project"] is False
    assert by_dest["primary"]["revision"] == "primary-commit"
    assert by_dest["primary"]["revision_source"] == "benchmark.yaml.commit"
    assert by_dest["primary"]["is_primary_project"] is True
    archive = next(repo for repo in repos if repo["kind"] == "archive")
    assert archive["url"] == "https://example.invalid/releases/archive-1.2.3.tar.gz"


def test_libxslt_archive_urls_expand_declared_env_values() -> None:
    repos = hgb_targets.parse_clone_repos(Path("artifacts/fuzzbench/benchmarks/libxslt_xpath/Dockerfile"))
    urls = {repo["url"] for repo in repos if repo["kind"] == "archive"}
    archive_destinations = {repo["url"]: repo["dest"] for repo in repos if repo["kind"] == "archive"}

    assert "https://ftp.gnu.org/gnu/m4/m4-1.4.19.tar.gz" in urls
    assert "https://ftp.gnu.org/gnu/autoconf/autoconf-2.71.tar.gz" in urls
    assert "https://ftp.gnu.org/gnu/automake/automake-1.16.5.tar.gz" in urls
    assert archive_destinations["https://ftp.gnu.org/gnu/m4/m4-1.4.19.tar.gz"] == "m4-1.4.19"
    assert archive_destinations["https://ftp.gnu.org/gnu/autoconf/autoconf-2.71.tar.gz"] == "autoconf-2.71"
    assert archive_destinations["https://ftp.gnu.org/gnu/automake/automake-1.16.5.tar.gz"] == "automake-1.16.5"


def test_source_override_replaces_inferred_archive_destination(tmp_path: Path) -> None:
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    (metadata / "fuzzbench_source_overrides.json").write_text(
        json.dumps(
            {
                "sqlite": [
                    {
                        "kind": "archive",
                        "url": "https://sqlite.org/src/tarball/sqlite.tar.gz?r=abc",
                        "dest": "sqlite3",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM scratch\nRUN curl 'https://sqlite.org/src/tarball/sqlite.tar.gz?r=abc' -o sqlite3.tar.gz\n",
        encoding="utf-8",
    )

    repos = hgb_targets.parse_clone_repos(dockerfile, tmp_path, "sqlite")

    assert [(repo["url"], repo["dest"]) for repo in repos] == [
        ("https://sqlite.org/src/tarball/sqlite.tar.gz?r=abc", "sqlite3")
    ]


def test_dynamic_branch_sources_expand_from_captured_branch_list(tmp_path: Path) -> None:
    branch_source = tmp_path / "fuzz"
    branch_source.mkdir()
    (branch_source / "branches.txt").write_text("main\n3.1.x\n3.0.x\n", encoding="utf-8")
    repos = [
        {"kind": "git", "url": "https://example.invalid/fuzz", "dest": "fuzz"},
        {
            "kind": "git",
            "url": "https://example.invalid/project",
            "dest": "project._branch",
            "docker_dest": "project.$branch",
            "revision": "benchmark-commit",
            "is_primary_project": True,
        },
    ]

    expanded = hgb_targets.expand_dynamic_branch_sources(
        repos,
        [{"artifact_path": str(branch_source)}],
    )

    assert [(repo["dest"], repo["clone_branch"]) for repo in expanded] == [
        ("project.main", "main"),
        ("project.3.1.x", "3.1.x"),
        ("project.3.0.x", "3.0.x"),
    ]
    assert expanded[0]["revision"] == "benchmark-commit"
    assert "revision" not in expanded[1]
    assert expanded[1]["revision_source"] == "captured_dynamic_branch_head"


def test_materialize_repo_clones_requested_dynamic_branch(monkeypatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd, cwd=None, check=False):
        del cwd, check
        calls.append(cmd)
        if cmd[:2] == ["git", "clone"]:
            (Path(cmd[-1]) / ".git").mkdir(parents=True)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if "checkout" in cmd or "submodule" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if "rev-parse" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "captured-branch-head\n", "")
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(hgb_targets, "run", fake_run)
    result = hgb_targets.materialize_repo(
        {
            "kind": "git",
            "url": "https://example.invalid/project",
            "dest": "project.3.1.x",
            "clone_branch": "3.1.x",
        },
        "target",
        "",
        tmp_path,
    )

    assert ["--branch", "3.1.x"] == calls[0][2:4]
    assert result["clone_branch"] == "3.1.x"
    assert result["revision_status"] == "captured_unpinned"


def test_materialize_repo_captures_unpinned_or_rejects_failed_revisions(monkeypatch, tmp_path: Path) -> None:
    def fake_run(cmd, cwd=None, check=False):
        del cwd, check
        if cmd[:2] == ["git", "clone"]:
            (Path(cmd[-1]) / ".git").mkdir(parents=True)
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if "fetch" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if "checkout" in cmd:
            if cmd[-1] == "head-after-failure":
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return subprocess.CompletedProcess(cmd, 1, "", "revision is unavailable")
        if "rev-parse" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "head-after-failure\n", "")
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(hgb_targets, "run", fake_run)
    captured = hgb_targets.materialize_repo(
        {"kind": "git", "url": "https://example.invalid/dependency.git", "dest": "dependency"},
        "target",
        "",
        tmp_path,
    )
    assert captured["checkout_status"] == "captured_unpinned_commit"
    assert captured["revision_status"] == "captured_unpinned"
    assert captured["captured_revision"] == "head-after-failure"
    # Keep the recipe's missing (or otherwise unresolved) revision visible;
    # the captured SHA is a package-time observation, not a benchmark pin.
    assert captured["requested_revision"] == ""
    assert captured["source_reproducibility"] == "captured_at_package_time"

    failed = hgb_targets.materialize_repo(
        {
            "kind": "git",
            "url": "https://example.invalid/dependency.git",
            "dest": "dependency",
            "revision": "required-commit",
        },
        "target",
        "",
        tmp_path,
    )

    assert failed["checkout_status"] == "checkout_failed"
    assert failed["materialize_status"] == "checkout_failed"
    assert failed["revision_status"] == "unavailable"
    assert failed["checked_out_commit"] == "head-after-failure"


def test_copy_tree_preserves_symlinks_and_replaces_destination_atomically(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    (source / "real.txt").write_text("new", encoding="utf-8")
    os.symlink("real.txt", source / "linked.txt")
    destination.mkdir()
    (destination / "old.txt").write_text("old", encoding="utf-8")

    hgb_targets.copy_tree(source, destination)

    assert not (destination / "old.txt").exists()
    assert (destination / "linked.txt").is_symlink()
    assert os.readlink(destination / "linked.txt") == "real.txt"
    assert (destination / "linked.txt").read_text(encoding="utf-8") == "new"


def test_synthetic_build_script_is_excluded_from_native_docker_context(tmp_path: Path) -> None:
    benchmark = tmp_path / "fuzzbench_benchmark"
    benchmark.mkdir()
    (benchmark / "Dockerfile").write_text(
        "RUN cp libpng/contrib/oss-fuzz/build.sh $SRC\nCOPY * $SRC/\n",
        encoding="utf-8",
    )

    assert hgb_targets.ensure_package_build_script(benchmark) == "missing_stubbed_soft_skip"
    assert (benchmark / "build.sh").is_file()
    assert "/build.sh" in (benchmark / ".dockerignore").read_text(encoding="utf-8").splitlines()


def test_source_status_requires_copied_resolved_revisions() -> None:
    assert hgb_targets.source_status_for_records(
        [{"copy_status": "copied_to_source_input", "revision_status": "resolved"}]
    ) == "materialized"
    assert hgb_targets.source_status_for_records(
        [{"copy_status": "copied_to_source_input", "revision_status": "unresolved"}]
    ) == "partial"
    assert hgb_targets.source_status_for_records(
        [{"copy_status": "copied_to_source_input", "revision_status": "captured_unpinned"}]
    ) == "materialized"


def test_ckgfuzzer_stage_ignores_package_only_dockerignore(tmp_path: Path) -> None:
    target = tmp_path / "target"
    source = target / "source_input" / "project"
    benchmark = target / "fuzzbench_benchmark"
    source.mkdir(parents=True)
    benchmark.mkdir(parents=True)
    (source / "api.c").write_text("int api(void);\n", encoding="utf-8")
    (benchmark / "build.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (benchmark / ".dockerignore").write_text("/build.sh\n", encoding="utf-8")

    ckg_stage.stage_project(target, tmp_path / "project", tmp_path / "analysis", "project")

    assert (tmp_path / "project" / "build.sh").is_file()
    assert not (tmp_path / "project" / ".dockerignore").exists()


def test_package_target_applies_benchmark_commit_only_to_primary_repo(monkeypatch, tmp_path: Path) -> None:
    benchmark = tmp_path / "benchmark"
    source = tmp_path / "cached_source"
    benchmark.mkdir()
    source.mkdir()
    (benchmark / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (benchmark / "benchmark.yaml").write_text("project: primary\n", encoding="utf-8")
    (benchmark / "build.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (source / "library.c").write_text("int library(void) { return 0; }\n", encoding="utf-8")
    repos = [
        {"kind": "git", "url": "https://example.invalid/dependency.git", "dest": "dependency", "source": "Dockerfile"},
        {"kind": "git", "url": "https://example.invalid/primary.git", "dest": "primary", "source": "Dockerfile"},
    ]
    seen_commit_arguments: list[str] = []

    monkeypatch.setattr(
        hgb_targets,
        "resolve_target",
        lambda _root, _target: {
            "benchmark_dir": str(benchmark),
            "project": "primary",
            "commit": "primary-commit",
            "fuzz_target": "native_fuzzer",
            "fuzzbench_commit": "fuzzbench-commit",
        },
    )
    monkeypatch.setattr(hgb_targets, "parse_clone_repos", lambda *_args: [dict(repo) for repo in repos])

    def fake_materialize(repo, _target, commit, _root):
        seen_commit_arguments.append(commit)
        record = dict(repo)
        record.update(
            {
                "artifact_path": str(source),
                "materialize_status": "fetched" if repo.get("revision") else "revision_unresolved",
                "revision_status": "resolved" if repo.get("revision") else "unresolved",
            }
        )
        return record

    monkeypatch.setattr(hgb_targets, "materialize_source", fake_materialize)
    output = hgb_targets.package_target(tmp_path, "target", tmp_path / "package")
    manifest = json.loads((output / "target_manifest.json").read_text(encoding="utf-8"))
    records = {record["dest"]: record for record in manifest["source_repos"]}

    assert seen_commit_arguments == ["", ""]
    assert records["primary"]["revision"] == "primary-commit"
    assert records["dependency"]["revision_source"] == "unresolved"
    assert records["dependency"].get("copy_status") is None
    assert manifest["source_status"] == "partial"



def _project_fuzz_keys(registry: dict, targets: list[str]) -> list[tuple[str, str]]:
    return [
        (hgb_targets.resolve_target(Path("."), target)["project"], hgb_targets.resolve_target(Path("."), target)["fuzz_target"])
        for target in targets
    ]


def test_target_sets_select_curated_deduplicated_targets() -> None:
    registry = hgb_targets.load_registry(Path("."))
    all_targets = hgb_targets.targets_for_set(registry, "all")
    deduped = hgb_targets.targets_for_set(registry, "deduped")
    valuable = hgb_targets.targets_for_set(registry, "valuable")

    assert len(all_targets) == 29
    assert len(deduped) == 25
    assert len(valuable) == 20
    assert set(valuable).issubset(deduped)

    for duplicate in (
        "bloaty_fuzz_target_52948c",
        "harfbuzz_hb-shape-fuzzer_17863b",
        "libxml2_xml_e85b9b",
        "mbedtls_fuzz_dtlsclient_7c6b0e",
    ):
        assert duplicate not in deduped
        assert duplicate not in valuable

    assert len(_project_fuzz_keys(registry, deduped)) == len(set(_project_fuzz_keys(registry, deduped)))
    assert len(_project_fuzz_keys(registry, valuable)) == len(set(_project_fuzz_keys(registry, valuable)))


def test_matrix_script_accepts_named_target_sets() -> None:
    matrix = Path("scripts/hgb_generate_matrix.sh").read_text(encoding="utf-8")

    assert "LIST|all|valuable|deduped" in matrix
    assert 'hgb_targets.sh" list "$targets"' in matrix


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
