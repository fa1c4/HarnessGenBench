from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "docker/common"))
import ckgfuzzer_feedback_repair as repair  # noqa: E402


def test_compiler_feedback_keeps_error_and_nearby_context() -> None:
    log = "\n".join(["noise"] * 200 + ["candidate.cc:18:10: fatal error: input_file.h file not found", "compilation terminated"])
    result = repair.compiler_feedback(log)
    assert "input_file.h" in result
    assert result.count("noise") < 5


def test_visible_headers_use_generator_source_only(tmp_path: Path) -> None:
    source = tmp_path / "source_input" / "project"
    source.mkdir(parents=True)
    (source / "bloaty.h").write_text("struct InputFileFactory {};\n")
    other = tmp_path / "evaluator_only"
    other.mkdir()
    (other / "secret.h").write_text("REFERENCE_SECRET\n")
    snippets = repair.visible_headers('#include "bloaty.h"\n#include "secret.h"\n', tmp_path / "source_input")
    assert "InputFileFactory" in snippets
    assert "REFERENCE_SECRET" not in snippets


def test_visible_headers_include_schema_for_generated_project_header(tmp_path: Path) -> None:
    source = tmp_path / "source_input" / "project"
    source.mkdir(parents=True)
    (source / "bloaty.h").write_text('#include "bloaty.pb.h"\nstruct InputFileFactory {};\n')
    (source / "bloaty.proto").write_text('message Options { repeated string filename = 1; }\n')
    snippets = repair.visible_headers('#include "bloaty.h"\n', tmp_path / "source_input")
    assert "message Options" in snippets


def test_extract_code_requires_complete_driver() -> None:
    code = repair.extract_code('Here is the fix:\n```cpp\n#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t*, size_t) { return 0; }\n```')
    assert code.startswith("#include")
    with pytest.raises(ValueError):
        repair.extract_code("Use a different include")


def test_guarded_c_linkage_is_valid_in_c_target() -> None:
    assert repair.has_cpp_only_syntax_for_c_target('extern "C" int LLVMFuzzerTestOneInput(void);')
    assert not repair.has_cpp_only_syntax_for_c_target(
        '#ifdef __cplusplus\nextern "C"\n#endif\nint LLVMFuzzerTestOneInput(void);')
    assert not repair.has_cpp_only_syntax_for_c_target(
        '#if defined(__cplusplus)\nextern "C"\n#endif\nint LLVMFuzzerTestOneInput(void);')


def test_openssl_public_driver_abi_adaptation(tmp_path: Path) -> None:
    driver = tmp_path / "openssl/fuzz/driver.c"
    driver.parent.mkdir(parents=True)
    driver.write_text("int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {\n"
                      "    return FuzzerTestOneInput(buf, len);\n}\n")
    source = '#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return 0; }\n'
    adapted, changed = repair.adapt_public_fuzz_driver_abi(source, tmp_path, "/src/openssl/fuzz/x509.c")
    assert changed
    assert "int FuzzerTestOneInput(" in adapted
    assert "int FuzzerInitialize(" in adapted
    assert "void FuzzerCleanup(" in adapted
    assert "LLVMFuzzerTestOneInput" not in adapted
    assert repair.adapt_public_fuzz_driver_abi(adapted, tmp_path, "/src/openssl/fuzz/x509.c") == (adapted, False)


def test_model_revision_retries_when_required_api_call_is_dropped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = tmp_path / "driver.cc"
    candidate.write_text('#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { real_api(d); return 0; }\n')
    build_log = tmp_path / "build.log"
    build_log.write_text("driver.cc:1: error: wrong type\n")
    source_root = tmp_path / "source"
    source_root.mkdir()
    selection = tmp_path / "api_selection.json"
    selection.write_text('{"selected_api_names":["real_api"]}')
    replies = iter([
        '#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return 0; }',
        '#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { real_api(d); return 0; }',
    ])
    calls: list[str] = []

    class FakeOpenAI:
        def __init__(self, **kwargs: object) -> None:
            self.chat = types.SimpleNamespace(completions=types.SimpleNamespace(create=self.create))

        def create(self, **kwargs: object) -> object:
            calls.append("model")
            return types.SimpleNamespace(choices=[types.SimpleNamespace(message=types.SimpleNamespace(content=next(replies)))])

    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(OpenAI=FakeOpenAI))
    import hgb_llm_trace
    monkeypatch.setattr(hgb_llm_trace, "trace_call", lambda func, **kwargs: func())
    monkeypatch.setattr(hgb_llm_trace, "record_retry", lambda **kwargs: calls.append("retry"))
    monkeypatch.setattr(hgb_llm_trace, "record_driver_fix", lambda **kwargs: calls.append("fix"))
    for key, value in {"CKGFUZZER_LLM_MODEL": "test-model", "CKGFUZZER_API_KEY": "test-key",
                       "CKGFUZZER_BASE_URL": "http://example.invalid/v1", "CKGFUZZER_LLM_MAX_RETRIES": "2"}.items():
        monkeypatch.setenv(key, value)
    output = repair.repair(candidate, build_log, source_root, tmp_path / "output", selection)
    assert "real_api(d)" in output.read_text()
    assert (tmp_path / "output/repair_attempts.json").read_text().strip() == '{"count": 2}'
    assert calls == ["model", "fix", "retry", "model", "fix"]


def test_c_target_repair_retries_cpp_linkage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = tmp_path / "driver.cc"
    candidate.write_text('#include <stdint.h>\nextern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return real_api(d); }\n')
    build_log = tmp_path / "build.log"
    build_log.write_text('fuzz_both.c:2:8: error: expected identifier or \'(\'\n')
    source_root = tmp_path / "source"
    source_root.mkdir()
    replies = iter([
        candidate.read_text(),
        '#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return real_api(d); }\n',
    ])
    prompts: list[str] = []
    retries: list[int] = []

    class FakeOpenAI:
        def __init__(self, **kwargs: object) -> None:
            self.chat = types.SimpleNamespace(completions=types.SimpleNamespace(create=self.create))

        def create(self, **kwargs: object) -> object:
            prompts.append(str(kwargs["messages"][0]["content"]))
            return types.SimpleNamespace(choices=[types.SimpleNamespace(message=types.SimpleNamespace(content=next(replies)))])

    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(OpenAI=FakeOpenAI))
    import hgb_llm_trace
    monkeypatch.setattr(hgb_llm_trace, "trace_call", lambda func, **kwargs: func())
    monkeypatch.setattr(hgb_llm_trace, "record_retry", lambda **kwargs: retries.append(1))
    monkeypatch.setattr(hgb_llm_trace, "record_driver_fix", lambda **kwargs: None)
    for key, value in {"CKGFUZZER_LLM_MODEL": "test-model", "CKGFUZZER_API_KEY": "test-key",
                       "CKGFUZZER_BASE_URL": "http://example.invalid/v1", "CKGFUZZER_LLM_MAX_RETRIES": "2"}.items():
        monkeypatch.setenv(key, value)
    output = repair.repair(candidate, build_log, source_root, tmp_path / "output")
    assert 'extern "C"' not in output.read_text()
    assert "as C11" in prompts[0]
    assert retries == [1]


def test_sanitizer_feedback_requests_runtime_fix_without_dropping_api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = tmp_path / "driver.c"
    candidate.write_text('#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { real_api(d); return 0; }\n')
    diagnostic = tmp_path / "smoke.log"
    diagnostic.write_text('AddressSanitizer: SEGV in _emalloc\n')
    source_root = tmp_path / "source"
    source_root.mkdir()
    selection = tmp_path / "api_selection.json"
    selection.write_text('{"selected_api_names":["real_api"]}')
    prompts: list[str] = []

    class FakeOpenAI:
        def __init__(self, **kwargs: object) -> None:
            self.chat = types.SimpleNamespace(completions=types.SimpleNamespace(create=self.create))

        def create(self, **kwargs: object) -> object:
            prompts.append(str(kwargs["messages"][0]["content"]))
            return types.SimpleNamespace(choices=[types.SimpleNamespace(message=types.SimpleNamespace(content=candidate.read_text()))])

    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(OpenAI=FakeOpenAI))
    import hgb_llm_trace
    monkeypatch.setattr(hgb_llm_trace, "trace_call", lambda func, **kwargs: func())
    monkeypatch.setattr(hgb_llm_trace, "record_driver_fix", lambda **kwargs: None)
    for key, value in {"CKGFUZZER_LLM_MODEL": "test-model", "CKGFUZZER_API_KEY": "test-key",
                       "CKGFUZZER_BASE_URL": "http://example.invalid/v1"}.items():
        monkeypatch.setenv(key, value)
    output = repair.repair(candidate, diagnostic, source_root, tmp_path / "output", selection,
                           native_destination="/src/fuzzer.c", feedback_kind="sanitizer_smoke")
    assert "real_api(d)" in output.read_text()
    assert "runtime initialization or memory misuse" in prompts[0]
    assert "AddressSanitizer" in prompts[0]


def test_comment_only_api_mention_is_not_required_call(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    candidate = tmp_path / "driver.c"
    candidate.write_text(
        '#include <stdint.h>\n// bio_new() is internal.\n'
        'int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { (void)d; (void)n; return 0; }\n')
    build_log = tmp_path / "build.log"
    build_log.write_text("driver.c:1:1: error: old source\n")
    source_root = tmp_path / "source"
    source_root.mkdir()
    selection = tmp_path / "api_selection.json"
    selection.write_text('{"selected_api_names":["bio_new"]}')
    prompts: list[str] = []

    class FakeOpenAI:
        def __init__(self, **kwargs: object) -> None:
            self.chat = types.SimpleNamespace(completions=types.SimpleNamespace(create=self.create))

        def create(self, **kwargs: object) -> object:
            prompts.append(str(kwargs["messages"][0]["content"]))
            return types.SimpleNamespace(choices=[types.SimpleNamespace(message=types.SimpleNamespace(
                content='#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return 0; }\n'))])

    monkeypatch.setitem(sys.modules, "openai", types.SimpleNamespace(OpenAI=FakeOpenAI))
    import hgb_llm_trace
    monkeypatch.setattr(hgb_llm_trace, "trace_call", lambda func, **kwargs: func())
    monkeypatch.setattr(hgb_llm_trace, "record_driver_fix", lambda **kwargs: None)
    for key, value in {"CKGFUZZER_LLM_MODEL": "test-model", "CKGFUZZER_API_KEY": "test-key",
                       "CKGFUZZER_BASE_URL": "http://example.invalid/v1"}.items():
        monkeypatch.setenv(key, value)
    output = repair.repair(candidate, build_log, source_root, tmp_path / "output", selection,
                           native_destination="/src/fuzzer.c")
    assert output.is_file()
    assert "must still call them: []" in prompts[0]
