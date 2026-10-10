"""Tests for OFG candidate rescue and vendored-function selection."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "docker" / "common"))

from ofg_rescue_candidates import (
    append_extern_c,
    rescue_file,
    strip_pollution,
)
from ofg_introspector_adapter import select_functions


def _records() -> list[dict]:
    return [
        {"name": "FT_Load_Glyph", "path": "/src/x-testing/external/freetype2/src/base/ftobjs.c",
         "signature": "FT_Error FT_Load_Glyph(void)", "public": True, "complexity": 60,
         "covered": False, "callees": []},
        {"name": "BrotliDecoderDecompressStream",
         "path": "/src/x-testing/external/brotli/c/dec/decode.c",
         "signature": "int BrotliDecoderDecompressStream(void)", "public": True,
         "complexity": 60, "covered": False, "callees": []},
    ]


def test_strip_pollution_removes_solution_tag() -> None:
    text = "<solution>\n#include <stdint.h>\n#include <stdlib.h>\n"
    cleaned, fixes = strip_pollution(text)
    assert fixes == ["stripped_xml_tag:<solution>"]
    assert cleaned.startswith("#include <stdint.h>")


def test_append_extern_c_only_when_missing() -> None:
    text = "#include <cstdint>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { return 0; }\n"
    fixed, applied = append_extern_c(text)
    assert applied
    assert 'extern "C" int LLVMFuzzerTestOneInput' in fixed
    _, applied_again = append_extern_c(fixed)
    assert not applied_again


def test_rescue_file_cpp_extern_and_pollution(tmp_path: Path) -> None:
    p = tmp_path / "cand.cc"
    p.write_text("<solution>\n#include <string>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) { return 0; }\n")
    rec = rescue_file(p, target="jsoncpp_jsoncpp_fuzzer", language="c++")
    assert rec["changed"]
    assert any(f.startswith("stripped_xml_tag") for f in rec["fixes"])
    assert "append_extern_c" in rec["fixes"]
    assert 'extern "C"' in p.read_text()


def test_openssl_rescue_supplies_driver_hooks_and_missing_context(tmp_path: Path) -> None:
    p = tmp_path / "candidate.c"
    p.write_text(
        "#include <openssl/crypto.h>\n#include <stdint.h>\n#include <stddef.h>\n"
        "int FuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
        "    (void)data; (void)size; libctx = OSSL_LIB_CTX_new(); return 0;\n}\n"
    )
    record = rescue_file(p, target="openssl_x509", language="c")
    source = p.read_text()
    assert record["changed"]
    assert "adapt_openssl_fuzz_abi" in record["fixes"]
    assert "declare_libctx_propq" in record["fixes"]
    assert "FuzzerInitialize" in source and "FuzzerCleanup" in source
    assert "OSSL_LIB_CTX *libctx = NULL;" in source
    assert not rescue_file(p, target="openssl_x509", language="c")["changed"]


def test_php_rescue_initializes_public_fuzzer_sapi_once(tmp_path: Path) -> None:
    p = tmp_path / "candidate.c"
    p.write_text(
        '#include "php.h"\n#include "ext/json/php_json.h"\n'
        'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n'
        '    zval result; php_json_decode_ex(&result, (const char *)data, size, 0, 512); return 0;\n}\n'
    )
    record = rescue_file(p, target="php_php-fuzz-parser_0dbedb", language="c")
    source = p.read_text()
    assert record["fixes"] == ["adapt_php_fuzzer_lifecycle"]
    assert source.count('LLVMFuzzerTestOneInput(') == 1
    assert source.count('hgb_generated_test_one_input(') == 2
    assert 'fuzzer_init_php(NULL)' in source
    assert 'padded[size] = 0;' in source
    assert 'fuzzer_request_shutdown()' in source
    assert not rescue_file(p, target="php_php-fuzz-parser_0dbedb", language="c")["changed"]


def test_php_rescue_keeps_generated_request_scope(tmp_path: Path) -> None:
    p = tmp_path / "candidate.c"
    p.write_text(
        '#include "php.h"\n#include "fuzzer-sapi.h"\n'
        'int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n'
        '    if (fuzzer_request_startup() == FAILURE) return 0;\n'
        '    fuzzer_request_shutdown(); return 0;\n}\n'
    )
    rescue_file(p, target="php_php-fuzz-parser_0dbedb", language="c")
    source = p.read_text()
    assert source.count('fuzzer_request_startup()') == 1
    assert source.count('fuzzer_request_shutdown()') == 1
    assert 'padded[size] = 0;' in source


def test_systemd_rescue_uses_pinned_link_config_api(tmp_path: Path) -> None:
    p = tmp_path / "generated.cc"
    p.write_text(
        '#include "networkd-link.h"\n'
        'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n'
        '  LinkConfigContext *ctx = NULL;\n'
        '  link_config_context_new(&ctx);\n'
        '  link_load_one(ctx, "/tmp/test.link");\n'
        '  link_config_context_free(ctx);\n'
        '  return 0;\n}\n'
    )
    record = rescue_file(p, target="systemd_fuzz-link-parser", language="c")
    source = p.read_text()
    assert "adapt_systemd_link_parser" in record["fixes"]
    assert '#include "link-config.h"' in source
    assert "link_config_ctx_new(&ctx)" in source
    assert "link_config_ctx_free(ctx)" in source
    assert "link_load_one(ctx" in source
    assert 'extern "C"' not in source
    assert not rescue_file(p, target="systemd_fuzz-link-parser", language="c")["changed"]


def test_select_functions_prefers_primary_project_over_vendored() -> None:
    sel = select_functions(_records(), max_functions=1, project="freetype2",
                           target_name="freetype2_ftfuzzer", fuzz_target="ftfuzzer")
    assert sel["selected"][0]["name"] == "FT_Load_Glyph"


def test_select_functions_keeps_vendored_as_fallback() -> None:
    records = [_records()[1]]
    sel = select_functions(records, max_functions=1, project="freetype2",
                           target_name="freetype2_ftfuzzer", fuzz_target="ftfuzzer")
    assert sel["selected"][0]["name"] == "BrotliDecoderDecompressStream"
