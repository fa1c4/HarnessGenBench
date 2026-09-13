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


def test_select_functions_prefers_primary_project_over_vendored() -> None:
    sel = select_functions(_records(), max_functions=1, project="freetype2",
                           target_name="freetype2_ftfuzzer", fuzz_target="ftfuzzer")
    assert sel["selected"][0]["name"] == "FT_Load_Glyph"


def test_select_functions_keeps_vendored_as_fallback() -> None:
    records = [_records()[1]]
    sel = select_functions(records, max_functions=1, project="freetype2",
                           target_name="freetype2_ftfuzzer", fuzz_target="ftfuzzer")
    assert sel["selected"][0]["name"] == "BrotliDecoderDecompressStream"
