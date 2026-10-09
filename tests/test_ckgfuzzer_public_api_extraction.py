from __future__ import annotations

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "docker/common"))
import extract_api_list as api  # noqa: E402


def test_freetype_public_header_survives_generic_limit(tmp_path: Path) -> None:
    root = tmp_path / "source_input"
    header = root / "freetype2/include/freetype/freetype.h"
    header.parent.mkdir(parents=True)
    header.write_text("FT_EXPORT( FT_Error ) FT_Init_FreeType( FT_Library *alibrary );\n")
    records = api.public_header_records(root, ("include/freetype/freetype.h",), (api.FT_EXPORT_RE,))
    selected, _ = api.select_records(
        records, max_records=8, fallback_max=4, selection_mode="ranked",
        project="freetype2", target_name="freetype2_ftfuzzer", fuzz_target="ftfuzzer",
        reference_dir="", keep_rejected=False, report_mode="dynamic_only",
        public_freetype_apis=True,
    )
    assert [record["name"] for record in selected] == ["FT_Init_FreeType"]


def test_libxml_public_header_filter_accepts_project_prefix(tmp_path: Path) -> None:
    root = tmp_path / "source_input"
    header = root / "libxml2/include/libxml/parser.h"
    header.parent.mkdir(parents=True)
    header.write_text("xmlDocPtr xmlReadMemory(const char *buffer, int size);\n")
    records = api.public_header_records(root, ("include/libxml/parser.h",), (api.DECL_RE,))
    selected, _ = api.select_records(
        records, max_records=8, fallback_max=4, selection_mode="ranked",
        project="libxml2", target_name="libxml2_xml", fuzz_target="xml",
        reference_dir="", keep_rejected=False, report_mode="dynamic_only",
        public_libxml_parser_apis=True,
    )
    assert [record["name"] for record in selected] == ["xmlReadMemory"]
