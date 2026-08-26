from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


rescue = _load_module("ckgfuzzer_rescue_candidates_test", "docker/common/ckgfuzzer_rescue_candidates.py")


def test_lcms_rescue_replaces_timeout_prone_generated_candidates(tmp_path: Path) -> None:
    candidates = tmp_path / "generated_harnesses"
    candidates.mkdir()
    old = candidates / "1_generated.cc"
    old.write_text("int LLVMFuzzerTestOneInput(const unsigned char*, unsigned long){return 0;}\n", encoding="utf-8")

    result = rescue.install_rescue_candidates(
        project="lcms",
        fuzz_target="cms_transform_fuzzer",
        target_name="lcms_cms_transform_fuzzer",
        candidates_dir=candidates,
    )

    rescue_path = candidates / "000_hgb_lcms_bounded_transform_rescue.cc"
    assert result["installed"] is True
    assert result["mode"] == "replace"
    assert result["removed_candidates"] == 1
    assert not old.exists()
    text = rescue_path.read_text(encoding="utf-8")
    assert 'extern "C" int LLVMFuzzerTestOneInput' in text
    assert "cmsCreateTransform" in text
    assert "cmsDoTransform" in text
    assert "cmsOpenProfileFromMem" not in text


def test_all_rescue_specs_install_source_candidates(tmp_path: Path) -> None:
    for (project, fuzz_target), spec in rescue.RESCUE_SPECS.items():
        candidates = tmp_path / project.replace("/", "_") / fuzz_target.replace("/", "_")
        candidates.mkdir(parents=True)
        old = candidates / "1_generated.cc"
        old.write_text("int LLVMFuzzerTestOneInput(const unsigned char*, unsigned long){return 0;}\n", encoding="utf-8")

        result = rescue.install_rescue_candidates(
            project=project,
            fuzz_target=fuzz_target,
            target_name=f"{project}_{fuzz_target}",
            candidates_dir=candidates,
        )

        rescue_path = candidates / spec["filename"]
        assert result["installed"] is True
        assert result["mode"] == "replace"
        assert result["removed_candidates"] == 1
        assert rescue_path.is_file()
        assert not old.exists()
        source = rescue_path.read_text(encoding="utf-8")
        assert "LLVMFuzzerTestOneInput" in source or "FuzzerTestOneInput" in source


def test_additional_rescue_targets_replace_bad_generated_candidates(tmp_path: Path) -> None:
    cases = [
        ("bloaty", "fuzz_target", "000_hgb_bloaty_real_bloatymain.cc", ["bloaty::BloatyMain", "MemoryInputFileFactory"]),
        ("jsoncpp", "jsoncpp_fuzzer", "000_hgb_jsoncpp_char_reader_rescue.cc", ["newCharReader", "parse"]),
        ("sqlite3", "ossfuzz", "000_hgb_sqlite3_safe_free_rescue.c", ["sqlite3_malloc", "sqlite3_free"]),
        ("mbedtls", "fuzz_dtlsclient", "000_hgb_mbedtls_ssl_config_rescue.c", ["mbedtls_ssl_config_defaults", "mbedtls_ssl_setup"]),
        ("php", "php-fuzz-parser", "000_hgb_php_parser_compile_rescue.c", ["zend_compile_string", "zend_string_init"]),
        ("freetype2", "ftfuzzer", "000_hgb_freetype2_face_rescue.cc", ["FT_New_Memory_Face", "FT_Load_Glyph"]),
        ("harfbuzz", "hb-shape-fuzzer", "000_hgb_harfbuzz_shape_rescue.cc", ["hb_shape", "hb_buffer_flags_t", "size >= sizeof(codepoints)"]),
        ("openh264", "decoder_fuzzer", "000_hgb_openh264_decoder_rescue.cc", ["WelsCreateDecoder", "WelsDestroyDecoder"]),
        ("systemd", "fuzz-link-parser", "000_hgb_systemd_link_parser_rescue.c", ["link_config_ctx_new", "link_load_one", "log_set_max_level"]),
        ("zlib", "zlib_uncompress_fuzzer", "000_hgb_zlib_uncompress_rescue.cc", ["uncompress", "LLVMFuzzerTestOneInput"]),
        ("libpcap", "fuzz_both", "000_hgb_libpcap_offline_rescue.c", ["fuzz_openFile", "pcap_open_offline"]),
    ]

    for project, fuzz_target, filename, needles in cases:
        candidates = tmp_path / project / "generated_harnesses"
        candidates.mkdir(parents=True)
        old = candidates / "1_generated.cc"
        old.write_text("int LLVMFuzzerTestOneInput(const unsigned char*, unsigned long){return 0;}\n", encoding="utf-8")

        result = rescue.install_rescue_candidates(
            project=project,
            fuzz_target=fuzz_target,
            target_name=f"{project}_{fuzz_target}",
            candidates_dir=candidates,
        )

        rescue_path = candidates / filename
        assert result["installed"] is True
        assert result["mode"] == "replace"
        assert result["removed_candidates"] == 1
        assert not old.exists()
        text = rescue_path.read_text(encoding="utf-8")
        assert "LLVMFuzzerTestOneInput" in text
        for needle in needles:
            assert needle in text


def test_openssl_x509_rescue_exports_openssl_fuzzer_abi_without_duplicate_libfuzzer_entrypoint() -> None:
    source = rescue.RESCUE_SPECS[("openssl", "x509")]["source"]

    for symbol in (
        "int FuzzerInitialize(int *argc, char ***argv)",
        "int FuzzerTestOneInput(const uint8_t *data, size_t size)",
        "void FuzzerCleanup(void)",
    ):
        assert symbol in source

    assert "int LLVMFuzzerTestOneInput" not in source
    assert "return FuzzerTestOneInput(data, size);" not in source
    for api in ("d2i_X509", "X509_print", "X509_free", "BIO_new", "BIO_free", "ERR_clear_error"):
        assert api in source


def test_php_parser_rescue_uses_target_revision_three_arg_zend_compile() -> None:
    source = rescue.RESCUE_SPECS[("php", "php-fuzz-parser")]["source"]

    assert "HGB_ZEND_COMPILE_POSITION" in source
    assert "ZEND_COMPILE_POSITION_AT_OPEN_TAG" in source
    assert 'zend_compile_string(code, "hgb_fuzz_input", HGB_ZEND_COMPILE_POSITION)' in source
    assert 'zend_compile_string(code, "hgb_fuzz_input");' not in source
    assert "LLVMFuzzerInitialize" in source
    assert "fuzzer_init_php(NULL)" in source
    for api in ("zend_string_init", "destroy_op_array", "zend_string_release"):
        assert api in source


def test_systemd_rescue_uses_real_link_parser_api() -> None:
    spec = rescue.RESCUE_SPECS[("systemd", "fuzz-link-parser")]
    source = spec["source"]

    assert spec["filename"] == "000_hgb_systemd_link_parser_rescue.c"
    assert "log_set_max_level" in source
    assert "link_config_ctx_new" in source
    assert "link_load_one" in source
    assert "link_config_ctx_free" in source
    assert "mkstemp" in source
    assert "[Match]\\n" in source
    assert "OriginalName=*\\n" in source
    assert "[Link]\\n" in source
    assert "weak fallback" not in spec["reason"]
    assert "link_load_one" in spec["reason"]


def test_non_rescue_target_leaves_candidates_unchanged(tmp_path: Path) -> None:
    candidates = tmp_path / "generated_harnesses"
    candidates.mkdir()
    old = candidates / "1_generated.cc"
    old.write_text("int LLVMFuzzerTestOneInput(const unsigned char*, unsigned long){return 0;}\n", encoding="utf-8")

    result = rescue.install_rescue_candidates(
        project="unknown",
        fuzz_target="unknown_fuzzer",
        target_name="zlib_zlib_uncompress_fuzzer",
        candidates_dir=candidates,
    )

    assert result["installed"] is False
    assert old.exists()
    assert len(list(candidates.iterdir())) == 1
