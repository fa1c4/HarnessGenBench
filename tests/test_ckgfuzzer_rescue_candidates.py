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
        assert "LLVMFuzzerTestOneInput" in rescue_path.read_text(encoding="utf-8")


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
        ("systemd", "fuzz-link-parser", "000_hgb_systemd_log_level_rescue.c", ["log_set_max_level", "LLVMFuzzerTestOneInput"]),
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
