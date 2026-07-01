# FuzzBench Targets

HarnessGenBench uses FuzzBench as the target corpus because it gives each benchmark a reproducible project/fuzz-target pairing, a build recipe, and a pinned upstream source commit. The target registry is tracked in `metadata/fuzzbench_targets.json`, while project details are resolved at runtime from the checked-out FuzzBench artifact under `artifacts/fuzzbench/benchmarks/<target>/benchmark.yaml`.

## Target Names

- `bloaty_fuzz_target`
- `bloaty_fuzz_target_52948c`
- `curl_curl_fuzzer_http`
- `freetype2_ftfuzzer`
- `harfbuzz_hb-shape-fuzzer`
- `harfbuzz_hb-shape-fuzzer_17863b`
- `jsoncpp_jsoncpp_fuzzer`
- `lcms_cms_transform_fuzzer`
- `libjpeg-turbo_libjpeg_turbo_fuzzer`
- `libpcap_fuzz_both`
- `libpng_libpng_read_fuzzer`
- `libxml2_xml`
- `libxml2_xml_e85b9b`
- `libxslt_xpath`
- `mbedtls_fuzz_dtlsclient`
- `mbedtls_fuzz_dtlsclient_7c6b0e`
- `mruby_mruby_fuzzer_8c8bbd`
- `openh264_decoder_fuzzer`
- `openssl_x509`
- `openthread_ot-ip6-send-fuzzer`
- `php_php-fuzz-parser_0dbedb`
- `proj4_proj_crs_to_crs_fuzzer`
- `re2_fuzzer`
- `sqlite3_ossfuzz`
- `stb_stbi_read_fuzzer`
- `systemd_fuzz-link-parser`
- `vorbis_decode_fuzzer`
- `woff2_convert_woff2ttf_fuzzer`
- `zlib_zlib_uncompress_fuzzer`

## Resolution

Run `bash scripts/hgb_targets.sh resolve <target> --json` to resolve a target. The resolver reads `project`, `fuzz_target`, `commit`, `commit_date`, and `unsupported_fuzzers` from FuzzBench `benchmark.yaml`, so metadata follows the pinned FuzzBench checkout recorded in `metadata/work_index.yaml`.

## Packaging

`bash scripts/hgb_prepare_target.sh <target>` creates `workspace/targets/<target>/<run_id>/`. The packager copies the FuzzBench benchmark, parses `git clone` commands from the benchmark Dockerfile, materializes source checkouts under `artifacts/fuzzbench-target-sources/<target>/`, and copies those sources into the package.

Existing fuzz harnesses are stripped from `source_input/` by default and copied to `reference_harnesses/`. This avoids handing the generator the human-written answer while preserving the harnesses for optional reference and audit. Set `HGB_TARGET_STRIP_REFERENCE_HARNESS=0` to keep `source_input/` identical to `source_full/`.

Seeds, corpora, dictionaries, and options files are copied when present. Missing optional source or build products are recorded in `target_manifest.json` and downstream generators soft-skip when the package is insufficient.

## Results

Prepared targets are written under `workspace/targets/<target>/<run_id>/`. Generator runs are written under `workspace/<generator>/<target>/<run_id>/`, with `metadata.json`, `HGB_SUMMARY.md`, `command.txt`, logs, and generated outputs.
