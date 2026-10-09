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

Run `python3 scripts/hgb_audit_valuable_reproduction.py` to refresh `workspace/reproduction_audit_valuable.json`. The audit checks the independent evaluator, real campaign executions, and LLVM source coverage. It also rejects CKGFuzzer source-derived rescue drivers and ELFuzz AFL campaigns shorter than their configured profile budget. The pinned systemd OSS-Fuzz build explicitly rejects Fuzz Introspector, so `systemd_fuzz-link-parser` is outside OSS-Fuzz-Gen's scope; ELFuzz's text-input scope is listed in `metadata/elfuzz_target_adapters.yaml`.

G2Fuzz's 20 applicable adapters are reported separately as 9 `paper-core` targets and 11 `extension` targets. An evaluated extension is a verified benchmark adaptation, not a paper-core reproduction.

Each baseline invocation also writes `workspace/<generator>/<target>/<run_id>/statistics.json` and updates `workspace/<generator>/statistics.json` under `runs[target][run_id]`, first with status `running` and then with the final result. The record includes observed retry decisions, evaluator retries (`evaluation_retry_count`), provider reported input (`read_tokens`) and output (`write_tokens`) tokens, and generated driver fix rounds. `token_totals_complete` is false when a provider omitted usage or an older run had only sampled traces; unavailable legacy counts are `null`. `driver_fix_rounds` is `null` for G2Fuzz and ELFuzz because they generate inputs rather than repair drivers. Retry counts include instrumented baseline loops and evaluator retries; retries hidden inside provider SDKs are not observable.

All 20 valuable PromeFuzz targets had a verified `evaluated` run on 2026-10-09. Verification requires a candidate overlay, copy audit, FuzzBench build, sanitizer smoke, API reachability, a nonempty campaign, and measured source coverage. The PHP and systemd successes came from recorded evaluator retries; their earlier retry results remain in their retry directories, and systemd's original evaluator result is backed up as `evaluation/result.pre_reevaluation.json`.

The PromeFuzz pass means the generated driver satisfied those evaluator checks. The selected PHP driver exercises Zend arena APIs rather than the PHP parser, and the selected HarfBuzz driver covered only three source lines; neither result demonstrates broad target behavior.

To retry any future unfinished PromeFuzz targets, run `bash scripts/hgb_retry_promefuzz.sh`. It loads `configs/set_api_key_ds.sh`, runs the remaining targets with `--parallel-worker 5`, records each result, waits five minutes between quality-failure rounds (30 minutes for rate limits), and continues until every target has an `evaluated` result. Set `HGB_RETRY_TARGETS` to a comma-separated subset when only some targets need another attempt.
