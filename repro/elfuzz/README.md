# ELFuzz Reproduction

ELFuzz is tracked as an HGB **`input_generator`**: it synthesizes and evolves
input-producing fuzzer programs against a fixed native FuzzBench target, then
runs a final AFL++ campaign with the evolved generators. It **does not**
generate `LLVMFuzzerTestOneInput`, the native target harness is kept fixed, and
ELFuzz is never ranked with harness generators (CKGFuzzer, PromeFuzz,
OSS-Fuzz-Gen).

## Applicability

ELFuzz supports **text-input targets only**. The committed, explicit adapter
contract is `metadata/elfuzz_target_adapters.yaml`. Applicability is decided
from that manifest, not from runtime filename substrings or permissive
environment overrides.

- **Applicable text targets (9):** `curl_curl_fuzzer_http`,
  `jsoncpp_jsoncpp_fuzzer`, `libxml2_xml`, `libxslt_xpath`,
  `mruby_mruby_fuzzer_8c8bbd`, `php_php-fuzz-parser_0dbedb`, `re2_fuzzer`,
  `sqlite3_ossfuzz`, `systemd_fuzz-link-parser`.
- **Invalid non-text targets (11):** `bloaty_fuzz_target`,
  `freetype2_ftfuzzer`, `harfbuzz_hb-shape-fuzzer`, `lcms_cms_transform_fuzzer`,
  `libjpeg-turbo_libjpeg_turbo_fuzzer`, `libpcap_fuzz_both`,
  `libpng_libpng_read_fuzzer`, `mbedtls_fuzz_dtlsclient`,
  `openh264_decoder_fuzzer`, `openssl_x509`, `zlib_zlib_uncompress_fuzzer`.

Non-text targets are reported as **`Invalid`** before Docker model download,
TGI, synthesis, or fuzzing starts:

```text
Invalid: ELFuzz supports text-input targets only
```

and stored as `status=not_applicable`, `applicability=Invalid`,
`reason_code=elfuzz_non_text_target`. Invalid rows are not counted as
evaluated and never enter coverage rankings, but matrix execution continues
with exit code 0 for the contractually Invalid pair. `infra_missing` and
actual failures remain nonzero in strict mode.

## Canonical commands

```bash
bash scripts/hgb_run_baseline.sh \
  --generator elfuzz \
  --target jsoncpp_jsoncpp_fuzzer \
  --profile alpha \
  --protocol paper-native \
  --strict
```

A non-text target prints the Invalid line and exits 0 without credentials or
Docker:

```bash
bash scripts/hgb_run_baseline.sh \
  --generator elfuzz \
  --target libpng_libpng_read_fuzzer \
  --profile alpha \
  --protocol paper-native \
  --strict
```

## Profiles / budgets

| Profile | Evolution | Production | Campaign | Aggregate |
|---|---|---|---|---|
| `ci-smoke` / `compat-smoke` | 1 iteration | 60s | 60s | excluded |
| `alpha` | upstream-default-or-greater (>= 2 iter, >= 61s) | nontrivial | nontrivial (>= 60s) | included |
| `paper-faithful` | 50 (pinned upstream) | 600s | 86400s | included |

`alpha` cannot use the 1-iteration / 60-second smoke defaults; those are
`compat-smoke` values only. All budgets are CLI/configurable via
`ELFUZZ_EVOLUTION_ITERATIONS`, `ELFUZZ_PRODUCE_SECONDS`, `ELFUZZ_AFL_SECONDS`,
and `ELFUZZ_TGI_WAITING_SECONDS`, and are recorded in `result.json` provenance.

## Workflow and run layout

The full alpha workflow runs the pinned upstream equivalent of `setup`/cache
validation, model/TGI readiness, `elfuzz synth`, `elfuzz produce`, `elfuzz run
rq1.afl`, and coverage collection. The current `elfuzz run`/campaign stage is
**not** skipped; stopping after `synth`/`produce` is the old behavior and is
fixed.

```text
workspace/elfuzz/<target>/<run-id>/
  target/            adapter_manifest.json, binary/, build.log, build.json
  synthesis/         fuzzer_programs/, lineage.jsonl, prompts/
  generated_inputs/  produced/, provenance.jsonl
  campaign/          queue/, crashes/, hangs/, stats/, command.txt
  coverage/          summary.json
  metadata.json
  result.json
  HGB_SUMMARY.md
```

Fuzzer programs, produced inputs, and the campaign corpus are kept on distinct
paths. Only actual produced input files are counted as generated inputs;
configs, logs, Python sources, model files, and lineage metadata are not.

## Adapters

HGB-owned adapter overlays live under `repro/elfuzz/targets/<target>/`
(`format.md`, `seed_fuzzer.py`, `adapter.json`, `adapter_manifest.json`).
Upstream-native adapters (jsoncpp, libxml2, re2, sqlite3) are bound to the
exact pinned FuzzBench binaries; HGB text extensions cover curl HTTP, libxslt
XPath/XML, mruby, PHP parser, and systemd `.link` parser.

## Compatibility wrappers

```bash
bash scripts/elfuzz_pull_image.sh
bash scripts/elfuzz_start_container.sh --smoke || true
bash scripts/elfuzz_smoke_jsoncpp.sh || true
bash scripts/elfuzz_copy_results.sh workspace/elfuzz/<run-id>
```

The primary image is built from `docker/elfuzz/Dockerfile`, based on
`ghcr.io/osuseclab/elfuzz:25.08.0` (pin by digest via the
`ELFUZZ_BASE_IMAGE` build arg for reproducibility).
