# MAGMA baseline evaluation plan

Second benchmark phase: run the five HarnessGenBench baselines on the nine MAGMA
targets with a MAGMA-native build and evaluation stack.

## Protocol

* Harness generators (OSS-Fuzz-Gen, CKGFuzzer, PromeFuzz) receive the target
  source and the parsed harness API (`results/magma_harness_apis.md`) and
  generate a harness.
* Corpus generators (ELFuzz, G2Fuzz) receive the original MAGMA harness and
  generate an input corpus.
* Evaluation: 5 independent 86,400-second campaigns per (baseline, target),
  coverage measured as covered target-source lines with
  `fuzzers/llvm_cov`; crash counts from the ASan libFuzzer campaign.

## Backend

`scripts/hgb_magma_eval.py` drives the MAGMA checkout
(`/data/zym/magma-directed`, override with `HGB_MAGMA_ROOT`):

| Command | Purpose |
| :--- | :--- |
| `build-image --target T --fuzzer F` | build the MAGMA target image (`docker/Dockerfile`, `F` = `libfuzzer_asan` or `llvm_cov`) |
| `rebuild --target T --fuzzer F --work DIR [--harness CAND]` | overlay a harness and re-run `fuzzers/F/instrument.sh`, extracting the binary |
| `campaign --target T --fuzzer libfuzzer_asan --binary B --seconds S --out DIR` | run one libFuzzer campaign seeded from the MAGMA corpus |
| `coverage --target T --fuzzer llvm_cov --corpus DIR --out DIR` | replay a saved corpus, merge profiles, export LCOV, summarize |

`metadata/magma_targets.yaml` records each target's program, harness path,
corpus directory, project root, and parsed first/entry API.

Verified on libpng: a 60 s campaign produced 213 corpus files and 27.12 %
(5,266 / 19,420) target-source line coverage; a harness overlay rebuild and a
45 s candidate campaign also work.

## Status

1. MAGMA sources fetched under `/data/zym/magma-work` (libpng, libsndfile,
   libtiff, libxml2, lua, openssl, sqlite3, poppler; php clone still running at
   time of writing).
2. First/entry harness APIs extracted for all nine targets
   (`results/magma_harness_apis.md`, `workspace/magma/harness_apis.json`).
3. Image queue building `libfuzzer_asan` and `llvm_cov` images for all nine
   targets with BuildKit (sequential queue, log `/tmp/magma_build_queue.log`).
4. Harness-generation bridge: a FuzzBench-style MAGMA benchmark for libpng is
   built and verified (`docker build` with the base-builder compile step,
   `workspace/magma/benchmarks/libpng`). The remaining work is to wrap each
   target's benchmark into an HGB split package (source_input + benchmark_copy +
   evaluator manifests) so the generator containers can run against it.
5. First end-to-end generation: OSS-Fuzz-Gen on the MAGMA libpng package completed
   introspector build, benchmark synthesis (`png_create_read_struct`), and wrote
   three generated fuzz targets under
   `workspace/oss-fuzz-gen/magma_libpng/20261111T084828Z/generation/work/output-libpng-oss_fuzz_png_create_read_struct/fuzz_targets/`.
6. php source was re-fetched with a shallow clone at the MAGMA pin (bc39abe8).
7. Credentials: `~/api_keys/HarnessGenBench/set_api_key_magma.sh` sources the
   shared `~/api_keys/set_api_key.sh` key and keeps the HGB provider/embedding
   settings; `HGB_API_KEY_CONFIG=... bash scripts/hgb_llm_preflight.sh --live`
   reports `status=ok` (the default HGB config's key currently returns 401).

## Verified generation -> native evaluation chain (libpng)

OSS-Fuzz-Gen generated harness `01.fuzz_target` for `png_create_read_struct`
(`workspace/oss-fuzz-gen/magma_libpng/20261111T084828Z`). Normalizing the
OSS-Fuzz symbol prefix (`OSS_FUZZ_png_*` -> `png_*`) lets the MAGMA libpng
backend compile and run it: a 40 s campaign with the MAGMA seed corpus reaches
4,433 / 19,420 = **22.83 %** target-source line coverage (original harness,
60 s campaign: 27.12 %). Harness evaluation artifacts:
`workspace/magma/{builds,campaigns,coverage}/libpng_ofg01d`.
