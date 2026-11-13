# MAGMA smoke tests (5-minute campaign budget)

Scope change (2026-11-12): the 24-hour fuzzing matrix and the nine-target
OSS-Fuzz-Gen generation batch were stopped. The goal of this stage is one
end-to-end 5-minute smoke per baseline, in the order OSS-Fuzz-Gen, CKGFuzzer,
PromeFuzz, ELFuzz, G2Fuzz. Any divergence from the agreed protocol is listed at
the end for a decision.

## OSS-Fuzz-Gen: PASS (libpng)

Evidence: `workspace/magma/smoke/oss-fuzz-gen/` (`result.json`,
`coverage.json`, harness source).

* Target package: `workspace/magma/targets/magma_libpng/pkg` (split layout).
* Generator: `oss-fuzz-gen`, profile `alpha`, protocol `blind-project`.
* Candidate: `1_01.fuzz_target.c` generated for `png_create_read_struct`
  (the only one of the three generated candidates that actually reads the
  fuzzer input; the other two only create/destroy a `png_struct`).
* Independent evaluator: `status=evaluated`; every stage `completed`
  (`candidate_build`, `candidate_overlay`, `sanitizer_smoke`,
  `api_reachability`, `campaign`, `coverage`). Campaign budget 60 s,
  coverage replay produced a real LLVM report.
* The evaluator campaign count was >6 M executions for the 60 s run.

Reproduce:

```bash
export HGB_API_KEY_CONFIG=$HOME/api_keys/HarnessGenBench/set_api_key_magma.sh
export HGB_SKIP_IMAGE_PREFLIGHT=1
bash scripts/hgb_generate_harness.sh --generator oss-fuzz-gen \
  --target magma_libpng \
  --target-package $PWD/workspace/magma/targets/magma_libpng/pkg \
  --profile alpha --protocol blind-project --run-id <id> --timeout 7200
```

Notes: OFG's generated symbols use `OSS_FUZZ_png_*`; the evaluator and the
MAGMA benchmark build normalize this namespace to the plain API before
compiling. The generated harness is otherwise untouched.

## CKGFuzzer: in progress (libpng)

* The first run failed at `knowledge_graph` with
  `CodeQL produced no selected-API call-graph artifact`. `libpng` declares
  `png_create_read_struct` through the `PNG_EXPORTA` macro, and CKGFuzzer's
  tree-sitter extractor found 0 definitions/declarations matching the declared
  API (`Found 0 function definitions, 0 function declarations`).
* Workaround under test: a generator-visible
  `hgb_declared_api.h` in `generator_input/source_input/libpng/` carrying the
  committed prototype. This is api-oracle input (the entry API is already
  committed public metadata), not a reference harness.
* Relaunched smoke: `workspace/ckgfuzzer/magma_libpng/20261112T031227Z_ckg_smoke`
  with `HGB_CAMPAIGN_SECONDS=300` (5 minutes).

## PromeFuzz: image rebuild in progress

* The generator image rebuild was failing at the NLTK data self-check because
  the public NLTK download is unreliable on this host. The validated corpora
  were extracted from the previous image into `docker/promefuzz/nltk_data`
  (79 MB) and the Dockerfile now bakes them in.
* Rebuild is still running (shared-host apt is the bottleneck). No PromeFuzz
  smoke yet.
* Known risk: PromeFuzz `alpha` requires a real `compile_commands.json`
  captured from the target build. The MAGMA benchmark dirs can provide one via
  the native build; this has not yet been verified for all nine targets.

## ELFuzz / G2Fuzz: delegated integration in progress

* Both are corpus generators. They need a FuzzBench-style MAGMA benchmark
  directory and per-target adapters; the nine benchmark dirs exist.
* Open issue: upstream ELFuzz applicability is text-input only. MAGMA targets
  are binary-format parsers (PNG, TIFF, PDF, ...). Either the adapters must be
  extended with binary format specs (LLM-generated seed programs), or those
  cells must be marked N/A. This changes the 5×9 table and needs a decision.

## Divergences for decision

1. **Declared-API shim for macro-declared APIs.** CKGFuzzer/CodeQL cannot see
   `png_create_read_struct` because libpng declares it via `PNG_EXPORTA`.
   Options: (a) ship the committed prototype as a generator-visible header
   (current workaround); (b) use the first plainly-declared harness API
   (`png_sig_cmp`) for harness generators that need source declarations;
   (c) drop such cells. This affects several targets whose public APIs are
   macro-generated (`XMLPUBFUN`, `LUA_API`, `DECLARE_ASN1_FUNCTIONS`).
2. **OFG candidate breadth.** Only 1 of 3 OFG candidates consumes the input;
   the selection rule currently picks the highest measured coverage. Is that
   the intended "generated harness" for OFG?
3. **ELFuzz on binary formats.** Keep upstream text-only applicability (mark
   N/A) or extend to binary targets? The agreed protocol says all five
   baselines on all nine MAGMA targets.
4. **5-minute budget scope.** The 24-hour 5×86400 s matrix is paused; the
   smoke campaign budget is 300 s (OFG's 60 s run above is shorter). Confirm
   that the final table will use 86,400 s trials once smokes pass.
5. **OFG generation matrix stopped.** Nine OFG generation runs were launched
   before the scope change and then stopped to honor "no fuzzing". Their
   partial `generation/work` artifacts are under
   `workspace/oss-fuzz-gen/magma_<target>/`; OFG's smoke evidence uses the
   completed libpng run from 2026-11-11.

## Update 2026-11-12 12:20

### CKGFuzzer

The knowledge-graph blocker is fixed. libpng declares the entry API through
`PNG_EXPORTA`; CKGFuzzer's extractor needs a source *definition* matching the
declared API name. Two generator-visible analysis-only files were added to the
libpng generator input:

* `hgb_declared_api.h` — committed prototype;
* `hgb_declared_api.c` — analysis-only definition (not in the project build
  files, never compiled or linked by the target).

With both, CodeQL reports the API and the knowledge graph completes. The
candidate build then exposed three target-recipe gaps, now fixed in every MAGMA
benchmark recipe:

1. the final harness link must use `$LIB_FUZZING_ENGINE` (MAGMA recipes link
   `$LIBS`, which is empty under the FuzzBench compile contract);
2. `set -u` recipes need defaults for `LDFLAGS`, `LIBS`,
   `REQUIRE_GET_BITCODE`, `REQUIRE_COPY_BITCODE`;
3. generated harnesses that do not include the project header need
   `-include png.h` so the `MAGMA_` symbol prefix is applied before linking.

Status: CKG smoke5
(`workspace/ckgfuzzer/magma_libpng/20261112T041835Z_ckg_smoke5`) is running
with `HGB_CAMPAIGN_SECONDS=300`.

### PromeFuzz

Three baseline-build fixes were required:

1. NLTK corpora are baked into the image (`docker/promefuzz/nltk_data`);
2. the neutral fuzz-entrypoint stub must use C++ linkage when the native
   harness suffix is `.cc` (`promefuzz_build_context.py`);
3. the target recipe engine/link defaults above.

The smoke now completes `build_context`, `api_preprocess` and `knowledge`, and
is in upstream ALL-COVER generation (64 drivers, 21/64 after 22 minutes).
The 5-minute campaign applies to the candidate evaluation after generation.

### ELFuzz / G2Fuzz (from the corpus-generator integration)

* ELFuzz: 4/9 applicable (libxml2, lua, php, sqlite3); libpng, libsndfile,
  libtiff, openssl, poppler return `not_applicable` by the upstream text-only
  contract. Real corpora: libxml2 201 files, lua 493, sqlite3 378.
* G2Fuzz: 9/9 wired; real corpora for libpng (79 PNGs) and libtiff (81 TIFFs);
  other targets runnable with the same driver.
* Driver: `scripts/hgb_magma_corpus_generate.py`; report:
  `docs/magma_corpus_generators.md`.

## CKGFuzzer: PASS (libpng, 300 s campaign)

Run: `workspace/ckgfuzzer/magma_libpng/20261112T044202Z_ckg_smoke7`
— `status=evaluated`, every stage `completed`, 267,005 executions in the
5-minute campaign, real coverage report.

Evidence copied to `workspace/magma/smoke/ckgfuzzer/`.

Final recipe fixes on top of the analysis-only API definition:

* the CKGFuzzer evaluator now builds a separate coverage-instrumented image
  for every non-`compat-smoke` profile (alpha reused the ASan image and the
  coverage stage reported "coverage report missing or empty");
* generated C++ candidates that declare C project APIs without `extern "C"`
  are linked through a force-included libpng symbol map
  (`png_magma_symbols.h`: 216 `png_* -> MAGMA_png_*` macros) instead of
  `-include png.h`, which conflicted with candidate-declared prototypes;
* the CKGFuzzer repair loop itself converged after one feedback round once the
  recipe-level `LDFLAGS/LIBS/REQUIRE_*` unbound-variable failures were removed.

## PromeFuzz: generation in progress (slow)

`workspace/promefuzz/magma_libpng/20261112T034400Z_prome_smoke5` completed
`build_context` (real compile DB), `api_preprocess` and `knowledge`, and is in
upstream ALL-COVER generation: 64 drivers, 77% after ~80 minutes. The upstream
pipeline sanitizes/validates each driver, so a full run is ~1.5–2 h per target
on this shared host even before the 5-minute campaign. The 5-minute campaign
only applies to the candidate evaluation after generation.

Decision needed: for the nine-target smoke matrix, keep the full 64-driver
ALL-COVER budget (faithful, ~1.5–2 h/target) or cap the driver/API budget
(e.g. `PROME_FUZZ_MAX_APIS`, all-cover mode) to make one target smoke in
~15–20 min.

## Current smoke matrix

| Baseline | Target | Status | Campaign budget | Evidence |
| --- | --- | --- | --- | --- |
| OSS-Fuzz-Gen | libpng | PASS (`evaluated`) | 60 s | `workspace/magma/smoke/oss-fuzz-gen/` |
| CKGFuzzer | libpng | PASS (`evaluated`) | 300 s, 267k execs | `workspace/magma/smoke/ckgfuzzer/` |
| PromeFuzz | libpng | drivers generated; native smoke PASS | 300 s | 22.95% (4,455 / 19,415) |
| ELFuzz | libpng | N/A (text-only contract) | — | `workspace/magma/corpus/elfuzz/libpng/manifest.json` |
| ELFuzz | libxml2/lua/sqlite3 | corpus ready, short validation | 15–30 s | `workspace/magma/corpus/elfuzz/*/corpus/` |
| G2Fuzz | libpng | corpus ready, short validation | 20 s | `workspace/magma/corpus/g2fuzz/libpng/corpus/` (79 PNGs) |
| G2Fuzz | libtiff | corpus ready, short validation | 20 s | `workspace/magma/corpus/g2fuzz/libtiff/corpus/` (81 TIFFs) |

## ELFuzz / G2Fuzz: 300 s native smoke

The corpus generators produced real corpora; each corpus was then fed to the
MAGMA-native ASan binary for a 300 s campaign and replayed with llvm_cov:

| Generator | Target | Corpus files | 300 s coverage | Crashes |
| --- | --- | ---: | ---: | ---: |
| G2Fuzz | libpng | 79 | 6,515 / 19,420 = **33.55%** | 0 |
| G2Fuzz | libtiff | 81 | 7,233 / 28,658 = **25.24%** | 0 |
| ELFuzz | libxml2 | 201 | 3,248 / 113,247 = **2.87%** | 0 |
| ELFuzz | lua | 493 | 6,037 / 11,692 = **51.63%** | 0 |

Artifacts: `workspace/magma/campaigns/corpus_smoke/<gen>_<target>/`,
`workspace/magma/coverage/corpus_smoke/<gen>_<target>/coverage.json`.

## Native 300 s smoke (selected harnesses)

| Baseline | Target | Campaign | Native llvm_cov (300 s) |
| --- | --- | --- | ---: |
| OSS-Fuzz-Gen | libpng | 300 s | 2,769 / 18,944 = **14.62%** |
| CKGFuzzer | libpng | 300 s | 135 / 18,941 = **0.71%** |
| G2Fuzz | libpng | 300 s | 6,515 / 19,420 = **33.55%** |
| G2Fuzz | libtiff | 300 s | 7,233 / 28,658 = **25.24%** |
| ELFuzz | libxml2 | 300 s | 3,248 / 113,247 = **2.87%** |
| ELFuzz | lua | 300 s | 6,037 / 11,692 = **51.63%** |

The native rebuild of a generated harness applies the libpng
`png_* -> MAGMA_png_*` function map before compiling; without it a harness that
declares its own prototypes (CKGFuzzer) links against the unprefixed symbol and
fails. This is a native-evaluation integration step, not a harness edit.

CKGFuzzer's libpng harness only exercises `png_create_read_struct` and does not
consume the input as a decoder; its 0.71% is a property of the generated
harness, not an evaluation failure. The same candidate reached 267k executions
in the 300 s FuzzBench evaluator campaign.

## PromeFuzz: artifact smoke PASS under the native evaluator

Generation completed and produced four LLVM-discovered drivers under
`workspace/promefuzz/magma_libpng/20261112T034400Z_prome_smoke5/generated_harnesses/`.
The PromeFuzz entrypoint's own candidate evaluation then hung in its
`sanitizer_smoke` stage: it runs each seed without libFuzzer's `-timeout`, and
the generated driver can block on a read callback (smoke timeout is 600 s per
seed, so this scales to hours across four candidates).

The same driver was evaluated with the MAGMA-native stack:

* native rebuild: OK (driver already calls `MAGMA_png_*` and includes `png.h`);
* 300 s campaign with `-timeout=25`: **4,455 / 19,415 = 22.95%**;
* real llvm_cov replay: OK; 0 crashes.

This is the PromeFuzz artifact used for the smoke row; the HGB evaluator's
per-seed smoke timeout needs a hard cap (and/or libFuzzer timeout flags) before
the full matrix, otherwise a valid-but-blocking driver costs ~10 min/seed.

## PromeFuzz: PASS via the shared evaluator

`workspace/magma/smoke/promefuzz/result.json` — `status=evaluated`, every
stage `completed`, 300 s campaign, real coverage, api-reachability passed.
The entrypoint's own evaluator had hung in sanitizer smoke; the shared
evaluator now:

* runs smoke and campaign inputs with `-timeout=25` and a 90 s outer smoke cap;
* strips the `MAGMA_` symbol prefix when matching the intended API against
  covered functions (coverage reports `MAGMA_png_create_read_struct`).

## Full-matrix smoke progress (300 s)

New cells measured on 2026-11-12 evening:

| Baseline | Target | Corpus/seed file count | 300 s coverage |
| --- | --- | ---: | ---: |
| G2Fuzz | libsndfile | 98 | 3,482 / 39,586 = **8.80%** |
| G2Fuzz | lua | 99 | 6,983 / 11,692 = **59.72%** |
| ELFuzz | php | 154 | 30,321 / 346,223 = **8.76%** |

Generation/quality note: the OSS-Fuzz-Gen libxml2 candidates call
`libxml_domnode_binary_insertion_find`, which is a *local* symbol
(`nm` type `t`) in `libxml2.a`; all three candidates fail to link. This is a
generator quality failure for that cell (OFG benchmark synthesis selected an
internal function), not an evaluator failure. It is recorded as failed rather
than replaced.

## Corrected 300 s corpus cells (seeded from the real generated corpus)

The first 300 s batch accidentally seeded corpus cells from the per-target
directory instead of its `corpus/` subdirectory; the corrected rerun is below
(batch `smoke9c`), and it supersedes those numbers.

| Generator | Target | 300 s coverage |
| --- | --- | ---: |
| ELFuzz | libxml2 | 5,201 / 113,247 = **4.59%** |
| ELFuzz | lua | 5,571 / 11,692 = **47.65%** |
| ELFuzz | php | 29,148 / 346,223 = **8.42%** |
| ELFuzz | sqlite3 | 6,329 / 86,912 = **7.28%** |
| G2Fuzz | libpng | 6,645 / 19,420 = **34.22%** |
| G2Fuzz | libsndfile | 3,466 / 39,586 = **8.76%** |
| G2Fuzz | libtiff | 7,233 / 28,658 = **25.24%** |
| G2Fuzz | libxml2 | 16,391 / 113,262 = **14.47%** |
| G2Fuzz | lua | 6,976 / 11,692 = **59.66%** |
| G2Fuzz | openssl | 4,763 / 173,176 = **2.75%** |
| G2Fuzz | php | 39,746 / 346,223 = **11.48%** |
| G2Fuzz | poppler | 21,855 / 92,376 = **23.66%** (partial: generator aborted on PyMuPDF install timeout; 17 real seeds) |
| G2Fuzz | sqlite3 | 30,377 / 87,496 = **34.72%** |

Harness-generator cells from the same 300 s batch:

| Generator | Target | 300 s coverage |
| --- | --- | ---: |
| OSS-Fuzz-Gen | libpng | 2,752 / 18,944 = **14.53%** |
| CKGFuzzer | libsndfile | 4,505 / 39,586 = **11.38%** |
| CKGFuzzer | libtiff | 2,534 / 25,845 = **9.80%** |
| CKGFuzzer | sqlite3 | 58,711 / 87,905 = **66.79%** |
| PromeFuzz | libpng | 3,838 / 19,415 = **19.77%** |

Failures recorded (not replaced): OFG libxml2 (all candidates call local
`libxml_domnode_binary_insertion_find`), CKG poppler (generated harness includes
non-existent `document.h`), Prome sqlite3 (generated include path
`sqlite3/work/sqlite3.h`).
