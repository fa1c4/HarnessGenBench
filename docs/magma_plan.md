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

## 2026-11-12 progress: benchmark/package factory and evaluator fixes

### Prefix normalization (unblocks generated-harness builds)

OSS-Fuzz-Gen emits harnesses in the OSS-Fuzz symbol namespace
(`OSS_FUZZ_png_create_read_struct`, plus `#define PNG_PREFIX OSS_FUZZ_`),
because the official libpng OSS-Fuzz recipe configures the library with
`--with-libpng-prefix=OSS_FUZZ_`. The MAGMA build configures
`--with-libpng-prefix=MAGMA_`, so the candidate failed at
`candidate_build` with an undeclared `OSS_FUZZ_png_create_read_struct`.

Every MAGMA benchmark `build.sh` now normalizes a *copy* of the harness just
before compiling: `OSS_FUZZ_<x>` -> `<x>` and any leftover `*_PREFIX` define is
dropped. The plain name is then macro-renamed to `MAGMA_*` by the project
headers. This is a symbol-namespace adaptation, not a harness edit: the
generated source stays byte-identical in the run directory.

### Target factory

`scripts/hgb_magma_targets.py` materializes, from the already-built native
images (no rebuild, no re-fetch):

* `workspace/magma/benchmarks/<target>/`: `source_input/<dest>` (the
  MAGMA-patched repo plus `src/`, `configrc`, `freetype2` where needed),
  `build.sh` (the target's MAGMA recipe with `$TARGET/repo` -> `$SRC/<dest>`),
  `Dockerfile` (base-builder + the target's apt dependencies), `seeds/`,
  `benchmark.yaml`.
* `workspace/magma/targets/magma_<target>/pkg/`: the HGB split package
  (`generator_input/` with source, seeds, manifests, `declared_api.json`;
  `evaluator_only/` with `benchmark_copy`, the exact native harness path, and
  the evaluator reference copy).

`metadata/oss_fuzz_gen_target_overrides.yaml` now has `magma_*` entries with
the committed entry API as `preferred_apis`; `ofg_introspector_adapter.py`
matches preferred names after stripping the `OSS_FUZZ_` report prefix.

### API injection for CKGFuzzer / PromeFuzz (api-oracle)

`generator_input/declared_api.json` carries the single committed entry API
(name + public signature). `extract_api_list.py` has a `declared` selection
mode (`--declared-apis` / `--declared-api-file`) that returns exactly this
list, and the CKGFuzzer/PromeFuzz entrypoints switch to it automatically when
`/target/declared_api.json` exists. This is the previously missing API hook.

### Infrastructure blocker: BuildKit wedged on the shared host

Concurrent `docker build` calls (sealed evaluator candidates, generator image
rebuilds) stalled indefinitely in the BuildKit worker (`docker buildx du`
also hung) while the host load average exceeded 400 from unrelated sessions.
Switching Docker to the legacy builder (`DOCKER_BUILDKIT=0`, now the default
in `scripts/lib/common.sh` and forwarded into generator containers) restores
progress. Recorded here because it can recur under shared-host pressure.

## 2026-11-12: generation and campaigns launched

* All nine benchmark dirs and split packages are materialized
  (`scripts/hgb_magma_targets.py`). Each package carries
  `generator_input/declared_api.json` with the committed entry API from
  `results/magma_harness_apis.md`.
* OSS-Fuzz-Gen synthesizes the benchmark YAML from the committed entry API:
  libsndfile selects `sf_open_virtual`, libxml2 `xmlReadMemory`, libtiff a
  public TIFF API. The override reader in `docker/oss-fuzz-gen/entrypoint.sh`
  now uses a `|`-delimited record (empty `candidate_destination` previously
  shifted the `read` fields and produced `language: '1800'`).
* The generator images were rebuilt with the declared-API support (OSS-Fuzz-Gen,
  CKGFuzzer). PromeFuzz's rebuild now bakes NLTK corpora into the image
  (`docker/promefuzz/nltk_data`) rather than downloading them at build time.
* `HGB_SKIP_IMAGE_PREFLIGHT=1` must be used for MAGMA generation runs: the
  historical image staleness markers do not include the MAGMA changes, and
  without it every run starts a full (~20 min) generator image rebuild.
  `scripts/lib/common.sh` also mounts the current
  `docker/oss-fuzz-gen/entrypoint.sh` into the generator container so the
  override-parsing fix applies without another rebuild.
* `scripts/hgb_magma_campaigns.py` drives variant rebuilds, the five-trial
  campaign queue, and the llvm_cov replay queue from `workspace/magma/selection.json`.
  Campaigns now pass `-timeout=25 -len_control=0`, matching OSS-Fuzz defaults;
  without a per-input timeout a generated harness that loops in its read
  callback can stall a whole 24 h trial on the seed corpus.
* Running: five 86,400 s OSS-Fuzz-Gen/libpng trials (`batch magma_v1`), OSS-Fuzz-Gen
  generation for libsndfile/libtiff/libxml2/lua, and CKGFuzzer generation for
  libpng. The remaining harness-generator cells and the corpus generators are
  next.

## 2026-11-12: smoke-only phase (24 h matrix paused)

Per the latest human instruction, the 24-hour campaigns and the nine-target
OSS-Fuzz-Gen generation batch were stopped. The current gate is one 5-minute
smoke per baseline (see `docs/magma_smoke.md` for the full evidence and the
divergence list).

Passing smoke evidence:

* OSS-Fuzz-Gen/libpng: evaluated, 300 s native campaign 14.62%.
* CKGFuzzer/libpng: evaluated (267k execs in its 300 s evaluator campaign),
  native 300 s campaign 0.71% (harness only creates/destroys a png_struct).
* PromeFuzz/libpng: generation produced four drivers; its own evaluator hung in
  sanitizer smoke on blocking inputs, so the drivers are being evaluated with
  the shared evaluator plus the native 300 s campaign (native campaign of
  driver 1: 22.95%).
* ELFuzz: libxml2 300 s 2.87%, lua 300 s 51.63%; five binary targets are N/A
  under the upstream text-only contract.
* G2Fuzz: libpng 300 s 33.55%, libtiff 300 s 25.24%.

Integration fixes: CKGFuzzer declared-API definition + coverage image + C++
linkage; benchmark recipes engine/LDFLAGS/REQUIRE defaults + libpng symbol map;
PromeFuzz NLTK data, C++ neutral stub, engine linkage; evaluator smoke now runs
with `-timeout=25` and a 90 s external cap.

Open decisions are listed at the end of `docs/magma_smoke.md` (ELFuzz binary
scope, PromeFuzz generation budget, whether the build-level API adaptations are
accepted, OFG remaining targets, and when to resume the 5x86,400 s matrix).

The smoke evidence is summarized in `results/magma_smoke_5min.md`
(generated by `scripts/hgb_magma_smoke_report.py`). All three harness
generators are `status=evaluated`; corpus generators have 300 s native
campaigns. No 86,400 s campaigns were launched in this phase.

## Prepared for the final matrix (not started)

* `scripts/hgb_magma_baselines_5times.py` renders the final
  `results/magma_baselines_5times.md` from
  `workspace/magma/coverage/<batch>/<baseline>_<target>/trial_*/coverage.lcov`
  and the matching campaign crash directories. It computes the common-source
  projection per target, mean ± sample stdev over trials, percentages against
  the common denominator, and a crash table. It was validated on a synthetic
  five-trial batch.
* `scripts/hgb_magma_campaigns.py prepare|run|coverage|status` drives variant
  builds, the resumable 5-trial campaign queue, and the llvm_cov replay queue
  from `workspace/magma/selection.json`.
* The smoke gate is complete and summarized in `results/magma_smoke_5min.md`.

Remaining work requires the pending human decisions: ELFuzz binary-target
scope, the PromeFuzz generation budget, acceptance of the committed API/build
adaptations, whether to run the remaining OFG target generations, and
authorization to start the 5x86,400 s campaigns.

## 2026-11-12 evening: full 300 s smoke matrix running

Per the human decision, ELFuzz's five binary targets are `N/A`; the full matrix
is 4 baselines x 9 targets plus ELFuzz on libxml2/lua/sqlite3/php, all with
300 s campaigns.

Launched: OFG 8 targets (4 concurrent), CKGFuzzer 8 (3), PromeFuzz 8 (2,
`PROME_FUZZ_MAX_APIS=8`), G2Fuzz 7 remaining corpora (3), ELFuzz php.
`declared_api.json` and analysis-only API shims were added to every package.

Early fixes: libtiff recipes skip network `autogen.sh` when `configure` exists;
the PromeFuzz image is being rebuilt with the target build dependencies
(libjpeg/lzma/png/tiff/openjp2/lcms2/freetype/boost/icu/readline/bison/re2c) so
libtiff/libxml2/poppler/php baselines and link probes can build. Failed Prome
cells will be relaunched after the image rebuild. OFG php remains unpinned
because its MAGMA HEAD is not fetchable from the shallow upstream clone.

## Decision A1: CKGFuzzer skips macro-declared entry APIs

Accepted: CKGFuzzer is not evaluated on targets whose committed entry API is
only declared through an export macro, because its extractor needs a real
source definition.  Marked `ckgfuzzer_skip_macro_api: true` for libpng,
libxml2, lua, openssl and php; the analysis-only shims were removed for those
packages.  CKGFuzzer cells remain only where the API is a plain declaration:
libsndfile, libtiff, poppler, sqlite3.

## Decisions A2/A3 (2026-11-12)

* A2: keep the current OSS-Fuzz-Gen symbol namespace normalization
  (`OSS_FUZZ_<project>_*` -> plain API, drop the `*_PREFIX` define).
* A3: keep the force-included libpng symbol map
  (`png_magma_symbols.h`, 216 `png_* -> MAGMA_png_*` macros) for benchmark
  builds, and the equivalent name mapping in the native harness rebuild.

Consolidated smoke report: `results/magma_smoke_5min.md`
(`scripts/hgb_magma_smoke_report.py`) merges `smoke9` (harness cells),
`smoke9c` (corrected corpus seeding) and the earlier flat `corpus_smoke` batch.
It marks N/A from the applicability flags and lists Failed cells separately.
Remaining pending cells: OSS-Fuzz-Gen lua/openssl/php/poppler/sqlite3 and most
PromeFuzz targets, which are still generating.

Additional native build shims found while filling the matrix: libtiff generated
harnesses need `fuzzer/FuzzedDataProvider.h`; lua generated harnesses include
`<lauxlib.h>`/`<lua/lauxlib.h>` although the MAGMA repo keeps headers at the
root (and a `lua` executable file blocks a `lua/` directory). The rebuild
wrapper now installs the fuzzer header under `/usr/local/include` and creates a
`/tmp/luainc` include tree for lua. PromeFuzz lua then measured 46.07%
(5,368 / 11,651) in the 300 s smoke.

PromeFuzz php/poppler baseline builds fail before generation: the generated
`configrc` does `PROGRAM_LIBS[$__p]=...` without `declare -A`, so bash with
`set -u` evaluates the key (`json`, `pdf_fuzzer`) arithmetically and aborts with
"unbound variable". This is a PromeFuzz-side configrc bug; openssl fails earlier
in `build_context` (`valid=false`). These three cells remain unfilled unless the
configrc generator is patched or the files are fixed at staging time.

PromeFuzz configrc/toolchain fixes (2026-11-12): the packaged `configrc` for
php/poppler now declares `PROGRAM_LIBS` associative array; the native build
wrapper exports `AR/AS/RANLIB/LD/NM/STRIP/OBJCOPY` defaults. php then reached
its native build; poppler progressed to the recipe's `poppler_BUILD_PROGRAMS`
variable, which remains unfilled. openssl compile-DB capture is retried with
`bear_replay` instead of the unsupported generic cmake path.

OSS-Fuzz-Gen sqlite3 now measured: 67.63% (59,453 / 87,905) in the 300 s
smoke, using candidate 1_01 and the normalized native build.

OSS-Fuzz-Gen lua measured 11.11% (1,287 / 11,587) in the 300 s smoke. Its three
candidates do not call the committed `luaL_loadbufferx` entry API; they exercise
other Lua APIs (`luaL_newstate`, `lua_pcall`, ...). This is recorded as a
generator/API-selection divergence, not a silent replacement.

PromeFuzz poppler's baseline build now reaches CMake but the project build
fails (`make[1] ... poppler.dir/rule Error 2`); php's baseline build reaches the
native parser build. php/poppler recipe invocations no longer abort on
`*_BUILD_PROGRAMS` because the generated build scripts dropped `set -u`.

Smoke matrix status at the 2026-11-12 22:35 cutoff: 4 of 5 baselines are
complete on their applicable cells (ELFuzz 4/4, G2Fuzz 9/9 with poppler partial,
CKGFuzzer 3 measured + 5 N/A, OSS-Fuzz-Gen 4 measured + 1 failed + 3 pending).
PromeFuzz has 3 measured (libpng/lua/sqlite3) and 6 failed or pending. The
remaining three generation runs (OFG openssl, OFG poppler, Prome libtiff) are
still in their project/introspector builds and produced no harness at cutoff.
The consolidated table is `results/magma_smoke_5min.md`; Failed cells and
reasons are in the notes of this document.

Blocking condition (2026-11-12 22:47): the 300 s smoke matrix is delivered in
`results/magma_smoke_5min.md`, but the 5x86,400 s objective needs a human
decision. OSS-Fuzz-Gen openssl/poppler and PromeFuzz libtiff have been inside
their generator builds for >2 h with no harness; the user must decide whether to
keep fixing/waiting or accept those cells as Failed, whether to invest in the
remaining PromeFuzz per-target fixes, and whether to authorize the 225 24-hour
campaigns. No 86,400 s campaign has been started.

Smoke counts (final): 45 nominal (baseline,target) cells = 25 measured valid,
10 Failed, 10 N/A. Applicable cells = 35. OFG openssl was measured after the
cutoff at 1.58%. Failed cells: OFG libxml2/php/poppler, CKG poppler, PromeFuzz
libsndfile/libtiff/libxml2/openssl/php/poppler.

CKG poppler now builds and runs: the package ships a `document.h` compatibility
header (`#include <poppler-document.h>; using poppler::document;`) and
`declared_api.json` carries `headers`. The 300 s smoke measured 0.00%
(0 / 79,448) because every input fails/returns before covering target lines;
it is recorded as a real 0% cell, not Failed.

Fix round status: CKG poppler now evaluates at 0.00% (0/79,448) with the
document.h shim and declared headers, so the applicable set now has 26 measured
cells and 9 Failed. OFG php pin was hard-coded in the project patch step,
independent of OFG_INTROSPECTOR_UNPINNED; that branch now skips when php is
unpinned. Prome php moved from the ICU/intl error to an engine-link error
(`undefined reference to main`); Prome libxml2 still has no harness at 16 APIs;
libsndfile/libtiff reruns are in flight.

The OFG local-symbol filter initially did not apply because `/target` is the
target package's `generator_input/` directory (not its parent); the adapter now
checks `/target/local_symbols.txt` as well. libxml2 was regenerated with the
correct path. OFG php's pin is applied by a separate hard-coded project patch;
that patch now skips when php is in OFG_INTROSPECTOR_UNPINNED.

PromeFuzz php engine fix: the recipe's `LIB_FUZZING_ENGINE="-Wall"` configure
override made config.m4 set FUZZING_LIB=-Wall, so fuzzer targets linked without
libFuzzer (`undefined reference to main`). The fuzzer make targets now pass
`FUZZING_LIB="${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}"`; the baseline build
proceeds past that error. PromeFuzz libsndfile/libxml2 reached
`generation: failed` at 16 APIs, so the budget increase alone did not produce a
harness.

Ongoing after the 10-strategy fixes: OFG libxml2 pubfilter2 (correct
/target path) and OFG php unpin2 are still generating; PromeFuzz libtiff
(7200 s eval build timeout), php (engine fix), libsndfile/libxml2 (32 APIs)
are in generation. The earlier OFG libxml2 pubfilter run still contained the
local symbol because it started before the mount-path fix; only pubfilter2 is
authoritative. PromeFuzz libsndfile/libxml2 at 16 APIs ended in
`generation: failed`.

OFG libxml2 public-symbol filter now works: after fixing the /target mount
path, the regenerated candidates contain zero calls to
libxml_domnode_binary_insertion_find; candidate 1_01 builds and measures
1.21% (1,371 / 113,247) in the 300 s smoke. OFG libxml2 moves from Failed to
measured; counts are now 27 measured / 8 Failed / 10 N/A.

PromeFuzz budget experiment: libsndfile and libxml2 ended in
`generation: failed` at 8, 16 and 32 APIs. Raising the API budget alone does
not produce a sanitized harness for these entry APIs. PromeFuzz libtiff's
7200 s eval-build rerun then hung for >1 h at "Retrieving function usage"
(comprehend stage); the run was killed and the cell remains Failed. OFG php and
OFG poppler unpinned reruns are still active.

Smoke status at 2026-11-13 09:25: 27 measured / 8 Failed / 10 N/A. OFG php
(unpinned) and OFG poppler (unpinned) remain in benchmark/introspector prep
without generated harnesses; PromeFuzz php is still generating. PromeFuzz
libsndfile/libxml2 exhausted the 8/16/32 API-budget attempts with
`generation: failed`. No 86,400 s campaign has been started.

Deeper PromeFuzz adaptation (per human decision to keep investing):
`PROME_FUZZ_SEED_HARNESS` is now forwarded into the PromeFuzz container; the
mounted `artifacts/promefuzz/src/llm/prompter.py` appends the seed harness code
to the C/C++ generation prompt. Seed files come from the package reference
harnesses (`libsndfile ossfuzz/sndfile_fuzzer.cc`,
`libxml2 src/libxml2_xml_read_memory_fuzzer.cc`) and are mounted as
`/target/seed_harness.cc`. libsndfile/libxml2 are being regenerated with
`PROME_FUZZ_MAX_APIS=1` plus the seed, i.e. entry-only + seed-driver, and this
deviation must be recorded in the final results.

PromeFuzz openssl deeper fixes: all configrc files now declare the
PROGRAM_LIBS associative array (the bear build_context had been dying on
`asn1: unbound variable`), and the openssl recipe now links fuzz targets with
`LDCMD="$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $LDFLAGS"` (previously the engine was
missing, so every fuzz target failed with `undefined reference to main`).
openssl is being retried with these fixes. OFG php's unpinned retry still ends
in introspector failure.

Seed-driver diagnosis: the generated drivers were failing at sanitize time with
`undefined reference to LLVMFuzzerTestOneInput` (libFuzzer's C main expecting a
C symbol), not because the seed API was unusable. The seed prompt now states
that the entry point must be exactly
`extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`.
libsndfile/libxml2 were restarted with this seed+extern-C prompt.

Seed3 (entry-only + seed + extern "C" instruction) is still sanitizing drivers;
by 10:20 it had reached driver 5/5 with no successful build yet, so the seed
prompt has not produced a sanitized harness so far. libxml2 seed3 and openssl
are in the same slow loop; OFG poppler remains in prep.

Seed sanitizer stall root cause for libsndfile: every driver build ran the
package's `./autogen.sh` even though `configure` already exists, and the
sanitizer logs stop inside that autotools step. libsndfile's recipe now runs
autogen only when configure is absent; seed4 restarted with entry-only + seed.

Skipping libsndfile autogen alone was not enough: the shipped configure and the
installed libtool 2.4.7 disagreed (aclocal.m4 generated by 2.4.6), so make
failed with libtool error 63. The recipe now runs `autoreconf -fiv` when
configure exists, then `./configure`, and seed5 restarted.

PromeFuzz libsndfile now has a sanitized seed5 harness and evaluates:
0.00% (0 / 39,586). The harness includes the project-relative
`libsndfile/include/sndfile.h`; the native rebuild adds a `repo/libsndfile -> .`
symlink so that spelling resolves. Like CKG poppler, it builds/runs but every
input fails before covering target lines, so it is recorded as a real 0% cell.
Counts: 28 measured / 7 Failed / 10 N/A.

PromeFuzz php produced four harnesses (php_dl-based); the native MAGMA build is
in progress (php build is the slowest target). PromeFuzz openssl produced one
harness but its own evaluation ended in quality_failure. libxml2 seed6
(autoreconf + entry-only + seed) is generating driver 4.

libxml2 seed6 still deprecated xmlReadMemory, but the sanitizer log exposed the
real build error: the staged `FuzzedDataProvider.h` lacked `#include <limits>`
(`std::numeric_limits` / `std::max` errors). Both benchmark and package copies
now include <limits>; seed7 restarted with the same entry-only+seed setup.
Native PHP rebuild now disables intl inside the image via the eval rebuild
wrapper (`--enable-intl` -> `--disable-intl`), because the image's target
build.sh is not the package copy.

PHP native rebuild with intl disabled is still in configure (very slow on the
shared host); libxml2 seed7 is sanitizing driver 4 with the <limits> fix.
No new measured cell this round.

PHP native rebuild is blocked by an autoconf hang, not by the harness: the
container's `./configure` spawns `./conftest` which spins at 99% CPU for many
minutes (observed 8m55s) inside the DES/MD5 crypt check; killing and retrying
reproduces the same loop. The generated php harness therefore cannot be built
through the native rebuild path in this image. PromeFuzz php remains Failed.

PromeFuzz php and openssl are now measured via the native MAGMA build:
php 0.00% (0 / 346,194) after reusing the image's preconfigured PHP tree and
rebuilding only the fuzzer target; openssl 14.26% (24,692 / 173,192) after
normalizing the generated `openssl/include/openssl/...` include path. Counts:
30 measured / 5 Failed / 10 N/A.

Repair loop in tmux session `hgeval`: PromeFuzz php is measured at 0.00% by
reusing the image's preconfigured PHP tree (only the fuzzer target is
rebuilt); PromeFuzz openssl is measured at 14.26% after normalizing the
generated `openssl/include/openssl/...` include. PromeFuzz libtiff runs with
`PROME_FUZZ_SKIP_COMPREHEND=1` and reached 7/8 driver generation. PromeFuzz
poppler's baseline build now uses absolute `/usr/bin/ar`/`ranlib` and
`PROGRAMS=(pdf_fuzzer)`, reaches the native build, but generation ended in
quality_failure. OFG php now copies the local MAGMA php-src into the OSS-Fuzz
project Dockerfile (COPY php-src) and the introspector is analyzing it; OFG
poppler's local source lacks `test/ossfuzz/prepare_build.sh`, so that path
fails at Docker build.

OFG php's first local-source attempt failed because the copied php-src carried
the image's generated Makefile with absolute `/magma/targets/php/repo/...`
dependencies. The local-copy branch now deletes all generated Makefile/*.o/*.lo/
*.la files and config.status before the Docker build; local2 restarted.

The OFG php local-source patch now applies at the final point before
helper.py build_fuzzers (earlier patching was overwritten by the checkout
staging), so the project Dockerfile really contains `COPY php-src php-src` and
the introspector is building from the MAGMA source. PromeFuzz libtiff is still
generating/sanitizing drivers (driver 11) without a successful harness.

PromeFuzz libtiff now evaluates: 10.26% (2,624 / 25,580). The harness includes
`libtiff/tiffio.h`; the native rebuild normalizes it to `tiffio.h` so the
recipe's `-I$WORK/include` resolves it. This used the skip-comprehend path.
Counts: 31 measured / 4 Failed / 10 N/A.

OFG php's local-source introspector still fails: the copied MAGMA php tree's
generated build files retain absolute `/magma/targets/php/repo/ext/...` paths,
so `make` stops with "No rule to make target .../php_date.c" even after deleting
top-level Makefiles. The final-localization path is therefore not yet producing
a report. The repair loop continues with the remaining PromeFuzz/OFG cells.

PromeFuzz poppler's ftconfig failure persists even with the project-root
symlink because PromeFuzz's CGprocessor opens `ftconfig.h` from the staged
source root. Both `stage_fuzzbench_source` and the native-build wrapper now
create `<root>/ftconfig.h -> poppler/freetype2/builds/unix/ftconfig.h`;
poppler restarted with this fix (ft2).

OFG php upstream-clone attempt now builds the introspector but fails because
the OSS-Fuzz build.sh expects `sapi/fuzzer/php-fuzz-function-jit`, which the
upstream php snapshot does not produce (`cp: cannot stat ...`). The local MAGMA
tree fails earlier on absolute build paths. php remains Failed.

Final repair-loop status: PromeFuzz php/openssl/libtiff were fixed (0.00%,
14.26%, 10.26%), PromeFuzz libsndfile is 0.00%. Remaining four remain blocked:
PromeFuzz poppler's generation still deprecates load_from_raw_data without a
sanitized harness; PromeFuzz libxml2's seed driver builds/runs but PromeFuzz
rejects it; OFG php's OSS-Fuzz build.sh still copies the missing
php-fuzz-function-jit target even after deleting the literal line (the name is
constructed from configrc PROGRAMS); OFG poppler's local tree lacks
test/ossfuzz/prepare_build.sh.

OFG php final build.sh patch: at the helper.py call point both project
build.sh/replay_build.sh are scrubbed of `php-fuzz-function-jit` (verified 0
occurrences in the staged project). The introspector Docker build is currently
reinstalling fuzz-introspector dependencies (numpy/matplotlib), which takes
~15 min per attempt.

Final decision point after the repair loop: OFG php kept rebuilding the
fuzz-introspector image and reinstalling pip dependencies (numpy/matplotlib) on
each attempt; the function-jit build error was fixed but the report was never
produced. Stopped it and kept the cell Failed. Remaining Failed cells:
OFG php, OFG poppler, PromeFuzz libxml2, PromeFuzz poppler. Smoke matrix is
31 measured / 4 Failed / 10 N/A.

2026-11-13 24-hour matrix launched in tmux `hgeval`:
`scripts/hgb_magma_24h.py --manifest workspace/magma/selection_24h.json
--batch magma24h --seconds 86400 --trials 5 --workers 150`.

Scope: 31 validated cells (OFG 7, CKGFuzzer 4, PromeFuzz 7, ELFuzz 4, G2Fuzz 9),
31 x 5 = 155 independent 86,400 s campaigns, 150 concurrent (second wave 5).
OFG php/poppler remain pending; PromeFuzz libxml2/poppler are skipped per the
human decision; the 10 N/A cells are not run. Each trial writes
`campaigns/magma24h/<baseline>_<target>/trial_N`; the launcher runs llvm_cov
replay after all campaigns complete.

OFG poppler failed in its introspector build: the upstream prepare_build.sh
builds NSS and boost, but NSS fails (`No best alternative for
boost_1_92_0/libs/histogram/install-libraries-shared` and a linker error in
nspr export). The poppler project image with fuzz-introspector deps was built
successfully, but the project build itself remains broken. OFG php also
remains Failed, so the 24h matrix stays at 31 validated cells (155 campaigns).

The 24 h matrix is launched (2026-11-13 19:52, tmux hgeval, 150 workers,
155 trials). Because the matrix needs ~48 h, the coverage replay and final
table are deferred: run `scripts/hgb_magma_24h_finish.sh` when every
`campaign.done` exists (or on the next session resume). It runs the 150-worker
llvm_cov replay and then `hgb_magma_baselines_5times.py --batch magma24h
--min-trials 5` to produce results/magma_baselines_5times.md.

Final state at goal round 60: tmux session hgeval is running 150 of the 155
86,400 s campaigns (31 validated cells x 5); started 2026-11-13 19:52 and the
last trial is expected around 2026-11-15 19:52. No campaign has finished yet
(done=0), host memory 82/436 GB, no fatal ASan/libFuzzer errors. The deferred
finish path is scripts/hgb_magma_24h_finish.sh (150-worker llvm_cov replay,
then hgb_magma_baselines_5times.py --batch magma24h --min-trials 5).
