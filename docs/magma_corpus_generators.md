# MAGMA corpus generators: ELFuzz and G2Fuzz

This document covers the corpus-generator leg of the MAGMA phase.  It is the
companion of `docs/magma_plan.md`; the harness generators and the long MAGMA
campaigns are handled separately.  Nothing here launches an evaluation
campaign — the optional `--validate-seconds` smoke only proves that the
produced seeds are consumable by the MAGMA native binary.

## Matrix at a glance

| Target | ELFuzz | G2Fuzz |
| :--- | :--- | :--- |
| libpng | **N/A** (`elfuzz_non_text_target`) | applicable — paper-faithful (PNG) |
| libsndfile | **N/A** (`elfuzz_non_text_target`) | applicable — paper-faithful (WAV/AIFF/AU/MP3/CAF) |
| libtiff | **N/A** (`elfuzz_non_text_target`) | applicable — paper-faithful (TIFF) |
| libxml2 | applicable — upstream `libxml2` preset (XML) | applicable — extension (XML) |
| lua | applicable — generated preset (Lua source) | applicable — extension (Lua source) |
| openssl | **N/A** (`elfuzz_non_text_target`) | applicable — paper-faithful (`binary_large_object_BLOB`) |
| php | applicable — generated preset (PHP source) | applicable — extension (PHP source) |
| poppler | **N/A** (`elfuzz_non_text_target`) | applicable — paper-faithful (PDF) |
| sqlite3 | applicable — upstream `sqlite3` preset (SQL) | applicable — extension (SQL) |

ELFuzz supports **4 / 9** targets.  The other five are binary container
formats, which ELFuzz contractually rejects before any Docker, model, or TGI
work; they are recorded as `not_applicable`, not silently skipped.  G2Fuzz is
format-directed and is wired for **9 / 9** targets; five use the upstream
program map (`paper-faithful`) and four are clean extensions (`XML`, Lua, PHP,
SQL) whose format-directed generator method applies unchanged.

> Smoke status in this session: G2Fuzz libpng and libtiff (full corpora +
> native consumption checks), ELFuzz libxml2 / lua / sqlite3, and the ELFuzz
> libpng N/A cell.  The remaining cells are runnable with the same command but
> were not all completed in this short smoke window; their status is reported
> honestly by the driver manifests.

## Design

### Parallel adapter manifests (no FuzzBench regression)

The committed FuzzBench adapter files are untouched:

* `metadata/elfuzz_target_adapters.yaml` still describes exactly the 20
  valuable targets, and `validate_adapter_coverage` still sees exactly that
  set.
* `metadata/g2fuzz_target_adapters.yaml` is unchanged.

MAGMA adapters live in two parallel files:

* `metadata/elfuzz_target_adapters_magma.yaml` — 9 MAGMA targets, with the 4
  text targets applicable and the 5 binary targets `Invalid`/
  `elfuzz_non_text_target`.
* `metadata/g2fuzz_target_adapters_magma.yaml` — 9 MAGMA targets, formats,
  method profile (`paper-faithful` vs `extension`), program id, and input
  contract.

Per-target ELFuzz adapter assets live under `repro/elfuzz/magma/<target>/`
(`format.md`, `seed_fuzzer.py`, `adapter.yaml`); G2Fuzz format notes live under
`repro/g2fuzz/magma_specs/`.

Neither corpus-generation path needs the FuzzBench-style MAGMA benchmark
directory (`workspace/magma/benchmarks/<target>`).  For ELFuzz the driver
materialises a minimal package under
`workspace/magma/corpus/_packages/magma_<target>/` with `target_manifest.json`
and placeholder `fuzzbench_benchmark/{benchmark.yaml,build.sh}` files, which is
exactly what the corpus-only entrypoint contract checks; the real benchmark
directory, Dockerfile, and `build.sh` belong to the evaluator and are only
used when a native SUT is built.  G2Fuzz needs no benchmark directory at all
because `program_gen.py` is format-directed.

`docker/common/elfuzz_target_pipeline.py` gained `load_magma_adapters()` and
`load_target_adapters()`; the original `load_adapters()` keeps its exact
FuzzBench-only semantics, so existing adapter-coverage tests and matrix code
are unaffected.  `validate_magma_adapters` (CLI subcommand
`validate-magma-adapters`) checks that every applicable MAGMA adapter ships its
files.  `classify_target` uses the merged view so the MAGMA target names are
recognised.

### ELFuzz corpus-only mode

`elfuzz_target_pipeline.py --corpus-only` runs:

```
target_classification -> model_ready -> synthesis -> evolution -> production
```

It deliberately skips `target_build`, `generated_input_validation`, `campaign`,
and `coverage`: those are evaluator stages, need a native SUT or FuzzBench
image, and are not required to emit a corpus.  The result status is
`corpus_ready`.

Because MAGMA benchmark names are not in ELFuzz's
`evaluation/binary/<benchmark>/meta.json` registry, upstream `elfuzz produce`
cannot materialise seeds for them (this is the same failure seen in the
part-1 runs for `php`).  In corpus-only mode the pipeline therefore:

1. retains a bounded sample of the inputs that ELFuzz's synthesized variant
   programs write during synthesis (`gen*/outputs/...`) and collects them; or,
2. if that retained set is empty, executes the evolved generator programs
   directly with a per-call time budget
   (`ELFUZZ_FALLBACK_MAX_PROGRAMS=64`,
   `ELFUZZ_FALLBACK_CALL_TIMEOUT_SECONDS=2`).

Both paths consume only ELFuzz-generated artifacts, never the MAGMA seed
corpus.  The smoke runs below used the bounded direct-execution path
(`production.mode=corpus_only_fallback` in their manifests); the retention
path is the preferred production path for unattended runs.

The container entrypoint (`docker/elfuzz/entrypoint.sh`) gained an
env-gated corpus mode used only when `ELFUZZ_CORPUS_ONLY=1`:

* `ELFUZZ_SKIP_FUZZBENCH_PREPARE=1` — do not build a FuzzBench image.
* `ELFUZZ_SKIP_COVERAGE=1` — do not run the generator-coverage collector (a
  `{}` coverage file is written so the selection loop continues).
* `ELFUZZ_KEEP_GENERATED_OUTPUTS=1` — retain a bounded sample of the inputs
  each variant program produces before `do_gen.sh` deletes its output tree.
* `ELFUZZ_NUM_VARIANTS`, `ELFUZZ_NUM_OUTPUTS_PER_VARIANT`,
  `ELFUZZ_VARIANT_JOBS`, `ELFUZZ_CORPUS_MAX_OUTPUTS` — scale the generation
  budget for a short smoke.
* `batchrun.py` tolerates unknown benchmark names (`.get(benchmark, [])`) so
  extension benchmarks do not crash the produce path.

These variables are also forwarded by `scripts/lib/common.sh` for callers that
use the standard `hgb_generate_harness.sh` path.

### G2Fuzz MAGMA program map

G2Fuzz's `program_gen.py` is driven entirely by `program_to_format.json` and an
output directory; it needs no target binary or FuzzBench benchmark.  The host
driver builds a MAGMA-specific map from the parallel adapter manifest and
bind-mounts it over
`/opt/hgb/artifacts/g2fuzz/program_to_format.json`; the image's
`generate-seeds` entrypoint then runs upstream `program_gen.py` with
`G2FUZZ_PROGRAM=magma_<target>`.

`G2FUZZ_MAX_PRESEEDED_CORPUS_FILES=0` is set so the MAGMA seed corpus is not
injected into the generated set: the reported corpus contains only G2-generated
inputs.  `--g2fuzz-all-formats` uses every format in the adapter; the default
uses the first/primary format (e.g. PNG for libpng, WAV for libsndfile) to keep
a smoke short.  `G2FUZZ_TRY_NUM` defaults to 1 and is overridable.

### Driver

`scripts/hgb_magma_corpus_generate.py` orchestrates everything:

* selects MAGMA targets from `metadata/magma_targets.yaml`;
* materialises a minimal target package under
  `workspace/magma/corpus/_packages/magma_<target>` (manifest + placeholder
  benchmark files) so the ELFuzz entrypoint's package gate is satisfied without
  touching the real MAGMA packages;
* runs the pinned `hgb-elfuzz:latest` / `hgb-g2fuzz:latest` images with the
  repository's current pipeline/entrypoint/metadata mounted over the image
  (the local ELFuzz image predates the corpus-only code and lacks
  `hgb_campaign_storage.py`; mounting avoids a slow image rebuild);
* deduplicates seed payloads by SHA-256 into a canonical `corpus/` directory;
* writes `manifest.json`, `corpus_manifest.jsonl`, `host.log`, and a
  generator-wide `summary.json`;
* optionally runs a short MAGMA-native libFuzzer campaign over the corpus and
  records how many seeds the target accepted.

Output layout:

```
workspace/magma/corpus/<generator>/<target>/
  <run-id>/               raw generator run (logs, result.json/metadata.json)
  current -> <run-id>
  corpus/                 canonical, deduplicated seed files
  corpus_manifest.jsonl   per-file sha256/size/source mapping
  manifest.json           status, counts, model, adapter, validation
  validation/<run-id>/    optional native consumption smoke
workspace/magma/corpus/<generator>/summary.json
workspace/magma/corpus/summary.json        (when --generator all)
```

## Exact commands

```bash
cd /data/zym/HarnessGenBench
export HGB_API_KEY_CONFIG=$HOME/api_keys/HarnessGenBench/set_api_key_magma.sh
export DOCKER_BUILDKIT=0

# One cell (the main-agent invocation):
python3 scripts/hgb_magma_corpus_generate.py \
  --generator g2fuzz --targets libpng --validate-seconds 20

python3 scripts/hgb_magma_corpus_generate.py \
  --generator elfuzz --targets libxml2 --validate-seconds 15

# Other applicable ELFuzz cells:
python3 scripts/hgb_magma_corpus_generate.py \
  --generator elfuzz --targets lua php sqlite3 --parallel 2

# All nine cells for both generators (no 24 h campaigns):
python3 scripts/hgb_magma_corpus_generate.py \
  --generator all --targets all --parallel 2

# Rerun an already-successful cell:
python3 scripts/hgb_magma_corpus_generate.py \
  --generator g2fuzz --targets libpng --force
```

`--validate-seconds 0` (the default) skips the native consumption smoke.
Useful knobs: `--elfuzz-iterations`, `--elfuzz-variants`,
`--elfuzz-outputs`, `--elfuzz-max-outputs`, `--g2fuzz-try-num`,
`--g2fuzz-all-formats`, `--max-corpus-files`.

A single per-(baseline,target) command is therefore:

```bash
python3 scripts/hgb_magma_corpus_generate.py \
  --generator <elfuzz|g2fuzz> --targets <libpng|...|sqlite3> [--force] [--validate-seconds N]
```

## Smoke evidence

Environment: Docker 28 legacy builder (`DOCKER_BUILDKIT=0`), provider
`deepseek-flash` via the `HGB_API_KEY_CONFIG` key, `hgb-elfuzz:latest`,
`hgb-g2fuzz:latest`, and the MAGMA native
`hgb-magma-<target>-libfuzzer_asan:latest` images.

### G2Fuzz / libpng (success)

* raw run: `workspace/magma/corpus/g2fuzz/libpng/20261112T022257Z`
* corpus: `workspace/magma/corpus/g2fuzz/libpng/corpus`
* 80 generated source files, **79 unique PNG seeds** (3,401,396 bytes),
  28 generator programs, model `deepseek-flash`, format `PNG`
* native smoke: 20 s libFuzzer campaign on `libpng_read_fuzzer`;
  libFuzzer reported **54 seed inputs** accepted, 0 crashes; final corpus 79
  files (`workspace/magma/corpus/g2fuzz/libpng/validation/20261112T022257Z/`)
* manifest: `workspace/magma/corpus/g2fuzz/libpng/manifest.json`
  (`status=corpus_ready`)

### ELFuzz / libpng (N/A, exact failing stage)

* manifest: `workspace/magma/corpus/elfuzz/libpng/manifest.json`
* `status=not_applicable`, `applicability=Invalid`,
  `reason_code=elfuzz_non_text_target`,
  `failure_stage=target_classification`,
  reason: `Invalid: ELFuzz supports text-input targets only`
* The committed adapter classifies PNG as a non-text container; no generator
  container, model request, or corpus is started.  This is a contractual N/A,
  not a failed attempt at faking a corpus.

### ELFuzz / libxml2 (success)

* raw run: `workspace/magma/corpus/elfuzz/libxml2/20261112T022719Z-libxml2`
* corpus: `workspace/magma/corpus/elfuzz/libxml2/corpus`
* 860 raw generated inputs from executing the evolved variant programs
  directly (`production.mode=corpus_only_fallback`), **201 unique seeds**
  (21,381 bytes), 81 fuzzer programs, model `deepseek-flash`
* native consumption check: 15 s libFuzzer campaign on
  `libxml2_xml_read_memory_fuzzer` reported **21 seed inputs** accepted and 0
  crashes; an independent `-runs=0` replay admitted **20** of 201 seeds
  (`workspace/magma/corpus/elfuzz/libxml2/validation/20261112T022719Z-libxml2/`)
* manifest: `workspace/magma/corpus/elfuzz/libxml2/manifest.json`
  (`status=corpus_ready`)

The generated libxml2 inputs are ELFuzz-mutated documents: every file retains
the XML declaration but many are deliberately malformed after it.  That is the
expected ELFuzz behaviour (mutated generator programs) and is why only 21 of
201 were admitted as distinct valid seeds by libFuzzer.

### Additional smoke runs

All runs below used the same driver; see the per-target `manifest.json` under
`workspace/magma/corpus/{elfuzz,g2fuzz}/<target>/`.

| Generator | Target | Corpus dir | Unique files | Native consumption check |
| :--- | :--- | :--- | ---: | :--- |
| ELFuzz | lua | `workspace/magma/corpus/elfuzz/lua/corpus` | 493 (from 577 raw) | 175 admitted by 10 s libFuzzer campaign (172 by `-runs=0` replay); 0 crashes; 379/493 parse as valid Lua chunks (`lua -e 'assert(loadfile(...))'`) |
| ELFuzz | sqlite3 | `workspace/magma/corpus/elfuzz/sqlite3/corpus` | 378 (all unique) | 107 admitted by 10 s libFuzzer campaign and by `-runs=0` replay; 0 crashes |
| G2Fuzz | libtiff | `workspace/magma/corpus/g2fuzz/libtiff/corpus` | 81 unique TIFFs (18,569,673 bytes), 25 generators | `-runs=0` replay admitted 63 / 81; 0 crashes (fork-mode fuzz startup exceeded the 30 s smoke window) |

The ELFuzz and G2Fuzz manifests record the exact `accepted_corpus_hint` and
the log paths.

## Remaining blockers and risks

1. **ELFuzz on binary MAGMA targets is N/A by contract.**  libpng, libsndfile,
   libtiff, openssl, and poppler are binary container formats and cannot be
   handled by ELFuzz's text-input generator synthesis.  This is the same
   `elfuzz_non_text_target` policy used for the FuzzBench set; no corpus is
   produced or faked for these cells.
2. **ELFuzz upstream `elfuzz produce` does not work for MAGMA benchmark names.**
   ELFuzz resolves `evaluation/workdir` presets and prebuilt
   `evaluation/binary/<benchmark>` entries, neither of which exists for MAGMA
   (nor for the part-1 `php` target).  Corpus-only mode materialises the
   variant-program outputs directly; the fallback path is recorded in
   `generated_inputs/command.txt` and the manifest.  This is a MAGMA-name
   limitation, not a model or Docker failure.
3. **ELFuzz TGI.**  There is no local GPU/TGI model; the entrypoint's
   OpenAI-compatible `/generate` proxy is required and is used here
   (`ELFUZZ_TGI_PROXY_PORT=8192`).  Without `OPENAI_BASE_URL`/key the proxy is
   not started and the run fails at `model_ready`.
4. **The local `hgb-elfuzz:latest` image is stale.**  It predates
   `hgb_campaign_storage.py` and the corpus-only mode.  The driver mounts
   `docker/common` at `/opt/hgb/bin`, the repo entrypoint, and metadata over
   the image; this is reproducible but a rebuild of `hgb-elfuzz` and
   `hgb-g2fuzz` from the current Dockerfiles is recommended for production.
5. **G2Fuzz format coverage is empirical.**  Some formats (notably DER X.509)
   may lead the LLM to emit generators that import unavailable libraries; the
   driver reports such a cell as `failed` with the program-gen log rather than
   substituting the MAGMA seed corpus.  The openssl adapter uses the upstream
   `binary_large_object_BLOB` format name to stay close to G2Fuzz's artifact.
6. **Cost/time.**  A one-format G2Fuzz run takes about 10–20 minutes with
   `G2FUZZ_TRY_NUM=1` (30–80 LLM calls).  ELFuzz with 1 iteration and 4
   variants takes about 5–12 minutes.  Nine cells per generator are therefore
   hours, not minutes; no 24-hour campaign is launched by this tooling.
7. **Shared-host Docker stalls.**  Under the current host load, a host-side
   `docker run ... chown` can wait minutes; the driver bounds that step to
   180 s and continues.  If it times out, the run directory may stay
   root-owned; the corpus is still readable and the validator writes to a
   writable directory.  The seeded `-runs=0` replay is the reliable short
   consumption check; fork-mode libFuzzer startup may not finish a 15–30 s
   window on a loaded host.
8. **Not all nine cells were smoke-tested in this session.**  libpng and
   libxml2 were required; lua/sqlite3/libtiff were run as extra confirmation.
   The database (`workspace/magma/corpus/{elfuzz,g2fuzz}/summary.json`) is the
   source of truth for which cells are `corpus_ready` vs pending.

## Files

Created:

* `metadata/elfuzz_target_adapters_magma.yaml`
* `metadata/g2fuzz_target_adapters_magma.yaml`
* `repro/elfuzz/magma/{libxml2,lua,php,sqlite3}/{format.md,seed_fuzzer.py,adapter.yaml}`
* `repro/g2fuzz/magma_specs/magma_{libpng,libsndfile,libtiff,libxml2,lua,openssl,php,poppler,sqlite3}.md`
* `scripts/hgb_magma_corpus_generate.py`
* `docs/magma_corpus_generators.md` (this file)

Modified (backward compatible):

* `docker/common/elfuzz_target_pipeline.py` — parallel-manifest loading,
  MAGMA adapter validation, `--corpus-only`, preset budget tuning, corpus
  collection from variant outputs, `validate-magma-adapters` CLI.
* `docker/elfuzz/entrypoint.sh` — env-gated corpus mode guards for
  `all_gen.sh` / `do_gen.sh` / `batchrun.py`, `--corpus-only` forwarding.
* `scripts/lib/common.sh` — forward the corpus-only `ELFUZZ_*` variables
  through the standard generator container runner.

Unchanged on purpose: `metadata/elfuzz_target_adapters.yaml`,
`metadata/g2fuzz_target_adapters.yaml`, `docs/magma_plan.md`,
`results/hgb_baselines_5times.md`.
