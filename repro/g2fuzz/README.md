# G2Fuzz Reproduction

G2Fuzz is tracked as an HGB `input_generator`: it creates executable input
generators and generated seeds for an existing native FuzzBench target, then
runs the pinned modified AFL++ workflow against a target pair built as `.afl`
(default AFL++ instrumentation) and `.cmp`/CmpLog binaries. It does not
generate `LLVMFuzzerTestOneInput` and is not part of the harness-generator
leaderboard.

## .afl/.cmp are auto-built

The `.afl` and `.cmp` binaries are now built automatically from the pinned
FuzzBench target inside the G2Fuzz image. No externally prebuilt target pair is
required:

- `target.afl` — `CC/CXX = <g2fuzz>/afl-clang-fast`, `FUZZING_ENGINE=afl`,
  `SANITIZER=address`, `AFL_LLVM_CMPLOG=0`.
- `target.cmp` — same command with `AFL_LLVM_CMPLOG=1` (CmpLog only for `.cmp`).

Both binaries are built from the same benchmark commit/project/fuzz target, then
smoke-tested (empty input + a bootstrap seed) and AFL-handshake-verified. A
failed or missing pair build is `infra_failure`/`infra_missing`, never a soft
skip. `G2FUZZ_TARGET_DIR` remains available as an *optional* override for a
host-provided pair; it is not required in alpha or paper-faithful.

## Running one target

```bash
bash scripts/clone_artifacts.sh --locked
export HGB_BASELINE_PROFILE=paper-faithful
export HGB_CAMPAIGN_SECONDS=300
export G2FUZZ_AFL_TIMEOUT_SECONDS=300
export OPENAI_API_KEY=...
bash scripts/hgb_generate_harness.sh --generator g2fuzz \
  --target libpng_libpng_read_fuzzer --allow-input-generator --strict
jq . results/g2fuzz/libpng_libpng_read_fuzzer*/result.json
```

## Running the full matrix

```bash
bash scripts/hgb_generate_matrix.sh --generators g2fuzz --targets valuable \
  --allow-input-generator --strict
python3 scripts/hgb_collect_matrix.py --generators g2fuzz --targets valuable \
  --strict --split-by method_profile
```

The collector separately reports `paper-faithful` and `extension` target groups.
No row may be `evaluated` without `.afl`/`.cmp` build evidence, a valid
G2-generated input, nonzero AFL executions, and a real coverage report.

## What the workflow writes

Under `workspace/g2fuzz/<target>/<run-id>/`:

- `target/build.json` — pair build record (binaries, sha256, build commands,
  smoke, input contract).
- `generators/source/` — synthesized Python generators + manifest.
- `seeds/common_initial/`, `seeds/bootstrap/`, `seeds/g2_generated/`,
  `seeds/afl_initial/`, `seeds/afl_queue/` — seed provenance classes.
- `seeds/provenance.jsonl` — per-file sha256, size, source_class, bytes.
- `campaign/` — modified AFL++ output, `metrics.json`, `fuzzer_stats`.
- `coverage/summary.json` — real LLVM/lcov coverage; `edge_coverage` is
  `unavailable` when no edge report exists (AFL `paths_total` is never coverage).
- `result.json` / `metadata.json` / `HGB_SUMMARY.md`.

## Seed provenance

Seed provenance is tracked separately so G2-generated inputs are never conflated
with common/bootstrap corpus:

- `common_initial` — FuzzBench seeds/dictionaries only.
- `bootstrap` — minimal hand-written seed to start AFL (non-G2).
- `g2_generated` — only inputs produced by G2Fuzz generator execution.
- `afl_initial` — merge of common/bootstrap/g2_generated admitted to AFL.
- `afl_queue` — AFL campaign queue output.

`result.json` reports counts and bytes for each class under `seed_provenance`
and `seed_provenance_bytes`.

## paper-faithful vs extension

`metadata/g2fuzz_target_adapters.yaml` records each valuable target's format,
input mode, argv placement, and `method_profile`:

- `paper-faithful` — targets whose format/program family is directly aligned
  with the G2Fuzz paper experiments or official artifact support.
- `extension` — text/custom targets or formats not directly in the paper's core
  set.

Both profiles may run, but matrix summaries separate the aggregates. Extension
rows are excluded from paper-only aggregates.

## Why compat-smoke is not paper reproduction

`compat-smoke` truncates formats/try-num to 1 and sets
`excluded_from_aggregate=true`. It is an offline wiring test, never a paper
reproduction: it does not satisfy the `evaluated` contract (real pair build,
valid G2 inputs, nonzero AFL executions, real coverage).

## Compatibility wrappers

```bash
bash scripts/g2fuzz_generate_seeds.sh libpng_libpng_read_fuzzer
bash scripts/g2fuzz_smoke_afl.sh libpng_libpng_read_fuzzer
```

Both wrappers call the same staged baseline runner. `g2fuzz-data` is optional
comparison data; set `G2FUZZ_USE_DATA=1` to mount a local
`artifacts/g2fuzz-data` checkout read-only for comparison reporting.
