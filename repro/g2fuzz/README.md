# G2Fuzz Reproduction

G2Fuzz is tracked as an HGB `input_generator`: it creates executable input
generators and generated seeds for an existing native FuzzBench target, then
runs the pinned modified AFL++ workflow against a target pair built as `.afl`
and `.cmp`/CmpLog binaries. It does not generate `LLVMFuzzerTestOneInput` and
is not part of the harness-generator leaderboard.

```bash
make artifacts
bash scripts/g2fuzz_setup.sh
bash scripts/hgb_run_baseline.sh \
  --generator g2fuzz \
  --target libpng_libpng_read_fuzzer \
  --profile alpha \
  --protocol paper-native \
  --strict
```

The target-aware workflow writes `target/`, `generators/source/`, separated
seed provenance directories, `campaign/`, `coverage/`, `metadata.json`,
`result.json`, and `HGB_SUMMARY.md` under `workspace/g2fuzz/<target>/<run-id>/`.

`metadata/g2fuzz_target_adapters.yaml` is the committed target contract. It
records each valuable target format, input mode, argv placement, and whether the
row is `paper-faithful` or an HGB `extension`. Extension rows remain excluded
from paper-only aggregates.

`g2fuzz-data` is optional comparison data. Normal image builds and runs do not
require it; set `G2FUZZ_USE_DATA=1` only when you want to mount a local
`artifacts/g2fuzz-data` checkout read-only for comparison reporting.

Compatibility wrappers remain available:

```bash
bash scripts/g2fuzz_generate_seeds.sh libpng_libpng_read_fuzzer
bash scripts/g2fuzz_smoke_afl.sh libpng_libpng_read_fuzzer
```

Both wrappers call the same staged baseline runner. If `G2FUZZ_TARGET_DIR`
points at host-built `.afl`/`.cmp` binaries, the runner mounts it at
`/g2fuzz-target-pair` inside the container before launching the pipeline.
