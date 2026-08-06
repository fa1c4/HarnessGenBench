# OSS-Fuzz-Gen Reproduction

OSS-Fuzz-Gen is a **`harness_generator`** baseline. It generates, repairs,
builds, fuzzes, and evaluates harness artifacts for FuzzBench targets.

## Profiles

- **`alpha`** (default): real Fuzz Introspector build, real coverage,
  automatic compile/build repair, >=3 generation samples, default 5 repair
  rounds, and an independent exact-FuzzBench evaluator. Only
  `status=evaluated` counts as a successful matrix row.
- **`paper-faithful`**: pinned upstream/paper experiment settings; never
  lowered to smoke values.
- **`compat-smoke`**: local introspector shim, 1/1/1 budgets, coverage skip.
  Always `excluded_from_aggregate=true` and never the default.

## Blind-project isolation

In `blind-project` (the default protocol), the exact FuzzBench reference
harness is **evaluator-only**. The generator never receives
`HGB_TARGET_REFERENCE_DIR`, never reads reference-backed examples, and never
ranks APIs by reference harness calls. The independent evaluator alone sees
the native harness and replays the pinned FuzzBench build.

## Run a single target

```bash
bash scripts/hgb_run_baseline.sh \
  --generator oss-fuzz-gen \
  --target jsoncpp_jsoncpp_fuzzer \
  --profile alpha \
  --protocol blind-project \
  --strict
```

`--strict` requires `status=evaluated`. With Docker and credentials this runs
the full pipeline: introspector build, benchmark synthesis, generation +
repair, candidate preservation, and independent evaluation (build, sanitizer
smoke, API reachability, campaign, coverage).

## Run the matrix

```bash
bash scripts/hgb_generate_matrix.sh \
  --generators oss-fuzz-gen \
  --targets valuable \
  --profile alpha \
  --protocol blind-project \
  --strict
```

## Artifacts

```text
workspace/oss-fuzz-gen/<target>/<run-id>/
  introspector/        # real Fuzz Introspector reports
  benchmark/           # generated.yaml, selection.json
  generation/          # work/, candidates/, repair_iterations/
  generated_harnesses/ # final.c|final.cc
  evaluation/          # build/, smoke/, campaign/, coverage/
  result.json          # schema v2 with stages + provenance
  HGB_SUMMARY.md
```

## Reproduction (legacy smoke)

```bash
make artifacts
bash scripts/oss_fuzz_gen_setup.sh
bash scripts/oss_fuzz_gen_smoke.sh || true
bash scripts/oss_fuzz_gen_collect_report.sh workspace/oss-fuzz-gen/<run-id>
```

The Docker image copies the **pinned** `artifacts/oss-fuzz-gen` and
`artifacts/oss-fuzz` checkouts (see `metadata/work_index.yaml`). Cloning a
floating OSS-Fuzz `master` is forbidden. Configure LLM settings with
`configs/set_api_key.sh`; OSS-Fuzz-Gen also receives `/var/run/docker.sock`
because upstream invokes Docker/OSS-Fuzz builders.
