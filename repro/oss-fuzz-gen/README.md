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
  evaluation/          # build/, smoke/, campaign/, coverage/, candidates/
  result.json          # schema v2 with stages + provenance
  HGB_SUMMARY.md
```

## Independent evaluator and coverage diff

The entrypoint delegates to the shared `hgb_harness_evaluator.py`
(`--generator oss-fuzz-gen`). For each candidate it:

1. overlays the candidate at the exact native FuzzBench harness path
   (evaluator-only metadata);
2. builds the sealed target image with **one deterministic image tag** reused
   for build, smoke, campaign, and coverage;
3. runs sanitizer smoke on empty input and seeds;
4. confirms intended project API reachability (from the benchmark
   YAML/Introspector, never the reference harness);
5. runs a fixed-budget libFuzzer campaign requiring `execs_done > 0`;
6. measures real LLVM source-based coverage from a report file (never a
   process exit code);
7. builds a native/reference coverage control and computes the **runtime line
   coverage diff** (`coverage_diff`): `candidate_lines_covered`,
   `native_lines_covered`, `new_lines_vs_native`,
   `line_coverage_diff_percent`, `runtime_coverage_valid`. When the native
   control cannot be computed, candidate coverage is still emitted but
   `coverage_diff.status="unavailable"`; the row is never labelled
   paper-equivalent.

Evaluator CLI failure is never swallowed: a nonzero exit propagates to
`infra_failure/failed_stage=evaluator`.

## Budgets

`alpha` defaults to `OFG_NUM_SAMPLES=3`, `OFG_NUM_EVALUATIONS=3`,
`OFG_GENERATION_TIMEOUT_SECONDS=7200`, `OFG_MAX_ROUND=5`. `paper-faithful`
defaults to `OFG_NUM_SAMPLES=10`. `compat-smoke` uses 1/1/1 budgets. All
budgets are recorded in `result.json` provenance.

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
