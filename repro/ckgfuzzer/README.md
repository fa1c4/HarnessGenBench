# CKGFuzzer Reproduction

CKGFuzzer is a `harness_generator` baseline. The canonical runner is
`scripts/hgb_run_baseline.sh`:

```bash
make artifacts
bash scripts/hgb_run_baseline.sh \
  --generator ckgfuzzer \
  --target jsoncpp_jsoncpp_fuzzer \
  --profile alpha \
  --protocol blind-project \
  --strict
```

`scripts/hgb_generate_harness.sh` remains as a backwards-compatible wrapper but
the new runner is canonical.

## Profiles

- `alpha` (default): real CodeQL database and knowledge graph, real embedding
  service, upstream LLM API summaries, upstream API-combination planner, and
  upstream compilation-check/repair loop. No method-changing fallbacks.
- `paper-faithful`: same algorithmic requirements as `alpha` with larger
  paper-aligned budgets.
- `compat-smoke`: may use `MockEmbedding`, local deterministic API
  summaries/combinations, source-only graph fallback, and tiny budgets. Results
  are excluded from scientific aggregates (`excluded_from_aggregate=true`) and
  never selected by default.

`alpha` and `paper-faithful` require:
- `CKGFUZZER_EMBEDDING_MODEL` set to a real embedding service (not `mock`/`local`/empty)
- `CKGFUZZER_LOCAL_API_SUMMARY=0` (the upstream LLM summary path)
- `CKGFUZZER_LOCAL_API_COMBINATION=0` (the upstream LLM planner)
- No `--skip_check_compilation` (the upstream compilation-check/repair loop)

## Protocols

- `blind-project` (default): APIs are discovered from public headers, source
  declarations, project docs, and protocol-allowed examples/tests. The exact
  FuzzBench reference harness is evaluator-only and never reaches generation.
- `api-oracle`: accepts independently declared API names/signatures in
  `declared_api.json`.

## Target package isolation (beta)

`scripts/hgb_prepare_target.sh` produces a physical split of each target
package so a blind generator cannot read the evaluator-only answer:

```
<target-package>/generator_input/      # mounted at /target for the generator
    source_input/ docs/ seeds/ dictionary/ build_metadata/
    target_manifest.generator.json      # no reference-harness fields
<target-package>/evaluator_only/        # mounted at /evaluator for the evaluator
    reference_harnesses/ selected_reference_harnesses/ benchmark_copy/
    native_harness_path.json            # exact native harness path
    target_manifest.evaluator.json
```

`scripts/lib/common.sh` mounts only `generator_input` at `/target` for
CKGFuzzer in `blind-project`; `evaluator_only` is mounted at `/evaluator` for
the independent harness evaluator. A repo-wide audit test fails if
`reference_harnesses`, `selected_reference`, or
`fuzzbench_selected_harness_apis.json` is visible to the blind generator.

## Full harness evaluator (beta)

`docker/common/hgb_harness_evaluator.py` replaces the build-only verifier. For
each generated candidate it overlays the candidate at the exact native
FuzzBench harness path, builds the sealed target image with a deterministic
tag, runs sanitizer smoke, confirms API reachability, runs a fixed-budget
libFuzzer campaign, and measures real LLVM source-based coverage. A candidate
that merely compiles never marks `campaign` or `coverage` completed.

`status=evaluated` requires a real overlay, per-candidate evaluator JSON,
`execs_done > 0`, and a real coverage report. Anything else is
`quality_failure` or `infra_failure` -- never a silent success.

Required external services:
- a real embedding service (`CKGFUZZER_EMBEDDING_MODEL=openai-*` or `ollama-*`)
- a real OpenAI-compatible LLM endpoint (`OPENAI_API_KEY`/`OPENAI_BASE_URL`)
- CodeQL (mounted via `HGB_CODEQL_DIR` or built with `HGB_INSTALL_CODEQL=1`)
- Docker (the evaluator builds/replays the sealed FuzzBench target image)

## Single target reproduction

```bash
export OPENAI_API_KEY=...
export HGB_BASELINE_PROFILE=paper-faithful
export HGB_BASELINE_PROTOCOL=blind-project
export HGB_CAMPAIGN_SECONDS=300
bash scripts/hgb_generate_harness.sh --generator ckgfuzzer --target jsoncpp_jsoncpp_fuzzer --strict
jq . results/ckgfuzzer/jsoncpp_jsoncpp_fuzzer*/result.json
```

## Full valuable matrix

```bash
bash scripts/hgb_generate_matrix.sh --generators ckgfuzzer --targets valuable --strict
python3 scripts/hgb_collect_matrix.py --generators ckgfuzzer --targets valuable --strict
```

The matrix collector emits 20 rows for `target_sets.valuable.targets`, no
`not_applicable` CKGFuzzer rows, no `evaluated` row without a coverage file and
nonzero campaign execs, and an aggregate success rate based only on
`status=evaluated`. `quality_failure` rows are included but never counted as
success.

## Legacy smoke workflow

```bash
make artifacts
bash scripts/ckgfuzzer_setup.sh
bash scripts/ckgfuzzer_smoke.sh || true
bash scripts/ckgfuzzer_collect_report.sh workspace/ckgfuzzer/<run-id>
```

The HGB Docker image copies `artifacts/ckgfuzzer` into `/opt/hgb/artifacts/ckgfuzzer`. The smoke entrypoint prepares a small `hgb-sample` project under `workspace/ckgfuzzer/<run-id>/project/hgb-sample` when a complete upstream example is unavailable. Its `build.sh` is location-independent and can be run from any current working directory.

LLM configuration is sourced on the host from `configs/set_api_key.sh` and passed to Docker as environment variables.
