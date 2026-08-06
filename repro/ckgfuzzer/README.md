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

## Legacy smoke workflow

```bash
make artifacts
bash scripts/ckgfuzzer_setup.sh
bash scripts/ckgfuzzer_smoke.sh || true
bash scripts/ckgfuzzer_collect_report.sh workspace/ckgfuzzer/<run-id>
```

The HGB Docker image copies `artifacts/ckgfuzzer` into `/opt/hgb/artifacts/ckgfuzzer`. The smoke entrypoint prepares a small `hgb-sample` project under `workspace/ckgfuzzer/<run-id>/project/hgb-sample` when a complete upstream example is unavailable. Its `build.sh` is location-independent and can be run from any current working directory.

LLM configuration is sourced on the host from `configs/set_api_key.sh` and passed to Docker as environment variables.
