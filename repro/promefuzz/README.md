# PromeFuzz Reproduction

PromeFuzz is a `harness_generator` baseline. The canonical alpha command is:

```bash
make artifacts
bash scripts/hgb_run_baseline.sh \
  --generator promefuzz \
  --target jsoncpp_jsoncpp_fuzzer \
  --profile alpha \
  --protocol blind-project \
  --strict
```

The legacy smoke wrapper remains available:

```bash
make artifacts
bash scripts/promefuzz_build_docker.sh
bash scripts/promefuzz_smoke_pugixml.sh || true
bash scripts/promefuzz_collect_report.sh workspace/promefuzz/<run-id>
```

## Profiles

- `alpha` (default): real compile database captured from the pinned FuzzBench
  build, real link/library context (`driver_build_args`), legitimate consumer
  knowledge when available, a real semantic embedding provider, the official
  ALL-COVER generation path with practical multi-candidate budgets, iterative
  native target build validation, and the common harness evaluator
  (build + sanitizer smoke + API reachability + campaign + coverage).
- `paper-faithful`: same method components as `alpha`, using pinned
  upstream/paper experiment defaults where available; all deviations are
  recorded.
- `compat-smoke`: may use the synthetic compile database and local hash
  embeddings for offline wiring tests only. It sets
  `excluded_from_aggregate=true` and `method_variant=compat-smoke` and is never
  selected by default.

## Required configuration

`alpha`/`paper-faithful` require a real embedding service:

```bash
export PROME_FUZZ_EMBEDDING_LLM_TYPE=openai   # or ollama
export PROME_FUZZ_EMBEDDING_MODEL=text-embedding-3-small
export PROME_FUZZ_EMBEDDING_BASE_URL=https://api.openai.com/v1
export PROME_FUZZ_EMBEDDING_API_KEY=$API_KEY
```

A preflight request validates the embedding endpoint before expensive
preprocessing; an unavailable embedding service fails the run
(`promefuzz_embedding_unavailable`) rather than silently falling back to hash
embeddings. `PROME_FUZZ_EMBEDDING_LLM_TYPE=mock`/`local`/`hash` and
`PROME_FUZZ_EMBEDDING_MODEL=hgb-hash-embedding` are forbidden in
`alpha`/`paper-faithful`.

## Blind-project isolation

In `blind-project`, the PromeFuzz generator never receives the exact FuzzBench
reference harness, `metadata/fuzzbench_selected_harness_apis.json`, or
reference-derived API filtering. Build-context capture overlays a neutral
`LLVMFuzzerTestOneInput` stub when the build needs a fuzz entrypoint. A canary
leakage audit (`HGB_REF_CANARY`) proves the reference harness never reaches
prompts, logs, configs, API collections, embeddings, or candidates.

## Successful output

A run reaches `status=evaluated` only after the common harness evaluator
completes the exact FuzzBench build, sanitizer smoke, API reachability,
fixed-budget campaign, and coverage. `dry_run`, `partial_completed`,
`soft_skip`, and `generation_completed` are not `evaluated`; only `evaluated`
counts as a successful alpha matrix row.

The HGB Docker image copies `artifacts/promefuzz` into
`/opt/hgb/artifacts/promefuzz`. Runtime LLM/embedding config is generated inside
the container; persistent `results/` or `workspace/` configs do not contain
secrets. Metadata records only whether an API key was present. Image provenance
is recorded in `/opt/hgb/provenance.json`.
