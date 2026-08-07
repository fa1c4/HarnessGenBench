# PromeFuzz Config Notes

The Docker reproduction no longer writes persistent TOML files containing LLM settings under `results/` or `workspace/`.

At container runtime, `docker/promefuzz/entrypoint.sh` derives a temporary config at `/run/hgb/promefuzz_config.toml` from Docker environment variables:

- `API_KEY` / `OPENAI_API_KEY`
- `BASE_URL` / `OPENAI_BASE_URL`
- `MODEL` / `OPENAI_MODEL`

Metadata records only `api_key_present`, never the key value.

## Exact FuzzBench compile database and link context (alpha/paper-faithful)

PromeFuzz `alpha`/`paper-faithful` must not consume a synthetic or generic
compile database. `docker/common/promefuzz_build_context.py` replays the pinned
FuzzBench target build (`bear_replay` or `cmake_export` over the staged source)
and emits a `compile_commands.json` plus a `link_context.json` with:

- `mode = "fuzzbench_build_replay"` for an exact capture (never `"synthetic"`
  or `"generic_cmake"` in alpha);
- `compiler_wrapper` (`bear`/`cmake`/`synthetic`);
- `compile_commands_count`, `benchmark_project`, `fuzz_target`, `image_digest`;
- recovered `driver_build_args`, `library_paths`, `compile_flags`, `link_flags`.

`driver_build_args` must be non-empty and verified by `verify_link_set` (a
minimal consumer is built with the recovered flags) before `libraries.toml` is
generated. Empty or unverified `driver_build_args` is an `infra_failure` with
`failed_stage=link_context`, never a soft skip. A synthetic compile database is
reachable only under `compat-smoke` (`allow_synthetic=true`,
`excluded_from_aggregate=true`).

## Consumer knowledge wiring

`build_context` writes `knowledge/consumer_cases.json` from legitimate examples,
tests, and docs only — never the exact FuzzBench reference harness. The
entrypoint wires it into the upstream PromeFuzz `libraries.toml`:

```toml
consumer_case_paths = ["/workspace/knowledge/consumer_cases"]
```

When consumer cases are unavailable, `consumer_cases.status="unavailable"` is
recorded and PromeFuzz still runs with code metadata and docs. After
`comprehend`, a runtime assertion checks that PromeFuzz produced nonempty
retrieval/correlation knowledge when consumer cases are available.

## Real embeddings

`alpha`/`paper-faithful` require a real semantic embedding provider
(`PROME_FUZZ_EMBEDDING_LLM_TYPE=openai|ollama`, a real `PROME_FUZZ_EMBEDDING_MODEL`).
`mock`/`local`/`hash` and `hgb-hash-embedding` are forbidden. A preflight
embedding request validates the endpoint before generation. `compat-smoke` may
use local hash embeddings but is excluded from the aggregate.

## Shared harness evaluator

PromeFuzz reuses `docker/common/hgb_harness_evaluator.py` (the same evaluator
CKGFuzzer/OSS-Fuzz-Gen use), not the thin `promefuzz_evaluator.py` facade. It
overlays each candidate at the exact native FuzzBench harness path, replays the
pinned build, runs sanitizer smoke, API reachability (from PromeFuzz-intended
APIs, never reference-harness APIs), a fixed-budget campaign, and real LLVM
coverage. `status=evaluated` requires `candidate_count>0`,
`verified_candidate_count>0`, `coverage.line_coverage.covered != null`,
`campaign.execs_done>0`, and `api_reachability.reached_count>0`. A
compile-only candidate yields `quality_failure`, never `evaluated`.
