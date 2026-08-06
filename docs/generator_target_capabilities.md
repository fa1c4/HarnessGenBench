# Generator Target Capabilities

| Generator | Capability | `generate-target` default | Notes |
|---|---|---|---|
| OSS-Fuzz-Gen | harness generator | run if OFG YAML exists, otherwise soft-skip | Needs a function/test benchmark YAML, not just a FuzzBench fuzz target. |
| CKGFuzzer | harness generator | run | Needs API candidates, runtime config, and a real CodeQL/code knowledge graph. `alpha`/`paper-faithful` require a real embedding service, upstream LLM API summaries, the upstream API-combination planner, and the upstream compilation-check/repair loop. The beta harness evaluator overlays each candidate, runs sanitizer smoke, API reachability, a fixed-budget campaign, and real LLVM coverage. |
| PromeFuzz | harness generator | run if compile DB exists, otherwise soft-skip | Needs headers and `compile_commands.json`. |
| ELFuzz | input generator | soft-skip | Can run with `--allow-input-generator`. |
| G2Fuzz | input generator | run target-aware staged pipeline | Requires a native `.afl`/`.cmp` pair and reports `evaluated` only after generation, campaign, and coverage/queue metric collection. |

All target-aware runs execute inside Docker. Host-side outputs stay under
`workspace/`, and upstream artifacts or target source checkouts stay under
`artifacts/`.

## paper-faithful vs compat-smoke

`paper-faithful` (and `alpha`) reproduce the upstream algorithm with no
method-changing fallbacks: real CodeQL/CKG context, real embeddings, upstream
LLM API summaries/combinations, the upstream compilation-check/repair loop,
and the full harness evaluator. `compat-smoke` may retain deterministic/mock
fallbacks for offline wiring tests only; it sets
`excluded_from_aggregate=true` and `method_variant=compat-smoke` and is never
selected by default or counted in paper reproduction tables.

For harness generators, only `status=evaluated` counts as a successful matrix
row. `quality_failure` (generation ran but no candidate passed
build/smoke/reachability/campaign/coverage) and `infra_failure` (tooling
failed) are never counted as success.
