# OSS-Fuzz-Gen Smoke Config

Docker smoke runs use the pinned checkout at `artifacts/oss-fuzz-gen` inside the image.

Default benchmark selection:

```bash
OFG_BENCHMARK=tinyxml2
OFG_RUN_TIMEOUT=300
OFG_TOTAL_TIMEOUT_SECONDS=600
OFG_MAX_ROUNDS=1
OFG_WORKERS=1
```

The container searches the copied benchmark sets for a YAML file whose filename or contents mention the benchmark name. Outputs are written to `workspace/oss-fuzz-gen/<run-id>/`.

## compat-smoke is not paper reproduction

`compat-smoke` may use the local introspector shim, 1/1/1 budgets, and
`OFG_SKIP_COVERAGE_GAINS=1` for offline wiring tests only. It always sets
`excluded_from_aggregate=true` and `method_variant=compat-smoke` and is never
the default. A `compat-smoke` row is never counted as a successful
reproduction: it does not run real Fuzz Introspector, does not measure real
coverage, and cannot reach `status=evaluated` (it emits
`compat_smoke_completed` at most).

`alpha` and `paper-faithful` require real target-scoped Fuzz Introspector, a
benchmark YAML synthesized from that introspector output (passing a leak
audit), real automatic build repair, and the shared harness evaluator with
real coverage and a runtime line coverage diff.
