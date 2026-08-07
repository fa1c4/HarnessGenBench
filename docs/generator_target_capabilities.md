# Generator Target Capabilities

| Generator | Capability | `generate-target` default | Notes |
|---|---|---|---|
| OSS-Fuzz-Gen | harness generator | run | Synthesizes a target-aware benchmark YAML from a real target-scoped Fuzz Introspector build (never soft-skip). `alpha`/`paper-faithful` require real Introspector, real coverage, automatic build repair, and the shared harness evaluator that overlays each candidate at the exact native path, runs sanitizer smoke, API reachability, a fixed-budget campaign (`execs_done>0`), real LLVM coverage, and a runtime line coverage diff vs a native control. Reference harnesses are evaluator-only in `blind-project`; selected-harness API ranking and reference-harness examples are forbidden. |
| CKGFuzzer | harness generator | run | Needs API candidates, runtime config, and a real CodeQL/code knowledge graph. `alpha`/`paper-faithful` require a real embedding service, upstream LLM API summaries, the upstream API-combination planner, and the upstream compilation-check/repair loop. The beta harness evaluator overlays each candidate, runs sanitizer smoke, API reachability, a fixed-budget campaign, and real LLVM coverage. |
| PromeFuzz | harness generator | run | PromeFuzz is a `harness_generator`. `alpha`/`paper-faithful` require a real compile database captured from the pinned FuzzBench build (`mode=fuzzbench_build_replay`; synthetic and generic CMake DBs are forbidden), real link/library context with non-empty verified `driver_build_args` (`verify_link_set`), legitimate consumer knowledge wired into the upstream PromeFuzz config via `consumer_case_paths` (never the reference harness), a real semantic embedding provider (never mock/hash), the official ALL-COVER generation path with practical multi-candidate budgets, and the shared harness evaluator (`hgb_harness_evaluator.py`) that overlays each candidate at the exact native path, runs sanitizer smoke, API reachability, a fixed-budget campaign (`execs_done>0`), and real LLVM coverage. A compile-only candidate can never be `evaluated`. |
| ELFuzz | input generator | run via manifest applicability gate | Synthesizes/evolves input-producing fuzzer programs against a fixed native FuzzBench target, then runs a final campaign. Applicability is decided from `metadata/elfuzz_target_adapters.yaml`; non-text targets return `Invalid`/`not_applicable` before Docker, TGI, or model work. `--allow-input-generator` is a deprecated no-op. |
| G2Fuzz | input generator | run target-aware staged pipeline | Auto-builds the native `.afl`/`.cmp` pair from the pinned FuzzBench target with the modified afl-clang-fast (CmpLog for `.cmp`); no externally prebuilt pair is required. Reports `evaluated` only after a completed pair build, at least one valid G2-generated input, a modified AFL++ campaign with `execs_done>0` and a nonempty queue, and a real coverage report. AFL `paths_total` is never coverage. |

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

## ELFuzz applicability and Invalid rows

ELFuzz is an `input_generator`, not a harness generator. It supports only the
explicit text-input target set in `metadata/elfuzz_target_adapters.yaml`:

- **Applicable (9):** `curl_curl_fuzzer_http`, `jsoncpp_jsoncpp_fuzzer`,
  `libxml2_xml`, `libxslt_xpath`, `mruby_mruby_fuzzer_8c8bbd`,
  `php_php-fuzz-parser_0dbedb`, `re2_fuzzer`, `sqlite3_ossfuzz`,
  `systemd_fuzz-link-parser`.
- **Invalid (11 non-text):** returned as `not_applicable` /
  `applicability=Invalid` / `reason_code=elfuzz_non_text_target` before Docker,
  TGI, model download, synthesis, or fuzzing starts.

Each applicable target ships a per-target adapter at
`repro/elfuzz/targets/<target>/adapter.yaml` naming the exact FuzzBench target
(no `jsoncpp`/`libxml2` aliasing for extension targets). The collector excludes
Invalid rows from the success/failure denominator and reports coverage only for
applicable evaluated rows.

## G2Fuzz method profiles

G2Fuzz is an `input_generator`, not a harness generator. Every valuable target
has an adapter in `metadata/g2fuzz_target_adapters.yaml` with a `method_profile`:

- **paper-faithful (9):** targets whose format/program family is directly
  aligned with the G2Fuzz paper experiments or official artifact support.
- **extension (11):** text/custom targets or formats not directly in the
  paper's core set.

Both profiles may run, but matrix summaries separate the aggregates
(`--split-by method_profile`). Extension rows are excluded from paper-only
aggregates. The `.afl`/`.cmp` pair is auto-built from the pinned FuzzBench
target; `G2FUZZ_TARGET_DIR` is an optional override only, never required in
alpha or paper-faithful.
