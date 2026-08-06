# HarnessGenBench

HarnessGenBench keeps reproducible, Docker-based smoke workflows for recent fuzz harness generation systems.

## Configuration

Secrets are local only. Create the real config from the tracked placeholder:

```bash
cp configs/set_api_key.example.sh configs/set_api_key.sh
$EDITOR configs/set_api_key.sh
source configs/set_api_key.sh
```

Do not commit `configs/set_api_key.sh` or any generated workspace output.

### OpenAI-compatible provider profiles

All remote-LLM harness generators use the same profile resolver. Set
`HGB_LLM_PROVIDER` to `ustc`, `deepseek`, `custom`, or `auto`; the first two
supply the appropriate base URL and default model. `HGB_LLM_API_KEY`,
`HGB_LLM_BASE_URL`, and `HGB_LLM_MODEL` override a profile. Existing
`API_KEY`, `BASE_URL`, and `MODEL` settings remain supported.

```bash
# USTC defaults to https://api.llm.ustc.edu.cn and glm-5.2
export HGB_LLM_PROVIDER=ustc
export API_KEY='...'

# DeepSeek defaults to https://api.deepseek.com and deepseek-v4-pro
export HGB_LLM_PROVIDER=deepseek
export API_KEY='...'
# export HGB_LLM_MODEL=deepseek-v4-flash
```

Inspect the resolved configuration without a network request with
`bash scripts/hgb_llm_preflight.sh`; append `--live` to send one minimal
OpenAI-compatible chat request. The command never prints the credential.
ELFuzz remains a local TGI/Hugging Face input-generation workflow; it receives
profile metadata but does not use the remote chat API.

CKGFuzzer defaults to a 900-second OpenAI-compatible request timeout and three
SDK retries. These are built into the integration; set
`CKGFUZZER_LLM_REQUEST_TIMEOUT_SECONDS` or `CKGFUZZER_LLM_MAX_RETRIES` only to
override them for an individual run.

## Artifact Refresh

Upstream source checkouts live under ignored `artifacts/`. Refreshing artifacts fetches current upstream HEAD, overwrites `metadata/work_index.yaml`, and checks out the pinned commit recorded there:

```bash
make artifacts
```

`plans/` is intentionally ignored. Historical host-side checkouts are not part of the active workflow.

## Docker Reproduction Workflow

All reproduction runs execute inside HGB Docker images and write primary outputs under ignored `workspace/<fuzzer>/<run_id>/`.

```bash
make artifacts
make docker-build-oss-fuzz-gen
make smoke-oss-fuzz-gen
make smoke-ckgfuzzer
make smoke-promefuzz
make smoke-elfuzz
make smoke-g2fuzz
```

Useful direct commands:

```bash
bash scripts/oss_fuzz_gen_setup.sh
bash scripts/oss_fuzz_gen_smoke.sh || true
bash scripts/ckgfuzzer_setup.sh
bash scripts/ckgfuzzer_smoke.sh || true
bash scripts/promefuzz_build_docker.sh
bash scripts/promefuzz_smoke_pugixml.sh || true
bash scripts/elfuzz_start_container.sh --smoke || true
bash scripts/g2fuzz_setup.sh
bash scripts/hgb_run_baseline.sh --generator g2fuzz --target libpng_libpng_read_fuzzer --profile alpha --protocol paper-native
```

LLM-backed smoke runs may fail because credentials, quota, model access, Docker-in-Docker, or upstream CLIs are unavailable. They should still leave `metadata.json`, logs, and `HGB_SUMMARY.md` in `workspace/`.

CKGFuzzer requires the CodeQL CLI for target-aware generation. The CKGFuzzer Docker image installs the CodeQL bundle during `bash scripts/ckgfuzzer_setup.sh` by default. Set `HGB_INSTALL_CODEQL=0` only when rebuilding a smaller image for dry runs or when mounting an external CodeQL checkout with `HGB_CODEQL_DIR`.

### CKGFuzzer profiles and protocols

CKGFuzzer is a `harness_generator` baseline. The canonical command is:

```bash
bash scripts/hgb_run_baseline.sh \
  --generator ckgfuzzer \
  --target jsoncpp_jsoncpp_fuzzer \
  --profile alpha \
  --protocol blind-project \
  --strict
```

`alpha` and `paper-faithful` require a real CodeQL database and knowledge graph, a real embedding service (`CKGFUZZER_EMBEDDING_MODEL` must not be `mock`/`local`/empty), upstream LLM API summaries, the upstream API-combination planner, and the upstream compilation-check/repair loop. Mock/hash embeddings, `CKGFUZZER_LOCAL_API_SUMMARY=1`, `CKGFUZZER_LOCAL_API_COMBINATION=1`, source-only graph fallback, and `--skip_check_compilation` are forbidden in `alpha` and `paper-faithful`; a failed or empty CodeQL graph is a failed run, not a successful source fallback.

`compat-smoke` may retain deterministic/mock fallbacks and tiny budgets, but its results are excluded from scientific aggregates (`excluded_from_aggregate=true`, `method_variant=compat-smoke`) and it is never selected by default.

In `blind-project`, CKGFuzzer never receives the exact FuzzBench reference harness, a path to it, or `metadata/fuzzbench_selected_harness_apis.json`. APIs are discovered from public headers, source declarations, project docs, and protocol-allowed examples/tests. A canary leakage audit proves the reference harness never reaches CKG prompts, logs, API lists, summaries, embeddings, or candidates.

Successful generation means exact FuzzBench build + smoke + reachability + campaign + coverage (`status=evaluated`), not merely a saved `.c/.cc` file. `dry_run`, `partial_completed`, `soft_skip`, and `generation_completed` are not `evaluated`.

### OSS-Fuzz-Gen profiles and protocols

OSS-Fuzz-Gen is a `harness_generator` baseline. The canonical command is:

```bash
bash scripts/hgb_run_baseline.sh \
  --generator oss-fuzz-gen \
  --target jsoncpp_jsoncpp_fuzzer \
  --profile alpha \
  --protocol blind-project \
  --strict
```

`alpha` and `paper-faithful` require a real Fuzz Introspector build (`all_functions.json`/`calltree.json`/`type_info.json`/`report_manifest.json`), a target-aware benchmark YAML synthesized from that introspector output, real coverage, automatic compile/build repair (>=3 samples, default 5 repair rounds), and an independent exact-FuzzBench evaluator. The local introspector shim, `OFG_SKIP_COVERAGE_GAINS=1`, empty coverage shims, no-op processes, tiny 1/1/1 budgets, reference-harness examples, and reference-derived API ranking are forbidden in `alpha` and `paper-faithful`; missing benchmark YAML must synthesize or fail (never a soft skip). The OSS-Fuzz checkout is pinned and immutable (`detached-pinned-immutable` in `metadata/work_index.yaml`); cloning floating `master` is forbidden.

`compat-smoke` may use the local introspector shim, 1/1/1 budgets, and coverage skip, but its results are excluded from scientific aggregates (`excluded_from_aggregate=true`, `method_variant=compat-smoke`) and it is never the default.

In `blind-project`, OSS-Fuzz-Gen never receives the exact FuzzBench reference harness (`HGB_TARGET_REFERENCE_DIR` is withheld), never downloads the current target answer via GCS, and never ranks APIs by reference harness calls. A canary leakage audit proves the reference harness never reaches prompts, benchmark YAML, examples, logs, API rankings, or candidates. Successful generation means the independent evaluator reaches `status=evaluated`; only `evaluated` counts as a successful alpha matrix row.

### PromeFuzz profiles and protocols

PromeFuzz is a `harness_generator` baseline. The canonical command is:

```bash
bash scripts/hgb_run_baseline.sh \
  --generator promefuzz \
  --target jsoncpp_jsoncpp_fuzzer \
  --profile alpha \
  --protocol blind-project \
  --strict
```

`alpha` and `paper-faithful` require a real compile database captured from the pinned FuzzBench build (`docker/common/promefuzz_build_context.py` replays the build under `bear`/CMake export with a neutral fuzz-entrypoint stub, never the reference harness body), real link/library context with non-empty `driver_build_args`, legitimate consumer knowledge when available, a real semantic embedding provider (`PROME_FUZZ_EMBEDDING_LLM_TYPE` must not be `mock`/`local`/`hash`; `PROME_FUZZ_EMBEDDING_MODEL` must not be `hgb-hash-embedding`), the official ALL-COVER generation path with practical multi-candidate budgets, iterative native target build validation through `docker/common/promefuzz_target_build.sh`, and the common harness evaluator (`docker/common/promefuzz_evaluator.py`, reusing `ofg_evaluator`) for build + sanitizer smoke + API reachability + fixed-budget campaign + coverage. Synthetic compile databases (`HGB_PROMEFUZZ_SYNTHETIC_COMPILE_DB=1`), hash/mock embeddings, `selected_harness_fallback`/`selected_harness` API selection, `report_first`/`report_only` API report modes, empty `driver_build_args`, and method-changing fallbacks are forbidden in `alpha` and `paper-faithful`; a missing real build context is a concrete failure, not a soft skip.

`compat-smoke` may use the synthetic compile database and local hash embeddings for offline wiring tests only, must set `excluded_from_aggregate=true` and `method_variant=compat-smoke`, and is never selected by default.

In `blind-project`, PromeFuzz never receives the exact FuzzBench reference harness, `metadata/fuzzbench_selected_harness_apis.json`, or reference-derived API filtering; APIs are discovered from public headers/source/build evidence. A canary leakage audit proves the reference harness never reaches prompts, logs, configs, API collections, embeddings, or candidates. Successful generation means the independent evaluator reaches `status=evaluated`; only `evaluated` counts as a successful alpha matrix row.

G2Fuzz is evaluated as an input-generator plus modified-AFL++ workflow. It requires a native target pair (`.afl` and `.cmp`) for the fixed FuzzBench harness; missing target binaries are reported as `infra_missing`, not as a successful or soft-skipped run. `g2fuzz-data` is optional comparison data and is mounted only when explicitly requested with `G2FUZZ_USE_DATA=1`.

## FuzzBench Target Integration

List targets:

```bash
make artifacts
make targets
bash scripts/hgb_targets.sh list --sets
bash scripts/hgb_targets.sh list valuable
```

Use `--targets valuable` for the curated high-signal deduplicated target set, or `--targets deduped` for all unique project/fuzz-target representatives.

Prepare a target package:

```bash
make target-smoke TARGET=jsoncpp_jsoncpp_fuzzer
```

Generate a harness with one generator:

```bash
source configs/set_api_key.sh
make generate GENERATOR=promefuzz TARGET=jsoncpp_jsoncpp_fuzzer
```

Dry-run without calling an LLM:

```bash
make generate-dry-run GENERATOR=ckgfuzzer TARGET=jsoncpp_jsoncpp_fuzzer
```

Run a small matrix:

```bash
bash scripts/hgb_generate_matrix.sh \
  --generators oss-fuzz-gen,ckgfuzzer,promefuzz \
  --targets jsoncpp_jsoncpp_fuzzer,zlib_zlib_uncompress_fuzzer \
  --dry-run
```

ELFuzz and G2Fuzz are input-generation baselines, not source-level harness generators, and are evaluated in a separate `input_generator` leaderboard; matrix summaries split `input_generator` from `harness_generator`. G2Fuzz target-aware runs use `scripts/hgb_run_baseline.sh` directly and report `status=evaluated` only after target-pair discovery, generator synthesis, input validation, modified-AFL campaign execution, and coverage/queue metric collection. ELFuzz synthesizes and evolves input-producing fuzzer programs against a fixed native FuzzBench target (the harness is never generated), then runs a final `elfuzz run rq1.afl` campaign. Applicability is manifest-driven (`metadata/elfuzz_target_adapters.yaml`): the nine text-input targets in `valuable` are applicable and run the full `synth`/`produce`/`run`/coverage workflow; the eleven non-text targets are contractually `Invalid` (`status=not_applicable`, `applicability=Invalid`, `reason_code=elfuzz_non_text_target`) and are resolved before Docker model download, TGI, synthesis, or fuzzing. `alpha` uses nontrivial upstream-default-or-greater budgets (never the 1-iteration/60-second `compat-smoke` values); eligible runs are serialized because the upstream workflow starts a global `tgi-server` Docker container. The legacy `--allow-input-generator` flag is a deprecated no-op; the runner resolves the task family from `metadata/baseline_contracts.yaml`.

If Docker reports a layerdb collision during image preflight, HGB records a per-image guard and later runs fail quickly instead of repeating the image pull. Stop competing builds and have the Docker administrator repair the daemon storage; then retry explicitly with `HGB_RETRY_DOCKER_LAYERDB_BUILD=1`. HGB never prunes or modifies `/data/docker` automatically.
