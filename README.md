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

ELFuzz and G2Fuzz are input-generation baselines, not source-level harness generators. G2Fuzz target-aware runs use `scripts/hgb_run_baseline.sh` directly and report `status=evaluated` only after target-pair discovery, generator synthesis, input validation, modified-AFL campaign execution, and coverage/queue metric collection. The ELFuzz mappings exercised by `valuable` are `jsoncpp_jsoncpp_fuzzer`, `libxml2_xml`, `re2_fuzzer`, and `sqlite3_ossfuzz` (with optional cpython/librsvg and explicit override mappings); the matrix marks other targets as not applicable without preparing them, and serializes eligible runs because the upstream workflow starts a global `tgi-server` Docker container.

If Docker reports a layerdb collision during image preflight, HGB records a per-image guard and later runs fail quickly instead of repeating the image pull. Stop competing builds and have the Docker administrator repair the daemon storage; then retry explicitly with `HGB_RETRY_DOCKER_LAYERDB_BUILD=1`. HGB never prunes or modifies `/data/docker` automatically.
