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
bash scripts/g2fuzz_generate_seeds.sh || true
bash scripts/g2fuzz_smoke_afl.sh || true
```

LLM-backed smoke runs may fail because credentials, quota, model access, Docker-in-Docker, or upstream CLIs are unavailable. They should still leave `metadata.json`, logs, and `HGB_SUMMARY.md` in `workspace/`.

G2FUZZ target `.afl` and `.cmp` binaries are not bundled by the upstream artifact. Missing target binaries soft-skip by default and produce `TARGET_BUILD_MISSING.md`; set `G2FUZZ_REQUIRE_TARGET_BINARIES=1` to make that condition fail.

## FuzzBench Target Integration

List targets:

```bash
make artifacts
make targets
```

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

ELFuzz and G2FUZZ are input-generation baselines, not source-level harness generators. Their target-aware runs soft-skip by default with `not_harness_generator`; pass `--allow-input-generator` to run them as input-generation baselines.
