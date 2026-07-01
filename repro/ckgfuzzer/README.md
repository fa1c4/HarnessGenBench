# CKGFuzzer Reproduction

```bash
make artifacts
bash scripts/ckgfuzzer_setup.sh
bash scripts/ckgfuzzer_smoke.sh || true
bash scripts/ckgfuzzer_collect_report.sh workspace/ckgfuzzer/<run-id>
```

The HGB Docker image copies `artifacts/ckgfuzzer` into `/opt/hgb/artifacts/ckgfuzzer`. The smoke entrypoint prepares a small `hgb-sample` project under `workspace/ckgfuzzer/<run-id>/project/hgb-sample` when a complete upstream example is unavailable. Its `build.sh` is location-independent and can be run from any current working directory.

LLM configuration is sourced on the host from `configs/set_api_key.sh` and passed to Docker as environment variables.
