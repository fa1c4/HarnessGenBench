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
