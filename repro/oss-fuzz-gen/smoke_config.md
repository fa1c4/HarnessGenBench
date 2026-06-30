# OSS-Fuzz-Gen Smoke Configuration

The smoke workflow runs one OSS-Fuzz-Gen benchmark with short runtime settings.

Default values:

```bash
OFG_BENCHMARK=tinyxml2
OFG_MODEL=gpt-4o-mini
OFG_RUN_TIMEOUT=300
OFG_TOTAL_TIMEOUT_SECONDS=600
OFG_MAX_ROUNDS=1
OFG_WORKERS=1
```

The smoke script looks first for:

```text
external/oss-fuzz-gen/benchmark-sets/all/${OFG_BENCHMARK}.yaml
```

If that file is absent, it searches `external/oss-fuzz-gen/benchmark-sets/` for a YAML file whose filename or contents mention the benchmark name.

Outputs are written to:

```text
results/oss-fuzz-gen/smoke_<UTC timestamp>/
```

Each run contains `run.log` and `metadata.json`. Generated upstream artifacts remain under that run directory and are ignored by git.

`OFG_RUN_TIMEOUT` is passed to OSS-Fuzz-Gen as the per-run timeout. `OFG_TOTAL_TIMEOUT_SECONDS` is an outer HarnessGenBench timeout that preserves logs and metadata if upstream setup, model calls, or external report queries linger.
