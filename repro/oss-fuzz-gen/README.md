# OSS-Fuzz-Gen Reproduction

OSS-Fuzz-Gen is Google's LLM-based artifact for generating and evaluating OSS-Fuzz fuzz targets. This wrapper keeps the upstream repository in `external/oss-fuzz-gen` and records HarnessGenBench smoke outputs under `results/oss-fuzz-gen/`.

## Setup

Prepare local environment variables from the template:

```bash
cp repro/oss-fuzz-gen/env.example .env
```

Fill in only the credentials and model settings needed for your backend. Do not commit `.env`.

Then run:

```bash
make clone
bash scripts/oss_fuzz_gen_setup.sh
```

The setup script creates `external/oss-fuzz-gen/.venv-hgb`, installs upstream Python dependencies when available, checks Docker access, and writes setup metadata to `results/oss-fuzz-gen/setup_<timestamp>/metadata.json`.

## Smoke Run

Run the default `tinyxml2` smoke test:

```bash
bash scripts/oss_fuzz_gen_smoke.sh
```

Useful knobs:

```bash
OFG_BENCHMARK=tinyxml2
OFG_MODEL=gpt-4o-mini
OFG_RUN_TIMEOUT=300
OFG_TOTAL_TIMEOUT_SECONDS=600
OFG_MAX_ROUNDS=1
OFG_WORKERS=1
```

Each smoke run writes:

```text
results/oss-fuzz-gen/smoke_<timestamp>/
  run.log
  metadata.json
```

The run can fail before generating harnesses if credentials are missing, Docker cannot build or run OSS-Fuzz images, the selected model/backend is unavailable, the upstream benchmark image fails to build, or an external report query exceeds `OFG_TOTAL_TIMEOUT_SECONDS`. In those cases, `run.log` and `metadata.json` should contain enough detail to reproduce the failure.

## Report Collection

Summarize a run directory:

```bash
bash scripts/oss_fuzz_gen_collect_report.sh results/oss-fuzz-gen/<run-dir>
```

The collector writes `HGB_SUMMARY.md` into that run directory and links to logs, generated fuzz targets, report artifacts, coverage summaries, and Fuzz Introspector files when present.

## Scaling Later

Smoke mode intentionally uses one benchmark and short timeouts. For benchmark-scale reproduction, add a benchmark-set YAML under `configs/` or point `OFG_BENCHMARK` to another upstream benchmark name, increase `OFG_RUN_TIMEOUT`, `OFG_MAX_ROUNDS`, and `OFG_WORKERS`, then run the same smoke script. Keep large generated outputs under `results/` or `artifacts/`.
