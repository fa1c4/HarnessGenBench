# CKGFuzzer Reproduction

CKGFuzzer is an LLM-based fuzz-driver generation artifact enhanced by code knowledge graph extraction. This wrapper keeps the upstream source in `external/CKGFuzzer` and writes all generated workspaces and smoke outputs under `results/ckgfuzzer/`.

## Setup

Prepare local environment variables from the template when you want to run LLM-backed stages:

```bash
cp repro/ckgfuzzer/env.example .env
```

Do not commit `.env`. The wrapper never writes `OPENAI_API_KEY` into generated `config.yaml`; model credentials must be handled outside git-tracked files.

Run setup:

```bash
make clone
bash scripts/ckgfuzzer_setup.sh
```

The setup script creates `external/CKGFuzzer/.venv-hgb`, installs a smoke-sized dependency set derived from upstream requirements, checks Docker, and checks for CodeQL. By default, missing CodeQL is a graceful setup failure after metadata is written. Install CodeQL yourself under `external/CKGFuzzer/docker_shared/codeql/` or run:

```bash
bash scripts/ckgfuzzer_setup.sh --install-codeql
```

## Prepare Project

```bash
bash scripts/ckgfuzzer_prepare_project.sh
```

The script first searches for an upstream project with `config.yaml`, `api_list.json`, tests, and a Dockerfile. The current upstream checkout does not include committed `api_list.json` files, so the wrapper prepares `hgb-sample` from `repro/ckgfuzzer/sample_project/`.

Prepared files are written to:

```text
results/ckgfuzzer/workspace/<project>/
```

For CKGFuzzer compatibility, the script creates controlled symlinks inside the ignored upstream checkout:

```text
external/CKGFuzzer/fuzzing_llm_engine/projects/<project>
external/CKGFuzzer/fuzzing_llm_engine/external_database/<project>
```

## Smoke Run

```bash
bash scripts/ckgfuzzer_smoke.sh || true
bash scripts/ckgfuzzer_collect_report.sh results/ckgfuzzer/<run-dir>
```

The smoke script runs the real upstream stages with separate logs:

```text
repo.log
preproc.log
fuzzing.log
```

It records exit codes in `metadata.json` and copies small generated artifacts into `generated/`. The sample workspace includes a tiny preseeded API database so `preproc.py` can still be exercised even when CodeQL is missing.

## Common Failure Causes

- Missing CodeQL: `repo.py` cannot create a CodeQL database.
- Docker permission problems: project image build or compile-check containers fail.
- Absolute path assumptions: upstream code expects project directories below `fuzzing_llm_engine/projects/`.
- Missing LLM credentials or unavailable model backend: `fuzzing.py` fails during summary/generation.
- Python dependency gaps: upstream `requirements.txt` is a Conda export, so full reproduction may require a Conda environment rather than only the smoke venv.
- Generated drivers may fail compilation; check `fuzzing.log` and copied files in `generated/`.

## Scaling Later

After the smoke path works, prepare a real target by adding `api_list.json`, usage tests, and project Docker files under a generated workspace or an upstream-compatible project directory. Increase `CKGFUZZER_TIMEOUT_SECONDS` and use a real CodeQL installation plus model credentials.
