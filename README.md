# HarnessGenBench

HarnessGenBench reproduces five fuzzing baselines on a curated set of 20 FuzzBench targets. OSS-Fuzz-Gen, PromeFuzz, and CKGFuzzer generate harnesses; G2Fuzz and ELFuzz generate inputs for fixed harnesses. Runs use Docker and write outputs under `workspace/`.

## Requirements

Run commands from the repository root on Linux. You need Python 3, Git, Make, Docker Engine, access to the Docker socket, enough disk for target builds and model files, and network access to fetch upstream artifacts and images. The setup scripts install baseline tools into their Docker images.

| Baseline | Additional requirements | Image setup |
| --- | --- | --- |
| OSS-Fuzz-Gen | Pinned OSS-Fuzz checkout, Fuzz Introspector, target build, and an OpenAI-compatible chat API. | `make docker-build-oss-fuzz-gen` |
| PromeFuzz | Real target compilation database (captured with Bear/CMake), chat API, and a semantic embedding endpoint. | `make docker-build-promefuzz` |
| CKGFuzzer | CodeQL CLI/database, chat API, and a local semantic embedding model. The setup script installs CodeQL in the image. | `make docker-build-ckgfuzzer` |
| G2Fuzz | Modified AFL++ and target `.afl`/`.cmp` binaries, built from the pinned FuzzBench target, plus a chat API. | `make docker-build-g2fuzz` |
| ELFuzz | TGI-compatible generation service and target build. Native TGI needs model access and an NVIDIA runtime; on a host without that runtime, the integration can use the configured chat API through its TGI proxy. | `make docker-build-elfuzz` |

Fetch upstream sources and build the images:

```bash
make artifacts
make docker-build
```

## Configure your API key

Keep credentials outside the repository in `~/api_keys/HarnessGenBench/set_api_key.sh`. The scripts load this path by default. Create it from the tracked template only if the file does not already exist:

```bash
mkdir -p -m 700 ~/api_keys/HarnessGenBench
cp -n configs/set_api_key.example.sh ~/api_keys/HarnessGenBench/set_api_key.sh
chmod 600 ~/api_keys/HarnessGenBench/set_api_key.sh
$EDITOR ~/api_keys/HarnessGenBench/set_api_key.sh
source ~/api_keys/HarnessGenBench/set_api_key.sh
bash scripts/hgb_llm_preflight.sh --live
```

For example, put your **own** key in that file:

```bash
export HGB_LLM_PROVIDER=deepseek
export API_KEY='YOUR_API_KEY'
```

For another OpenAI-compatible provider, set `HGB_LLM_PROVIDER=custom` and provide `HGB_LLM_API_KEY`, `HGB_LLM_BASE_URL`, and `HGB_LLM_MODEL` in the same file. The template documents the built-in `deepseek` and `ustc` profiles. The preflight command sends one small chat request and does not print the credential. Keep real credentials out of the repository. Use `HGB_API_KEY_CONFIG` to select another file under `~/api_keys/`.

### Local embeddings for CKGFuzzer and PromeFuzz

The current CKGFuzzer reproduction uses [Qwen/Qwen3-Embedding-0.6B](https://huggingface.co/Qwen/Qwen3-Embedding-0.6B) locally through the CPU Text Embeddings Inference server. Download and start it from the repository root:

```bash
python3 -m pip install -U huggingface_hub
python3 scripts/download_embedding_model.py
source configs/local_embedding.example.sh
bash scripts/local_embedding_server.sh start
bash scripts/local_embedding_server.sh probe
```

The example exports `CKGFUZZER_EMBEDDING_BACKEND=openai_compatible_local_tei_cpu`, `CKGFUZZER_EMBEDDING_MODEL=text-embeddings-inference`, `CKGFUZZER_EMBEDDING_BASE_URL=http://host.docker.internal:18080/v1`, and `CKGFUZZER_EMBEDDING_MODEL_SOURCE=Qwen/Qwen3-Embedding-0.6B`. Its local embedding API key is `-`; your chat API key remains separate. You can copy these exports into `~/api_keys/HarnessGenBench/set_api_key.sh` for later shells.

PromeFuzz also needs real embeddings. To use the same local server, add these exports to `~/api_keys/HarnessGenBench/set_api_key.sh` (or export them in the shell before running):

```bash
export PROME_FUZZ_EMBEDDING_LLM_TYPE=openai
export PROME_FUZZ_EMBEDDING_MODEL=text-embeddings-inference
export PROME_FUZZ_EMBEDDING_BASE_URL=http://host.docker.internal:18080/v1
export PROME_FUZZ_EMBEDDING_API_KEY=-
```

## Reproduce the 20 valuable targets

`bash scripts/hgb_targets.sh list valuable` prints the target set. Run these commands after loading your API configuration and starting the embedding service. They use the profiles from the verified reproduction audit:

```bash
bash scripts/hgb_run_baseline_matrix.sh --generator oss-fuzz-gen --profile alpha --protocol blind-project --targets valuable --parallel-worker 5 --strict
bash scripts/hgb_run_baseline_matrix.sh --generator promefuzz --profile alpha --protocol blind-project --targets valuable --parallel-worker 5 --strict
bash scripts/hgb_run_baseline_matrix.sh --generator ckgfuzzer --profile reproduction-eta --protocol blind-project --targets valuable --parallel-worker 5 --strict
bash scripts/hgb_run_baseline_matrix.sh --generator g2fuzz --profile alpha --protocol paper-native --targets valuable --parallel-worker 5 --strict
bash scripts/hgb_run_baseline_matrix.sh --generator elfuzz --profile alpha --protocol paper-native --targets valuable --parallel-worker 5 --strict
```

`--parallel-worker` controls target concurrency; the matrix runner defaults to 5. ELFuzz applies only to the nine text-input targets listed in `metadata/elfuzz_target_adapters.yaml`; its other eleven valuable targets are recorded as not applicable. The runner serializes ELFuzz's shared TGI service. `--strict` exits nonzero when an applicable pair does not reach `evaluated`. Matrix summaries live under `workspace/matrix/<run_id>/`; per-baseline statistics are in `workspace/<baseline>/statistics.json`.

## Run generation and fuzzing separately

Phase A records the verified generated harnesses and inputs for every applicable pair. Existing artifacts are reused; generation runs only where an artifact is missing.

```bash
python3 scripts/hgb_eval_all.py --phase generate --parallel-worker 32
```

Phase B starts a fresh 24-hour fuzzing campaign from each saved Phase A artifact. It reuses verified harness images when present, does not repeat successful Phase A smoke checks, and does not call a baseline's generator or LLM. Run it after Phase A succeeds:

```bash
time python3 scripts/hgb_eval_all.py \
    --phase fuzz \
    --parallel-worker 64 \
    --campaign-seconds 86400 \
    --memory-per-job-gib 8
```

The date defaults to today. Phase A writes `workspace/eval_all/YYYY-MM-DD.phase_a.json` and `.phase_a.csv`; Phase B uses that manifest and updates `workspace/eval_all/YYYY-MM-DD.csv` as jobs finish. If today's manifest is absent, the script copies the latest complete saved Phase A manifest into today's workspace path. The default run ID records the phase, date, and campaign duration, such as `eval_all_phase_b_20261016_86400s`. Supply a new `--output` and `--run-id` for another run on the same day.

For repeated independent fuzzing campaigns of every applicable saved artifact, add `--trials 5` to the Phase B command. The default is one trial. Five trials create `workspace/eval_all/YYYY-MM-DD.trials5.csv` with one row per target and trial, plus `workspace/eval_all/YYYY-MM-DD.trials5.summary.csv` with mean and sample standard deviation of covered lines from completed trials. Trials of the same baseline and target can run concurrently; each has its own run directory and log. `--resume` keeps completed trials and gives unfinished trials new run directories.

The default is 64 workers. Each replay container is limited to one logical CPU and 8 GiB RAM. In Phase B, `--parallel-worker` is a ceiling: the scheduler samples this run's outer and campaign container memory plus host available memory every 15 seconds, then admits at most four new jobs per sample. `--memory-budget-gib` limits the projected combined usage (default: 70% of host RAM), while a separate host reserve protects other workloads. If memory sampling fails, the scheduler temporarily uses the older cap-based limit. Phase A still uses the cap-based limit. Docker image builds also use host memory. Generated harnesses, inputs, fuzzing artifacts, logs, and evaluation reports go under `workspace/`. Phase B records `N/A` for out-of-scope pairs. Use `--plan` with either phase to inspect its jobs without launching Docker, and `--resume` to continue an existing CSV. Saved-input libFuzzer campaigns continue after crash, OOM, and target timeout findings and preserve their artifact files. ELFuzz Phase B labels its method variant `saved-input-libfuzzer`.
