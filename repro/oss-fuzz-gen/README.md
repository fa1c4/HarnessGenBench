# OSS-Fuzz-Gen Reproduction

```bash
make artifacts
bash scripts/oss_fuzz_gen_setup.sh
bash scripts/oss_fuzz_gen_smoke.sh || true
bash scripts/oss_fuzz_gen_collect_report.sh workspace/oss-fuzz-gen/<run-id>
```

The setup script builds the HarnessGenBench Docker image from `docker/oss-fuzz-gen/Dockerfile`, copying the pinned checkout from `artifacts/oss-fuzz-gen`. Smoke output is written to `workspace/oss-fuzz-gen/<run-id>/`.

Configure LLM settings with `configs/set_api_key.sh`; the Docker run receives only environment variables. OSS-Fuzz-Gen also receives `/var/run/docker.sock` because upstream invokes Docker/OSS-Fuzz builders.
