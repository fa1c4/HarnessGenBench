# ELFuzz Reproduction

```bash
make artifacts
bash scripts/elfuzz_pull_image.sh
bash scripts/elfuzz_start_container.sh --smoke || true
bash scripts/elfuzz_smoke_jsoncpp.sh || true
bash scripts/elfuzz_copy_results.sh workspace/elfuzz/<run-id>
```

The primary image is built from `docker/elfuzz/Dockerfile`, based on `ghcr.io/osuseclab/elfuzz:25.08.0`, and copies `artifacts/elfuzz` into the image. Smoke runs are direct `docker run --rm --init` executions with `workspace/elfuzz/<run-id>/` mounted at `/workspace`.

`elfuzz_start_container.sh --shell` is available for manual debugging and invokes shell commands as `bash -lc ...`.
