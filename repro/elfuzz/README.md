# ELFuzz Reproduction

This workflow wraps the official ELFuzz Docker artifact:
`ghcr.io/osuseclab/elfuzz:25.08.0`.

```bash
make clone
bash scripts/elfuzz_pull_image.sh
bash scripts/elfuzz_start_container.sh
bash scripts/elfuzz_smoke_jsoncpp.sh || true
bash scripts/elfuzz_copy_results.sh
```

Copy `repro/elfuzz/env.example` to `.env` or export equivalent variables before
running the scripts. `HF_TOKEN` is optional for container startup, but fuzzer
synthesis may fail without it when model downloads require Hugging Face access.

The start script creates a detached container named
`${ELFUZZ_CONTAINER:-elfuzz-hgb}` so the smoke script can drive it with
`docker exec`. It mounts `results/elfuzz/host-tmp` at `/tmp/host` and the host
Docker socket at `/var/run/docker.sock`, matching the artifact's sibling
container requirement.

The default smoke is deliberately small: `jsoncpp`, `fuzzer.elfuzz`, the small
model option, one evolution iteration, 60 seconds of seed production, and a
short optional AFL++ run. Full RQ1/RQ2/RQ3 commands are documented in the
upstream Docker README; after the smoke works, expand by increasing the target
set, repetitions, fuzzing time, and evolution iterations.

Generated corpora, model caches, AFL++ workspaces, downloaded Zenodo data, and
large archives stay under ignored `results/elfuzz` or inside the container.
`scripts/elfuzz_copy_results.sh` copies only small logs, spreadsheets, plots,
and generated fuzzer files into `results/elfuzz/export_<timestamp>/`.
