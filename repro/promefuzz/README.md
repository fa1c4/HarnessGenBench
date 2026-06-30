# PromeFuzz Reproduction

This workflow wraps the official `pvz122/PromeFuzz` artifact and starts with
the upstream `pugixml` example.

```bash
make clone
bash scripts/promefuzz_build_docker.sh
bash scripts/promefuzz_setup_config.sh
bash scripts/promefuzz_smoke_pugixml.sh || true
bash scripts/promefuzz_collect_report.sh results/promefuzz/<run-dir>
```

Copy `repro/promefuzz/env.example` into `.env` or export equivalent variables
before running the setup and smoke scripts. `OPENAI_API_KEY` is required for the
comprehension and generation stages. The generated TOML leaves `api_key = ""`,
so PromeFuzz reads the secret from the runtime environment instead of from a
tracked or generated config file.

Docker is the default path because upstream ships a Dockerfile. The local image
name used by this repo is `hgb-promefuzz:latest`; build evidence is written to
`results/promefuzz/setup_<timestamp>/metadata.json`.

Smoke logs are written under `results/promefuzz/smoke_<timestamp>/logs/`.
Generated PromeFuzz outputs remain in the ignored upstream workspace at
`external/PromeFuzz/database/pugixml/latest/out/`, and a focused copy of
generated fuzz drivers is preserved under the smoke run's `artifacts/` directory
when the generation stage reaches that point.

To expand beyond `pugixml`, fetch or prepare the target library using the
upstream database layout, pass the target `lib.toml` with `-F`, and run the same
stage order used by `scripts/promefuzz_smoke_pugixml.sh`: fetch/build,
preprocess, comprehend, generate, synthesize, build, run, and stats.
