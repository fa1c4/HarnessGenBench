# PromeFuzz Config Notes

The Docker reproduction no longer writes persistent TOML files containing LLM settings under `results/` or `workspace/`.

At container runtime, `docker/promefuzz/entrypoint.sh` derives a temporary config at `/run/hgb/promefuzz_config.toml` from Docker environment variables:

- `API_KEY` / `OPENAI_API_KEY`
- `BASE_URL` / `OPENAI_BASE_URL`
- `MODEL` / `OPENAI_MODEL`

Metadata records only `api_key_present`, never the key value.
