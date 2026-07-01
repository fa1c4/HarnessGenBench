# PromeFuzz Reproduction

```bash
make artifacts
bash scripts/promefuzz_build_docker.sh
bash scripts/promefuzz_smoke_pugixml.sh || true
bash scripts/promefuzz_collect_report.sh workspace/promefuzz/<run-id>
```

The HGB Docker image copies `artifacts/promefuzz` into `/opt/hgb/artifacts/promefuzz`. Runtime LLM config is generated inside the container at `/run/hgb/promefuzz_config.toml`; persistent `results/` or `workspace/` configs do not contain secrets. Metadata records only whether an API key was present.

The smoke target is `pugixml`. If the upstream CLI changes or credentials are missing, the run should still leave metadata, logs, and `HGB_SUMMARY.md` in `workspace/promefuzz/<run-id>/`.
