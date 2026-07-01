# G2FUZZ Reproduction

```bash
make artifacts
bash scripts/g2fuzz_setup.sh
bash scripts/g2fuzz_select_target.sh
bash scripts/g2fuzz_generate_seeds.sh || true
bash scripts/g2fuzz_smoke_afl.sh || true
bash scripts/g2fuzz_collect_report.sh workspace/g2fuzz/<run-id>
```

The HGB Docker image copies `artifacts/g2fuzz` and `artifacts/g2fuzz-data` into `/opt/hgb/artifacts/`, installs `openai==1.63.2`, and builds G2FUZZ with `make source-only`.

Seed generation uses a runtime-only `openai_key.txt` under `/run/hgb` inside the container, not in the mounted workspace. Config copies and outputs are written under `workspace/g2fuzz/<run-id>/`.

G2FUZZ AFL target binaries are not bundled. `g2fuzz_smoke_afl.sh` searches `$G2FUZZ_TARGET_DIR`, `/workspace/targets/<program>/`, and `/opt/hgb/artifacts/g2fuzz/`. Missing `.afl` and `.cmp` binaries soft-skip by default and produce `TARGET_BUILD_MISSING.md`; set `G2FUZZ_REQUIRE_TARGET_BINARIES=1` to make that condition fail.
