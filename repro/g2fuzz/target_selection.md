# G2FUZZ Target Selection

- Selected program: `jhead`
- Formats: `jpg, xmp`
- Reason: auto-selected as upstream README example and G2FUZZ-DATA reference target; local .afl/.cmp binaries are not bundled
- AFL binary: `not found`
- CMPLOG binary: `not found`
- Reference data path: `/data/zym/HarnessGenBench/external/G2FUZZ-DATA/unifuzz/G2FUZZ_GPT35/jhead`

The upstream README uses `jhead` as its seed-generation and AFL command example. The local source/data checkouts do not include target `.afl` and `.cmp` binaries, so `scripts/g2fuzz_smoke_afl.sh` will write `TARGET_BUILD_MISSING.md` unless you provide those binaries with `G2FUZZ_TARGET_DIR` or `results/g2fuzz/targets/jhead/`.
