# G2FUZZ Target Selection

- Selected program: `jhead`
- Formats: `jpg, xmp`
- Reason: auto-selected as upstream README example and G2FUZZ-DATA reference target; local `.afl`/`.cmp` binaries are not bundled
- AFL binary: `not found`
- CMPLOG binary: `not found`
- Reference data path: `artifacts/g2fuzz-data/unifuzz/G2FUZZ_GPT35/jhead`

G2FUZZ AFL target binaries are not bundled in the pinned artifact checkout. Docker smoke runs search `$G2FUZZ_TARGET_DIR`, `/workspace/targets/jhead/`, and `/opt/hgb/artifacts/g2fuzz/`. Missing binaries soft-skip by default and write `TARGET_BUILD_MISSING.md`.
