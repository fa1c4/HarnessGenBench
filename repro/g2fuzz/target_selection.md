# G2FUZZ Target Selection

- Selected program: `jhead`
- Formats: `jpg, xmp`
- Reason: auto-selected as upstream README example and G2FUZZ-DATA reference target
- AFL binary: `auto-built from pinned FuzzBench target`
- CMPLOG binary: `auto-built from pinned FuzzBench target (AFL_LLVM_CMPLOG=1)`
- Reference data path: `artifacts/g2fuzz-data/unifuzz/G2FUZZ_GPT35/jhead`

G2Fuzz auto-builds the `.afl`/`.cmp` target pair from the pinned FuzzBench
benchmark source inside the G2Fuzz image (CC/CXX = modified afl-clang-fast,
FUZZING_ENGINE=afl, SANITIZER=address; CmpLog for `.cmp`). A host-provided pair
may still be supplied via `G2FUZZ_TARGET_DIR` as an optional override. Missing
toolchain or a failed build is `infra_missing`/`infra_failure`, never a soft
skip.
