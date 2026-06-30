# G2FUZZ Reproduction

This workflow wraps the official `G2FUZZ/G2FUZZ` artifact plus optional
reference outputs from `G2FUZZ/G2FUZZ-DATA`.

```bash
make clone
bash scripts/g2fuzz_setup.sh
bash scripts/g2fuzz_select_target.sh
bash scripts/g2fuzz_generate_seeds.sh || true
bash scripts/g2fuzz_smoke_afl.sh results/g2fuzz/<seed-run> || true
bash scripts/g2fuzz_collect_report.sh results/g2fuzz/<run-dir>
```

Copy `repro/g2fuzz/env.example` to `.env` or export equivalent variables.
`OPENAI_API_KEY` is required for real seed generation because upstream reads
`openai_key.txt` from the runtime working directory. The wrapper creates that
file only under ignored `results/g2fuzz/seeds_*/runtime/`.

Target selection reads `external/G2FUZZ/program_to_format.json`. In auto mode,
the script prefers targets with local `.afl` and `.cmp` binaries. The current
source and data checkouts do not ship those binaries, so auto mode selects
`jhead`, the upstream README example, and records that AFL cannot run until
`jhead.afl` and `jhead.cmp` are supplied.

The AFL smoke requires:

```text
<program>.afl
<program>.cmp
```

Set `G2FUZZ_TARGET_DIR` to a directory containing those files, or place them
under `results/g2fuzz/targets/<program>/`. Generated seeds, AFL queues, crashes,
hangs, and credential files are ignored and remain in `results/g2fuzz/`.

For comparison with prior runs, see `external/G2FUZZ-DATA/unifuzz/G2FUZZ_GPT35`
and `external/G2FUZZ-DATA/unifuzz/G2FUZZ_GPT4`.
