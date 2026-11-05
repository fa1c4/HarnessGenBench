# Memory-first campaign implementation plan

1. Audit all five baseline fuzzing paths and identify active corpus, AFL output,
   temporary input, logs, and durable evidence. The path matrix is in
   `campaign-storage.md`.
2. Give each campaign a bounded tmpfs hot area. Move G2Fuzz AFL `-o`, ELFuzz
   upstream temporary AFL output, and the shared libFuzzer corpus/artifact/log
   paths there. Preserve the baseline's fuzzing command and time budget.
3. Checkpoint only valuable findings and status into `workspace/` every 300
   seconds, then save and validate the final corpus and evidence before marking
   a campaign complete.
4. Remove the campaign's own temporary tree on completion. Use
   `scripts/clean_tmp.sh` manually for stale host `/tmp` trees after an
   interrupted direct run; Docker releases its tmpfs mounts on stop.
5. Run syntax checks and focused tests for AFL checkpointing, all shared
   libFuzzer consumers, and the G2Fuzz/ELFuzz campaign paths. Compare live IO
   only after new campaigns are launched with the new container configuration.
