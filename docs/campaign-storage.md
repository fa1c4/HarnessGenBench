# Campaign storage design

HGB keeps high-frequency fuzzing state in memory and writes selected evidence
to `workspace/` at intervals. Campaign-managed writable paths are its
`workspace/` (including bind-mounted shared caches) and `/tmp`. Docker image layers and the
daemon's own storage remain Docker-managed; the campaign does not use them as
an AFL output or libFuzzer corpus directory.

## Storage classes

| Data | Active location | Durable location |
|---|---|---|
| AFL working input, queue, crashes, hangs, `fuzzer_stats` | container `/tmp` tmpfs | incremental checkpoint under `workspace/campaign/` |
| libFuzzer corpus, artifact prefix, fork-mode temporary files, active log | container `/tmp/hgb-campaign` tmpfs (`TMPDIR` points there) | `workspace/.../campaign/live_corpus`, `live_artifacts`, recent log checkpoint |
| Final corpus, crash artifacts, full log, metrics, coverage inputs | tmpfs until campaign exit | `workspace/`, with the existing Phase B archive verification and fsync |
| Docker copy-in seed staging and final archive transport | container `/tmp` overlay | copied to `workspace/` once; these are bounded setup/finalization writes |

The tmpfs size defaults to **4 GiB per campaign** and is configurable with
`HGB_CAMPAIGN_TMPFS_SIZE` (Docker size syntax, for example `6g`). It is a
maximum, not a reservation. Actual use counts against the campaign container's
memory limit and the Phase B host memory scheduler. A full tmpfs causes a
campaign failure instead of silently spilling the hot workload to `/data`.
Choose the size with the target's memory demand and concurrent job count in
mind.

`HGB_CAMPAIGN_CHECKPOINT_SECONDS` defaults to **300 seconds**. G2Fuzz copies
only new or changed queue, crash, hang, and statistics files to
`workspace/campaign/output/`, using an atomic replacement for each file. The
ELFuzz upstream AFL run uses Python temporary directories; its AFL findings
are copied to `workspace/campaign/live_checkpoint/` while running. Its final
compressed result archive goes directly to `workspace/campaign/afl_results/`. The
libFuzzer runner copies new or changed corpus and artifact files plus a recent
log tail to its mounted workspace. These live checkpoints are recovery
material; the final verified corpus archive is authoritative for measurement.
Phase A and Phase B shared-runner campaigns both checkpoint when the outer
container supplies `HGB_WORKSPACE_HOST`.
The worst-case loss on an unexpected stop is the work since the last
successful checkpoint.

## Baseline IO audit

| Baseline | Fuzzing path | Previous high-frequency disk path | New hot path |
|---|---|---|---|
| CKGFuzzer | shared `hgb_harness_evaluator` libFuzzer campaign | inner Docker `/tmp/corpus`, `/tmp/artifacts`, fork temporary files on `/data/docker` | inner `/tmp/hgb-campaign` tmpfs |
| PromeFuzz | same shared evaluator | same | same |
| OSS-Fuzz-Gen | same shared evaluator | same | same |
| G2Fuzz | modified AFL++ `-o` | `/workspace/campaign/output` bind mounted on `/data` | outer container `/tmp` tmpfs; `-o` and active log are in a per-campaign directory |
| ELFuzz | upstream `elfuzz run rq1.afl`, then saved-input libFuzzer replay in Phase B | upstream `tempfile.TemporaryDirectory()` on Docker overlay; Phase B shared runner | outer `/tmp` tmpfs with AFL checkpoints; Phase B shared tmpfs runner |

The shared runner sets `TMPDIR` to its tmpfs mount because [libFuzzer reads
that environment variable for temporary files](https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/fuzzer/FuzzerIOPosix.cpp).

CKGFuzzer's CodeQL database, PromeFuzz and OSS-Fuzz-Gen's generated sources,
target builds, and ELFuzz's selected generated inputs remain durable evidence
in the workspace. These are build/generation outputs rather than per-execution
fuzzer state. ELFuzz has a 300-second archive grace after its AFL time budget
(zero in CI smoke profiles). The shared libFuzzer runner writes one final corpus archive to
`/tmp` before copying it to the workspace. Those sequential finalization
writes are intentional.

## Lifecycle and recovery

Each successful campaign removes its own hot directory after persisting final
results. Docker releases tmpfs automatically if its container stops
unexpectedly. G2Fuzz and ELFuzz also remove their per-campaign `/tmp` trees in
the normal and handled-error paths. For a direct host run that leaves an HGB
directory in `/tmp`, inspect it with `bash scripts/clean_tmp.sh`; after
checking that no owner PID is active, run `bash scripts/clean_tmp.sh --execute`.
The script only considers the current user's stale `/tmp/hgb-campaign-*`
directories and does not remove Docker containers or saved workspace results.

## Verification

Use the campaign storage unit tests and the affected baseline campaign tests.
For an operational check, compare `iostat -dxm sda 1` before and after a new
campaign: the hot-path small-write rate should fall while the periodic
workspace checkpoint and final archive writes remain visible. Existing running
containers retain their original mounts and need a newly started campaign to
use this design.
