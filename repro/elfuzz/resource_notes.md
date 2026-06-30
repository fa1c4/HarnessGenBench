# ELFuzz Resource Notes

ELFuzz is packaged as a large Docker artifact and expects sibling containers,
substantial writable storage, and enough CPU/GPU capacity for LLM serving.

HarnessGenBench defaults are intentionally small:

- `ELFUZZ_CPUS=8`
- `ELFUZZ_STORAGE_SIZE=100G`
- `ELFUZZ_TARGET=jsoncpp`
- `ELFUZZ_EVOLUTION_ITERATIONS=1`
- `ELFUZZ_TGI_WAITING_SECONDS=120`
- `ELFUZZ_PRODUCE_SECONDS=60`
- `ELFUZZ_AFL_SECONDS=300`

The official docs recommend setting `/proc/sys/kernel/core_pattern` to `core`
before AFL++ runs:

```bash
sudo sh -c 'echo core > /proc/sys/kernel/core_pattern'
```

The synthesis stage may need a Hugging Face token because the artifact starts a
text-generation-inference server and downloads models. Set `HF_TOKEN` in `.env`
or export it in the shell. The wrapper passes it into the container without
printing it to logs.

The official `elfuzz download` step can download and relocate very large
Zenodo data. For a dry infrastructure check, set `ELFUZZ_SKIP_DOWNLOAD=1`; for a
normal artifact smoke, leave it unset.
