# Generator Target Capabilities

| Generator | Capability | `generate-target` default | Notes |
|---|---|---|---|
| OSS-Fuzz-Gen | harness generator | run if OFG YAML exists, otherwise soft-skip | Needs a function/test benchmark YAML, not just a FuzzBench fuzz target. |
| CKGFuzzer | harness generator | run | Needs API candidates, runtime config, and usually CodeQL/call graph support. |
| PromeFuzz | harness generator | run if compile DB exists, otherwise soft-skip | Needs headers and `compile_commands.json`. |
| ELFuzz | input generator | soft-skip | Can run with `--allow-input-generator`. |
| G2FUZZ | input generator | soft-skip | Can run seed/input generation with `--allow-input-generator`. |

All target-aware runs execute inside Docker. Host-side outputs stay under `workspace/`, and upstream artifacts or target source checkouts stay under `artifacts/`.
