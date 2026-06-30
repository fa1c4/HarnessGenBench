# Source Registry

This registry records the upstream sources that later reproduction tasks should inspect and pin through `metadata/work_index.yaml`.

## OSS-Fuzz-Gen

- Paper / article URL: https://arxiv.org/abs/2307.12469
- Artifact repository URL: https://github.com/google/oss-fuzz-gen
- Optional dataset / reports URL: https://github.com/google/oss-fuzz-gen/tree/main/report
- Reproduction coverage: small OSS-Fuzz-Gen smoke workflow for one benchmark, then hooks for broader benchmark sets.

## CKGFuzzer

- Paper / article URL: https://arxiv.org/abs/2411.11532
- Artifact repository URL: https://github.com/security-pride/CKGFuzzer
- Optional dataset / Zenodo URL: TBD
- Reproduction coverage: code-knowledge-graph preparation, preprocessing, LLM driver generation, and compile checking on one small project.

## PromeFuzz

- Paper / article URL: TBD
- Artifact repository URL: https://github.com/pvz122/PromeFuzz
- Optional dataset / Zenodo URL: TBD
- Reproduction coverage: upstream `pugixml` workflow from setup through driver generation, synthesis, smoke execution, and statistics.

## ELFuzz

- Paper / article URL: https://arxiv.org/abs/2506.10323
- Artifact repository URL: https://github.com/OSUSecLab/elfuzz
- Optional dataset / Docker image URL: https://ghcr.io/osuseclab/elfuzz
- Reproduction coverage: official Docker-image smoke run for one target with small-model synthesis and short seed/coverage steps.

## G2FUZZ

- Paper / article URL: TBD
- Artifact repository URL: https://github.com/G2FUZZ/G2FUZZ
- Optional dataset / Zenodo URL: https://github.com/G2FUZZ/G2FUZZ-DATA
- Reproduction coverage: source build, target selection, seed/program generation, and a short AFL++ run when target binaries are available.
