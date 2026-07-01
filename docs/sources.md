# Source Registry

This registry records upstream sources pinned by `metadata/work_index.yaml`. Run `make artifacts` to refresh all ignored checkouts under `artifacts/` and overwrite the pinned work index.

## OSS-Fuzz-Gen

- Paper / article URL: https://arxiv.org/abs/2307.12469
- Artifact repository URL: https://github.com/google/oss-fuzz-gen
- Optional dataset / reports URL: https://github.com/google/oss-fuzz-gen/tree/main/report
- Local path: `artifacts/oss-fuzz-gen`
- Docker output path: `workspace/oss-fuzz-gen/`

## CKGFuzzer

- Paper / article URL: https://arxiv.org/abs/2411.11532
- Artifact repository URL: https://github.com/security-pride/CKGFuzzer
- Optional dataset / Zenodo URL: TBD
- Local path: `artifacts/ckgfuzzer`
- Docker output path: `workspace/ckgfuzzer/`

## PromeFuzz

- Paper / article URL: TBD
- Artifact repository URL: https://github.com/pvz122/PromeFuzz
- Optional dataset / Zenodo URL: TBD
- Local path: `artifacts/promefuzz`
- Docker output path: `workspace/promefuzz/`

## ELFuzz

- Paper / article URL: https://arxiv.org/abs/2506.10323
- Artifact repository URL: https://github.com/OSUSecLab/elfuzz
- Optional dataset / Docker image URL: https://ghcr.io/osuseclab/elfuzz
- Local path: `artifacts/elfuzz`
- Docker output path: `workspace/elfuzz/`

## G2FUZZ

- Paper / article URL: TBD
- Artifact repository URL: https://github.com/G2FUZZ/G2FUZZ
- Optional dataset / Zenodo URL: https://github.com/G2FUZZ/G2FUZZ-DATA
- Local paths: `artifacts/g2fuzz`, `artifacts/g2fuzz-data`
- Docker output path: `workspace/g2fuzz/`
