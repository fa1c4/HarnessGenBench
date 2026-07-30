FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv build-essential git make zlib1g-dev clang llvm lld llvm-dev ca-certificates jq rsync ripgrep universal-ctags bear file pkg-config \
  && rm -rf /var/lib/apt/lists/*
COPY artifacts/g2fuzz /opt/hgb/artifacts/g2fuzz
RUN python3 -m venv /opt/hgb/venv \
  && /opt/hgb/venv/bin/python -m pip install --upgrade pip \
  && /opt/hgb/venv/bin/python -m pip install openai==1.63.2 \
  && cd /opt/hgb/artifacts/g2fuzz \
  && make source-only
ENV PATH="/opt/hgb/venv/bin:${PATH}"
RUN mkdir -p /opt/hgb/bin /opt/hgb/metadata
COPY docker/common/target_contract.sh docker/common/extract_api_list.py docker/common/ofg_api_rank.py docker/common/hgb_llm_trace.py docker/common/llm_provider.sh docker/common/g2fuzz_target_pipeline.py /opt/hgb/bin/
COPY metadata/fuzzbench_target_formats.json /opt/hgb/metadata/fuzzbench_target_formats.json
COPY metadata/fuzzbench_targets.json metadata/g2fuzz_target_adapters.yaml metadata/baseline_contracts.yaml /opt/hgb/metadata/
COPY repro/g2fuzz/specs /opt/hgb/repro/g2fuzz/specs
RUN chmod +x /opt/hgb/bin/target_contract.sh /opt/hgb/bin/llm_provider.sh /opt/hgb/bin/extract_api_list.py /opt/hgb/bin/g2fuzz_target_pipeline.py
COPY docker/g2fuzz/entrypoint.sh /opt/hgb/entrypoint.sh
RUN chmod +x /opt/hgb/entrypoint.sh
WORKDIR /opt/hgb/artifacts/g2fuzz
ENTRYPOINT ["/opt/hgb/entrypoint.sh"]
