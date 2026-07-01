FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv build-essential git make zlib1g-dev clang llvm lld llvm-dev ca-certificates jq rsync ripgrep universal-ctags bear file pkg-config \
  && rm -rf /var/lib/apt/lists/*
COPY artifacts/g2fuzz /opt/hgb/artifacts/g2fuzz
COPY artifacts/g2fuzz-data /opt/hgb/artifacts/g2fuzz-data
RUN python3 -m venv /opt/hgb/venv \
  && /opt/hgb/venv/bin/python -m pip install --upgrade pip \
  && /opt/hgb/venv/bin/python -m pip install openai==1.63.2 \
  && cd /opt/hgb/artifacts/g2fuzz \
  && make source-only
ENV PATH="/opt/hgb/venv/bin:${PATH}"
RUN mkdir -p /opt/hgb/bin /opt/hgb/metadata
COPY docker/common/target_contract.sh docker/common/extract_api_list.py /opt/hgb/bin/
COPY metadata/fuzzbench_target_formats.json /opt/hgb/metadata/fuzzbench_target_formats.json
RUN chmod +x /opt/hgb/bin/target_contract.sh /opt/hgb/bin/extract_api_list.py
COPY docker/g2fuzz/entrypoint.sh /opt/hgb/entrypoint.sh
RUN chmod +x /opt/hgb/entrypoint.sh
WORKDIR /opt/hgb/artifacts/g2fuzz
ENTRYPOINT ["/opt/hgb/entrypoint.sh"]
