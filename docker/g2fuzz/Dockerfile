FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv build-essential git make zlib1g-dev clang llvm lld llvm-dev ca-certificates jq rsync ripgrep universal-ctags bear file pkg-config \
    libclang-rt-18-dev libclang-common-18-dev libc++-18-dev libc++abi-18-dev \
    autoconf automake libtool cmake ninja-build meson flex bison yasm nasm ragel ruby tcl \
    re2c gawk subversion libcap-dev libz-dev liblzma-dev g++ wget zip unzip gperf m4 gettext \
    libssl-dev libxml2-dev libsqlite3-dev libbz2-dev libjpeg-dev libpng-dev \
    libmount-dev libgcrypt20-dev libc6-dev-i386 lib32stdc++-12-dev libstdc++-12-dev \
    python3-jinja2 curl \
  && rm -rf /var/lib/apt/lists/*
COPY artifacts/g2fuzz /opt/hgb/artifacts/g2fuzz
RUN python3 -m venv /opt/hgb/venv \
  && /opt/hgb/venv/bin/python -m pip install --upgrade pip \
  && /opt/hgb/venv/bin/python -m pip install openai==1.63.2 \
  && /opt/hgb/venv/bin/python -m pip install ninja "meson==0.56.0" \
  && cd /opt/hgb/artifacts/g2fuzz \
  && make source-only
ENV PATH="/opt/hgb/venv/bin:${PATH}"
RUN mkdir -p /opt/hgb/bin /opt/hgb/metadata
COPY docker/common/target_contract.sh docker/common/extract_api_list.py docker/common/ofg_api_rank.py docker/common/hgb_llm_trace.py docker/common/llm_provider.sh docker/common/g2fuzz_target_pipeline.py docker/common/g2fuzz_contract.py docker/common/hgb_coverage.py docker/common/hgb_input_campaign.py docker/common/hgb_fuzzbench_builder.py /opt/hgb/bin/
COPY metadata/fuzzbench_target_formats.json /opt/hgb/metadata/fuzzbench_target_formats.json
COPY metadata/fuzzbench_targets.json metadata/g2fuzz_target_adapters.yaml metadata/baseline_contracts.yaml /opt/hgb/metadata/
COPY repro/g2fuzz/specs /opt/hgb/repro/g2fuzz/specs
RUN chmod +x /opt/hgb/bin/target_contract.sh /opt/hgb/bin/llm_provider.sh /opt/hgb/bin/extract_api_list.py /opt/hgb/bin/g2fuzz_target_pipeline.py /opt/hgb/bin/g2fuzz_contract.py /opt/hgb/bin/hgb_coverage.py /opt/hgb/bin/hgb_input_campaign.py /opt/hgb/bin/hgb_fuzzbench_builder.py
COPY docker/g2fuzz/entrypoint.sh /opt/hgb/entrypoint.sh
RUN chmod +x /opt/hgb/entrypoint.sh
WORKDIR /opt/hgb/artifacts/g2fuzz
ENTRYPOINT ["/opt/hgb/entrypoint.sh"]
