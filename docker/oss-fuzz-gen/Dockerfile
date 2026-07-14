FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip python3-dev build-essential git make binutils curl ca-certificates docker.io jq rsync ripgrep universal-ctags bear file pkg-config libffi-dev libssl-dev \
  && rm -rf /var/lib/apt/lists/*
ARG OFG_OSS_FUZZ_REPO=https://github.com/google/oss-fuzz.git
ARG OFG_OSS_FUZZ_REF=master
ARG OFG_INSTALL_OSS_FUZZ=1
COPY artifacts/oss-fuzz-gen/requirements.txt /tmp/oss-fuzz-gen-requirements.txt
RUN python3 -m venv /opt/hgb/venv \
  && /opt/hgb/venv/bin/python -m pip install --upgrade pip "setuptools==80.9.0" wheel \
  && /opt/hgb/venv/bin/python -m pip install -r /tmp/oss-fuzz-gen-requirements.txt \
  && /opt/hgb/venv/bin/python -m pip install "setuptools==80.9.0" \
  && /opt/hgb/venv/bin/python -c "import pkg_resources; import google.cloud.logging"
RUN if [ "$OFG_INSTALL_OSS_FUZZ" = "1" ]; then \
      git clone --depth 1 --branch "$OFG_OSS_FUZZ_REF" "$OFG_OSS_FUZZ_REPO" /opt/hgb/oss-fuzz; \
    else \
      mkdir -p /opt/hgb/oss-fuzz; \
    fi
RUN python3 -m venv /opt/hgb/oss-fuzz-venv \
  && /opt/hgb/oss-fuzz-venv/bin/python -m pip install --upgrade pip "setuptools==80.9.0" wheel \
  && if [ -f /opt/hgb/oss-fuzz/infra/build/functions/requirements.txt ]; then \
      /opt/hgb/oss-fuzz-venv/bin/python -m pip install -r /opt/hgb/oss-fuzz/infra/build/functions/requirements.txt; \
    fi \
  && /opt/hgb/oss-fuzz-venv/bin/python -m pip install "setuptools==80.9.0" \
  && /opt/hgb/oss-fuzz-venv/bin/python -c "import pkg_resources; import yaml"
COPY artifacts/oss-fuzz-gen /opt/hgb/artifacts/oss-fuzz-gen
ENV OFG_OSS_FUZZ_DIR=/opt/hgb/oss-fuzz
ENV OFG_OSS_FUZZ_VENV=/opt/hgb/oss-fuzz-venv
RUN mkdir -p /opt/hgb/bin
COPY docker/common/target_contract.sh docker/common/extract_api_list.py docker/common/ofg_api_rank.py docker/common/hgb_api_report.py docker/common/ofg_select_benchmark.py docker/common/ofg_run_wrapper.py docker/common/ofg_trim_benchmark.py docker/common/hgb_llm_trace.py docker/common/llm_provider.sh /opt/hgb/bin/
RUN chmod +x /opt/hgb/bin/target_contract.sh /opt/hgb/bin/llm_provider.sh /opt/hgb/bin/extract_api_list.py /opt/hgb/bin/ofg_select_benchmark.py /opt/hgb/bin/ofg_run_wrapper.py /opt/hgb/bin/ofg_trim_benchmark.py
COPY docker/oss-fuzz-gen/entrypoint.sh /opt/hgb/entrypoint.sh
RUN chmod +x /opt/hgb/entrypoint.sh
WORKDIR /opt/hgb/artifacts/oss-fuzz-gen
ENTRYPOINT ["/opt/hgb/entrypoint.sh"]
