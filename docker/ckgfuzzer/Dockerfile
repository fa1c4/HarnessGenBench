FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv build-essential cmake git curl unzip jq ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY artifacts/ckgfuzzer /opt/hgb/artifacts/ckgfuzzer
RUN python3 -m venv /opt/hgb/venv \
  && /opt/hgb/venv/bin/python -m pip install --upgrade pip \
  && /opt/hgb/venv/bin/python -m pip install beautifulsoup4==4.12.3 chardet==5.2.0 loguru==0.7.2 pandas==2.2.2 pyyaml==6.0.1 tqdm==4.66.4 sympy==1.12 tree-sitter==0.21.3 \
  && mkdir -p /opt/codeql \
  && if [ -x /opt/hgb/artifacts/ckgfuzzer/docker_shared/codeql/codeql ]; then cp -a /opt/hgb/artifacts/ckgfuzzer/docker_shared/codeql /opt/codeql/codeql; fi
ENV PATH="/opt/codeql/codeql:/opt/hgb/venv/bin:${PATH}"
COPY docker/ckgfuzzer/entrypoint.sh /opt/hgb/entrypoint.sh
RUN chmod +x /opt/hgb/entrypoint.sh
WORKDIR /opt/hgb/artifacts/ckgfuzzer
ENTRYPOINT ["/opt/hgb/entrypoint.sh"]
