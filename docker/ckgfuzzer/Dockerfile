FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv build-essential cmake git curl unzip jq ca-certificates rsync ripgrep universal-ctags bear file pkg-config \
  && rm -rf /var/lib/apt/lists/*
COPY artifacts/ckgfuzzer /opt/hgb/artifacts/ckgfuzzer
RUN python3 -m venv /opt/hgb/venv \
  && /opt/hgb/venv/bin/python -m pip install --upgrade pip \
  && /opt/hgb/venv/bin/python -m pip install beautifulsoup4==4.12.3 chardet==5.2.0 loguru==0.7.2 pandas==2.2.2 pyyaml==6.0.1 tqdm==4.66.4 sympy==1.12 tree-sitter==0.21.3
ARG HGB_INSTALL_CODEQL=0
ARG CODEQL_CLI_URL=https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip
RUN mkdir -p /opt/codeql \
  && if [ -x /opt/hgb/artifacts/ckgfuzzer/docker_shared/codeql/codeql ]; then \
       cp -a /opt/hgb/artifacts/ckgfuzzer/docker_shared/codeql /opt/codeql/codeql; \
     elif [ "$HGB_INSTALL_CODEQL" = "1" ]; then \
       curl -fsSL "$CODEQL_CLI_URL" -o /tmp/codeql.zip \
       && unzip -q /tmp/codeql.zip -d /opt/codeql \
       && rm -f /tmp/codeql.zip; \
     fi
ENV PATH="/opt/hgb/codeql-host:/opt/hgb/codeql-host/codeql:/opt/codeql/codeql:/opt/hgb/venv/bin:${PATH}"
RUN mkdir -p /opt/hgb/bin
COPY docker/common/target_contract.sh docker/common/extract_api_list.py /opt/hgb/bin/
RUN chmod +x /opt/hgb/bin/target_contract.sh /opt/hgb/bin/extract_api_list.py
COPY docker/ckgfuzzer/entrypoint.sh /opt/hgb/entrypoint.sh
RUN chmod +x /opt/hgb/entrypoint.sh
WORKDIR /opt/hgb/artifacts/ckgfuzzer
ENTRYPOINT ["/opt/hgb/entrypoint.sh"]
