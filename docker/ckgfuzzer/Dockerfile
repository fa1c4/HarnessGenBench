FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv build-essential cmake git curl jq ca-certificates rsync ripgrep universal-ctags bear file pkg-config docker.io \
  && rm -rf /var/lib/apt/lists/*
COPY artifacts/ckgfuzzer /opt/hgb/artifacts/ckgfuzzer
RUN python3 -m venv /opt/hgb/venv \
  && /opt/hgb/venv/bin/python -m pip install --upgrade pip \
  && /opt/hgb/venv/bin/python -m pip install beautifulsoup4==4.12.3 chardet==5.2.0 loguru==0.7.2 pandas==2.2.2 pyyaml==6.0.1 tqdm==4.66.4 sympy==1.12 tree-sitter==0.21.3
ARG HGB_INSTALL_CODEQL=1
ARG CODEQL_BUNDLE_URL=https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.25.6/codeql-bundle-linux64.tar.gz
RUN mkdir -p /opt/codeql \
  && if [ -x /opt/hgb/artifacts/ckgfuzzer/docker_shared/codeql/codeql ]; then \
       cp -a /opt/hgb/artifacts/ckgfuzzer/docker_shared/codeql /opt/codeql/codeql; \
     elif [ "$HGB_INSTALL_CODEQL" = "1" ]; then \
       curl -fsSL "$CODEQL_BUNDLE_URL" -o /tmp/codeql-bundle.tar.gz \
       && tar -xzf /tmp/codeql-bundle.tar.gz -C /opt/codeql \
       && rm -f /tmp/codeql-bundle.tar.gz; \
     fi
ENV PATH="/opt/hgb/codeql-host:/opt/hgb/codeql-host/codeql:/opt/codeql/codeql:/opt/hgb/venv/bin:${PATH}"
RUN /opt/hgb/venv/bin/python -m pip install --upgrade setuptools wheel \
  && /opt/hgb/venv/bin/python -m pip install \
    llama-index-core==0.11.8 \
    llama-index-legacy==0.9.48 \
    chromadb==0.5.5 \
    openai==1.40.8 \
  && /opt/hgb/venv/bin/python -m pip install --no-deps \
    llama-index-llms-openai-like==0.2.0 \
    llama-index-llms-ollama==0.1.5 \
    llama-index-embeddings-openai==0.2.4 \
    llama-index-embeddings-ollama==0.1.2 \
    llama-index-embeddings-huggingface==0.3.1 \
    llama-index-vector-stores-chroma==0.2.0
RUN /opt/hgb/venv/bin/python -m pip install --no-deps llama-index-llms-openai==0.2.3
RUN /opt/hgb/venv/bin/python -m pip install llama-index-readers-file==0.2.1
RUN /opt/hgb/venv/bin/python -m pip install httpx==0.27.0 httpcore==1.0.5
RUN /opt/hgb/venv/bin/python -m pip install transformers==4.44.0
RUN mkdir -p /opt/hgb/artifacts/ckgfuzzer/fuzzing_llm_engine/codetext/parser/tree-sitter \
  && git clone --depth 1 --branch v0.20.5 https://github.com/tree-sitter/tree-sitter-cpp.git /opt/hgb/artifacts/ckgfuzzer/fuzzing_llm_engine/codetext/parser/tree-sitter/tree-sitter-cpp \
  && /opt/hgb/venv/bin/python -c "from tree_sitter import Language; Language.build_library('/opt/hgb/artifacts/ckgfuzzer/fuzzing_llm_engine/codetext/parser/tree-sitter/cpp.so', ['/opt/hgb/artifacts/ckgfuzzer/fuzzing_llm_engine/codetext/parser/tree-sitter/tree-sitter-cpp'])"
RUN mkdir -p /opt/hgb/bin
COPY docker/common/target_contract.sh docker/common/extract_api_list.py /opt/hgb/bin/
RUN chmod +x /opt/hgb/bin/target_contract.sh /opt/hgb/bin/extract_api_list.py
COPY docker/ckgfuzzer/entrypoint.sh /opt/hgb/entrypoint.sh
RUN chmod +x /opt/hgb/entrypoint.sh
WORKDIR /opt/hgb/artifacts/ckgfuzzer
ENTRYPOINT ["/opt/hgb/entrypoint.sh"]
