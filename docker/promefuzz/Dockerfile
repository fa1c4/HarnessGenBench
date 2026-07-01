FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv build-essential cmake git curl ca-certificates pkg-config clang llvm make \
  && rm -rf /var/lib/apt/lists/*
COPY artifacts/promefuzz /opt/hgb/artifacts/promefuzz
RUN python3 -m venv /opt/hgb/venv \
  && /opt/hgb/venv/bin/python -m pip install --upgrade pip \
  && if [ -f /opt/hgb/artifacts/promefuzz/requirements.txt ]; then /opt/hgb/venv/bin/python -m pip install -r /opt/hgb/artifacts/promefuzz/requirements.txt; fi
ENV PATH="/opt/hgb/venv/bin:${PATH}"
COPY docker/promefuzz/entrypoint.sh /opt/hgb/entrypoint.sh
RUN chmod +x /opt/hgb/entrypoint.sh
WORKDIR /opt/hgb/artifacts/promefuzz
ENTRYPOINT ["/opt/hgb/entrypoint.sh"]
