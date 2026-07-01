FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip git make binutils curl ca-certificates docker.io \
  && rm -rf /var/lib/apt/lists/*
COPY artifacts/oss-fuzz-gen /opt/hgb/artifacts/oss-fuzz-gen
RUN python3 -m venv /opt/hgb/venv \
  && if [ -f /opt/hgb/artifacts/oss-fuzz-gen/requirements.txt ]; then /opt/hgb/venv/bin/python -m pip install --upgrade pip && /opt/hgb/venv/bin/python -m pip install -r /opt/hgb/artifacts/oss-fuzz-gen/requirements.txt; fi
COPY docker/oss-fuzz-gen/entrypoint.sh /opt/hgb/entrypoint.sh
RUN chmod +x /opt/hgb/entrypoint.sh
WORKDIR /opt/hgb/artifacts/oss-fuzz-gen
ENTRYPOINT ["/opt/hgb/entrypoint.sh"]
