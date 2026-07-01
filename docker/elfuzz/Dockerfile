FROM ghcr.io/osuseclab/elfuzz:25.08.0
USER root
SHELL ["/bin/bash", "-lc"]
COPY artifacts/elfuzz /opt/hgb/artifacts/elfuzz
RUN if command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y --no-install-recommends python3 git jq rsync ripgrep universal-ctags bear file pkg-config && rm -rf /var/lib/apt/lists/*; fi || true
RUN mkdir -p /opt/hgb/bin
COPY docker/common/target_contract.sh docker/common/extract_api_list.py /opt/hgb/bin/
RUN chmod +x /opt/hgb/bin/target_contract.sh /opt/hgb/bin/extract_api_list.py
COPY docker/elfuzz/entrypoint.sh /opt/hgb/entrypoint.sh
RUN chmod +x /opt/hgb/entrypoint.sh
ENTRYPOINT ["/opt/hgb/entrypoint.sh"]
