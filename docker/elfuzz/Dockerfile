# ELFuzz base image. Prefer pinning by digest for reproducibility:
#   docker build --build-arg ELFUZZ_BASE_IMAGE=ghcr.io/osuseclab/elfuzz@sha256:<digest> ...
# The human-readable tag is retained below and recorded in image provenance.
ARG ELFUZZ_BASE_IMAGE=ghcr.io/osuseclab/elfuzz:25.08.0
ARG ELFUZZ_BASE_TAG=25.08.0
FROM ${ELFUZZ_BASE_IMAGE}
ARG ELFUZZ_BASE_TAG
LABEL org.harnessgenbench.elfuzz.base_tag="${ELFUZZ_BASE_TAG}"
USER root
SHELL ["/bin/bash", "-lc"]
COPY artifacts/elfuzz /opt/hgb/artifacts/elfuzz
RUN if command -v apt-get >/dev/null 2>&1; then \
      apt-get update && apt-get install -y --no-install-recommends \
        python3 git jq rsync ripgrep universal-ctags bear file pkg-config && \
      rm -rf /var/lib/apt/lists/* ; \
    fi
RUN mkdir -p /opt/hgb/bin /opt/hgb/metadata /opt/hgb/scripts
COPY metadata /opt/hgb/metadata
COPY repro /opt/hgb/repro
COPY docker/common/target_contract.sh docker/common/extract_api_list.py docker/common/ofg_api_rank.py docker/common/hgb_llm_trace.py docker/common/llm_provider.sh docker/common/elfuzz_target_pipeline.py /opt/hgb/bin/
RUN chmod +x /opt/hgb/bin/target_contract.sh /opt/hgb/bin/llm_provider.sh /opt/hgb/bin/extract_api_list.py /opt/hgb/bin/elfuzz_target_pipeline.py
COPY docker/elfuzz/entrypoint.sh /opt/hgb/entrypoint.sh
RUN chmod +x /opt/hgb/entrypoint.sh
# Image self-test: verify the ELFuzz CLI, adapter registration, trace hook, and
# the target invocation helper are wired. This fails the build if the pinned
# artifact layout changed incompatibly.
RUN set -e ; \
    python3 -m py_compile /opt/hgb/bin/elfuzz_target_pipeline.py ; \
    python3 /opt/hgb/bin/elfuzz_target_pipeline.py validate-adapters --metadata-root /opt/hgb/metadata ; \
    python3 /opt/hgb/bin/elfuzz_target_pipeline.py classify --target jsoncpp_jsoncpp_fuzzer --metadata-root /opt/hgb/metadata | grep -q '"applicability": "applicable"' ; \
    python3 /opt/hgb/bin/elfuzz_target_pipeline.py classify --target libpng_libpng_read_fuzzer --metadata-root /opt/hgb/metadata | grep -q '"applicability": "Invalid"' ; \
    test -f /opt/hgb/bin/hgb_llm_trace.py ; \
    grep -q 'stage=.elfuzz.' /opt/hgb/entrypoint.sh
ENTRYPOINT ["/opt/hgb/entrypoint.sh"]
