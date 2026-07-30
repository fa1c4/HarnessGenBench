FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv build-essential cmake ninja-build git curl wget ca-certificates pkg-config clang llvm llvm-dev libclang-dev libclang-rt-18-dev clang-format libomp-dev make jq rsync ripgrep universal-ctags bear file zip xz-utils zlib1g-dev libssl-dev libffi-dev libsqlite3-dev libbz2-dev liblzma-dev apt-transport-https gnupg \
  && rm -rf /var/lib/apt/lists/*
COPY artifacts/promefuzz /opt/hgb/artifacts/promefuzz
RUN python3 -m venv /opt/hgb/venv \
  && /opt/hgb/venv/bin/python -m pip install --upgrade pip setuptools wheel \
  && if [ -f /opt/hgb/artifacts/promefuzz/requirements.txt ]; then /opt/hgb/venv/bin/python -m pip install -r /opt/hgb/artifacts/promefuzz/requirements.txt; fi
RUN /opt/hgb/venv/bin/python -m pip install pdfminer.six nltk \
  && mkdir -p /opt/hgb/nltk_data \
  && /opt/hgb/venv/bin/python - <<'PY_NLTK_DOWNLOAD'
import nltk
for package in (
    "punkt",
    "punkt_tab",
    "averaged_perceptron_tagger",
    "averaged_perceptron_tagger_eng",
):
    nltk.download(package, download_dir="/opt/hgb/nltk_data", quiet=True)
PY_NLTK_DOWNLOAD
ENV NLTK_DATA=/opt/hgb/nltk_data
RUN cd /opt/hgb/artifacts/promefuzz \
  && bash ./setup.sh \
  && test -x build/bin/preprocessor \
  && test -x build/bin/cgprocessor
ENV PATH="/opt/hgb/venv/bin:${PATH}"
RUN mkdir -p /opt/hgb/bin
COPY docker/common/target_contract.sh docker/common/extract_api_list.py docker/common/ofg_api_rank.py docker/common/hgb_api_report.py docker/common/hgb_llm_trace.py docker/common/llm_provider.sh docker/common/hgb_compile_db.py docker/common/hgb_target_harness.py docker/common/promefuzz_target_build.sh /opt/hgb/bin/
RUN chmod +x /opt/hgb/bin/target_contract.sh /opt/hgb/bin/llm_provider.sh /opt/hgb/bin/extract_api_list.py /opt/hgb/bin/hgb_compile_db.py /opt/hgb/bin/hgb_target_harness.py /opt/hgb/bin/promefuzz_target_build.sh
COPY docker/promefuzz/entrypoint.sh /opt/hgb/entrypoint.sh
RUN chmod +x /opt/hgb/entrypoint.sh
# FuzzBench recipes normally inherit these utilities from OSS-Fuzz base images.
# Native target validation replays those recipes in this smaller image, so keep
# the compatibility layer separate from PromeFuzz's cached Python/tool build.
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf automake libtool libtool-bin flex bison ragel yasm nasm \
    ruby rake tcl re2c subversion libgcrypt20-dev libcap-dev \
  && ln -sfn /opt/hgb/venv/bin/python /usr/local/bin/python3.8 \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/hgb/artifacts/promefuzz
ENTRYPOINT ["/opt/hgb/entrypoint.sh"]
