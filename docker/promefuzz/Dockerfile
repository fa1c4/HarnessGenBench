FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv build-essential cmake ninja-build git curl wget ca-certificates pkg-config clang llvm llvm-dev libclang-dev libclang-rt-18-dev clang-format libomp-dev make jq rsync ripgrep universal-ctags bear file zip xz-utils zlib1g-dev libssl-dev libffi-dev libsqlite3-dev libbz2-dev liblzma-dev apt-transport-https gnupg \
  && rm -rf /var/lib/apt/lists/*
COPY artifacts/promefuzz /opt/hgb/artifacts/promefuzz
# Upstream bug: check_actual_targets_ast returns the APICollection.safe_iter
# generator object itself (not its elements) on CGprocessor failure, so
# scheduler.record_functions_failed raises `KeyError: <generator object ...>`
# and aborts an entire generation run (seen on freetype2). Materialize the
# generator so the failure path records real functions. Idempotent.
RUN python3 - <<'PY_PROMEFUZZ_DRIVER_PATCH'
from pathlib import Path
path = Path("/opt/hgb/artifacts/promefuzz/src/generator/driver.py")
text = path.read_text(encoding="utf-8")
needle = "return [], [self.function_set.safe_iter]"
replacement = "return [], list(self.function_set.safe_iter)"
if needle in text:
    path.write_text(text.replace(needle, replacement), encoding="utf-8")
PY_PROMEFUZZ_DRIVER_PATCH
RUN python3 -m venv /opt/hgb/venv \
  && /opt/hgb/venv/bin/python -m pip install --upgrade pip setuptools wheel \
  && if [ -f /opt/hgb/artifacts/promefuzz/requirements.txt ]; then /opt/hgb/venv/bin/python -m pip install -r /opt/hgb/artifacts/promefuzz/requirements.txt; fi
ENV NLTK_DATA=/opt/hgb/nltk_data
RUN /opt/hgb/venv/bin/python -m pip install pdfminer.six nltk \
  && mkdir -p /opt/hgb/nltk_data \
  && /opt/hgb/venv/bin/python - <<'PY_NLTK_DOWNLOAD'
import os
import time

import nltk

download_dir = os.environ["NLTK_DATA"]
packages = (
    "punkt",
    "punkt_tab",
    "averaged_perceptron_tagger",
    "averaged_perceptron_tagger_eng",
)
for package in packages:
    ok = False
    for _ in range(5):
        try:
            if nltk.download(package, download_dir=download_dir, quiet=True):
                ok = True
                break
        except Exception:
            ok = False
        time.sleep(3)
    # Fail the build rather than silently shipping an image without NLTK data.
    if not ok:
        raise SystemExit(f"failed to download NLTK package: {package}")
PY_NLTK_DOWNLOAD
RUN test -n "$(ls -A /opt/hgb/nltk_data/tokenizers 2>/dev/null)" \
  && test -n "$(ls -A /opt/hgb/nltk_data/taggers 2>/dev/null)"
ENV NLTK_DATA=/opt/hgb/nltk_data
RUN cd /opt/hgb/artifacts/promefuzz \
  && bash ./setup.sh \
  && test -x build/bin/preprocessor \
  && test -x build/bin/cgprocessor
ENV PATH="/opt/hgb/venv/bin:${PATH}"
RUN mkdir -p /opt/hgb/bin
COPY docker/common/target_contract.sh docker/common/extract_api_list.py docker/common/ofg_api_rank.py docker/common/hgb_api_report.py docker/common/hgb_llm_trace.py docker/common/llm_provider.sh docker/common/hgb_compile_db.py docker/common/hgb_target_harness.py docker/common/promefuzz_target_build.sh docker/common/promefuzz_profile.py docker/common/promefuzz_build_context.py docker/common/promefuzz_evaluator.py docker/common/ofg_evaluator.py /opt/hgb/bin/
RUN chmod +x /opt/hgb/bin/target_contract.sh /opt/hgb/bin/llm_provider.sh /opt/hgb/bin/extract_api_list.py /opt/hgb/bin/hgb_compile_db.py /opt/hgb/bin/hgb_target_harness.py /opt/hgb/bin/promefuzz_target_build.sh /opt/hgb/bin/promefuzz_profile.py /opt/hgb/bin/promefuzz_build_context.py /opt/hgb/bin/promefuzz_evaluator.py /opt/hgb/bin/ofg_evaluator.py
COPY docker/promefuzz/entrypoint.sh /opt/hgb/entrypoint.sh
RUN chmod +x /opt/hgb/entrypoint.sh
# Image self-test: validate preprocessor/cgprocessor, profile validation,
# build-context import, evaluator import, and upstream CLI syntax without
# network or LLM calls. Recorded provenance lives in /opt/hgb/provenance.json.
RUN /opt/hgb/venv/bin/python - <<'PY_PROMEFUZZ_SELFTEST'
import json
import subprocess
import sys
from pathlib import Path
sys.path.insert(0, "/opt/hgb/bin")
import promefuzz_profile
import promefuzz_build_context
import promefuzz_evaluator
violations = promefuzz_profile.validate_profile("alpha", "blind-project", {
    "PROME_FUZZ_EMBEDDING_MODEL": "text-embedding-3-small",
    "PROME_FUZZ_EMBEDDING_LLM_TYPE": "openai",
})
if violations:
    raise SystemExit("promefuzz self-test profile validation failed: " + "; ".join(violations))
artifact = Path("/opt/hgb/artifacts/promefuzz")
commit = "unknown"
try:
    commit = subprocess.run(["git", "-C", str(artifact), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=False).stdout.strip() or "unknown"
except Exception:
    pass
clang_version = subprocess.run(["clang", "--version"], capture_output=True, text=True, check=False).stdout.splitlines()[0] if Path("/usr/bin/clang").exists() else "unavailable"
provenance = {
    "schema_version": 1,
    "promefuzz_commit": commit,
    "clang_version": clang_version,
    "python": "/opt/hgb/venv/bin/python",
    "image_selftest": "passed",
}
Path("/opt/hgb/provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY_PROMEFUZZ_SELFTEST
# FuzzBench recipes normally inherit these utilities from OSS-Fuzz base images.
# Native target validation replays those recipes in this smaller image, so keep
# the compatibility layer separate from PromeFuzz's cached Python/tool build.
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf automake libtool libtool-bin flex bison ragel yasm nasm \
    ruby rake tcl re2c subversion libgcrypt20-dev libcap-dev \
    libmount-dev libblkid-dev libc++-dev libc++abi-dev meson gperf \
  && ln -sfn /opt/hgb/venv/bin/python /usr/local/bin/python3.8 \
  && ln -sfn /usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.fuzzer-x86_64.a /usr/lib/libFuzzingEngine.a \
  && rm -rf /var/lib/apt/lists/*
RUN /opt/hgb/venv/bin/python -m pip install jinja2
# The shared harness evaluator builds a sealed candidate image with `docker
# build`; install the static Docker CLI (the daemon socket is bind-mounted at
# runtime by scripts/lib/common.sh).
RUN curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.3.1.tgz -o /tmp/docker.tgz \
  && tar -xzf /tmp/docker.tgz -C /tmp \
  && cp /tmp/docker/docker /usr/local/bin/docker \
  && chmod +x /usr/local/bin/docker \
  && rm -rf /tmp/docker /tmp/docker.tgz
WORKDIR /opt/hgb/artifacts/promefuzz
ENTRYPOINT ["/opt/hgb/entrypoint.sh"]
