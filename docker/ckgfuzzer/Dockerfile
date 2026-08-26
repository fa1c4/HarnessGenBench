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
COPY docker/common/target_contract.sh docker/common/extract_api_list.py docker/common/ofg_api_rank.py docker/common/hgb_api_report.py docker/common/ckgfuzzer_stage_project.py docker/common/ckgfuzzer_cache.py docker/common/ckgfuzzer_runtime_patch.py docker/common/ckgfuzzer_candidate_verifier.py docker/common/ckgfuzzer_target_harness.py docker/common/ckgfuzzer_verifier_context.py docker/common/ckgfuzzer_api_recovery.py docker/common/ckgfuzzer_rescue_candidates.py docker/common/ckgfuzzer_profile.py docker/common/ckgfuzzer_model_config.py docker/common/hgb_llm_trace.py docker/common/hgb_target_package.py docker/common/hgb_result.py docker/common/hgb_coverage.py docker/common/hgb_reachability.py docker/common/hgb_fuzzbench_builder.py docker/common/hgb_harness_evaluator.py docker/common/llm_provider.sh /opt/hgb/bin/
RUN chmod +x /opt/hgb/bin/target_contract.sh /opt/hgb/bin/llm_provider.sh /opt/hgb/bin/extract_api_list.py /opt/hgb/bin/ckgfuzzer_stage_project.py /opt/hgb/bin/ckgfuzzer_cache.py /opt/hgb/bin/ckgfuzzer_runtime_patch.py /opt/hgb/bin/ckgfuzzer_candidate_verifier.py /opt/hgb/bin/ckgfuzzer_target_harness.py /opt/hgb/bin/ckgfuzzer_verifier_context.py /opt/hgb/bin/ckgfuzzer_api_recovery.py /opt/hgb/bin/ckgfuzzer_rescue_candidates.py /opt/hgb/bin/ckgfuzzer_profile.py /opt/hgb/bin/hgb_harness_evaluator.py /opt/hgb/bin/hgb_fuzzbench_builder.py
COPY docker/ckgfuzzer/entrypoint.sh /opt/hgb/entrypoint.sh
RUN chmod +x /opt/hgb/entrypoint.sh
RUN mkdir -p /opt/hgb/build-markers \
  && touch /opt/hgb/build-markers/ckgfuzzer_api_selection_ranked_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_entrypoint_python_init_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_ustc_embedding_runtime_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_embedding_model_name_override_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_local_embedding_theta3_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_embedding_batch_size_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_evaluator_compile_coverage_seed_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_codeql_cache_graph_counts_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_bloaty_staged_project_rescue_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_coverage_compile_cache_key_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_coverage_late_sanitizer_env_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_coverage_inline_compile_env_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_reachability_cpp_symbols_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_split_benchmark_context_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_candidate_language_normalization_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_cwe_index_cache_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_external_verifier_check_defer_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_legacy_fuzzer_lib_alias_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_cpp_fuzzer_entrypoint_abi_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_target_rescue_candidates_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_curl_single_target_sealed_deps_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_campaign_internal_timeout_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_primary_api_plan_filter_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_expanded_target_rescues_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_all_valuable_rescues_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_zero_candidate_rescue_override_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_function_like_api_plan_filter_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_rescue_first_fast_path_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_remaining_targets_fix_theta_v1 \
  && touch /opt/hgb/build-markers/ckgfuzzer_blind_project_name_only_report_apis_v1
# Self-test: verify profile module, upstream CLI availability, and candidate checker.
RUN /opt/hgb/venv/bin/python -c "import sys; sys.path.insert(0, '/opt/hgb/bin'); import ckgfuzzer_profile; print('ckgfuzzer_profile OK')" \
  && test -f /opt/hgb/artifacts/ckgfuzzer/fuzzing_llm_engine/repo/repo.py \
  && test -f /opt/hgb/artifacts/ckgfuzzer/fuzzing_llm_engine/repo/preproc.py \
  && test -f /opt/hgb/artifacts/ckgfuzzer/fuzzing_llm_engine/fuzzing.py \
  && /opt/hgb/venv/bin/python -c "import sys; sys.path.insert(0, '/opt/hgb/bin'); import ckgfuzzer_profile; v = ckgfuzzer_profile.validate_profile('alpha', 'blind-project', {'CKGFUZZER_EMBEDDING_MODEL': 'openai-text-embedding-3-small'}); assert not v, v; print('alpha profile validation OK')" \
  && /opt/hgb/venv/bin/python -c "import sys; sys.path.insert(0, '/opt/hgb/bin'); import ckgfuzzer_profile; v = ckgfuzzer_profile.validate_profile('compat-smoke', 'blind-project', {}); assert not v, v; print('compat-smoke profile validation OK')" \
  && /opt/hgb/venv/bin/python -c "import sys; sys.path.insert(0, '/opt/hgb/bin'); import hgb_harness_evaluator, hgb_result, hgb_coverage, hgb_reachability, hgb_target_package, hgb_fuzzbench_builder; print('beta evaluator modules OK')" \
  && /opt/hgb/venv/bin/python -c "import sys; sys.path.insert(0, '/opt/hgb/bin'); import hgb_fuzzbench_builder as b; assert b.deterministic_image_tag('r1','t1','c1').startswith('hgb-ckgfuzzer-'); print('deterministic image tag OK')"
WORKDIR /opt/hgb/artifacts/ckgfuzzer
ENTRYPOINT ["/opt/hgb/entrypoint.sh"]
