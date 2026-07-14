import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def resolve_provider(**overrides: str) -> tuple[str, str, str, str]:
    env = os.environ.copy()
    for name in (
        "API_KEY",
        "BASE_URL",
        "MODEL",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_MODEL",
        "HGB_LLM_PROVIDER",
        "HGB_LLM_API_KEY",
        "HGB_LLM_BASE_URL",
        "HGB_LLM_MODEL",
    ):
        env.pop(name, None)
    env.update(overrides)
    command = (
        "source docker/common/llm_provider.sh; hgb_resolve_llm_provider; "
        'printf "%s|%s|%s|%s\\n" "$HGB_LLM_PROVIDER_RESOLVED" '
        '"$OPENAI_BASE_URL" "$OPENAI_MODEL" '
        '"$([[ -n \"$OPENAI_API_KEY\" ]] && printf true || printf false)"'
    )
    result = subprocess.run(
        ["bash", "-c", command],
        cwd=ROOT,
        env=env,
        check=True,
        text=True,
        capture_output=True,
    )
    return tuple(result.stdout.strip().split("|"))  # type: ignore[return-value]


def test_ustc_profile_uses_its_documented_defaults() -> None:
    assert resolve_provider(HGB_LLM_PROVIDER="ustc") == (
        "ustc",
        "https://api.llm.ustc.edu.cn",
        "glm-5.2",
        "false",
    )


def test_deepseek_profile_accepts_explicit_model_and_key() -> None:
    assert resolve_provider(
        HGB_LLM_PROVIDER="deepseek",
        HGB_LLM_MODEL="deepseek-v4-flash",
        HGB_LLM_API_KEY="test-key",
    ) == (
        "deepseek",
        "https://api.deepseek.com",
        "deepseek-v4-flash",
        "true",
    )


def test_legacy_variables_remain_compatible_and_auto_detect_provider() -> None:
    assert resolve_provider(
        API_KEY="test-key",
        BASE_URL="https://api.deepseek.com",
        MODEL="deepseek-v4-pro",
    ) == (
        "deepseek",
        "https://api.deepseek.com",
        "deepseek-v4-pro",
        "true",
    )


def test_explicit_base_url_is_preserved_without_path_rewriting() -> None:
    assert resolve_provider(
        HGB_LLM_PROVIDER="custom",
        HGB_LLM_BASE_URL="https://provider.example/openai/v1",
        HGB_LLM_MODEL="provider-model",
    )[:3] == (
        "custom",
        "https://provider.example/openai/v1",
        "provider-model",
    )


def test_all_generator_images_source_the_shared_resolver() -> None:
    for generator in ("oss-fuzz-gen", "ckgfuzzer", "promefuzz", "g2fuzz", "elfuzz"):
        entrypoint = (ROOT / "docker" / generator / "entrypoint.sh").read_text(
            encoding="utf-8"
        )
        dockerfile = (ROOT / "docker" / generator / "Dockerfile").read_text(
            encoding="utf-8"
        )
        assert "source /opt/hgb/bin/llm_provider.sh" in entrypoint
        assert "hgb_resolve_llm_provider" in entrypoint
        assert "docker/common/llm_provider.sh" in dockerfile


def test_target_metadata_records_provider_without_credentials() -> None:
    contract = (ROOT / "docker/common/target_contract.sh").read_text(encoding="utf-8")
    assert '"llm_provider"' in contract
    assert '"llm_base_url"' in contract
    assert "OPENAI_API_KEY" not in contract.split('"llm_provider"', 1)[1].split(
        '"model"', 1
    )[0]


def test_g2fuzz_uses_resolved_base_url_and_promefuzz_fails_fast_on_provider_rejections() -> None:
    g2_entrypoint = (ROOT / "docker/g2fuzz/entrypoint.sh").read_text(encoding="utf-8")
    prome_entrypoint = (ROOT / "docker/promefuzz/entrypoint.sh").read_text(encoding="utf-8")
    assert "base_url=base_url" in g2_entrypoint
    assert "PROME_FUZZ_FAIL_FAST_ON_PROVIDER_ERROR" in prome_entrypoint
    assert "hgb_llm_nonretryable" in prome_entrypoint
    assert "os._exit(78)" in prome_entrypoint


def test_ckgfuzzer_timeout_retry_defaults_reach_the_client_and_containers() -> None:
    entrypoint = (ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    common = (ROOT / "scripts/lib/common.sh").read_text(encoding="utf-8")
    target_launcher = (ROOT / "scripts/hgb_generate_harness.sh").read_text(encoding="utf-8")
    matrix_launcher = (ROOT / "scripts/hgb_generate_matrix.sh").read_text(encoding="utf-8")

    assert "HGB_LLM_REQUEST_TIMEOUT_SECONDS:-900" in entrypoint
    assert "CKGFUZZER_LLM_MAX_RETRIES:-3" in entrypoint
    assert entrypoint.count("max_retries: ${CKGFUZZER_LLM_MAX_RETRIES:-3}") == 2
    assert r'timeout=float(llm_config.get(\"request_timeout\", 900))' in entrypoint
    assert r'max_retries=int(llm_config.get(\"max_retries\", 3))' in entrypoint
    assert "HGB_LLM_REQUEST_TIMEOUT_SECONDS:-900" in common
    assert common.count("-e CKGFUZZER_LLM_MAX_RETRIES") == 2
    assert "CKGFUZZER_LLM_MAX_RETRIES:-3" in target_launcher
    assert "rebuilding stale CKGFuzzer image" in target_launcher
    assert "rebuilding stale CKGFuzzer image" in matrix_launcher
