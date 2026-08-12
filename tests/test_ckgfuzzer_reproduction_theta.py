"""Theta reproduction tests for the CKGFuzzer harness-generator pipeline.

These tests exercise the USTC model fix contract from
``plans/ckgfuzzer_reproduction_theta.md``.

The theta plan fixes CKGFuzzer provider/model compatibility so a USTC
provider run no longer fails all 20 valuable targets because the embedding
model was empty or an OpenAI-only name. ``reproduction-theta`` is a strict
alias of ``reproduction-eta`` that additionally requires USTC provider-aware
model resolution and a live model preflight probe before target preparation.
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
_DOCKER_COMMON = REPO_ROOT / "docker" / "common"
if str(_DOCKER_COMMON) not in sys.path:
    sys.path.insert(0, str(_DOCKER_COMMON))


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ckgfuzzer_model_config = _load_module("ckgfuzzer_model_config_theta", "docker/common/ckgfuzzer_model_config.py")
profile = _load_module("ckgfuzzer_profile_theta", "docker/common/ckgfuzzer_profile.py")
hgb_result = _load_module("hgb_result_theta", "docker/common/hgb_result.py")


def _run_env():
    env = dict(os.environ)
    env["PATH"] = str(REPO_ROOT / "scripts") + os.pathsep + env.get("PATH", "")
    return env


# ---------------------------------------------------------------------------
# T0. Profile acceptance
# ---------------------------------------------------------------------------


def test_reproduction_theta_is_valid_profile() -> None:
    assert "reproduction-theta" in profile.VALID_PROFILES
    assert profile.is_method_faithful("reproduction-theta")
    assert "reproduction-theta" in profile.STRICT_REPRODUCTION_PROFILES
    assert "reproduction-theta" in profile.ETA_PROFILES
    assert "reproduction-theta" in profile.THETA_PROFILES


def test_reproduction_theta_keeps_eta_zeta_epsilon_delta_as_aliases() -> None:
    for p in ("reproduction-eta", "reproduction-zeta", "reproduction-epsilon", "reproduction-delta"):
        assert p in profile.VALID_PROFILES
        assert p in profile.STRICT_REPRODUCTION_PROFILES


def test_common_sh_theta_is_strict_reproduction() -> None:
    proc = subprocess.run(
        ["bash", "-c", "source scripts/lib/common.sh && hgb_profile_is_strict_reproduction reproduction-theta && echo OK"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30,
    )
    assert "OK" in proc.stdout, proc.stderr


def test_common_sh_theta_is_known_profile() -> None:
    proc = subprocess.run(
        ["bash", "-c", "source scripts/lib/common.sh && hgb_known_profile reproduction-theta && echo OK"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30,
    )
    assert "OK" in proc.stdout, proc.stderr


def test_dry_run_canonical_command_passes_theta_profile_validation() -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_run_baseline.sh", "--generator", "ckgfuzzer",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-theta",
         "--protocol", "blind-project", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    workspace = proc.stdout.strip().splitlines()[-1]
    result = json.loads((Path(workspace) / "result.json").read_text(encoding="utf-8"))
    assert result["status"] == "dry_run_ok"
    assert result["profile"] == "reproduction-theta"
    assert result["method_variant"] == "paper-faithful"


def test_hgb_generate_harness_accepts_reproduction_theta() -> None:
    proc = subprocess.run(
        ["bash", "scripts/hgb_generate_harness.sh", "--generator", "ckgfuzzer",
         "--target", "jsoncpp_jsoncpp_fuzzer", "--profile", "reproduction-theta", "--dry-run"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=_run_env(), timeout=120,
    )
    assert proc.returncode != 2
    assert "unknown profile" not in proc.stderr


# ---------------------------------------------------------------------------
# T1. USTC model registry and resolution
# ---------------------------------------------------------------------------


def test_model_registry_loads_ustc_models() -> None:
    registry = ckgfuzzer_model_config.load_model_registry()
    assert "ustc" in registry
    ustc = registry["ustc"]
    assert "deepseek-v4-pro" in ustc["chat_models"]
    assert "glm-5.2" in ustc["chat_models"]
    assert "qwen3-embedding" in ustc["embedding_models"]
    assert ustc["defaults"]["ckgfuzzer_chat"] == "deepseek-v4-pro"
    assert ustc["defaults"]["ckgfuzzer_embedding"] == "qwen3-embedding"


def test_ustc_empty_model_env_resolves_to_defaults() -> None:
    """T1.1: HGB_LLM_PROVIDER=ustc and empty CKGFuzzer model env resolves to
    chat=deepseek-v4-pro, embedding=qwen3-embedding."""
    config = ckgfuzzer_model_config.resolve_ckgfuzzer_model_config(
        {"HGB_LLM_PROVIDER": "ustc", "API_KEY": "test-key",
         "OPENAI_BASE_URL": "https://api.llm.ustc.edu.cn"},
        profile="reproduction-theta",
    )
    assert config["provider"] == "ustc"
    assert config["chat_model"] == "deepseek-v4-pro"
    assert config["embedding_model"] == "qwen3-embedding"
    assert config["api_key_present"] is True
    assert config["errors"] == []


def test_ustc_openai_embedding_model_fails_validation() -> None:
    """T1.2: HGB_LLM_PROVIDER=ustc with CKGFUZZER_EMBEDDING_MODEL=text-embedding-3-small
    fails validation unless explicitly registered."""
    with pytest.raises(ckgfuzzer_model_config.ModelConfigError) as exc_info:
        ckgfuzzer_model_config.resolve_ckgfuzzer_model_config(
            {"HGB_LLM_PROVIDER": "ustc", "API_KEY": "test-key",
             "OPENAI_BASE_URL": "https://api.llm.ustc.edu.cn",
             "CKGFUZZER_EMBEDDING_MODEL": "text-embedding-3-small",
             "CKGFUZZER_LLM_MODEL": "deepseek-v4-pro"},
            profile="reproduction-theta",
        )
    msg = str(exc_info.value)
    assert "text-embedding-3-small" in msg
    assert "not registered for provider ustc" in msg
    assert "qwen3-embedding" in msg


def test_mock_embedding_fails_strict_validation() -> None:
    """T1.3: CKGFUZZER_EMBEDDING_MODEL=mock fails strict validation."""
    with pytest.raises(ckgfuzzer_model_config.ModelConfigError) as exc_info:
        ckgfuzzer_model_config.resolve_ckgfuzzer_model_config(
            {"HGB_LLM_PROVIDER": "ustc", "API_KEY": "test-key",
             "OPENAI_BASE_URL": "https://api.llm.ustc.edu.cn",
             "CKGFUZZER_EMBEDDING_MODEL": "mock",
             "CKGFUZZER_LLM_MODEL": "deepseek-v4-pro"},
            profile="reproduction-theta",
        )
    assert "embedding model is not configured" in str(exc_info.value) or "mock" in str(exc_info.value)


def test_empty_embedding_fails_strict_validation() -> None:
    """Empty embedding model on a non-USTC provider fails strict validation."""
    with pytest.raises(ckgfuzzer_model_config.ModelConfigError):
        ckgfuzzer_model_config.resolve_ckgfuzzer_model_config(
            {"HGB_LLM_PROVIDER": "custom", "API_KEY": "test-key"},
            profile="reproduction-theta",
        )


def test_ustc_accepts_valid_chat_model_override() -> None:
    """The user can override with any registered USTC chat model."""
    config = ckgfuzzer_model_config.resolve_ckgfuzzer_model_config(
        {"HGB_LLM_PROVIDER": "ustc", "API_KEY": "test-key",
         "OPENAI_BASE_URL": "https://api.llm.ustc.edu.cn",
         "CKGFUZZER_LLM_MODEL": "glm-5.2",
         "CKGFUZZER_EMBEDDING_MODEL": "qwen3-embedding"},
        profile="reproduction-theta",
    )
    assert config["chat_model"] == "glm-5.2"
    assert config["embedding_model"] == "qwen3-embedding"


def test_ustc_rejects_unregistered_chat_model() -> None:
    """An unregistered chat model is rejected for USTC."""
    with pytest.raises(ckgfuzzer_model_config.ModelConfigError) as exc_info:
        ckgfuzzer_model_config.resolve_ckgfuzzer_model_config(
            {"HGB_LLM_PROVIDER": "ustc", "API_KEY": "test-key",
             "OPENAI_BASE_URL": "https://api.llm.ustc.edu.cn",
             "CKGFUZZER_LLM_MODEL": "gpt-4o-mini",
             "CKGFUZZER_EMBEDDING_MODEL": "qwen3-embedding"},
            profile="reproduction-theta",
        )
    assert "gpt-4o-mini" in str(exc_info.value)
    assert "not registered" in str(exc_info.value)


def test_non_ustc_provider_preserves_existing_behavior() -> None:
    """Non-USTC providers do not force USTC model names."""
    config = ckgfuzzer_model_config.resolve_ckgfuzzer_model_config(
        {"HGB_LLM_PROVIDER": "openai", "API_KEY": "test-key",
         "OPENAI_BASE_URL": "https://api.openai.com/v1",
         "CKGFUZZER_LLM_MODEL": "gpt-4o-mini",
         "CKGFUZZER_EMBEDDING_MODEL": "text-embedding-3-small"},
        profile="reproduction-theta",
    )
    assert config["chat_model"] == "gpt-4o-mini"
    assert config["embedding_model"] == "text-embedding-3-small"


# ---------------------------------------------------------------------------
# T2. Entrypoint ordering: defaults before validation
# ---------------------------------------------------------------------------


def test_entrypoint_theta_applies_defaults_before_validation() -> None:
    """T1.4: Entry point/profile helper applies defaults before validation."""
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert "reproduction-theta" in entrypoint
    # The theta model resolution block must appear before the embedding
    # validation block.
    theta_pos = entrypoint.index("reproduction-theta")
    emb_validation_pos = entrypoint.index("CKGFUZZER_EMBEDDING_MODEL must be a real embedding service")
    assert theta_pos < emb_validation_pos, "theta defaults must be applied before embedding validation"


def test_entrypoint_theta_has_model_config_resolution() -> None:
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert "ckgfuzzer_model_config.py" in entrypoint
    assert "model_preflight" in entrypoint
    assert "ckg_model_config_json" in entrypoint


def test_entrypoint_theta_has_model_config_in_result() -> None:
    """T1.9: CKGFuzzer result JSON includes model_config."""
    entrypoint = (REPO_ROOT / "docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    assert '"model_config"' in entrypoint


def test_run_baseline_theta_section_accepts_profile() -> None:
    script = (REPO_ROOT / "scripts/hgb_run_baseline.sh").read_text(encoding="utf-8")
    assert "reproduction-theta" in script


# ---------------------------------------------------------------------------
# T3. Live preflight probes
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body.encode("utf-8") if isinstance(body, str) else body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def _fake_opener_chat_ok(req, timeout=None):
    return _FakeResponse(200, json.dumps({"choices": [{"message": {"content": "OK"}}]}))


def _fake_opener_embedding_ok(req, timeout=None):
    return _FakeResponse(200, json.dumps({"data": [[0.1, 0.2, 0.3, 0.4, 0.5]]}))


def _fake_opener_embedding_fail(req, timeout=None):
    import urllib.error
    raise urllib.error.HTTPError(req.full_url, 500, "Internal Server Error", {}, io.BytesIO(b"server error"))


def test_fake_embedding_probe_returns_vector_length() -> None:
    """T1.5: Fake embedding probe returns vector length and writes embedding_dimension."""
    result = ckgfuzzer_model_config.probe_embedding(
        base_url="https://api.llm.ustc.edu.cn",
        api_key="test-key",
        model="qwen3-embedding",
        opener=_fake_opener_embedding_ok,
    )
    assert result["ok"] is True
    assert result["dimension"] == 5


def test_fake_chat_probe_succeeds() -> None:
    result = ckgfuzzer_model_config.probe_chat(
        base_url="https://api.llm.ustc.edu.cn",
        api_key="test-key",
        model="deepseek-v4-pro",
        opener=_fake_opener_chat_ok,
    )
    assert result["ok"] is True


def test_probe_failure_returns_embedding_probe_failed() -> None:
    """T1.6: Probe failure returns infra_failure with reason_code=embedding_probe_failed."""
    result = ckgfuzzer_model_config.run_model_preflight(
        {"HGB_LLM_PROVIDER": "ustc", "API_KEY": "test-key",
         "OPENAI_BASE_URL": "https://api.llm.ustc.edu.cn"},
        profile="reproduction-theta",
        chat_opener=_fake_opener_chat_ok,
        embedding_opener=_fake_opener_embedding_fail,
    )
    assert result["status"] == "probe_failed"
    assert result["reason_code"] == "embedding_probe_failed"
    assert result["model_config"]["embedding_probe_passed"] is False


def test_probe_chat_failure_returns_chat_probe_failed() -> None:
    result = ckgfuzzer_model_config.run_model_preflight(
        {"HGB_LLM_PROVIDER": "ustc", "API_KEY": "test-key",
         "OPENAI_BASE_URL": "https://api.llm.ustc.edu.cn"},
        profile="reproduction-theta",
        chat_opener=_fake_opener_embedding_fail,
        embedding_opener=_fake_opener_embedding_ok,
    )
    assert result["status"] == "probe_failed"
    assert result["reason_code"] == "chat_probe_failed"


def test_full_preflight_succeeds_with_fake_probes() -> None:
    """T1.5: Full preflight with fake probes succeeds and writes embedding_dimension."""
    result = ckgfuzzer_model_config.run_model_preflight(
        {"HGB_LLM_PROVIDER": "ustc", "API_KEY": "test-key",
         "OPENAI_BASE_URL": "https://api.llm.ustc.edu.cn"},
        profile="reproduction-theta",
        chat_opener=_fake_opener_chat_ok,
        embedding_opener=_fake_opener_embedding_ok,
    )
    assert result["status"] == "ok"
    assert result["model_config"]["chat_probe_passed"] is True
    assert result["model_config"]["embedding_probe_passed"] is True
    assert result["model_config"]["embedding_dimension"] == 5
    assert result["model_config"]["provider"] == "ustc"
    assert result["model_config"]["chat_model"] == "deepseek-v4-pro"
    assert result["model_config"]["embedding_model"] == "qwen3-embedding"


def test_resolution_failure_returns_resolution_failed() -> None:
    result = ckgfuzzer_model_config.run_model_preflight(
        {"HGB_LLM_PROVIDER": "ustc", "API_KEY": "test-key",
         "OPENAI_BASE_URL": "https://api.llm.ustc.edu.cn",
         "CKGFUZZER_EMBEDDING_MODEL": "text-embedding-3-small"},
        profile="reproduction-theta",
    )
    assert result["status"] == "resolution_failed"
    assert result["reason_code"] == "model_resolution_failed"


def test_missing_api_key_returns_missing_api_key() -> None:
    result = ckgfuzzer_model_config.run_model_preflight(
        {"HGB_LLM_PROVIDER": "ustc",
         "OPENAI_BASE_URL": "https://api.llm.ustc.edu.cn"},
        profile="reproduction-theta",
    )
    assert result["status"] == "probe_failed"
    assert result["reason_code"] == "missing_api_key"


# ---------------------------------------------------------------------------
# T4. API key redaction
# ---------------------------------------------------------------------------


def test_logs_and_json_redact_api_keys(tmp_path: Path) -> None:
    """T1.7: Logs and JSON redact API keys."""
    secret = "sk-test-secret-key-12345"
    result = ckgfuzzer_model_config.run_model_preflight(
        {"HGB_LLM_PROVIDER": "ustc", "API_KEY": secret,
         "OPENAI_BASE_URL": "https://api.llm.ustc.edu.cn"},
        profile="reproduction-theta",
        chat_opener=_fake_opener_chat_ok,
        embedding_opener=_fake_opener_embedding_ok,
    )
    out_path = tmp_path / "model_preflight.json"
    ckgfuzzer_model_config.write_model_preflight(result, out_path)
    text = out_path.read_text(encoding="utf-8")
    assert secret not in text
    assert "[REDACTED]" in text or "api_key_present" in text


def test_probe_error_redacts_api_key() -> None:
    """API keys in probe error messages are redacted."""
    secret = "sk-leaked-key-67890"
    import urllib.error
    def opener(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(f"bad key {secret}".encode()))
    result = ckgfuzzer_model_config.probe_chat(
        base_url="https://api.llm.ustc.edu.cn",
        api_key=secret,
        model="deepseek-v4-pro",
        opener=opener,
    )
    assert result["ok"] is False
    assert secret not in result["error"]


# ---------------------------------------------------------------------------
# T5. Matrix preflight stops early
# ---------------------------------------------------------------------------


def test_matrix_script_has_ckgfuzzer_model_preflight_stage() -> None:
    """T1.8: Matrix preflight stops early on model preflight failure."""
    script = (REPO_ROOT / "scripts/hgb_generate_matrix.sh").read_text(encoding="utf-8")
    assert "ckgfuzzer_model_config.py" in script
    assert "HGB_CKGFUZZER_MODEL_PREFLIGHT_CACHE" in script
    assert "model_preflight_failed" in script or "model_preflight" in script


def test_matrix_script_stops_early_on_preflight_failure() -> None:
    script = (REPO_ROOT / "scripts/hgb_generate_matrix.sh").read_text(encoding="utf-8")
    # The preflight must run BEFORE the call to prepare_shared_target_packages
    # in the main loop (not the function definition). The call is at the end
    # of the preflight block.
    preflight_pos = script.index("CKGFuzzer model preflight")
    # Find the call to prepare_shared_target_packages after the preflight block.
    prepare_call_pos = script.index("prepare_shared_target_packages \"${eligible_targets[@]}\"", preflight_pos)
    assert preflight_pos < prepare_call_pos, "model preflight must run before preparing all target packages"


# ---------------------------------------------------------------------------
# T6. Result JSON includes model_config and method evidence
# ---------------------------------------------------------------------------


def test_target_contract_maps_theta_to_paper_faithful() -> None:
    contract = (REPO_ROOT / "docker/common/target_contract.sh").read_text(encoding="utf-8")
    assert "reproduction-theta" in contract
    assert 'reproduction-theta) method_variant="paper-faithful"' in contract


def test_dockerfile_copies_model_config_module() -> None:
    dockerfile = (REPO_ROOT / "docker/ckgfuzzer/Dockerfile").read_text(encoding="utf-8")
    assert "ckgfuzzer_model_config.py" in dockerfile


def test_common_sh_passes_theta_env_vars_to_container() -> None:
    common = (REPO_ROOT / "scripts/lib/common.sh").read_text(encoding="utf-8")
    assert "HGB_CKGFUZZER_MODEL_PREFLIGHT_CACHE" in common
    assert "CKGFUZZER_LLM_MODEL" in common


def test_hgb_targets_infers_require_split_for_theta() -> None:
    env = dict(os.environ)
    env["HGB_BASELINE_PROFILE"] = "reproduction-theta"
    env["HGB_BASELINE_PROTOCOL"] = "blind-project"
    proc = subprocess.run(
        ["python3", "scripts/hgb_targets.py", "package", "--help"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, env=env, timeout=30,
    )
    assert "--require-split" in proc.stdout
