from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_module(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


recovery = _load_module("ckgfuzzer_api_recovery_source_fallback", "docker/common/ckgfuzzer_api_recovery.py")


def test_source_fallback_requires_a_recovered_body() -> None:
    selected = ["uncompress", "generated"]
    recovered = {
        "uncompress": "int uncompress(arg)\nint arg;\n{ return arg; }\n",
        "generated": "/* HGB recovered declaration. */\nint generated(void);\n",
    }

    assert recovery.recovered_body_count(selected, recovered) == 1
    assert recovery.recovered_body_count(selected, {"generated": recovered["generated"]}) == 0


def test_entrypoint_defers_no_graph_to_source_fallback() -> None:
    entrypoint = Path("docker/ckgfuzzer/entrypoint.sh").read_text(encoding="utf-8")
    heredoc = "PY_CKG_SOURCE_FALLBACK_BODIES"
    start = entrypoint.index(heredoc) + len(heredoc)
    end = entrypoint.index("\n" + heredoc, start)
    fallback_helper = entrypoint[start:end]

    assert "analysis_mode=source_fallback_only" in entrypoint
    assert "hgb_source_fallback_call_graph.csv" in entrypoint
    assert "source_fallback_recovered_body_count" in entrypoint
    assert "source_fallback_only output is intentionally excluded from the CodeQL cache" in entrypoint
    assert "from ckgfuzzer_api_recovery import recovered_body_count" in fallback_helper
