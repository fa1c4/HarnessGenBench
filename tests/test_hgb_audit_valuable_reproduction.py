from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("hgb_audit_valuable_reproduction", ROOT / "scripts/hgb_audit_valuable_reproduction.py")
assert spec and spec.loader
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def test_ckg_audit_accepts_upstream_hgb_project_name_but_rejects_rescue(tmp_path: Path) -> None:
    (tmp_path / "evaluation").mkdir()
    meta = {
        "status": "evaluated", "analysis_mode": "codeql", "codeql_graph_nodes": 1,
        "api_trace_total_count": 1, "method_variant": "paper-faithful",
    }
    (tmp_path / "metadata.json").write_text(json.dumps(meta))
    result = {
        "status": "evaluated",
        "stages": {name: "completed" for name in audit.HARNESS_STAGES},
        "metrics": {"campaign": {"execs_done": 2}, "coverage": {"line_coverage": {"covered": 1}}},
        "selected_candidate": {"candidate_path": "/workspace/generated_harnesses/hgb_jsoncpp_fuzz_driver_1.cc"},
    }
    path = tmp_path / "evaluation/result.json"
    path.write_text(json.dumps(result))
    assert audit.checked_run("ckgfuzzer", tmp_path)[0]
    result["selected_candidate"]["candidate_path"] = "/workspace/generated_harnesses/2_000_hgb_jsoncpp_rescue.cc"
    path.write_text(json.dumps(result))
    assert not audit.checked_run("ckgfuzzer", tmp_path)[0]
