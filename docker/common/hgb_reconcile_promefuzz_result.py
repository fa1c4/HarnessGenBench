#!/usr/bin/env python3
"""Copy canonical evaluator evidence into PromeFuzz's run summary."""

import argparse
import json
import os
import tempfile
from pathlib import Path

import hgb_result


REQUIRED_STAGES = (
    "candidate_overlay", "copy_audit", "candidate_build", "sanitizer_smoke",
    "api_reachability", "campaign", "coverage",
)


def _write_json(path: Path, data: dict) -> None:
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=path.name + ".",
        delete=False,
    ) as handle:
        temp_path = Path(handle.name)
        json.dump(data, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temp_path, path)


def reconcile(workspace: Path) -> bool:
    summary_path = workspace / "result.json"
    metadata_path = workspace / "metadata.json"
    evaluator_path = workspace / "evaluation" / "result.json"
    if not all(path.is_file() for path in (summary_path, metadata_path, evaluator_path)):
        return False
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    evaluator = json.loads(evaluator_path.read_text(encoding="utf-8"))
    if summary.get("generator") != "promefuzz" or evaluator.get("generator") != "promefuzz":
        return False
    for field in ("metrics", "selected_candidate"):
        value = evaluator.get(field)
        if isinstance(value, dict) and value:
            summary[field] = value
    selected = evaluator.get("selected_candidate") or {}
    stages = evaluator.get("stages") or {}
    verified = bool(selected.get("overlaid")) and all(
        stages.get(stage) == "completed" for stage in REQUIRED_STAGES
    )
    metadata["verified_harness_count"] = int(verified)
    _write_json(summary_path, summary)
    _write_json(metadata_path, metadata)
    return True


def promote_reevaluation(workspace: Path, evaluator_path: Path) -> bool:
    """Promote a fully verified evaluator retry into its generation run."""
    summary_path = workspace / "result.json"
    metadata_path = workspace / "metadata.json"
    if not evaluator_path.is_file():
        return False
    evaluator = json.loads(evaluator_path.read_text(encoding="utf-8"))
    if evaluator.get("generator") != "promefuzz" or evaluator.get("status") != "evaluated":
        return False
    violations = hgb_result.assert_evaluated_invariants(evaluator)
    if violations:
        raise ValueError("evaluator retry violates evaluated invariants: " + "; ".join(violations))
    canonical_evaluator_path = workspace / "evaluation" / "result.json"
    canonical_evaluator_path.parent.mkdir(parents=True, exist_ok=True)
    if canonical_evaluator_path.is_file():
        backup = canonical_evaluator_path.with_name("result.pre_reevaluation.json")
        if not backup.exists():
            _write_json(backup, json.loads(canonical_evaluator_path.read_text(encoding="utf-8")))
    # An interrupted generator wrapper may have finalized drivers and LLM
    # traces without reaching its final metadata write. The independent
    # evaluator is the authority for stage status in that case.
    summary = (json.loads(summary_path.read_text(encoding="utf-8"))
               if summary_path.is_file() else {**evaluator, "target": workspace.parent.name})
    metadata = (json.loads(metadata_path.read_text(encoding="utf-8"))
                if metadata_path.is_file() else {
                    "schema_version": 1,
                    "generator": "promefuzz",
                    "target": workspace.parent.name,
                    "fuzz_target": evaluator.get("target"),
                    "profile": evaluator.get("profile"),
                    "protocol": evaluator.get("protocol"),
                    "task_family": "harness_generator",
                    "run_type": "reevaluated_generated_driver",
                    "generated_harness_count": len(list((workspace / "all_sanitized_harnesses").glob("*")))
                    if (workspace / "all_sanitized_harnesses").is_dir() else
                    len(list((workspace / "generated_harnesses").glob("*"))),
                })
    if summary.get("generator") != "promefuzz" or metadata.get("generator") != "promefuzz":
        return False
    if metadata.get("fuzz_target") != evaluator.get("target"):
        raise ValueError("reevaluation target does not match generation run")
    for path, old_path, contents in ((workspace / "result.pre_reevaluation.json", summary_path, summary),
                                     (workspace / "metadata.pre_reevaluation.json", metadata_path, metadata)):
        if old_path.is_file() and not path.exists():
            _write_json(path, contents)
    summary["status"] = "evaluated"
    summary["reason"] = "none"
    summary["stages"].update(evaluator["stages"])
    for field in ("metrics", "selected_candidate"):
        summary[field] = evaluator[field]
    summary.setdefault("artifacts", {}).update(evaluator.get("artifacts", {}))
    summary.setdefault("provenance", {})["reevaluation_result"] = str(evaluator_path.relative_to(workspace))
    metadata.update(status="evaluated", reason="none", failed_stage="none",
                    exit_code=0, candidate_verification_exit_code="0", verified_harness_count=1)
    metadata.setdefault("final_harness_count", metadata.get("generated_harness_count", 0))
    metadata.setdefault("applicability", evaluator.get("applicability", "applicable"))
    metadata.setdefault("native_harness_destination",
                        (evaluator.get("selected_candidate") or {}).get("native_destination", ""))
    _write_json(summary_path, summary)
    _write_json(metadata_path, metadata)
    _write_json(canonical_evaluator_path, evaluator)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--promote-evaluation", type=Path)
    args = parser.parse_args()
    if args.promote_evaluation:
        if not promote_reevaluation(args.workspace.resolve(), args.promote_evaluation.resolve()):
            raise SystemExit("reevaluation is not eligible for promotion")
    else:
        reconcile(args.workspace)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
