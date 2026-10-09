#!/usr/bin/env python3
"""Audit saved valuable-target runs against observable evaluator evidence."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


BASELINES = ("ckgfuzzer", "promefuzz", "oss-fuzz-gen", "g2fuzz", "elfuzz")
HARNESS_STAGES = (
    "candidate_overlay", "copy_audit", "candidate_build", "sanitizer_smoke",
    "api_reachability", "campaign", "coverage",
)


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def checked_run(baseline: str, run: Path) -> tuple[bool, str, int, int]:
    meta = read_json(run / "metadata.json")
    if meta.get("status") != "evaluated":
        return False, str(meta.get("reason") or meta.get("status") or "missing metadata"), 0, 0
    if meta.get("excluded_from_aggregate") or meta.get("method_variant") == "compat-smoke":
        return False, "excluded compatibility run", 0, 0
    result_path = run / ("evaluation/result.json" if baseline in BASELINES[:3] else "result.json")
    result = read_json(result_path)
    if result.get("status") != "evaluated":
        return False, "missing evaluated result", 0, 0
    stages = result.get("stages") or {}
    if baseline in BASELINES[:3]:
        # OSS-Fuzz-Gen writes some early-stage records at the run level; the
        # independent evaluator is authoritative for the shared seven stages.
        missing = [name for name in HARNESS_STAGES if stages.get(name) != "completed"]
        if missing:
            return False, "incomplete evaluator stages: " + ", ".join(missing), 0, 0
        if baseline == "ckgfuzzer":
            selected = (result.get("selected_candidate") or {}).get("candidate_path", "")
            if "hgb_" in Path(selected).name:
                return False, "selected HGB source-derived rescue driver; upstream CKGFuzzer generation was bypassed", 0, 0
            if meta.get("analysis_mode") != "codeql" or int(meta.get("codeql_graph_nodes") or 0) <= 0:
                return False, "missing real CodeQL graph evidence", 0, 0
            if int(meta.get("api_trace_total_count") or 0) <= 0:
                return False, "missing upstream LLM call evidence", 0, 0
    else:
        required = ("target_pair_build", "generated_input_validation", "campaign", "coverage") if baseline == "g2fuzz" else (
            "target_build", "synthesis", "evolution", "production", "generated_input_validation", "campaign", "coverage"
        )
        missing = [name for name in required if (stages.get(name) or {}).get("status") != "complete"]
        if missing:
            return False, "incomplete input-generation stages: " + ", ".join(missing), 0, 0
        if int((stages.get("generated_input_validation") or {}).get("valid_count") or 0) <= 0:
            return False, "no validated generated inputs", 0, 0
        if baseline == "elfuzz":
            source = run if (run / "campaign/fuzzer_stats").is_file() else Path(result.get("source_run") or run)
            evidence = read_json(source / "campaign/target_runtime.json")
            stats_path = source / "campaign/fuzzer_stats"
            stats = stats_path.read_text(encoding="utf-8", errors="replace") if stats_path.is_file() else ""
            runtime_log = source / "campaign/target_runtime.log"
            log = runtime_log.read_text(encoding="utf-8", errors="replace") if runtime_log.is_file() else ""
            if not (evidence.get("containerized") or evidence.get("exact_fuzzbench_afl")) or "start_time" not in stats or "last_update" not in stats:
                return False, "ELFuzz campaign lacks real exact-target AFL evidence", 0, 0
            if "Traceback (most recent call last)" in log or "FileNotFoundError" in log:
                return False, "upstream ELFuzz AFL campaign failed", 0, 0
            original = Path(result.get("source_run") or run)
            expected_seconds = int(read_json(original / "config/budget.json").get("campaign_seconds") or 0)
            actual_seconds = int((stages.get("campaign") or {}).get("afl_seconds") or 0)
            if expected_seconds and actual_seconds < expected_seconds:
                return False, f"AFL campaign {actual_seconds}s is shorter than alpha budget {expected_seconds}s", 0, 0
            stats_fields = {key.strip(): value.strip() for key, value in
                            (line.split(":", 1) for line in stats.splitlines() if ":" in line)}
            try:
                measured_seconds = int(stats_fields["last_update"].strip()) - int(stats_fields["start_time"].strip())
            except (KeyError, ValueError):
                return False, "AFL campaign has no measured elapsed time", 0, 0
            if expected_seconds and measured_seconds < expected_seconds:
                return False, f"AFL measured runtime {measured_seconds}s is shorter than alpha budget {expected_seconds}s", 0, 0
    campaign = result.get("campaign") or (result.get("metrics") or {}).get("campaign") or {}
    coverage = result.get("coverage") or (result.get("metrics") or {}).get("coverage") or {}
    execs = int(campaign.get("execs_done") or 0)
    lines = int((coverage.get("line_coverage") or {}).get("covered") or 0)
    if execs <= 0:
        return False, "zero campaign executions", execs, lines
    if lines <= 0:
        return False, "no measured LLVM source line coverage", execs, lines
    if baseline == "g2fuzz" and int(campaign.get("queue_count") or 0) <= 0:
        return False, "empty AFL queue", execs, lines
    return True, "verified", execs, lines


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    targets = read_json(root / "metadata/fuzzbench_targets.json")["target_sets"]["valuable"]["targets"]
    # The committed ELFuzz adapter manifest is the sole applicability source.
    import sys
    sys.path.insert(0, str(root / "docker/common"))
    from elfuzz_target_pipeline import load_adapters
    import yaml

    elf_scope = load_adapters(root / "metadata")
    ofg_scope = (yaml.safe_load((root / "metadata/oss_fuzz_gen_target_overrides.yaml").read_text(encoding="utf-8")) or {}).get("targets", {})
    rows = []
    summary = {}
    for baseline in BASELINES:
        count = {"applicable": 0, "verified": 0, "partial_completed": 0,
                 "reported_evaluated_unverified": 0, "failed": 0, "not_applicable": 0}
        for target in targets:
            if baseline == "oss-fuzz-gen" and ofg_scope.get(target, {}).get("applicability") == "not_applicable":
                rows.append({"baseline": baseline, "target": target, "status": "not_applicable",
                             "reason": ofg_scope[target].get("applicability_reason", "outside_scope")})
                count["not_applicable"] += 1
                continue
            if baseline == "elfuzz" and elf_scope.get(target, {}).get("applicability") != "applicable":
                rows.append({"baseline": baseline, "target": target, "status": "not_applicable", "reason": "elfuzz_non_text_target"})
                count["not_applicable"] += 1
                continue
            count["applicable"] += 1
            target_dir = root / "workspace" / baseline / target
            runs = [p for p in target_dir.iterdir() if p.is_dir() and (p / "metadata.json").is_file()] if target_dir.is_dir() else []
            runs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            chosen = None
            for run in runs:
                ok, reason, execs, lines = checked_run(baseline, run)
                if ok:
                    chosen = {"baseline": baseline, "target": target, "status": "verified", "run": str(run.relative_to(root)),
                              "campaign_execs": execs, "covered_lines": lines}
                    if baseline == "g2fuzz":
                        chosen["applicability_group"] = read_json(run / "metadata.json").get("applicability_group", "unknown")
                    break
            if chosen is None:
                partial = [p for p in runs if read_json(p / "metadata.json").get("status") == "partial_completed"
                           and read_json(p / "result.json").get("faithful_afl_campaign")]
                if partial:
                    run = partial[0]
                    record = read_json(run / "result.json")
                    campaign = record.get("campaign") or {}
                    coverage = record.get("coverage") or {}
                    chosen = {"baseline": baseline, "target": target, "status": "partial_completed",
                              "run": str(run.relative_to(root)), "reason": record.get("reason") or "incomplete campaign budget",
                              "campaign_execs": int(campaign.get("execs_done") or 0),
                              "covered_lines": int((coverage.get("line_coverage") or {}).get("covered") or 0)}
            if chosen is None:
                evaluated = [p for p in runs if read_json(p / "metadata.json").get("status") == "evaluated"]
                run = evaluated[0] if evaluated else runs[0] if runs else None
                if run:
                    _, reason, execs, lines = checked_run(baseline, run)
                    status = "reported_evaluated_unverified" if evaluated else "failed"
                    chosen = {"baseline": baseline, "target": target, "status": status, "run": str(run.relative_to(root)),
                              "reason": reason, "campaign_execs": execs, "covered_lines": lines}
                else:
                    chosen = {"baseline": baseline, "target": target, "status": "failed", "reason": "no saved run"}
            rows.append(chosen)
            count[chosen["status"]] += 1
            if baseline == "g2fuzz" and chosen["status"] == "verified":
                group = chosen.get("applicability_group", "unknown")
                count[f"verified_{group.replace('-', '_')}"] = count.get(f"verified_{group.replace('-', '_')}", 0) + 1
        summary[baseline] = count
    report = {"generated_at": datetime.now(timezone.utc).isoformat(),
              "criteria": "full evaluator stages, nonzero campaign and LLVM source line coverage; CKGFuzzer requires real CodeQL/LLM driver provenance, ELFuzz requires exact-target AFL campaign evidence, and input generators require validated generated inputs",
              "summary": summary, "rows": rows}
    output = args.out or root / "workspace/reproduction_audit_valuable.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for baseline, counts in summary.items():
        print(f"{baseline}: {counts['verified']}/{counts['applicable']} verified; {counts['partial_completed']} partial; {counts['not_applicable']} not applicable; {counts['reported_evaluated_unverified']} reported evaluated without full evidence")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
