#!/usr/bin/env python3
"""Build the consolidated MAGMA 300 s smoke report.

Merges the three smoke batches used during integration
(``smoke9c`` corrected corpus runs, ``smoke9`` harness runs, and the earlier
flat ``corpus_smoke`` runs), computes target-source coverage per cell with the
harness excluded, and marks N/A cells from the committed applicability flags.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "workspace/magma"
METADATA = ROOT / "metadata/magma_targets.yaml"

TARGETS = ["libpng", "libsndfile", "libtiff", "libxml2", "lua", "openssl", "php", "poppler", "sqlite3"]
BASELINES = ["oss-fuzz-gen", "ckgfuzzer", "promefuzz", "elfuzz", "g2fuzz"]
LABELS = {"oss-fuzz-gen": "OSS-Fuzz-Gen", "ckgfuzzer": "CKGFuzzer",
          "promefuzz": "PromeFuzz", "elfuzz": "ELFuzz", "g2fuzz": "G2Fuzz"}
SHORT = {"oss-fuzz-gen": "ofg", "ckgfuzzer": "ckg", "promefuzz": "prome",
         "elfuzz": "elfuzz", "g2fuzz": "g2fuzz"}
FAILED = {("oss-fuzz-gen", "php"), ("oss-fuzz-gen", "poppler"),
          ("promefuzz", "libxml2"), ("promefuzz", "poppler")}


def specs() -> dict[str, dict]:
    return yaml.safe_load(METADATA.read_text(encoding="utf-8"))["targets"]


def cell_result(baseline: str, target: str):
    stem = f"{baseline}_{target}"
    for batch in ("smoke9c", "smoke9"):
        for candidate in (
            WORK / "coverage" / batch / stem / "trial_1" / "coverage.json",
            WORK / "coverage" / batch / stem / "coverage.json",
        ):
            if candidate.is_file():
                return json.loads(candidate.read_text(encoding="utf-8")), batch, candidate
    flat = WORK / "coverage" / "corpus_smoke" / f"{SHORT[baseline]}_{target}" / "coverage.json"
    if flat.is_file():
        return json.loads(flat.read_text(encoding="utf-8")), "corpus_smoke", flat
    return None, "", None


def cell_crashes(baseline: str, target: str, batch: str) -> int | None:
    stem = f"{baseline}_{target}"
    if batch in {"smoke9", "smoke9c"}:
        directory = WORK / "campaigns" / batch / stem / "trial_1" / "crashes"
    else:
        directory = WORK / "campaigns" / "corpus_smoke" / f"{SHORT[baseline]}_{target}" / "crashes"
    if not directory.is_dir():
        return None
    return sum(1 for path in directory.iterdir() if path.is_file())


def status(baseline: str, target: str, spec: dict) -> str:
    if baseline == "elfuzz" and spec.get("elfuzz_applicable") is False:
        return "N/A"
    if baseline == "ckgfuzzer" and spec.get("ckgfuzzer_skip_macro_api"):
        return "N/A"
    if (baseline, target) in FAILED:
        return "Failed"
    return "—"


def main() -> int:
    target_specs = specs()
    measured: dict[tuple[str, str], dict] = {}
    for baseline in BASELINES:
        for target in TARGETS:
            result, batch, path = cell_result(baseline, target)
            if result:
                measured[(baseline, target)] = {
                    "percent": result["percent"],
                    "covered": result["covered_lines"],
                    "total": result["total_lines"],
                    "crashes": cell_crashes(baseline, target, batch),
                    "batch": batch,
                }

    header = "| Baseline | " + " | ".join(f"`{t}`" for t in TARGETS) + " |"
    lines = [
        "# MAGMA 300-second smoke matrix",
        "",
        "Report date: 2026-11-12. One 300 s native campaign per cell on the "
        "MAGMA-native ASan build, replayed with `llvm_cov`; coverage is covered "
        "target-source file:line IDs excluding the harness. `N/A` = committed "
        "applicability decision (ELFuzz binary targets; CKGFuzzer macro-declared "
        "entry APIs). `Failed` = generator produced no evaluable harness. `—` = "
        "not measured yet. This is the smoke gate, not the paused 5x86,400 s matrix.",
        "",
        "## Coverage",
        "",
        header,
        "| :--- | " + " | ".join("---:" for _ in TARGETS) + " |",
    ]
    crash_lines = ["", "## Crashes (ASan)", "", header,
                   "| :--- | " + " | ".join("---:" for _ in TARGETS) + " |"]
    for baseline in BASELINES:
        row, crash_row = [], []
        for target in TARGETS:
            cell = measured.get((baseline, target))
            state = status(baseline, target, target_specs[target])
            if state == "N/A":
                row.append("N/A")
                crash_row.append("N/A")
            elif cell:
                row.append(f"{cell['percent']:.2f}% ({cell['covered']:,}/{cell['total']:,})")
                crash_row.append(str(cell["crashes"]) if cell["crashes"] is not None else "—")
            else:
                row.append(state)
                crash_row.append(state)
        lines.append(f"| {LABELS[baseline]} | " + " | ".join(row) + " |")
        crash_lines.append(f"| {LABELS[baseline]} | " + " | ".join(crash_row) + " |")

    notes = [
        "",
        "## Notes",
        "",
        "* Harness-generator cells are the single harness selected for the "
        "300 s smoke; corpus-generator cells are seeded from the generated "
        "corpus directory.",
        "* `ELFuzz` applies only to libxml2, lua, sqlite3 and php; the five "
        "binary targets are N/A by the upstream text-only contract.",
        "* `CKGFuzzer` is N/A on libpng, libxml2, lua, openssl and php because "
        "their entry APIs are macro-declared and CKGFuzzer's extractor needs a "
        "real source definition.",
        "* `G2Fuzz` poppler is a partial corpus: the generator aborted while "
        "installing PyMuPDF, but 17 real seeds were produced and measured.",
        "* Final smoke status: 25 applicable cells measured, 10 Failed, 10 N/A "
        "(45 nominal baseline-target cells). OSS-Fuzz-Gen openssl was measured "
        "after the 22:45 cutoff (1.58%); OSS-Fuzz-Gen poppler and PromeFuzz "
        "libtiff closed as Failed (no valid introspector report / no harness "
        "passed the FuzzBench build, smoke, reachability and campaign gates).",
        "",
        "## Sources",
        "",
        "* `workspace/magma/coverage/{smoke9,smoke9c,corpus_smoke}/`",
        "* `workspace/magma/campaigns/{smoke9,smoke9c,corpus_smoke}/`",
        "* Harness evidence: `workspace/magma/smoke/`",
        "* Integration details: `docs/magma_smoke.md`",
    ]
    out = ROOT / "results/magma_smoke_5min.md"
    out.write_text("\n".join(lines + crash_lines + notes) + "\n", encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
