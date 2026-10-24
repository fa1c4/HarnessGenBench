#!/usr/bin/env python3
"""Plot final Phase B line coverage from a single hgb_eval_all CSV.

The CSV has one endpoint per baseline and target, not a coverage time series.
The curve figure therefore shows a profile across target categories. It must
not be interpreted as coverage growth during a fuzzing campaign.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("MPLCONFIGDIR", str(ROOT / "workspace" / "matplotlib-cache"))

import matplotlib  # noqa: E402

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402
from matplotlib.ticker import MaxNLocator  # noqa: E402


@dataclass(frozen=True)
class FuzzerStyle:
    key: str
    label: str
    color: str
    marker: str
    hatch: str


# Muted colors and hatched bars follow bofuzz_ablation_histogram.py. The
# distinct line markers and figure-level legend follow fun_eval_coverage.py.
FUZZERS = (
    FuzzerStyle("oss-fuzz-gen", "OSS-Fuzz-Gen", "#9a8e73", "^", "+"),
    FuzzerStyle("ckgfuzzer", "CKGFuzzer", "#8e7c93", "o", ""),
    FuzzerStyle("promefuzz", "PromeFuzz", "#9a7373", "x", "x"),
    FuzzerStyle("elfuzz", "ELFuzz", "#7a9a73", "D", "/"),
    FuzzerStyle("g2fuzz", "G2Fuzz", "#73929a", "s", "o"),
)


@dataclass(frozen=True)
class TargetCoverage:
    target: str
    covered: dict[str, float | None]
    status: dict[str, str]

    @property
    def label(self) -> str:
        return self.target.split("_", 1)[0]


def load_endpoint_csv(path: Path) -> list[TargetCoverage]:
    if not path.is_file():
        raise ValueError(f"evaluation CSV does not exist: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"target"}
        for fuzzer in FUZZERS:
            required.update((f"{fuzzer.key}_status", f"{fuzzer.key}_covered_lines"))
        missing = required - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"evaluation CSV is missing columns: {', '.join(sorted(missing))}")
        if "trial" in (reader.fieldnames or ()):
            raise ValueError("this plotter expects one final row per target, not a multi-trial CSV")
        rows = list(reader)
    if not rows:
        raise ValueError("evaluation CSV has no target rows")

    result: list[TargetCoverage] = []
    seen: set[str] = set()
    for row in rows:
        target = (row.get("target") or "").strip()
        if not target or target in seen:
            raise ValueError(f"target is empty or duplicated: {target!r}")
        seen.add(target)
        covered: dict[str, float | None] = {}
        statuses: dict[str, str] = {}
        for fuzzer in FUZZERS:
            status = (row.get(f"{fuzzer.key}_status") or "").strip()
            statuses[fuzzer.key] = status
            if status == "evaluated":
                raw = (row.get(f"{fuzzer.key}_covered_lines") or "").strip()
                try:
                    value = float(raw)
                except ValueError as exc:
                    raise ValueError(f"{fuzzer.label}/{target} has invalid covered_lines: {raw!r}") from exc
                if not math.isfinite(value) or value < 0:
                    raise ValueError(f"{fuzzer.label}/{target} has invalid covered_lines: {raw!r}")
                covered[fuzzer.key] = value
            else:
                # A short or failed campaign's endpoint is not a valid 24 h
                # result, even when an intermediate coverage number exists.
                covered[fuzzer.key] = None
        result.append(TargetCoverage(target, covered, statuses))
    return result


def _style_axes(ax: plt.Axes) -> None:
    ax.grid(axis="y", linestyle="--", linewidth=0.55, alpha=0.4)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def _save(fig: plt.Figure, directory: Path, stem: str) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    svg = directory / f"{stem}.svg"
    pdf = directory / f"{stem}.pdf"
    for path in (svg, pdf):
        fig.savefig(path, dpi=800, bbox_inches="tight", pad_inches=0.1,
                    facecolor="white", edgecolor="none")
    plt.close(fig)
    return svg, pdf


def plot_curve(data: list[TargetCoverage], directory: Path) -> tuple[Path, Path]:
    """Show final coverage as lines across ordered target categories."""
    plt.rcParams.update({"font.family": "DejaVu Sans", "svg.fonttype": "none", "pdf.fonttype": 42})
    midpoint = math.ceil(len(data) / 2)
    panels = (data[:midpoint], data[midpoint:])
    fig, axes = plt.subplots(2, 1, figsize=(20, 10.5), sharey=True)
    positive = [value for item in data for value in item.covered.values()
                if value is not None and value > 0]
    if not positive:
        raise ValueError("no positive evaluated covered-line values to plot")
    lower = 10 ** math.floor(math.log10(min(positive)))
    upper = 10 ** math.ceil(math.log10(max(positive) * 1.2))

    for panel_index, (ax, targets) in enumerate(zip(axes, panels)):
        x = np.arange(len(targets))
        for fuzzer in FUZZERS:
            y = [item.covered[fuzzer.key] if item.covered[fuzzer.key] is not None
                 and item.covered[fuzzer.key] > 0 else np.nan for item in targets]
            ax.plot(x, y, color=fuzzer.color, marker=fuzzer.marker,
                    markersize=5.3, linewidth=1.65, label=fuzzer.label)
        ax.set_yscale("log")
        ax.set_ylim(lower, upper)
        ax.set_xlim(-0.35, len(targets) - 0.65)
        ax.set_xticks(x, [item.label for item in targets], rotation=22, ha="right")
        ax.tick_params(axis="x", labelsize=10)
        ax.tick_params(axis="y", labelsize=14)
        ax.set_ylabel("Covered source lines (log scale)", fontsize=16)
        ax.set_title(f"({chr(97 + panel_index)}) Targets {panel_index * midpoint + 1}–"
                     f"{panel_index * midpoint + len(targets)}", fontsize=13,
                     fontweight="bold", loc="left", pad=8)
        _style_axes(ax)

    handles = [Line2D([0], [0], color=f.color, marker=f.marker, linewidth=1.65,
                      markersize=8, label=f.label) for f in FUZZERS]
    fig.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, 0.985),
               ncol=len(FUZZERS), fontsize=17, frameon=False)
    fig.tight_layout(rect=(0.025, 0.025, 1, 0.91), h_pad=2.0)
    return _save(fig, directory, "fuzzbench_eval_curve")


def plot_bar(data: list[TargetCoverage], directory: Path) -> tuple[Path, Path]:
    """Compare the five endpoints within each target on a zero-based axis."""
    plt.rcParams["hatch.linewidth"] = 0.8
    columns = 5
    rows = math.ceil(len(data) / columns)
    fig, axes = plt.subplots(rows, columns, figsize=(20, 3.4 * rows))
    axes_flat = np.atleast_1d(axes).ravel()

    for index, item in enumerate(data):
        ax = axes_flat[index]
        valid = [value for value in item.covered.values() if value is not None]
        y_max = max(valid, default=1.0)
        y_top = max(1.0, y_max * 1.18)
        for xpos, fuzzer in enumerate(FUZZERS):
            value = item.covered[fuzzer.key]
            if value is None:
                status = item.status[fuzzer.key]
                label = "N/A" if status == "N/A" else "short" if status == "short_campaign" else "failed"
                ax.text(xpos, y_top * 0.035, label, rotation=90,
                        ha="center", va="bottom", fontsize=12, color="#555555")
                continue
            ax.bar(xpos, value, width=0.82, color=fuzzer.color, hatch=fuzzer.hatch,
                   edgecolor="#333333", linewidth=0.7)
        ax.set_ylim(0, y_top)
        ax.set_xlim(-0.6, len(FUZZERS) - 0.4)
        ax.set_xticks([])
        ax.yaxis.set_major_locator(MaxNLocator(nbins=4))
        ax.tick_params(axis="y", labelsize=12)
        ax.set_title(f"({chr(97 + index)}) {item.label}", fontsize=11,
                     fontweight="bold", pad=6)
        _style_axes(ax)

    for ax in axes_flat[len(data):]:
        ax.set_visible(False)
    handles = [Patch(facecolor=f.color, edgecolor="#333333", hatch=f.hatch,
                     label=f.label) for f in FUZZERS]
    fig.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, 0.982),
               ncol=len(FUZZERS), prop={"size": 16, "weight": "bold"}, frameon=False)
    fig.supylabel("Covered source lines at 24 h", fontsize=16)
    fig.tight_layout(rect=(0.02, 0.02, 1, 0.91), h_pad=1.25, w_pad=1.2)
    return _save(fig, directory, "fuzzbench_eval_bar")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path,
                        default=ROOT / "workspace/eval_all/2026-10-16.coverage_corrected.csv",
                        help="single endpoint CSV with target-source coverage (default: corrected 2026-10-16 run)")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "results",
                        help="figure directory (default: results/)")
    args = parser.parse_args()
    try:
        data = load_endpoint_csv(args.input)
        curve = plot_curve(data, args.output_dir)
        bar = plot_bar(data, args.output_dir)
    except ValueError as exc:
        parser.error(str(exc))
    evaluated = sum(value is not None for item in data for value in item.covered.values())
    applicable = sum(status != "N/A" for item in data for status in item.status.values())
    print(f"Plotted {evaluated}/{applicable} evaluated baseline/target endpoints from {args.input}")
    for path in (*curve, *bar):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
