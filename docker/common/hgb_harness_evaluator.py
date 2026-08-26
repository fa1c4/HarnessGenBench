#!/usr/bin/env python3
"""Full harness-driver evaluator for HarnessGenBench harness generators.

Replaces the build-only ``ckgfuzzer_candidate_verifier`` semantics.  For each
generated candidate the evaluator:

  1. overlays the candidate at the exact native FuzzBench harness path;
  2. builds the sealed FuzzBench target image with a deterministic tag;
  3. runs sanitizer smoke on empty input and seeds;
  4. confirms at least one intended project API executes (reachability);
  5. runs a fixed-budget libFuzzer campaign and records ``execs_done``;
  6. measures real LLVM source-based coverage;
  7. selects the best evaluated candidate for the run-level result.

A candidate that merely compiles never marks campaign/coverage as completed.
``status=evaluated`` requires a real overlay, ``execs_done > 0``, and a real
coverage report.

CLI::

    python3 /opt/hgb/bin/hgb_harness_evaluator.py \
      --generator ckgfuzzer \
      --target-root /target --evaluator-root /evaluator \
      --candidates /workspace/generated_harnesses/repaired \
      --work-dir /workspace/evaluation \
      --project "$HGB_TARGET_PROJECT" --fuzz-target "$HGB_TARGET_FUZZ_TARGET" \
      --profile "$HGB_BASELINE_PROFILE" --campaign-seconds 300 --strict
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# Import sibling helpers defensively so this file works both when imported as a
# module (container venv) and when loaded by the offline pytest suite.
sys.path.insert(0, str(Path(__file__).resolve().parent))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_HERE = Path(__file__).resolve().parent
hgb_result = _load("hgb_result", _HERE / "hgb_result.py")
hgb_coverage = _load("hgb_coverage", _HERE / "hgb_coverage.py")
hgb_reachability = _load("hgb_reachability", _HERE / "hgb_reachability.py")
hgb_target_package = _load("hgb_target_package", _HERE / "hgb_target_package.py")
hgb_fuzzbench_builder = _load("hgb_fuzzbench_builder", _HERE / "hgb_fuzzbench_builder.py")

# Optional: the sealed context + native harness helpers from the CKGFuzzer
# container.  When absent (offline unit tests), callers inject substitutes.
try:
    ckgfuzzer_verifier_context = _load("ckgfuzzer_verifier_context", _HERE / "ckgfuzzer_verifier_context.py")
    ckgfuzzer_target_harness = _load("ckgfuzzer_target_harness", _HERE / "ckgfuzzer_target_harness.py")
except Exception:  # pragma: no cover - only in stripped-down test environments
    ckgfuzzer_verifier_context = None
    ckgfuzzer_target_harness = None

try:
    hgb_split_context = _load("hgb_split_context", _HERE / "hgb_split_context.py")
except Exception:  # pragma: no cover - only in stripped-down test environments
    hgb_split_context = None


SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}

# Eta is the canonical strictest profile (eta plan §6): coverage must come from
# a separate coverage-instrumented build that replays the final campaign
# corpus, with a copied coverage.json (no stdout fallback). copy_out_ok,
# coverage_report_path, and inputs_replayed > 0 are mandatory for an evaluated
# eta row.
ETA_PROFILES = {"reproduction-eta"}
SOURCE_TEXT_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc"}
_C_LIKE_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.DOTALL | re.MULTILINE)
_C_LIKE_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.DOTALL)


def _primary_source_roots(target_root: Path) -> list[Path]:
    """Return generator-visible primary-project source roots.

    Some FuzzBench packages include dependency trees beside the target project
    (for example Mbed TLS packages can contain BoringSSL/OpenSSL checkouts).
    CKGFuzzer API plans must not require symbols that only appear in those
    secondary dependency roots.
    """

    repos_path = target_root / "source_repos.json"
    if not repos_path.is_file():
        return []
    try:
        records = json.loads(repos_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(records, list):
        return []
    roots: list[Path] = []
    for record in records:
        if not isinstance(record, dict) or not record.get("is_primary_project"):
            continue
        rel = str(record.get("package_path") or "").strip()
        if not rel:
            dest = str(record.get("dest") or record.get("docker_dest") or "").strip().strip("/")
            rel = f"source_input/{dest}" if dest else ""
        if not rel:
            continue
        root = (target_root / rel).resolve()
        try:
            root.relative_to(target_root.resolve())
        except ValueError:
            continue
        if root.exists():
            roots.append(root)
    return roots


def _source_without_comments_or_strings(text: str) -> str:
    text = _C_LIKE_COMMENT_RE.sub(" ", text)
    return _C_LIKE_STRING_RE.sub(" ", text)


def _symbol_visible_in_roots(symbol: str, roots: list[Path]) -> bool:
    clean_symbol = symbol.strip()
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", clean_symbol):
        return False
    call_like = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(clean_symbol)}\s*\(")
    for root in roots:
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in SOURCE_TEXT_SUFFIXES:
                continue
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if call_like.search(_source_without_comments_or_strings(source)):
                return True
    return False


def _filter_intended_apis_by_primary_source(intended_apis: list[str], target_root: Path) -> list[str]:
    if not intended_apis:
        return []
    roots = _primary_source_roots(target_root)
    if not roots:
        return intended_apis
    filtered = [api for api in intended_apis if _symbol_visible_in_roots(api.split("::")[-1], roots)]
    return filtered


@dataclass
class CandidateRecord:
    candidate_id: str
    candidate_path: str
    candidate_sha256: str
    overlaid: bool = False
    native_destination: str = ""
    stages: dict[str, str] = field(default_factory=hgb_result.default_stages)
    sanitizer_smoke: dict[str, Any] = field(default_factory=dict)
    api_reachability: dict[str, Any] = field(default_factory=dict)
    campaign: dict[str, Any] = field(default_factory=dict)
    coverage: dict[str, Any] = field(default_factory=dict)
    coverage_diff: dict[str, Any] = field(default_factory=dict)
    native_coverage: dict[str, Any] = field(default_factory=dict)
    build: dict[str, Any] = field(default_factory=dict)
    copy_audit: dict[str, Any] = field(default_factory=dict)
    error: str = ""


def compute_coverage_diff(
    candidate_summary: dict[str, Any] | None,
    native_summary: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compute the runtime line coverage diff vs the native/reference control.

    Per beta plan section 8.6, emits ``candidate_lines_covered``,
    ``native_lines_covered``, ``new_lines_vs_native``,
    ``line_coverage_diff_percent`` and ``runtime_coverage_valid``. When the
    native/reference coverage cannot be computed, the candidate coverage is
    still emitted but ``status`` is ``unavailable`` so the row is never
    falsely labelled paper-equivalent.
    """
    cand_lines = _covered_lines(candidate_summary)
    native_lines = _covered_lines(native_summary)
    if candidate_summary is None or cand_lines is None:
        return {
            "candidate_lines_covered": cand_lines,
            "native_lines_covered": native_lines,
            "new_lines_vs_native": None,
            "line_coverage_diff_percent": None,
            "runtime_coverage_valid": False,
            "status": "unavailable",
        }
    if native_summary is None or native_lines is None:
        return {
            "candidate_lines_covered": cand_lines,
            "native_lines_covered": None,
            "new_lines_vs_native": None,
            "line_coverage_diff_percent": None,
            "runtime_coverage_valid": True,
            "status": "unavailable",
        }
    new_lines = max(0, cand_lines - native_lines)
    if native_lines:
        diff_percent = round(100.0 * (cand_lines - native_lines) / native_lines, 1)
    else:
        diff_percent = 100.0 if cand_lines else 0.0
    return {
        "candidate_lines_covered": cand_lines,
        "native_lines_covered": native_lines,
        "new_lines_vs_native": new_lines,
        "line_coverage_diff_percent": diff_percent,
        "runtime_coverage_valid": True,
        "status": "available",
    }


def _covered_lines(summary: dict[str, Any] | None) -> int | None:
    if not isinstance(summary, dict):
        return None
    line_cov = summary.get("line_coverage")
    if not isinstance(line_cov, dict):
        return None
    covered = line_cov.get("covered")
    if covered is None:
        return None
    return int(covered)


def _candidate_files(candidates_dir: Path) -> list[Path]:
    if not candidates_dir.is_dir():
        return []
    return [
        path
        for path in sorted(candidates_dir.iterdir())
        if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES
    ]


def _resolve_target_metadata(target_root: Path) -> tuple[str, str]:
    """Read project/fuzz_target from the generator-visible target manifest.

    The plan's stable evaluator CLI (section 4) does not pass ``--fuzz-target``
    or ``--project``; they are resolved from ``<target_root>/target_manifest.json``
    so the same CLI works for OSS-Fuzz-Gen, CKGFuzzer, and PromeFuzz. Returns
    ``(project, fuzz_target)``; both are "" if the manifest is unreadable.
    """
    for candidate in (Path(target_root) / "target_manifest.json", Path(target_root) / "target_manifest.generator.json"):
        if not candidate.is_file():
            continue
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        return str(data.get("project") or ""), str(data.get("fuzz_target") or "")
    return "", ""


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _resolve_native_harness(
    evaluator_root: Path,
    target_root: Path,
    fuzz_target: str,
    native_harness_provider: Callable[..., Any] | None,
) -> dict[str, Any]:
    """Resolve the exact native harness path from evaluator-only metadata."""
    native_path_json = evaluator_root / "native_harness_path.json"
    if native_path_json.is_file():
        try:
            data = json.loads(native_path_json.read_text(encoding="utf-8"))
            if data.get("container_destination") and data.get("selected_reference"):
                return data
        except (OSError, json.JSONDecodeError):
            pass
    ev_manifest = evaluator_root / "target_manifest.evaluator.json"
    if ev_manifest.is_file():
        try:
            data = json.loads(ev_manifest.read_text(encoding="utf-8"))
            if data.get("native_harness_destination") and data.get("native_harness_path"):
                return {
                    "selected_reference": data["native_harness_path"],
                    "container_destination": data["native_harness_destination"],
                }
        except (OSError, json.JSONDecodeError):
            pass
    if native_harness_provider is not None and ckgfuzzer_target_harness is not None:
        harness = native_harness_provider(target_root, fuzz_target)
        return {
            "selected_reference": harness.selected_reference,
            "container_destination": harness.container_destination,
            "language": harness.language,
        }
    raise RuntimeError("could not resolve native harness path from evaluator-only metadata")


def _prepare_sealed_context(
    target_root: Path,
    evaluator_root: Path,
    work_dir: Path,
    context_provider: Callable[..., Any] | None,
    *,
    strict: bool = False,
) -> dict[str, Any]:
    """Build the sealed Docker context for the evaluator.

    In blind-project split mode the evaluator must combine ``source_input``
    and ``source_repos.json`` from the generator half (``/target``) with
    ``benchmark_copy`` and ``native_harness_path.json`` from the evaluator
    half (``/evaluator``).  Passing either half alone into the monolithic
    ``prepare_verification_context`` fails because each half is missing files
    the other provides.

    In strict profiles (reproduction-zeta/epsilon/delta) a split-package
    failure must fail closed: never fall through to a monolithic package or
    evaluator half that could contain reference harnesses (zeta plan §3).
    """

    if context_provider is not None:
        return context_provider(target_root, work_dir)
    # Split-aware path: generator half has source_input, evaluator half has
    # benchmark_copy.  Use the split context loader to combine them.
    if hgb_split_context is not None:
        has_gen_source = (target_root / "source_input").is_dir()
        has_eval_benchmark = (evaluator_root / "benchmark_copy").is_dir()
        if has_gen_source and has_eval_benchmark and target_root != evaluator_root:
            try:
                ctx = hgb_split_context.SplitTargetContext.load(target_root, evaluator_root)
                return hgb_split_context.create_sealed_build_context(ctx, work_dir)
            except hgb_split_context.VerificationContextError as exc:
                if strict:
                    # Fail closed: a strict blind-project split error must not
                    # fall through to a monolithic package or evaluator half
                    # that could contain reference harnesses.
                    raise
                pass  # fall through to monolithic path
    # Monolithic fallback (non-split packages).
    if ckgfuzzer_verifier_context is None:
        raise RuntimeError("sealed context provider unavailable")
    benchmark_copy = evaluator_root / "benchmark_copy"
    if benchmark_copy.is_dir():
        return ckgfuzzer_verifier_context.prepare_verification_context(evaluator_root, work_dir)
    return ckgfuzzer_verifier_context.prepare_verification_context(target_root, work_dir)


def evaluate_candidate(
    *,
    candidate: Path,
    candidate_id: str,
    target_root: Path,
    evaluator_root: Path,
    work_dir: Path,
    project: str,
    fuzz_target: str,
    campaign_seconds: int,
    image_tag: str,
    runner: Callable[..., Any],
    native_harness: dict[str, Any],
    sealed_context: dict[str, Any],
    intended_apis: list[str],
    seeds: list[Path],
    coverage_parser: Callable[[Path], dict[str, Any]] | None = None,
    strict: bool = True,
    run_native_control: bool = False,
    native_image_tag: str = "",
    coverage_image_tag: str = "",
    build_coverage_image: bool = False,
    build_timeout_seconds: int = 1800,
    profile: str = "",
) -> CandidateRecord:
    """Evaluate a single candidate end-to-end."""
    strict_eta = profile in ETA_PROFILES

    rec = CandidateRecord(
        candidate_id=candidate_id,
        candidate_path=str(candidate),
        candidate_sha256=_sha256_file(candidate),
    )
    candidate_work = work_dir / candidate_id
    candidate_work.mkdir(parents=True, exist_ok=True)

    # 6.1 Candidate overlay at the exact native path.
    native_destination = native_harness["container_destination"]
    rec.native_destination = native_destination
    context_dir = Path(sealed_context["context_dir"])
    dockerfile = Path(sealed_context["dockerfile"])
    rel = native_destination
    for prefix in ("/src/", "src/"):
        if rel.startswith(prefix):
            rel = rel[len(prefix):]
            break
    overlay_path = context_dir / "source_input" / rel
    overlay_path.parent.mkdir(parents=True, exist_ok=True)
    original_sha = _sha256_file(overlay_path) if overlay_path.is_file() else ""
    shutil.copy2(candidate, overlay_path)
    new_sha = _sha256_file(overlay_path)
    rec.overlaid = new_sha != original_sha or original_sha == ""
    if strict and not rec.overlaid:
        rec.error = "candidate overlay did not change the native harness path"
        hgb_result.mark_stage(rec.stages, "generation", "completed")
        hgb_result.mark_stage(rec.stages, "candidate_overlay", "failed")
        hgb_result.mark_stage(rec.stages, "candidate_build", "failed")
        return rec
    hgb_result.mark_stage(rec.stages, "generation", "completed")
    hgb_result.mark_stage(rec.stages, "candidate_overlay", "completed")

    # 6.1b Copy audit: compare the candidate to evaluator-only reference
    # harnesses *after* generation. This never runs before generation and
    # never writes reference contents into generator-visible directories.
    ref_dir = evaluator_root / "reference_harnesses"
    if not ref_dir.is_dir():
        ref_dir = evaluator_root / "selected_reference_harnesses"
    canary = os.environ.get("HGB_REF_CANARY", "")
    if hgb_split_context is not None and ref_dir.is_dir():
        rec.copy_audit = hgb_split_context.audit_candidate_reference_copy(
            candidate, ref_dir, canary=canary,
        )
        hgb_result.mark_stage(rec.stages, "copy_audit", "completed")
    elif hgb_split_context is not None:
        rec.copy_audit = {"status": "not_requested", "reason": "no_reference_harnesses"}
        hgb_result.mark_stage(rec.stages, "copy_audit", "completed")
    else:
        hgb_result.mark_stage(rec.stages, "copy_audit", "completed")

    # 6.2 Exact FuzzBench build with the deterministic image tag.
    build = hgb_fuzzbench_builder.build_candidate_image(
        context_dir=context_dir,
        dockerfile=dockerfile,
        image_tag=image_tag,
        fuzz_target=fuzz_target,
        staged_candidate_host=candidate,
        native_destination=native_destination,
        work_dir=candidate_work / "build",
        runner=runner,
        timeout_seconds=build_timeout_seconds,
    )
    rec.build = {
        "image_tag": image_tag,
        "image_digest": build.image_digest,
        "binary_path": build.binary_path,
        "binary_sha256": build.binary_sha256,
        "binary_verified": build.binary_verified,
        "build_exit_code": build.build_exit_code,
        "compiler": build.compiler,
        "sanitizer": build.sanitizer,
        "engine": build.engine,
        "log": build.log,
        "overlay_audit": build.overlay_audit or {},
        "sealed_env_defaults": build.sealed_env_defaults or sealed_context.get("sealed_env_defaults", {}),
    }
    if build.build_exit_code != 0:
        hgb_result.mark_stage(rec.stages, "candidate_build", "failed")
        rec.error = f"FuzzBench build exited {build.build_exit_code}"
        return rec
    # Section 5.1: the built image must contain an executable /out/<fuzz_target>.
    if not build.binary_verified:
        hgb_result.mark_stage(rec.stages, "candidate_build", "failed")
        rec.error = "candidate_build: /out/<fuzz_target> is missing or not executable in the built image"
        return rec
    hgb_result.mark_stage(rec.stages, "candidate_build", "completed")
    # Section 3.5: if the source compiled at the native path does not match the
    # candidate, the reference harness overwrote the candidate. Do not proceed.
    overlay_audit = build.overlay_audit or {}
    if overlay_audit.get("container_native_sha256") and not overlay_audit.get("matches_candidate"):
        hgb_result.mark_stage(rec.stages, "candidate_overlay", "failed")
        rec.error = "candidate_overlay=failed: source at native path does not match the candidate (reference overwrote candidate)"
        return rec

    # 6.3 Sanitizer smoke.
    smoke = hgb_fuzzbench_builder.run_smoke(
        image_tag=image_tag,
        binary_path=build.binary_path,
        seeds=seeds,
        work_dir=candidate_work / "smoke",
        runner=runner,
    )
    rec.sanitizer_smoke = smoke
    if smoke.get("misuse_crash"):
        hgb_result.mark_stage(rec.stages, "sanitizer_smoke", "failed")
        rec.error = "sanitizer misuse crash on smoke samples"
        return rec
    if not smoke.get("any_executed"):
        hgb_result.mark_stage(rec.stages, "sanitizer_smoke", "failed")
        rec.error = "no smoke sample executed the target"
        return rec
    hgb_result.mark_stage(rec.stages, "sanitizer_smoke", "completed")

    # 6.4 Fuzzing campaign (fixed-budget libFuzzer).
    corpus_dir = candidate_work / "corpus"
    corpus_dir.mkdir(parents=True, exist_ok=True)
    for seed in seeds:
        if Path(seed).is_file():
            shutil.copy2(seed, corpus_dir / Path(seed).name)
    campaign = hgb_fuzzbench_builder.run_campaign(
        image_tag=image_tag,
        binary_path=build.binary_path,
        corpus_dir=corpus_dir,
        work_dir=candidate_work,
        campaign_seconds=campaign_seconds,
        runner=runner,
    )
    rec.campaign = campaign
    if int(campaign.get("execs_done", 0) or 0) <= 0:
        hgb_result.mark_stage(rec.stages, "campaign", "failed")
        rec.error = "campaign recorded execs_done <= 0"
        return rec
    # In strict profiles the campaign must produce a nonempty final corpus;
    # never fall back to the seed corpus for coverage replay (zeta plan §2/§3).
    final_corpus_file_count = int(campaign.get("final_corpus_file_count", 0) or 0)
    if strict and final_corpus_file_count <= 0:
        hgb_result.mark_stage(rec.stages, "campaign", "failed")
        rec.error = "campaign final corpus is empty; strict profiles never fall back to the seed corpus"
        return rec
    hgb_result.mark_stage(rec.stages, "campaign", "completed")

    # 6.5 Coverage (real LLVM source-based coverage with function detail).
    # Replay the final campaign corpus (not only the seed corpus) so coverage
    # reflects the inputs the fuzzer actually executed. Build a separate
    # coverage-instrumented image so an address/libFuzzer image is never reused
    # for source-based coverage unless explicitly built with coverage flags.
    coverage_corpus_dir = Path(campaign.get("corpus_dir", "")) if campaign.get("corpus_dir") else corpus_dir
    if not coverage_corpus_dir.is_dir() or not any(coverage_corpus_dir.iterdir()):
        # In strict mode do not fall back to the seed corpus when the campaign
        # final corpus is missing/empty (zeta plan §3).
        if strict:
            hgb_result.mark_stage(rec.stages, "coverage", "failed")
            rec.error = "coverage corpus missing/empty; strict profiles never fall back to the seed corpus"
            return rec
        coverage_corpus_dir = corpus_dir
    cov_image = image_tag
    if build_coverage_image and coverage_image_tag:
        cov_build = hgb_fuzzbench_builder.build_coverage_image(
            context_dir=context_dir,
            dockerfile=dockerfile,
            image_tag=coverage_image_tag,
            fuzz_target=fuzz_target,
            work_dir=candidate_work / "coverage_build",
            runner=runner,
            timeout_seconds=build_timeout_seconds,
        )
        # If a coverage image was requested but its build failed or the
        # coverage binary was not verified, fail coverage immediately. Do NOT
        # silently reuse the address/libFuzzer image (zeta plan §3).
        if cov_build.build_exit_code != 0 or not cov_build.binary_verified:
            hgb_result.mark_stage(rec.stages, "coverage", "failed")
            rec.error = (
                f"coverage image build failed (exit={cov_build.build_exit_code}, "
                f"binary_verified={cov_build.binary_verified}); not reusing the address image"
            )
            rec.coverage = {
                "report_exists": False,
                "line_coverage": {"covered": None},
                "build_exit_code": cov_build.build_exit_code,
                "binary_verified": cov_build.binary_verified,
            }
            return rec
        cov_image = coverage_image_tag
    cov = hgb_fuzzbench_builder.run_coverage(
        image_tag=cov_image,
        binary_path=build.binary_path,
        corpus_dir=coverage_corpus_dir,
        work_dir=candidate_work,
        runner=runner,
        require_coverage_report=strict_eta,
    )
    raw_text = cov.get("raw_text", "")
    cov_summary: dict[str, Any] | None = None
    coverage_report_path = cov.get("coverage_report_path", "")
    # Eta coverage invariants (eta plan §6): the coverage report must be a real
    # coverage.json copied out of the container (copy_out_ok, a
    # coverage_report_path that exists on disk, and inputs_replayed > 0). The
    # stdout-only fallback is removed for strict eta; a missing copied report
    # fails coverage immediately.
    if strict_eta:
        if not bool(cov.get("copy_out_ok", False)):
            hgb_result.mark_stage(rec.stages, "coverage", "failed")
            rec.error = "coverage.copy_out_ok != true; strict eta requires a copied coverage.json"
            rec.coverage = {
                "report_exists": bool(cov.get("report_exists", False)),
                "line_coverage": {"covered": None},
                "copy_out_ok": False,
                "inputs_replayed": int(cov.get("inputs_replayed", 0) or 0),
                "coverage_report_path": coverage_report_path,
            }
            return rec
        if not coverage_report_path or not Path(coverage_report_path).is_file():
            hgb_result.mark_stage(rec.stages, "coverage", "failed")
            rec.error = "coverage.coverage_report_path is missing or does not exist; strict eta requires a copied coverage.json"
            rec.coverage = {
                "report_exists": False,
                "line_coverage": {"covered": None},
                "copy_out_ok": True,
                "inputs_replayed": int(cov.get("inputs_replayed", 0) or 0),
                "coverage_report_path": coverage_report_path,
            }
            return rec
        if int(cov.get("inputs_replayed", 0) or 0) <= 0:
            hgb_result.mark_stage(rec.stages, "coverage", "failed")
            rec.error = "coverage.inputs_replayed <= 0; strict eta requires the final campaign corpus to be replayed"
            rec.coverage = {
                "report_exists": True,
                "line_coverage": {"covered": None},
                "copy_out_ok": True,
                "inputs_replayed": 0,
                "coverage_report_path": coverage_report_path,
            }
            return rec
        # Parse the copied coverage.json directly (not stdout).
        try:
            cov_path = Path(coverage_report_path)
            parser = coverage_parser or hgb_coverage.summarize_coverage_report
            cov_summary = parser(cov_path)
            hgb_coverage.write_coverage_outputs(candidate_work / "coverage", cov_summary, cov_path.read_text(encoding="utf-8"))
        except hgb_coverage.CoverageError as exc:
            rec.error = f"coverage report invalid: {exc}"
    elif raw_text.strip():
        try:
            cov_path = candidate_work / "coverage" / "coverage.json"
            cov_path.parent.mkdir(parents=True, exist_ok=True)
            cov_path.write_text(raw_text, encoding="utf-8")
            coverage_report_path = str(cov_path)
            parser = coverage_parser or hgb_coverage.summarize_coverage_report
            cov_summary = parser(cov_path)
            hgb_coverage.write_coverage_outputs(candidate_work / "coverage", cov_summary, raw_text)
        except hgb_coverage.CoverageError as exc:
            rec.error = f"coverage report invalid: {exc}"
    # Attach the coverage-phase audit so invariants can require report_exists.
    if cov_summary is not None:
        cov_summary = dict(cov_summary)
        if strict_eta:
            cov_summary["report_exists"] = bool(cov.get("report_exists", False))
        else:
            cov_summary["report_exists"] = bool(cov.get("report_exists", False)) or bool(raw_text.strip())
        cov_summary["inputs_replayed"] = int(cov.get("inputs_replayed", 0) or 0)
        cov_summary["copy_in_ok"] = bool(cov.get("copy_in_ok", True))
        cov_summary["copy_out_ok"] = bool(cov.get("copy_out_ok", True))
    rec.coverage = cov_summary or {}
    rec.coverage["coverage_report_path"] = coverage_report_path
    if cov_summary is None or cov_summary.get("line_coverage", {}).get("covered") is None:
        hgb_result.mark_stage(rec.stages, "coverage", "failed")
        if not rec.error:
            rec.error = "coverage report missing or empty"
        return rec
    hgb_result.mark_stage(rec.stages, "coverage", "completed")

    # 6.6 API reachability (real runtime evidence, never fabricated).
    # Replace the old fake reachability that passed intended_apis as
    # executed_functions.  Use the coverage report's covered function names
    # (from llvm-cov export without -summary-only) to match intended API
    # symbols.  If no intended API list exists, mark not_requested.
    if not intended_apis:
        rec.api_reachability = {
            "status": "not_requested",
            "reason": "no_intended_api_list",
            "intended_apis": [],
            "reached_apis": [],
            "reached": True,
        }
        hgb_result.mark_stage(rec.stages, "api_reachability", "completed")
    else:
        covered_functions = cov_summary.get("covered_functions", []) if cov_summary else []
        reach = hgb_reachability.check_reachability(intended_apis, {"executed_functions": covered_functions})
        rec.api_reachability = reach
        if not reach["reached"]:
            hgb_result.mark_stage(rec.stages, "api_reachability", "failed")
            rec.error = "no intended project API executed dynamically (no coverage evidence)"
            return rec
        hgb_result.mark_stage(rec.stages, "api_reachability", "completed")

    # 6.7 Native/reference coverage control + line coverage diff (beta 8.6).
    # The native control replays the native (reference) harness under the same
    # coverage instrumentation so candidate coverage can be compared against a
    # real control rather than an exit code. When the native control cannot be
    # computed, candidate coverage is still emitted but coverage_diff.status
    # is "unavailable" so the row is never labelled paper-equivalent.
    native_summary: dict[str, Any] | None = None
    if run_native_control:
        try:
            # Native control replays the same final campaign corpus as the
            # candidate (not the original seed corpus) so the coverage diff
            # compares candidate and reference harnesses on identical inputs
            # (eta plan §2).
            native_corpus_dir = coverage_corpus_dir if coverage_corpus_dir.is_dir() and any(coverage_corpus_dir.iterdir()) else corpus_dir
            native_summary = _run_native_coverage_control(
                target_root=target_root,
                evaluator_root=evaluator_root,
                sealed_context=sealed_context,
                native_harness=native_harness,
                fuzz_target=fuzz_target,
                image_tag=native_image_tag or (image_tag + "-native"),
                corpus_dir=native_corpus_dir,
                work_dir=candidate_work,
                runner=runner,
                coverage_parser=coverage_parser,
                require_coverage_report=strict_eta,
            )
        except Exception as exc:  # noqa: BLE001 - native control is best-effort
            rec.native_coverage = {"status": "unavailable", "error": str(exc)}
    rec.native_coverage = rec.native_coverage or (native_summary or {})
    rec.coverage_diff = compute_coverage_diff(cov_summary, native_summary)
    return rec


def _run_native_coverage_control(
    *,
    target_root: Path,
    evaluator_root: Path,
    sealed_context: dict[str, Any],
    native_harness: dict[str, Any],
    fuzz_target: str,
    image_tag: str,
    corpus_dir: Path,
    work_dir: Path,
    runner: Callable[..., Any],
    coverage_parser: Callable[[Path], dict[str, Any]] | None = None,
    require_coverage_report: bool = False,
) -> dict[str, Any] | None:
    """Build the native (reference) image and replay coverage as a control.

    Restores the original native harness into a copy of the sealed context so
    the FuzzBench build compiles the reference (not the candidate), then runs
    a coverage replay. Returns the parsed coverage summary or None.
    """
    import shutil

    context_dir = Path(sealed_context["context_dir"])
    dockerfile = Path(sealed_context["dockerfile"])
    native_dest = native_harness.get("container_destination", "")
    if not native_dest:
        return None
    native_rel = native_dest
    for prefix in ("/src/", "src/"):
        if native_rel.startswith(prefix):
            native_rel = native_rel[len(prefix):]
            break
    overlay_path = context_dir / "source_input" / native_rel
    # Locate the original native harness from the evaluator-only half.
    native_src = evaluator_root / "selected_reference_harnesses"
    native_file = Path(native_harness.get("selected_reference", ""))
    original = None
    if native_file.is_absolute():
        candidate_path = native_file
    else:
        candidate_path = evaluator_root / native_file
    if candidate_path.is_file():
        original = candidate_path
    if original is None and native_src.is_dir():
        for p in sorted(native_src.rglob("*")):
            if p.is_file() and p.name == Path(native_dest).name:
                original = p
                break
    if original is None:
        return None
    # The candidate was overlaid at overlay_path; restore the native harness.
    native_work = work_dir / "native_control"
    native_work.mkdir(parents=True, exist_ok=True)
    shutil.copy2(original, overlay_path)
    native_build = hgb_fuzzbench_builder.build_candidate_image(
        context_dir=context_dir,
        dockerfile=dockerfile,
        image_tag=image_tag,
        fuzz_target=fuzz_target,
        staged_candidate_host=original,
        native_destination=native_dest,
        work_dir=native_work / "build",
        runner=runner,
    )
    if native_build.build_exit_code != 0:
        return None
    native_cov = hgb_fuzzbench_builder.run_coverage(
        image_tag=image_tag,
        binary_path=native_build.binary_path,
        corpus_dir=corpus_dir,
        work_dir=native_work,
        runner=runner,
        require_coverage_report=require_coverage_report,
    )
    # For strict eta, the native control coverage must also come from a copied
    # coverage.json (no stdout fallback). For legacy profiles, parse stdout.
    if require_coverage_report:
        native_report = str(native_cov.get("coverage_report_path", ""))
        if not native_report or not Path(native_report).is_file():
            return None
        try:
            parser = coverage_parser or hgb_coverage.summarize_coverage_report
            return parser(Path(native_report))
        except hgb_coverage.CoverageError:
            return None
    raw_text = native_cov.get("raw_text", "")
    if not raw_text.strip():
        return None
    try:
        cov_path = native_work / "coverage" / "coverage.json"
        cov_path.parent.mkdir(parents=True, exist_ok=True)
        cov_path.write_text(raw_text, encoding="utf-8")
        parser = coverage_parser or hgb_coverage.summarize_coverage_report
        return parser(cov_path)
    except hgb_coverage.CoverageError:
        return None


def evaluate(
    *,
    generator: str,
    target_root: Path,
    evaluator_root: Path,
    candidates_dir: Path,
    work_dir: Path,
    project: str,
    fuzz_target: str,
    profile: str,
    campaign_seconds: int,
    strict: bool = True,
    runner: Callable[..., Any] | None = None,
    context_provider: Callable[..., Any] | None = None,
    native_harness_provider: Callable[..., Any] | None = None,
    coverage_parser: Callable[[Path], dict[str, Any]] | None = None,
    intended_apis: list[str] | None = None,
    seeds: list[Path] | None = None,
    run_id: str = "",
    run_native_control: bool = False,
    protocol: str = "blind-project",
    build_timeout_seconds: int = 1800,
    build_coverage_image: bool = False,
    result_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Evaluate all candidates and return the run-level result dict.

    ``protocol`` overrides the historical default (``blind-project``) so the
    shared evaluator can report ``api-oracle`` / ``target-aware`` variants
    faithfully.  ``build_timeout_seconds`` is the per-candidate FuzzBench
    Docker build timeout.  ``result_dir`` writes an additional copy of
    ``result.json`` (and the per-candidate JSONs) to a caller-chosen
    directory so OSS-Fuzz-Gen / CKGFuzzer / PromeFuzz entrypoints can collect
    auditable outputs at a stable path.
    """

    work_dir.mkdir(parents=True, exist_ok=True)
    runner = runner or hgb_fuzzbench_builder._run
    candidates = _candidate_files(candidates_dir)
    candidates_json_dir = work_dir / "candidates"
    candidates_json_dir.mkdir(parents=True, exist_ok=True)

    def _emit(result: dict[str, Any]) -> dict[str, Any]:
        hgb_result.write_result(result, work_dir / "result.json")
        if result_dir is not None:
            hgb_result.write_result(result, Path(result_dir) / "result.json")
        return result

    if not candidates:
        stages = hgb_result.default_stages()
        hgb_result.mark_stage(stages, "generation", "failed")
        result = hgb_result.build_result(
            generator=generator,
            profile=profile,
            protocol=protocol,
            target=fuzz_target,
            status=hgb_result.STATUS_QUALITY_FAILURE,
            stages=stages,
            reason="no candidate source files were supplied to the evaluator",
            candidate_count=0,
        )
        return _emit(result)

    try:
        native_harness = _resolve_native_harness(
            evaluator_root, target_root, fuzz_target, native_harness_provider
        )
    except Exception as exc:
        stages = hgb_result.default_stages()
        result = hgb_result.build_result(
            generator=generator,
            profile=profile,
            protocol=protocol,
            target=fuzz_target,
            status=hgb_result.STATUS_INFRA_FAILURE,
            stages=stages,
            reason=f"native_harness_unresolved: {exc}",
            candidate_count=len(candidates),
        )
        return _emit(result)

    try:
        sealed_context = _prepare_sealed_context(target_root, evaluator_root, work_dir / "sealed_context", context_provider, strict=strict)
    except Exception as exc:
        stages = hgb_result.default_stages()
        result = hgb_result.build_result(
            generator=generator,
            profile=profile,
            protocol=protocol,
            target=fuzz_target,
            status=hgb_result.STATUS_INFRA_FAILURE,
            stages=stages,
            reason=f"sealed_context_failed: {exc}",
            candidate_count=len(candidates),
        )
        return _emit(result)

    plan_apis = intended_apis
    if plan_apis is None:
        plan_path = work_dir.parent / "ckg" / "api_plan.json"
        if plan_path.is_file():
            try:
                plan_apis = hgb_reachability.extract_intended_apis(plan_path)
            except hgb_reachability.ReachabilityError:
                plan_apis = []
        else:
            plan_apis = []
    plan_apis = _filter_intended_apis_by_primary_source(plan_apis, target_root)

    if seeds is None:
        seeds_dir = target_root / "seeds"
        seeds = sorted(p for p in seeds_dir.iterdir() if p.is_file()) if seeds_dir.is_dir() else []
    else:
        seeds = [Path(p) for p in seeds if Path(p).is_file()]
    if not seeds:
        # Materialize libFuzzer's implicit empty seed as an explicit campaign
        # input so strict profiles have a real final corpus artifact to replay.
        seed_dir = work_dir / "campaign_seeds"
        seed_dir.mkdir(parents=True, exist_ok=True)
        empty_seed = seed_dir / "hgb_empty_seed"
        empty_seed.write_bytes(b"")
        seeds = [empty_seed]

    records: list[CandidateRecord] = []
    candidate_dicts: list[dict[str, Any]] = []
    run_id = run_id or os.environ.get("HGB_RUN_ID", "run")
    for index, candidate in enumerate(candidates, start=1):
        candidate_id = f"cand_{index:03d}"
        image_tag = hgb_fuzzbench_builder.deterministic_image_tag(
            run_id, fuzz_target, candidate_id, generator=generator,
        )
        native_image_tag = hgb_fuzzbench_builder.deterministic_image_tag(
            run_id, fuzz_target, candidate_id + "-native", generator=generator,
        )
        coverage_image_tag = hgb_fuzzbench_builder.deterministic_image_tag(
            run_id, fuzz_target, candidate_id + "-cov", generator=generator,
        )
        rec = evaluate_candidate(
            candidate=candidate,
            candidate_id=candidate_id,
            target_root=target_root,
            evaluator_root=evaluator_root,
            work_dir=work_dir,
            project=project,
            fuzz_target=fuzz_target,
            campaign_seconds=campaign_seconds,
            image_tag=image_tag,
            runner=runner,
            native_harness=native_harness,
            sealed_context=sealed_context,
            intended_apis=plan_apis,
            seeds=seeds,
            coverage_parser=coverage_parser,
            strict=strict,
            run_native_control=run_native_control,
            native_image_tag=native_image_tag,
            coverage_image_tag=coverage_image_tag,
            build_coverage_image=build_coverage_image,
            build_timeout_seconds=build_timeout_seconds,
            profile=profile,
        )
        records.append(rec)
        # Flatten key audit/provenance fields onto the candidate dict so the
        # selected_candidate record carries copy_audit, overlay_audit,
        # coverage_report_path, campaign_log, final_corpus_dir, and build_logs
        # (zeta plan §3).
        cand_dict = {
            "candidate_id": rec.candidate_id,
            "candidate_path": rec.candidate_path,
            "candidate_sha256": rec.candidate_sha256,
            "overlaid": rec.overlaid,
            "native_destination": rec.native_destination,
            "stages": rec.stages,
            "sanitizer_smoke": rec.sanitizer_smoke,
            "api_reachability": rec.api_reachability,
            "campaign": rec.campaign,
            "coverage": rec.coverage,
            "coverage_diff": rec.coverage_diff,
            "native_coverage": rec.native_coverage,
            "build": rec.build,
            "copy_audit": rec.copy_audit,
            "overlay_audit": (rec.build or {}).get("overlay_audit", {}),
            "coverage_report_path": (rec.coverage or {}).get("coverage_report_path", ""),
            "campaign_log": (rec.campaign or {}).get("log", ""),
            "final_corpus_dir": (rec.campaign or {}).get("final_corpus_dir", "")
            or (rec.campaign or {}).get("corpus_dir", ""),
            "build_logs": {
                "image_build_log": (rec.build or {}).get("log", ""),
                "campaign_log": (rec.campaign or {}).get("log", ""),
            },
            "error": rec.error,
            "image_tag": image_tag,
        }
        candidate_dicts.append(cand_dict)
        (candidates_json_dir / f"{candidate_id}.json").write_text(
            json.dumps(cand_dict, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    # 6.7 Candidate selection.
    selected = hgb_result.select_best_candidate(candidate_dicts)
    selected_stage_states: dict[str, str] = {}
    if selected:
        selected_stage_states = selected["stages"]
        selected_status = hgb_result.result_status_from_stages(
            selected_stage_states,
            has_candidate_json=True,
            coverage_covered_lines=selected.get("coverage", {}).get("line_coverage", {}).get("covered"),
            campaign_execs_done=int(selected.get("campaign", {}).get("execs_done", 0) or 0),
            candidate_overlaid=bool(selected.get("overlaid")),
        )
    else:
        selected_status = hgb_result.STATUS_QUALITY_FAILURE

    run_stages = hgb_result.default_stages()
    hgb_result.mark_stage(run_stages, "generation", "completed")
    if selected:
        for stage in hgb_result.STAGE_NAMES:
            if stage == "generation":
                continue
            hgb_result.mark_stage(run_stages, stage, selected_stage_states.get(stage, "pending"))
    else:
        for stage in ("candidate_overlay", "copy_audit", "candidate_build", "sanitizer_smoke", "api_reachability", "campaign", "coverage"):
            if all(rec.stages.get(stage) == "failed" for rec in records):
                hgb_result.mark_stage(run_stages, stage, "failed")

    cov_lines = None
    execs_done = 0
    if selected:
        cov_lines = selected.get("coverage", {}).get("line_coverage", {}).get("covered")
        execs_done = int(selected.get("campaign", {}).get("execs_done", 0) or 0)

    if selected_status == hgb_result.STATUS_EVALUATED:
        status = hgb_result.result_status_from_stages(
            run_stages,
            has_candidate_json=True,
            coverage_covered_lines=cov_lines,
            campaign_execs_done=execs_done,
            candidate_overlaid=bool(selected.get("overlaid")),
        )
    else:
        status = selected_status
        if records and all(rec.error and hgb_result.classify_infra_failure(rec.error) for rec in records):
            status = hgb_result.STATUS_INFRA_FAILURE

    metrics: dict[str, Any] = {}
    if selected:
        metrics = {
            "coverage": selected.get("coverage", {}),
            "campaign": selected.get("campaign", {}),
            "coverage_diff": selected.get("coverage_diff", {}),
            "native_coverage": selected.get("native_coverage", {}),
        }
    result = hgb_result.build_result(
        generator=generator,
        profile=profile,
        protocol=protocol,
        target=fuzz_target,
        status=status,
        stages=run_stages,
        reason=("" if status == hgb_result.STATUS_EVALUATED else (records[-1].error if records else "no candidates")),
        candidate_count=len(candidates),
        metrics=metrics,
        artifacts={
            "candidate_reports_dir": str(candidates_json_dir),
            "sealed_context_dir": str(work_dir / "sealed_context"),
            "sealed_env_defaults": sealed_context.get("sealed_env_defaults", {}),
        },
        selected_candidate=selected or {},
    )
    if status == hgb_result.STATUS_EVALUATED:
        violations = hgb_result.assert_evaluated_invariants(result)
        if violations and strict:
            result["status"] = hgb_result.STATUS_QUALITY_FAILURE
            result["reason"] = "evaluated invariants violated: " + "; ".join(violations)
    return _emit(result)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generator", default="ckgfuzzer")
    # --baseline is the plan's stable alias for --generator (used by the
    # shared OSS-Fuzz-Gen / CKGFuzzer / PromeFuzz entrypoint contract).
    parser.add_argument("--baseline", default="",
                        help="alias for --generator (overrides --generator when set)")
    parser.add_argument("--target-root", required=True, type=Path)
    parser.add_argument("--evaluator-root", required=True, type=Path)
    # --candidates is a directory of candidates; --candidate is a single file.
    # Exactly one of the two must be supplied so the shared CLI works for both
    # the multi-candidate (OFG) and single-candidate (plan section 4) flows.
    parser.add_argument("--candidates", default=None, type=Path,
                        help="directory of candidate source files")
    parser.add_argument("--candidate", default=None, type=Path,
                        help="single candidate source file (staged into a temp candidates dir)")
    parser.add_argument("--work-dir", default="", type=Path,
                        help="evaluation work directory (defaults to --result-dir/work)")
    parser.add_argument("--result-dir", default="", type=Path,
                        help="directory to write result.json and per-candidate JSONs")
    parser.add_argument("--project", default="")
    parser.add_argument("--fuzz-target", default="",
                        help="fuzz target name (defaults to target_manifest.json fuzz_target)")
    parser.add_argument("--profile", default="alpha")
    parser.add_argument("--protocol", default="blind-project",
                        help="reproduction protocol (blind-project or target-aware)")
    parser.add_argument("--campaign-seconds", type=int, default=300)
    parser.add_argument("--build-timeout-seconds", type=int, default=1800,
                        help="per-candidate FuzzBench Docker build timeout")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--intended-apis", default="", help="comma-separated intended APIs")
    parser.add_argument("--run-native-control", action="store_true",
                        help="build native/reference coverage control and compute line coverage diff")
    parser.add_argument("--build-coverage-image", action="store_true",
                        help="build a separate coverage-instrumented image for source-based coverage")
    args = parser.parse_args()

    generator = args.baseline or args.generator
    if not args.candidates and not args.candidate:
        parser.error("one of --candidates or --candidate is required")
    import tempfile

    staged_candidates_dir: Path
    cleanup_dir: Path | None = None
    if args.candidate:
        # Stage the single candidate into a temp directory so the evaluator's
        # multi-candidate loop processes exactly one candidate.
        single = Path(args.candidate)
        if not single.is_file():
            parser.error(f"--candidate file not found: {single}")
        staged = Path(tempfile.mkdtemp(prefix="hgb-eval-cand-"))
        cleanup_dir = staged
        dest = staged / single.name
        shutil.copy2(single, dest)
        staged_candidates_dir = staged
    else:
        staged_candidates_dir = Path(args.candidates)
        if not staged_candidates_dir.is_dir():
            parser.error(f"--candidates directory not found: {staged_candidates_dir}")

    result_dir = Path(args.result_dir) if args.result_dir else None
    if result_dir:
        result_dir.mkdir(parents=True, exist_ok=True)
    work_dir = Path(args.work_dir) if args.work_dir else (result_dir / "work" if result_dir else Path("/workspace/evaluation"))
    work_dir.mkdir(parents=True, exist_ok=True)

    project = args.project
    fuzz_target = args.fuzz_target
    if not fuzz_target or not project:
        m_project, m_fuzz_target = _resolve_target_metadata(args.target_root)
        if not project:
            project = m_project
        if not fuzz_target:
            fuzz_target = m_fuzz_target
    if not fuzz_target:
        parser.error("--fuzz-target is required and could not be resolved from the target manifest")

    intended = [a.strip() for a in args.intended_apis.split(",") if a.strip()] if args.intended_apis else None
    try:
        result = evaluate(
            generator=generator,
            target_root=args.target_root,
            evaluator_root=args.evaluator_root,
            candidates_dir=staged_candidates_dir,
            work_dir=work_dir,
            project=project,
            fuzz_target=fuzz_target,
            profile=args.profile,
            protocol=args.protocol,
            campaign_seconds=args.campaign_seconds,
            build_timeout_seconds=args.build_timeout_seconds,
            strict=args.strict,
            intended_apis=intended,
            run_native_control=args.run_native_control,
            build_coverage_image=args.build_coverage_image,
            result_dir=result_dir,
        )
    finally:
        if cleanup_dir is not None:
            shutil.rmtree(cleanup_dir, ignore_errors=True)
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["status"] == hgb_result.STATUS_INFRA_FAILURE:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
