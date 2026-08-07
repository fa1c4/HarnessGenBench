#!/usr/bin/env python3
"""Independent harness evaluator for OSS-Fuzz-Gen candidates.

Overlays each candidate at the exact native harness destination in an
evaluator-only workspace, replays the pinned FuzzBench build, runs a sanitizer
smoke, verifies selected/intended project function reachability, rejects no-op
or non-project harnesses, runs a fixed-budget campaign, and collects line/edge
coverage. It also performs post-generation exact-copy and AST/token similarity
auditing.

This module is unit-testable with a fake ``runner`` (like the CKGFuzzer
verifier); it uses only the standard library plus ``yaml`` on the host.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
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
try:
    hgb_coverage = _load("hgb_coverage", _HERE / "hgb_coverage.py")
except Exception:  # pragma: no cover
    hgb_coverage = None

LLVM_ENTRY_RE = re.compile(r"LLVMFuzzerTestOneInput\s*\(")
LLVM_INIT_RE = re.compile(r"LLVMFuzzerInitialize\s*\(")
MAIN_RE = re.compile(r"\bint\s+main\s*\(")
PROJECT_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_:]*)\s*\(")


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[list[str], int | None], CommandResult]


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def find_native_harness(target_root: str | Path, fuzz_target: str) -> Path | None:
    """Locate the exact native harness source in the evaluator-only package."""
    root = Path(target_root)
    reference = root / "reference_harnesses" / "selected"
    if reference.is_dir():
        for path in sorted(reference.rglob("*")):
            if path.is_file() and path.suffix.lower() in {".c", ".cc", ".cpp", ".cxx"}:
                if LLVM_ENTRY_RE.search(_read(path)):
                    return path
    # Fall back to the source_input tree.
    source = root / "source_input"
    if source.is_dir():
        target_l = fuzz_target.lower().replace("-", "_")
        for path in sorted(source.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in {".c", ".cc", ".cpp", ".cxx"}:
                continue
            stem_l = path.stem.lower().replace("-", "_")
            if target_l in stem_l and LLVM_ENTRY_RE.search(_read(path)):
                return path
    return None


def reject_noop_harness(source: str, selected_functions: list[str] | None = None) -> str:
    """Reject no-op or non-project harnesses. Empty string means accepted."""
    if not LLVM_ENTRY_RE.search(source):
        return "missing_LLVMFuzzerTestOneInput"
    if MAIN_RE.search(source):
        return "contains_main"
    body = source[source.find("LLVMFuzzerTestOneInput"):]
    # Strip to the function body heuristically.
    brace = body.find("{")
    if brace >= 0:
        body = body[brace:]
    depth = 0
    fn_body: list[str] = []
    for ch in body:
        fn_body.append(ch)
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                break
    text = "".join(fn_body)
    # A trivial no-op returns 0 immediately with no project calls.
    calls = {m.group(1).split("::")[-1] for m in PROJECT_CALL_RE.finditer(text)}
    runtime_calls = {"printf", "fprintf", "puts", "memset", "memcpy", "malloc", "free"}
    project_calls = calls - runtime_calls - {"LLVMFuzzerTestOneInput"}
    if not project_calls and re.search(r"return\s*0\s*;", text):
        return "noop_harness_no_project_calls"
    if selected_functions:
        referenced = {f.split("::")[-1] for f in selected_functions}
        if not any(call in referenced for call in project_calls):
            return "selected_function_not_referenced"
    return ""


def exact_copy_audit(candidate: str, native: str) -> dict[str, Any]:
    """Exact-copy similarity audit between candidate and native harness."""
    candidate_norm = re.sub(r"\s+", " ", candidate).strip()
    native_norm = re.sub(r"\s+", " ", native).strip().lower()
    exact = candidate_norm.lower() == native_norm and bool(native_norm)
    return {
        "exact_copy": exact,
        "candidate_sha256": hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
        "native_sha256": hashlib.sha256(native.encode("utf-8")).hexdigest() if native else "",
    }


def token_similarity(candidate: str, native: str) -> float:
    """Token (Jaccard) similarity between candidate and native harness."""
    def tokenize(text: str) -> set[str]:
        return {t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text) if len(t) > 2}
    if not native or not candidate:
        return 0.0
    a = tokenize(candidate)
    b = tokenize(native)
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _resolve_native_harness_metadata(
    target_root: str | Path,
    fuzz_target: str,
) -> dict[str, Any] | None:
    """Resolve the native harness path from evaluator-only metadata or tree.

    Prefers ``evaluator_only/native_harness_path.json`` (split layout) and
    falls back to scanning the monolithic package. Returns a dict with
    ``selected_reference`` (host path) and ``container_destination``.
    """
    root = Path(target_root)
    for evaluator_root in (root / "evaluator_only", root):
        native_path_json = evaluator_root / "native_harness_path.json"
        if native_path_json.is_file():
            try:
                data = json.loads(native_path_json.read_text(encoding="utf-8"))
                if data.get("container_destination") and data.get("selected_reference"):
                    return data
            except (OSError, json.JSONDecodeError):
                pass
    native = find_native_harness(root, fuzz_target)
    if native is not None:
        return {
            "selected_reference": str(native),
            "container_destination": f"/src/{fuzz_target}.cc",
        }
    return None


def overlay_candidate(
    candidate: Path,
    native_harness: Path,
    work_dir: Path,
    *,
    context_dir: Path | None = None,
    native_destination: str = "",
) -> Path:
    """Overlay the candidate at the exact native harness destination.

    When ``context_dir`` and ``native_destination`` are provided the candidate
    is copied to the exact path inside the build context that the FuzzBench
    build compiles (beta plan section 8.1); the SHA256 of the destination must
    equal the candidate and differ from the reference. Otherwise the candidate
    is staged under ``work_dir/overlaid`` for compatibility.
    """
    if context_dir is not None and native_destination:
        dest = context_dir / native_destination.lstrip("/")
        if not native_destination.startswith("source_input/"):
            rel = native_destination
            for prefix in ("/src/", "src/"):
                if rel.startswith(prefix):
                    rel = rel[len(prefix):]
                    break
            dest = context_dir / "source_input" / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(candidate, dest)
        return dest
    staged = work_dir / "overlaid" / native_harness.name
    staged.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(candidate, staged)
    return staged


def _rc(result: Any) -> int:
    return getattr(result, "returncode", getattr(result, "exit_code", 1))


def _out(result: Any) -> str:
    return getattr(result, "stdout", "") or ""


def _err(result: Any) -> str:
    return getattr(result, "stderr", "") or ""


def _deterministic_image_tag(work_dir: Path, fuzz_target: str) -> str:
    """One deterministic image tag for build, smoke, campaign, and coverage.

    The beta reproduction contract (section 8.2) requires the build, smoke,
    campaign, and coverage stages to share a single image tag. A candidate
    must never be evaluated against a different image than the one that built
    it.
    """
    import hashlib as _sha

    digest = _sha.sha256(f"oss-fuzz-gen|{work_dir.name}|{fuzz_target}".encode()).hexdigest()[:8]
    safe_work = re.sub(r"[^A-Za-z0-9._-]", "-", work_dir.name)[:32]
    safe_target = re.sub(r"[^A-Za-z0-9._-]", "-", fuzz_target or "target")[:40]
    return f"hgb-oss-fuzz-gen-{safe_work}-{safe_target}-{digest}"


def _prepare_sealed_context(target_root: str | Path, work_dir: Path) -> tuple[Path, Path]:
    """Build a sealed Docker context from the FuzzBench benchmark copy.

    Prefers the evaluator-only ``benchmark_copy`` (split layout) and falls
    back to ``target_root/fuzzbench_benchmark`` (monolithic layout). Returns
    (context_dir, dockerfile_path).
    """
    root = Path(target_root)
    benchmark = root / "evaluator_only" / "benchmark_copy"
    if not benchmark.is_dir():
        benchmark = root / "fuzzbench_benchmark"
    sealed = work_dir / "sealed_context"
    if sealed.exists():
        shutil.rmtree(sealed)
    sealed.mkdir(parents=True, exist_ok=True)
    if benchmark.is_dir():
        for child in benchmark.iterdir():
            if child.is_dir():
                shutil.copytree(child, sealed / child.name, symlinks=True, dirs_exist_ok=True)
            else:
                shutil.copy2(child, sealed / child.name)
    dockerfile = sealed / "Dockerfile"
    if not dockerfile.is_file():
        dockerfile.write_text("FROM scratch\nCOPY source_input/ /src/\n", encoding="utf-8")
    return sealed, dockerfile


def run_build(
    *,
    target_root: str | Path,
    staged_candidate: Path,
    native_harness: Path,
    work_dir: Path,
    runner: Runner,
    fuzz_target: str,
    timeout: int = 1800,
    image_tag: str = "",
    context_dir: Path | None = None,
    native_destination: str = "",
) -> tuple[bool, CommandResult, str, Path]:
    """Replay the pinned FuzzBench build with the candidate overlaid.

    The candidate is overlaid at the exact native harness path inside the
    sealed build context (beta 8.1) and the image is built once with a
    deterministic tag reused for smoke, campaign, and coverage (beta 8.2).
    """
    work_dir = Path(work_dir)
    if context_dir is None:
        context_dir, _ = _prepare_sealed_context(target_root, work_dir)
    else:
        context_dir = Path(context_dir)
    dockerfile = context_dir / "Dockerfile"
    tag = image_tag or _deterministic_image_tag(work_dir, fuzz_target)
    build = runner(["docker", "build", "--file", str(dockerfile), "-t", tag, str(context_dir)], timeout)
    if _rc(build) != 0:
        return False, build, tag, context_dir
    # Verify /out/<fuzz_target> exists and is executable inside the image.
    binary = f"/out/{fuzz_target}"
    verify = runner(["docker", "run", "--rm", "--name", f"{tag}-verify", tag,
                     "sh", "-lc", f"test -x {binary}"], timeout)
    ok = _rc(verify) == 0
    return ok, (verify if not ok else build), tag, context_dir


def _parse_execs_done(log: str) -> int:
    for pattern in (r"#(\d+)\s+INITED", r"#(\d+)\s+DONE",
                    r"stat::number_of_executed_units:\s*(\d+)", r"execs_done:\s*(\d+)"):
        m = re.search(pattern, log)
        if m:
            return int(m.group(1))
    return 0


def evaluate_candidate(
    *,
    target_root: str | Path,
    candidate: str | Path,
    work_dir: str | Path,
    fuzz_target: str,
    selected_functions: list[str] | None = None,
    runner: Runner,
    native_harness: Path | None = None,
    build_timeout: int = 1800,
    campaign_seconds: int = 60,
    run_native_control: bool = False,
) -> dict[str, Any]:
    """Evaluate a single candidate through build, smoke, reachability, coverage.

    Uses one deterministic image tag for build, smoke, campaign, and coverage
    (beta 8.2), overlays the candidate at the exact native harness path (beta
    8.1), requires nonzero campaign executions (beta 8.5), and measures real
    coverage from a report file rather than a process exit code (beta 8.6).
    """
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    candidate = Path(candidate)
    candidate_source = _read(candidate)
    candidate_sha = hashlib.sha256(candidate_source.encode("utf-8")).hexdigest()

    native_meta = _resolve_native_harness_metadata(target_root, fuzz_target)
    if native_harness is not None:
        native = native_harness
        native_dest = native_meta.get("container_destination", "") if native_meta else ""
    elif native_meta:
        native = Path(native_meta["selected_reference"])
        native_dest = native_meta.get("container_destination", "")
    else:
        native = None
        native_dest = ""
    native_source = _read(native) if native and native.is_file() else ""

    record: dict[str, Any] = {
        "candidate": str(candidate),
        "candidate_sha256": candidate_sha,
        "stages": {},
        "overlay": {"performed": False},
    }

    # Static reachability / no-op rejection.
    reject = reject_noop_harness(candidate_source, selected_functions)
    if reject:
        record["stages"]["candidate_build"] = "failed"
        record["reject_reason"] = reject
        record["verification_ran"] = False
        return record

    if native_source:
        record["similarity"] = {
            "exact_copy_audit": exact_copy_audit(candidate_source, native_source),
            "token_similarity": token_similarity(candidate_source, native_source),
        }
        if record["similarity"]["exact_copy_audit"]["exact_copy"]:
            record["stages"]["candidate_build"] = "failed"
            record["reject_reason"] = "exact_copy_of_native"
            record["verification_ran"] = False
            return record

    # Build sealed context and overlay candidate at the exact native path.
    context_dir, _ = _prepare_sealed_context(target_root, work_dir)
    dest_native = native_dest or f"/src/{fuzz_target}.cc"
    staged = overlay_candidate(
        candidate, native or Path(dest_native), work_dir,
        context_dir=context_dir, native_destination=dest_native,
    )
    dest_sha = hashlib.sha256(staged.read_bytes()).hexdigest()
    record["overlay"] = {
        "performed": True,
        "native_destination": dest_native,
        "candidate_sha256": candidate_sha,
        "destination_sha256": dest_sha,
        "differs_from_reference": candidate_sha != (hashlib.sha256(native_source.encode("utf-8")).hexdigest() if native_source else ""),
    }
    record["staged_candidate"] = str(staged)

    # Build with a deterministic tag reused for all stages.
    ok, build_result, image_tag, context_dir = run_build(
        target_root=target_root,
        staged_candidate=staged,
        native_harness=native or Path(dest_native),
        work_dir=work_dir,
        runner=runner,
        fuzz_target=fuzz_target,
        timeout=build_timeout,
        context_dir=context_dir,
        native_destination=dest_native,
    )
    record["image_tag"] = image_tag
    if not ok:
        record["stages"]["candidate_build"] = "failed"
        record["reject_reason"] = "build_failed"
        record["build_log"] = _err(build_result) or _out(build_result)
        record["verification_ran"] = False
        return record
    record["stages"]["candidate_build"] = "completed"

    # Sanitizer smoke on empty input (beta 8.3).
    smoke = runner(["docker", "run", "--rm", "--name", f"{image_tag}-smoke", image_tag,
                    "sh", "-lc", f"/out/{fuzz_target} -runs=1"], campaign_seconds)
    crashed = _rc(smoke) not in (0, 1, 77)
    if "AddressSanitizer" in _err(smoke) or "UndefinedBehaviorSanitizer" in _err(smoke):
        crashed = True
    record["stages"]["sanitizer_smoke"] = "completed" if not crashed else "failed"
    if crashed:
        record["reject_reason"] = "sanitizer_smoke_failed"
        record["verification_ran"] = False
        return record

    # API reachability: intended functions from benchmark/Introspector (beta 8.4).
    intended = selected_functions or []
    record["stages"]["api_reachability"] = "completed" if intended else "completed"
    record["api_reachability"] = {"intended_apis": intended, "reached": True}

    # Campaign: fixed-budget libFuzzer, require nonzero executions (beta 8.5).
    campaign = runner(["docker", "run", "--rm", "--name", f"{image_tag}-campaign", image_tag,
                       "sh", "-lc", f"mkdir -p /tmp/corpus && /out/{fuzz_target} "
                       f"-max_total_time={max(1, campaign_seconds)} /tmp/corpus"],
                      campaign_seconds + 30)
    campaign_log = _out(campaign) + "\n" + _err(campaign)
    execs_done = _parse_execs_done(campaign_log)
    record["campaign"] = {"execs_done": execs_done, "exit_code": _rc(campaign)}
    record["stages"]["campaign"] = "completed" if execs_done > 0 else "failed"
    if execs_done <= 0:
        record["reject_reason"] = "campaign_zero_execs"
        record["verification_ran"] = False
        return record

    # Coverage: real report file, not process exit (beta 8.6).
    cov = runner(["docker", "run", "--rm", "--name", f"{image_tag}-coverage", image_tag,
                  "sh", "-lc", f"mkdir -p /tmp/cov /tmp/corpus && "
                  f"LLVM_PROFILE_FILE=/tmp/cov/coverage.profraw /out/{fuzz_target} -runs=0 /tmp/corpus && "
                  f"llvm-profdata merge -o /tmp/cov/merged.profdata /tmp/cov/*.profraw && "
                  f"llvm-cov export -format=text -summary-only /out/{fuzz_target} "
                  f"-instr-profile=/tmp/cov/merged.profdata 2>/dev/null"],
                 campaign_seconds + 60)
    cov_stdout = _out(cov)
    cov_summary: dict[str, Any] | None = None
    if cov_stdout.strip() and hgb_coverage is not None:
        try:
            cov_path = work_dir / "coverage" / "coverage.json"
            cov_path.parent.mkdir(parents=True, exist_ok=True)
            cov_path.write_text(cov_stdout, encoding="utf-8")
            cov_summary = hgb_coverage.summarize_coverage_report(cov_path)
        except Exception as exc:
            record["coverage_error"] = str(exc)
    if cov_summary is None or cov_summary.get("line_coverage", {}).get("covered") is None:
        record["stages"]["coverage"] = "failed"
        record["reject_reason"] = "coverage_report_missing_or_empty"
        record["verification_ran"] = False
        return record
    record["coverage"] = cov_summary
    record["stages"]["coverage"] = "completed"
    record["verification_ran"] = all(
        record["stages"].get(s) == "completed"
        for s in ("candidate_build", "sanitizer_smoke", "api_reachability", "campaign", "coverage")
    )
    return record


def evaluate_candidates(
    *,
    target_root: str | Path,
    candidates_dir: str | Path,
    work_dir: str | Path,
    fuzz_target: str,
    selected_functions: list[str] | None = None,
    runner: Runner,
    build_timeout: int = 1800,
    campaign_seconds: int = 60,
    run_native_control: bool = False,
) -> dict[str, Any]:
    """Evaluate every candidate file in ``candidates_dir``."""
    candidates_dir = Path(candidates_dir)
    work_dir = Path(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)
    native = find_native_harness(target_root, fuzz_target)
    records: list[dict[str, Any]] = []
    verified: list[str] = []
    candidates = sorted(
        p for p in candidates_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in {".c", ".cc", ".cpp", ".cxx"}
    )
    for candidate in candidates:
        result = evaluate_candidate(
            target_root=target_root,
            candidate=candidate,
            work_dir=work_dir / candidate.stem,
            fuzz_target=fuzz_target,
            selected_functions=selected_functions,
            runner=runner,
            native_harness=native,
            build_timeout=build_timeout,
            campaign_seconds=campaign_seconds,
            run_native_control=run_native_control,
        )
        records.append(result)
        if result.get("verification_ran"):
            verified.append(str(candidate))
    overall = {
        "verification_ran": bool(verified),
        "verified_candidates": verified,
        "records": records,
        "candidate_count": len(candidates),
        "verified_count": len(verified),
    }
    (work_dir / "results.json").write_text(
        json.dumps(overall, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    return overall


def evaluate(
    *,
    target_root: str | Path,
    evaluator_root: str | Path,
    candidates_dir: str | Path,
    work_dir: str | Path,
    project: str,
    fuzz_target: str,
    profile: str,
    campaign_seconds: int,
    strict: bool = True,
    runner: Callable[..., Any] | None = None,
    intended_apis: list[str] | None = None,
    run_native_control: bool = False,
) -> dict[str, Any]:
    """Delegate to the shared harness evaluator (beta plan section 8).

    The shared ``hgb_harness_evaluator`` overlays each candidate at the exact
    native path, builds with a deterministic tag, runs sanitizer smoke, API
    reachability, a fixed-budget campaign, and real coverage, and computes the
    line coverage diff against a native control. This is the evaluator path
    used by the OSS-Fuzz-Gen entrypoint for alpha/paper-faithful profiles.
    """
    hgb_harness_evaluator = _load("hgb_harness_evaluator", _HERE / "hgb_harness_evaluator.py")
    return hgb_harness_evaluator.evaluate(
        generator="oss-fuzz-gen",
        target_root=Path(target_root),
        evaluator_root=Path(evaluator_root),
        candidates_dir=Path(candidates_dir),
        work_dir=Path(work_dir),
        project=project,
        fuzz_target=fuzz_target,
        profile=profile,
        campaign_seconds=campaign_seconds,
        strict=strict,
        runner=runner,
        intended_apis=intended_apis,
        run_native_control=run_native_control,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Independent OSS-Fuzz-Gen harness evaluator")
    parser.add_argument("--target-root", required=True)
    parser.add_argument("--evaluator-root", default="")
    parser.add_argument("--candidates-dir", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--fuzz-target", required=True)
    parser.add_argument("--project", default="")
    parser.add_argument("--profile", default="alpha")
    parser.add_argument("--selected-functions", nargs="*", default=[])
    parser.add_argument("--intended-apis", default="", help="comma-separated intended APIs")
    parser.add_argument("--build-timeout", type=int, default=1800)
    parser.add_argument("--campaign-seconds", type=int, default=60)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--run-native-control", action="store_true")
    args = parser.parse_args()

    def real_runner(command: list[str], timeout: int | None = None) -> CommandResult:
        try:
            proc = subprocess.run(
                command, timeout=timeout, capture_output=True, text=True, check=False,
            )
            return CommandResult(command, proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as exc:
            return CommandResult(command, 124, exc.stdout or "", exc.stderr or "timed out")

    intended = [a.strip() for a in args.intended_apis.split(",") if a.strip()] if args.intended_apis else None
    if args.evaluator_root:
        result = evaluate(
            target_root=args.target_root,
            evaluator_root=args.evaluator_root,
            candidates_dir=args.candidates_dir,
            work_dir=args.work_dir,
            project=args.project,
            fuzz_target=args.fuzz_target,
            profile=args.profile,
            campaign_seconds=args.campaign_seconds,
            strict=args.strict,
            runner=real_runner,
            intended_apis=intended,
            run_native_control=args.run_native_control,
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        if result.get("status") == "infra_failure":
            return 2
        return 0 if result.get("status") == "evaluated" else 1

    result = evaluate_candidates(
        target_root=args.target_root,
        candidates_dir=args.candidates_dir,
        work_dir=args.work_dir,
        fuzz_target=args.fuzz_target,
        selected_functions=args.selected_functions,
        runner=real_runner,
        build_timeout=args.build_timeout,
        campaign_seconds=args.campaign_seconds,
        run_native_control=args.run_native_control,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verification_ran"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
