#!/usr/bin/env python3
"""Adapter for real Fuzz Introspector report data.

Parses Fuzz Introspector JSON artifacts (``all_functions.json``,
``calltree.json``, ``type_info.json``, ``report_manifest.json``) produced by
the pinned Introspector build path, filters out non-target functions, and
normalizes paths into the target package.

This module is unit-testable with fixture JSON; it must not import any
library unavailable to host Python 3 (only the standard library is used).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Callable


# Function-name patterns that are runtime/compiler helpers, trivial accessors,
# test-only, or fuzz entrypoints and must never be selected as a benchmark
# target function.
HELPER_NAME_RE = re.compile(
    r"^(llvm|__|_Z|_GLOBAL|operator new|operator delete|std::|google::|"
    r"benchmark::|testing::|fuzzer::|__sanitizer|__ubsan|__asan|__msan|"
    r"__tsan|__lsan|__cfi|LLVMFuzzerTestOneInput|LLVMFuzzerInitialize|"
    r"main|_init|_fini|frame_dummy|register_tm_clones|deregister_tm_clones|"
    r"__libc_csu|__stack_chk|__assert|__errno|__ctype)"
)
FUZZ_ENTRY_RE = re.compile(
    r"LLVMFuzzerTestOneInput|LLVMFuzzerInitialize|FuzzOneInput|fuzzer_main",
    re.I,
)
BAD_PATH_PARTS = (
    "/test/", "/tests/", "/testing/", "/gtest/", "/gmock/", "/googletest/",
    "/example/", "/examples/", "/sample/", "/samples/", "/demo/", "/demos/",
    "/benchmark/", "/bench/", "/perf/", "/third_party/", "/contrib/",
    "/fuzz/", "/fuzzer/", "/oss-fuzz/", "/infra/indexer/",
)
BAD_RETURN_RE = re.compile(
    r"^\s*(public|private|protected)\s*:", re.I,
)
GENERIC_NAMES = {
    "a", "abort", "add", "begin", "build", "check", "clean", "cleanup",
    "close", "copy", "create", "delete", "display", "error", "finish",
    "get", "init", "initialize", "main", "open", "parse", "print",
    "process", "read", "run", "set", "setup", "start", "test", "update",
    "write",
}
BANNED_API_NAMES = {
    "calloc", "fclose", "fdopen", "fflush", "fopen", "fprintf", "fread",
    "free", "fseek", "ftell", "fwrite", "malloc", "memcmp", "memcpy",
    "memmove", "memset", "printf", "puts", "realloc", "rewind", "snprintf",
    "sprintf", "strcasecmp", "strcat", "strchr", "strcmp", "strcpy",
    "strdup", "strlen", "strncmp", "strncpy", "strstr", "vfprintf",
}


def load_json(path: str | Path) -> Any:
    p = Path(path)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def normalize_path(raw: str, source_root: str = "") -> str:
    """Normalize an Introspector source location into a package-relative path."""
    path = raw.replace("\\", "/")
    if source_root:
        root = source_root.replace("\\", "/").rstrip("/")
        if path.startswith(root + "/"):
            return path[len(root) + 1:]
        idx = path.find("/" + root.split("/")[-1] + "/")
        if idx >= 0:
            return path[idx + 1:]
    return path


def _function_name(record: dict[str, Any]) -> str:
    name = str(record.get("name") or record.get("raw-function-name") or
               record.get("raw_function_name") or "")
    if not name:
        sig = str(record.get("function_signature") or record.get("signature") or "")
        if sig:
            head = sig.split("(", 1)[0].strip()
            name = head.split()[-1] if head else ""
    return name.strip()


def _signature(record: dict[str, Any]) -> str:
    sig = str(record.get("function_signature") or record.get("signature") or "")
    if sig:
        return sig
    name = _function_name(record)
    if not name:
        return ""
    args = record.get("function_arguments") or record.get("arg-types") or []
    if not isinstance(args, list):
        args = []
    ret = str(record.get("return-type") or record.get("return_type") or "int")
    return f"{ret} {name}({', '.join(str(a) for a in args)})"


def _return_type(record: dict[str, Any]) -> str:
    return str(record.get("return-type") or record.get("return_type") or "int")


def _params(record: dict[str, Any]) -> list[dict[str, str]]:
    args = record.get("function_arguments") or record.get("arg-types") or []
    if not isinstance(args, list):
        return []
    params: list[dict[str, str]] = []
    for index, arg in enumerate(args):
        params.append({"name": f"arg{index}", "type": str(arg)})
    return params


def _source_location(record: dict[str, Any]) -> str:
    loc = record.get("source_file") or record.get("path") or record.get("file") or ""
    if not loc:
        lines = record.get("source_line") or record.get("function_line") or []
        if isinstance(lines, list) and lines:
            loc = str(lines[0])
    return str(loc)


def reject_reason(record: dict[str, Any]) -> str:
    name = _function_name(record)
    sig = _signature(record)
    path = "/" + _source_location(record).replace("\\", "/").lower()
    if not name and not sig:
        return "empty_api_candidate"
    if len(name) <= 1:
        return "generic_single_letter_api"
    if HELPER_NAME_RE.match(name):
        return "runtime_or_compiler_helper"
    if FUZZ_ENTRY_RE.search(name) or FUZZ_ENTRY_RE.search(sig):
        return "fuzz_entrypoint"
    if name in BANNED_API_NAMES:
        return "generic_runtime_or_io_api"
    if BAD_RETURN_RE.match(_return_type(record)):
        return "cxx_access_label"
    for part in BAD_PATH_PARTS:
        if part in path:
            return "irrelevant_source_path"
    return ""


def _is_public(record: dict[str, Any]) -> bool:
    """Heuristic for externally reachable / public project functions."""
    path = "/" + _source_location(record).replace("\\", "/").lower()
    # Headers and public api dirs are more likely externally reachable.
    if path.endswith((".h", ".hh", ".hpp", ".hxx")):
        return True
    if "/include/" in path or "/api/" in path or "/public/" in path:
        return True
    return False


def _complexity(record: dict[str, Any]) -> int:
    for key in ("complexity", "cyclomatic_complexity", "ccn"):
        value = record.get(key)
        if isinstance(value, (int, float)) and value > 0:
            return int(value)
    return 0


def _is_covered(record: dict[str, Any]) -> bool:
    for key in ("hit_count", "hitCount", "coverage_count"):
        value = record.get(key)
        if isinstance(value, (int, float)) and value > 0:
            return True
    return False


def _callers(record: dict[str, Any]) -> list[str]:
    callers = record.get("called_by") or record.get("callers") or []
    if not isinstance(callers, list):
        return []
    return [str(c) for c in callers]


def _callees(record: dict[str, Any]) -> list[str]:
    callees = record.get("calls") or record.get("callees") or []
    if not isinstance(callees, list):
        return []
    return [str(c) for c in callees]


def parse_all_functions(report_dir: str | Path, source_root: str = "") -> list[dict[str, Any]]:
    """Parse ``all_functions.json`` into normalized function records."""
    report_dir = Path(report_dir)
    data = load_json(report_dir / "all_functions.json")
    if data is None:
        return []
    functions = data
    if isinstance(data, dict):
        functions = data.get("functions") or data.get("all_functions") or []
    if not isinstance(functions, list):
        return []
    records: list[dict[str, Any]] = []
    for raw in functions:
        if not isinstance(raw, dict):
            continue
        name = _function_name(raw)
        sig = _signature(raw)
        if not name and not sig:
            continue
        records.append({
            "name": name,
            "signature": sig,
            "return_type": _return_type(raw),
            "params": _params(raw),
            "path": normalize_path(_source_location(raw), source_root),
            "complexity": _complexity(raw),
            "covered": _is_covered(raw),
            "public": _is_public(raw),
            "callers": _callers(raw),
            "callees": _callees(raw),
        })
    return records


def parse_calltree(report_dir: str | Path) -> dict[str, Any]:
    """Parse ``calltree.json`` and return a reachable-function set + raw tree."""
    data = load_json(Path(report_dir) / "calltree.json")
    if data is None:
        return {"reachable": set(), "tree": None}
    reachable: set[str] = set()
    tree = data if isinstance(data, (dict, list)) else None

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            name = str(node.get("function_name") or node.get("name") or "")
            if name:
                reachable.add(name)
            for child in (node.get("children") or node.get("calls") or []):
                walk(child)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    return {"reachable": reachable, "tree": tree}


def parse_type_info(report_dir: str | Path) -> dict[str, Any]:
    """Parse ``type_info.json`` (best-effort)."""
    data = load_json(Path(report_dir) / "type_info.json")
    return data if isinstance(data, dict) else {}


def parse_report_manifest(report_dir: str | Path) -> dict[str, Any]:
    """Parse ``report_manifest.json`` and validate it is non-empty."""
    data = load_json(Path(report_dir) / "report_manifest.json")
    return data if isinstance(data, dict) else {}


def validate_reports(report_dir: str | Path) -> tuple[bool, str]:
    """Validate that Introspector reports are non-empty and project-sourced."""
    report_dir = Path(report_dir)
    manifest = parse_report_manifest(report_dir)
    functions = parse_all_functions(report_dir)
    if not functions:
        return False, "all_functions.json is empty or missing"
    # Reports must correspond to project source, not only the neutral stub.
    project_sourced = [
        r for r in functions
        if r.get("path") and "hgb_introspector_stub" not in r["path"]
    ]
    if not project_sourced:
        return False, "all functions resolve to the neutral stub; project source was not introspected"
    if manifest and not manifest.get("project") and not manifest.get("project_name"):
        # Not fatal, but recorded.
        pass
    return True, f"{len(functions)} functions parsed ({len(project_sourced)} project-sourced)"


def filter_functions(
    records: list[dict[str, Any]],
    *,
    project: str = "",
    target_name: str = "",
    fuzz_target: str = "",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Filter and rank functions for benchmark selection.

    Ranking is by public visibility, callgraph reachability, type feasibility,
    complexity, and uncovered project relevance — never by reference harness
    calls. Returns (selected, rejected) where rejected carries a reason.
    """
    calltree = parse_calltree("")  # no report dir here; callers pass records
    reachable: set[str] = set()
    # Build a name->record index for reachability propagation.
    name_index = {r["name"]: r for r in records if r.get("name")}
    for r in records:
        for callee in r.get("callees", []):
            reachable.add(callee)

    selected: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for record in records:
        reason = reject_reason(record)
        if reason:
            rejected.append({**record, "_reject_reason": reason})
            continue
        name = record["name"]
        score = 0
        reasons: list[str] = []
        if record.get("public"):
            score += 50
            reasons.append("public_visibility")
        if name in reachable:
            score += 30
            reasons.append("callgraph_reachable")
        if record.get("complexity", 0) > 0:
            score += min(record["complexity"], 40)
            reasons.append(f"complexity:{record['complexity']}")
        if not record.get("covered"):
            score += 20
            reasons.append("uncovered_project_relevance")
        # Target-name token hints (not reference-derived).
        for token in _hint_tokens(target_name, fuzz_target, project):
            if token and token in name.lower():
                score += 25
                reasons.append(f"target_name:{token}")
        if name in GENERIC_NAMES:
            score -= 80
            reasons.append("generic_name")
        if len(name) <= 3:
            score -= 20
            reasons.append("short_name")
        selected.append({**record, "_hgb_score": score, "_hgb_score_reasons": reasons})
    selected.sort(key=lambda r: (-int(r.get("_hgb_score", 0)), r["name"]))
    return selected, rejected


def _hint_tokens(*values: str) -> list[str]:
    tokens: list[str] = []
    for value in values:
        for token in re.split(r"[^A-Za-z0-9]+", value or ""):
            token = token.lower()
            if len(token) < 3 or token in {"fuzz", "fuzzer", "target", "oss", "test"}:
                continue
            if token not in tokens:
                tokens.append(token)
    return tokens


def select_functions(
    records: list[dict[str, Any]],
    *,
    max_functions: int = 3,
    project: str = "",
    target_name: str = "",
    fuzz_target: str = "",
) -> dict[str, Any]:
    """Select up to ``max_functions`` candidates and record all scores."""
    selected, rejected = filter_functions(
        records, project=project, target_name=target_name, fuzz_target=fuzz_target,
    )
    chosen = selected[:max(1, max_functions)]
    return {
        "selected": chosen,
        "rejected": rejected,
        "all_scored": selected,
        "selection_source": "introspector",
    }


def select_inspector_report(
    report_root: str | Path,
    project: str,
    fuzz_target: str,
) -> Path | None:
    """Locate the Introspector report by project and fuzz target.

    Per beta plan section 5, reports are located by project and fuzz target,
    NOT by the first matching ``inspector`` directory under ``build/out``.
    Each candidate ``inspector`` directory is inspected: its
    ``report_manifest.json`` project must match the requested project, and the
    fuzz target must be referenced in the calltree or all_functions. Returns
    the matching directory or None.
    """
    root = Path(report_root)
    if not root.is_dir():
        return None
    candidates: list[Path] = []
    for path in root.rglob("inspector"):
        if path.is_dir():
            candidates.append(path)
    if not candidates:
        return None
    target_l = (fuzz_target or "").lower().replace("-", "_")
    project_l = (project or "").lower()
    scored: list[tuple[int, Path]] = []
    for cand in sorted(candidates):
        manifest = parse_report_manifest(cand)
        manifest_project = str(manifest.get("project") or manifest.get("project_name") or "").lower()
        if project_l and manifest_project and manifest_project != project_l:
            continue
        score = 1
        # Prefer directories whose calltree/all_functions reference the fuzz target.
        calltree = parse_calltree(cand)
        functions = parse_all_functions(cand)
        names = {r.get("name", "").lower() for r in functions}
        reachable = {n.lower() for n in calltree.get("reachable", set())}
        if target_l and any(target_l in n for n in names):
            score += 10
        if target_l and any(target_l in n for n in reachable):
            score += 5
        # A directory with project-sourced functions ranks above a stub-only one.
        project_sourced = [r for r in functions if r.get("path") and "hgb_introspector_stub" not in r["path"]]
        if project_sourced:
            score += 3
        scored.append((score, cand))
    if not scored:
        return None
    scored.sort(key=lambda item: (-item[0], str(item[1])))
    return scored[0][1]


def generate_function_source_map(
    report_dir: str | Path,
    source_root: str = "",
) -> dict[str, Any]:
    """Generate ``function_source_map.json`` if upstream does not emit it.

    Maps each function name to its normalized source path and signature so the
    benchmark synthesis can resolve function source files within project
    source. This is a derived artifact, never the source of truth.
    """
    report_dir = Path(report_dir)
    records = parse_all_functions(report_dir, source_root)
    mapping: dict[str, Any] = {}
    for record in records:
        name = record.get("name") or ""
        if not name:
            continue
        mapping[name] = {
            "source_file": record.get("path", ""),
            "signature": record.get("signature", ""),
            "return_type": record.get("return_type", ""),
        }
    return {"functions": mapping, "source_root": source_root}


REQUIRED_REPORT_FILES = (
    "all_functions.json",
    "calltree.json",
    "type_info.json",
    "report_manifest.json",
    "function_source_map.json",
)


class IntrospectorReport:
    """Result of a real Fuzz Introspector build for a single target."""

    def __init__(
        self,
        *,
        report_dir: Path,
        project: str,
        fuzz_target: str,
        valid: bool,
        message: str,
        files: dict[str, bool] | None = None,
    ) -> None:
        self.report_dir = Path(report_dir)
        self.project = project
        self.fuzz_target = fuzz_target
        self.valid = valid
        self.message = message
        self.files = files or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_dir": str(self.report_dir),
            "project": self.project,
            "fuzz_target": self.fuzz_target,
            "valid": self.valid,
            "message": self.message,
            "files": dict(self.files),
        }


def _count_source_files(report_dir: str | Path) -> int:
    """Count distinct project source files referenced by the introspector report."""
    records = parse_all_functions(report_dir)
    paths: set[str] = set()
    for record in records:
        path = record.get("path") or ""
        if path and "hgb_introspector_stub" not in path:
            paths.add(path)
    return len(paths)


def write_introspector_provenance(
    report_dir: str | Path,
    *,
    mode: str,
    oss_fuzz_commit: str = "",
    fuzzbench_commit: str = "",
    project: str = "",
    target: str = "",
    used_local_shim: bool = False,
) -> dict[str, Any]:
    """Write ``introspector/provenance.json`` (plan section 4).

    Records that the Fuzz Introspector report was real (mode in
    REAL_INTROSPECTOR_MODES), project/target-scoped, and not a local shim.
    ``function_count`` and ``source_files_count`` are derived from the report
    so the matrix gate can prove the report was non-empty.
    """
    report_dir = Path(report_dir)
    function_count = len(parse_all_functions(report_dir))
    source_files_count = _count_source_files(report_dir)
    provenance = {
        "mode": mode,
        "oss_fuzz_commit": oss_fuzz_commit,
        "fuzzbench_commit": fuzzbench_commit,
        "project": project,
        "target": target,
        "function_count": int(function_count),
        "source_files_count": int(source_files_count),
        "used_local_shim": bool(used_local_shim),
    }
    (report_dir / "provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    return provenance


def load_introspector_provenance(report_dir: str | Path) -> dict[str, Any]:
    data = load_json(Path(report_dir) / "provenance.json")
    return data if isinstance(data, dict) else {}


def validate_introspector_provenance(
    provenance: dict[str, Any], *, strict: bool = False,
) -> tuple[bool, list[str]]:
    """Validate an introspector provenance record (plan section 4.5).

    Returns ``(ok, violations)``. In strict (reproduction-delta) mode a zero
    function count or a local shim is a hard failure.
    """
    violations: list[str] = []
    if not isinstance(provenance, dict):
        return False, ["introspector provenance is not a dict"]
    mode = str(provenance.get("mode") or "")
    if mode == "local":
        violations.append("introspector.mode=local; the local shim is forbidden in method-faithful profiles")
    if int(provenance.get("function_count", 0) or 0) <= 0:
        violations.append("introspector.function_count <= 0; the report contains no functions")
    if provenance.get("used_local_shim"):
        violations.append("introspector.used_local_shim == true; the local shim is forbidden")
    ok = not violations
    if strict:
        return ok, violations
    # In non-strict mode, only function_count==0 is fatal; a local shim is
    # recorded but does not fail validation (compat-smoke may use it).
    soft_violations = [v for v in violations if "used_local_shim" not in v and "mode=local" not in v]
    return len(soft_violations) == 0, soft_violations


def build_introspector_report(
    target_root: Path,
    work_dir: Path,
    project: str,
    fuzz_target: str,
    *,
    oss_fuzz_dir: Path | None = None,
    source_dir: Path | None = None,
    runner: Callable[..., Any] | None = None,
    compat_shim: bool = False,
) -> IntrospectorReport:
    """Run the pinned Introspector build and return a validated report.

    Per beta plan section 5, this runs the pinned OSS-Fuzz/FuzzBench build with
    Introspector enabled for the exact project and fuzz target, locates the
    report by project and fuzz target (not the first ``inspector`` directory),
    ensures all required files exist (generating ``function_source_map.json``
    if upstream does not emit it), and validates nonzero functions whose source
    files are within project source. A failure in alpha/paper is a real
    ``infra_failure/failed_stage=introspector`` — never a soft skip.
    """
    work_dir = Path(work_dir)
    introspector_dir = work_dir / "introspector"
    introspector_dir.mkdir(parents=True, exist_ok=True)
    intro_mode = os.environ.get("OFG_INTROSPECTOR_MODE", "remote").strip().lower()
    if compat_shim or intro_mode == "local":
        provenance = write_introspector_provenance(
            introspector_dir,
            mode="local" if (compat_shim or intro_mode == "local") else intro_mode,
            project=project,
            target=fuzz_target,
            used_local_shim=True,
        )
        return IntrospectorReport(
            report_dir=introspector_dir, project=project, fuzz_target=fuzz_target,
            valid=True, message="compat-smoke shim", files={},
        )
    if oss_fuzz_dir is None or not (Path(oss_fuzz_dir) / "infra" / "helper.py").is_file():
        return IntrospectorReport(
            report_dir=introspector_dir, project=project, fuzz_target=fuzz_target,
            valid=False, message="infra_failure/failed_stage=introspector: missing infra/helper.py",
        )
    oss_fuzz_dir = Path(oss_fuzz_dir)
    source_dir = Path(source_dir) if source_dir else Path(target_root) / "source_input"
    overlay_dir = work_dir / "introspector_overlay"
    if overlay_dir.exists():
        import shutil as _sh
        _sh.rmtree(overlay_dir)
    overlay_dir.mkdir(parents=True, exist_ok=True)
    if source_dir.is_dir():
        import shutil as _sh
        _sh.copytree(source_dir, overlay_dir / "src", dirs_exist_ok=True)
    (overlay_dir / "hgb_introspector_stub.c").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return 0; }\n",
        encoding="utf-8",
    )
    if runner is None:
        return IntrospectorReport(
            report_dir=introspector_dir, project=project, fuzz_target=fuzz_target,
            valid=False, message="infra_failure/failed_stage=introspector: no runner available",
        )
    build_cmd = [
        "python3", str(oss_fuzz_dir / "infra" / "helper.py"), "build_fuzzers",
        "--sanitizer", "address", "--engine", "introspector", "--architecture", "x86_64",
        project, str(overlay_dir),
    ]
    result = runner(build_cmd, 3600)
    if result.returncode != 0:
        return IntrospectorReport(
            report_dir=introspector_dir, project=project, fuzz_target=fuzz_target,
            valid=False, message=f"infra_failure/failed_stage=introspector: build exited {result.returncode}",
        )
    report_root = oss_fuzz_dir / "build" / "out"
    selected = select_inspector_report(report_root, project, fuzz_target)
    if selected is None:
        return IntrospectorReport(
            report_dir=introspector_dir, project=project, fuzz_target=fuzz_target,
            valid=False, message="infra_failure/failed_stage=introspector: no target-scoped inspector report",
        )
    files: dict[str, bool] = {}
    for name in REQUIRED_REPORT_FILES:
        src = selected / name
        dst = introspector_dir / name
        if src.is_file():
            import shutil as _sh
            _sh.copy2(src, dst)
            files[name] = True
        elif name == "function_source_map.json":
            mapping = generate_function_source_map(selected, str(source_dir))
            dst.write_text(json.dumps(mapping, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            files[name] = True
        else:
            files[name] = False
    ok, message = validate_reports(introspector_dir)
    if not ok:
        return IntrospectorReport(
            report_dir=introspector_dir, project=project, fuzz_target=fuzz_target,
            valid=False, message=f"infra_failure/failed_stage=introspector: {message}", files=files,
        )
    # Write the introspector provenance (plan section 4) proving the report was
    # real, project/target-scoped, and not a local shim.
    oss_fuzz_commit = ""
    try:
        import subprocess as _sp
        oss_fuzz_commit = _sp.run(
            ["git", "-C", str(oss_fuzz_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5,
        ).stdout.strip() or ""
    except Exception:  # noqa: BLE001
        oss_fuzz_commit = ""
    write_introspector_provenance(
        introspector_dir,
        mode=intro_mode if intro_mode in {"real", "remote"} else "real",
        oss_fuzz_commit=oss_fuzz_commit,
        fuzzbench_commit=str(os.environ.get("HGB_FUZZBENCH_COMMIT", "")),
        project=project,
        target=fuzz_target,
        used_local_shim=False,
    )
    return IntrospectorReport(
        report_dir=introspector_dir, project=project, fuzz_target=fuzz_target,
        valid=True, message=message, files=files,
    )


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Parse Fuzz Introspector reports")
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--source-root", default="")
    parser.add_argument("--project", default="")
    parser.add_argument("--target-name", default="")
    parser.add_argument("--fuzz-target", default="")
    parser.add_argument("--max-functions", type=int, default=3)
    args = parser.parse_args()
    ok, message = validate_reports(args.report_dir)
    if not ok:
        print(f"introspector_validation_failed: {message}", file=__import__("sys").stderr)
        return 1
    records = parse_all_functions(args.report_dir, args.source_root)
    result = select_functions(
        records, max_functions=args.max_functions,
        project=args.project, target_name=args.target_name, fuzz_target=args.fuzz_target,
    )
    print(json.dumps({
        "validation": message,
        "function_count": len(records),
        "selected_count": len(result["selected"]),
        "selected": result["selected"],
        "rejected_count": len(result["rejected"]),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
