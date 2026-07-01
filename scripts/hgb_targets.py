#!/usr/bin/env python3
"""Resolve, validate, and package HarnessGenBench FuzzBench targets."""

from __future__ import annotations

import argparse
import datetime as _dt
import fnmatch
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any


SOURCE_URL_RE = re.compile(r"^(?:https?|git|ssh)://|^git@")
SOURCE_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
SHELL_OPS = {"&&", ";", "||", "|"}
GIT_CLONE_OPTIONS_WITH_ARG = {
    "-b",
    "--branch",
    "--depth",
    "--origin",
    "-o",
    "--config",
    "-c",
    "--reference",
    "--reference-if-able",
    "--separate-git-dir",
    "--template",
    "--upload-pack",
    "-u",
    "--jobs",
    "-j",
}


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def find_repo_root(start: Path | None = None) -> Path:
    cur = (start or Path(__file__)).resolve()
    if cur.is_file():
        cur = cur.parent
    for candidate in [cur, *cur.parents]:
        if (candidate / ".git").exists():
            return candidate
        if (candidate / "README.md").exists() and (candidate / "scripts").is_dir():
            return candidate
    raise SystemExit("could not locate HarnessGenBench repository root")


def run(cmd: list[str], cwd: Path | None = None, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, text=True, capture_output=True, check=check)


def git_head(path: Path) -> str:
    if not (path / ".git").exists():
        return "unknown"
    proc = run(["git", "-C", str(path), "rev-parse", "HEAD"])
    return proc.stdout.strip() if proc.returncode == 0 and proc.stdout.strip() else "unknown"


def load_registry(root: Path) -> dict[str, Any]:
    registry_path = root / "metadata" / "fuzzbench_targets.json"
    try:
        return json.loads(registry_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"missing target registry: {registry_path}") from exc


def enabled_targets(registry: dict[str, Any]) -> list[str]:
    return [entry["name"] for entry in registry.get("targets", []) if entry.get("enabled", True)]


def fuzzbench_dir(root: Path) -> Path:
    override = os.environ.get("HGB_FUZZBENCH_DIR")
    if override:
        return Path(override).expanduser().resolve()
    return root / "artifacts" / "fuzzbench"


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def parse_scalar(value: str) -> Any:
    value = unquote(value.split(" #", 1)[0].strip())
    if not value:
        return ""
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [unquote(part.strip()) for part in inner.split(",") if part.strip()]
    if value.lower() in {"true", "false"}:
        return value.lower() == "true"
    return value


def parse_benchmark_yaml(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = {}
    current_list: str | None = None
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if indent > 0 and current_list and line.startswith("- "):
            data.setdefault(current_list, []).append(parse_scalar(line[2:]))
            continue
        current_list = None
        if indent != 0 or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not value:
            data[key] = []
            current_list = key
        else:
            data[key] = parse_scalar(value)
    return data


def resolve_target(root: Path, target: str) -> dict[str, Any]:
    registry = load_registry(root)
    if target not in enabled_targets(registry):
        raise SystemExit(f"target is not enabled in metadata/fuzzbench_targets.json: {target}")
    fb_dir = fuzzbench_dir(root)
    bench_root = registry.get("source", {}).get("benchmark_root", "benchmarks")
    bench_dir = fb_dir / bench_root / target
    yaml_path = bench_dir / "benchmark.yaml"
    data: dict[str, Any] = {}
    if yaml_path.exists():
        data = parse_benchmark_yaml(yaml_path)
    return {
        "name": target,
        "source": "fuzzbench",
        "benchmark_dir": str(bench_dir),
        "project": str(data.get("project", "")),
        "fuzz_target": str(data.get("fuzz_target", "")),
        "commit": str(data.get("commit", "")),
        "commit_date": str(data.get("commit_date", "")),
        "unsupported_fuzzers": data.get("unsupported_fuzzers", [])
        if isinstance(data.get("unsupported_fuzzers", []), list)
        else [],
        "fuzzbench_commit": git_head(fb_dir),
    }


def validate(root: Path, soft: bool = False) -> int:
    registry = load_registry(root)
    targets = enabled_targets(registry)
    expected = int(registry.get("expected_target_count", -1))
    errors: list[str] = []
    warnings: list[str] = []
    if expected != len(targets):
        errors.append(f"enabled target count {len(targets)} does not match expected_target_count {expected}")
    fb_dir = fuzzbench_dir(root)
    for target in targets:
        bench_dir = fb_dir / registry.get("source", {}).get("benchmark_root", "benchmarks") / target
        mandatory = {
            "benchmark directory": bench_dir,
            "benchmark.yaml": bench_dir / "benchmark.yaml",
            "Dockerfile": bench_dir / "Dockerfile",
        }
        for label, path in mandatory.items():
            if label == "benchmark directory" and not path.is_dir():
                errors.append(f"{target}: missing {label}: {path}")
            elif label != "benchmark directory" and not path.is_file():
                errors.append(f"{target}: missing {label}: {path}")
        if bench_dir.is_dir() and not (bench_dir / "build.sh").is_file():
            if (bench_dir / "third_party" / "build.sh").is_file():
                warnings.append(f"{target}: top-level build.sh missing; package will wrap third_party/build.sh")
            else:
                warnings.append(f"{target}: top-level build.sh missing; package will create a soft-skip stub")
    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 0 if soft else 1
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    suffix = f" ({len(warnings)} build-script fallback warnings)" if warnings else ""
    print(f"validated {len(targets)} enabled FuzzBench targets{suffix}")
    return 0


def normalize_repo_name(url: str, dest: str | None, used: set[str]) -> str:
    candidate = dest or url.rstrip("/").split("/")[-1]
    candidate = candidate.rstrip("/")
    if candidate in {"", ".", "./"}:
        candidate = url.rstrip("/").split("/")[-1]
    candidate = candidate.split("/")[-1]
    if candidate.endswith(".git"):
        candidate = candidate[:-4]
    candidate = re.sub(r"[^A-Za-z0-9_.-]+", "_", candidate).strip("._") or "source"
    base = candidate
    idx = 2
    while candidate in used:
        candidate = f"{base}_{idx}"
        idx += 1
    used.add(candidate)
    return candidate


def is_source_url(value: str) -> bool:
    return bool(SOURCE_URL_RE.search(value.rstrip(".,")))


def logical_dockerfile_lines(dockerfile: Path) -> list[str]:
    if not dockerfile.exists():
        return []
    logical: list[str] = []
    current = ""
    for raw in dockerfile.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            current += stripped[:-1] + " "
            continue
        current += stripped
        logical.append(current)
        current = ""
    if current:
        logical.append(current)
    return logical


def shell_words(command: str) -> list[str]:
    if command.startswith("RUN "):
        command = command[4:].strip()
    command = command.replace("&&", " && ").replace("||", " || ").replace(";", " ; ")
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def parse_git_clone_sources(tokens: list[str], used: set[str]) -> list[dict[str, str]]:
    repos: list[dict[str, str]] = []
    i = 0
    while i < len(tokens):
        if tokens[i] != "git" or i + 1 >= len(tokens) or tokens[i + 1] != "clone":
            i += 1
            continue
        j = i + 2
        url = ""
        raw_dest: str | None = None
        while j < len(tokens):
            token = tokens[j]
            if token in SHELL_OPS:
                break
            if token.startswith("-"):
                opt = token.split("=", 1)[0]
                if "=" not in token and opt in GIT_CLONE_OPTIONS_WITH_ARG and j + 1 < len(tokens):
                    j += 2
                else:
                    j += 1
                continue
            if not url:
                url = token.rstrip(".,")
                j += 1
                continue
            raw_dest = token
            break
        if url and is_source_url(url):
            dest = normalize_repo_name(url, raw_dest, used)
            repos.append({"kind": "git", "url": url, "dest": dest, "source": "Dockerfile"})
        i = max(j + 1, i + 1)
    return repos


def docker_path_basename(value: str) -> str:
    value = value.strip().strip("'\"").rstrip("/")
    for prefix in ("${SRC}/", "$SRC/", "/src/", "${WORK}/", "$WORK/"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break
    if value in {"", "${SRC}", "$SRC", "/src", "."}:
        return "source"
    return value.split("/")[-1] or "source"


def archive_url(value: str) -> bool:
    lower = value.lower().rstrip(".,")
    return (
        lower.startswith(("http://", "https://"))
        and not lower.endswith((".dict", ".options"))
        and (".tar" in lower or lower.endswith((".tgz", ".zip")) or "tarball" in lower or "/archive/" in lower)
    )


def parse_archive_sources(tokens: list[str], used: set[str]) -> list[dict[str, str]]:
    repos: list[dict[str, str]] = []
    current_dir = ""
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token == "cd" and i + 1 < len(tokens):
            current_dir = tokens[i + 1]
            i += 2
            continue
        if token in {"curl", "wget"}:
            url = ""
            j = i + 1
            while j < len(tokens) and tokens[j] not in SHELL_OPS:
                candidate = tokens[j].rstrip(".,")
                if archive_url(candidate):
                    url = candidate
                j += 1
            if url:
                dest_hint = docker_path_basename(current_dir) if current_dir else None
                dest = normalize_repo_name(url, dest_hint, used)
                repos.append({"kind": "archive", "url": url, "dest": dest, "source": "Dockerfile"})
            i = max(j, i + 1)
            continue
        i += 1
    return repos


def load_source_overrides(root: Path, target: str) -> list[dict[str, str]]:
    path = root / "metadata" / "fuzzbench_source_overrides.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    overrides = data.get(target, [])
    if not isinstance(overrides, list):
        return []
    normalized: list[dict[str, str]] = []
    used: set[str] = set()
    for entry in overrides:
        if not isinstance(entry, dict) or not entry.get("url"):
            continue
        url = str(entry["url"]).rstrip(".,")
        kind = str(entry.get("kind") or ("archive" if archive_url(url) else "git"))
        dest = normalize_repo_name(url, str(entry.get("dest") or "") or None, used)
        normalized.append({"kind": kind, "url": url, "dest": dest, "source": "metadata/fuzzbench_source_overrides.json"})
    return normalized


def dedupe_sources(sources: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[dict[str, str]] = []
    for source in sources:
        key = (source.get("kind", "git"), source.get("url", ""), source.get("dest", ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(source)
    return deduped


def parse_clone_repos(dockerfile: Path, root: Path | None = None, target: str | None = None) -> list[dict[str, str]]:
    used: set[str] = set()
    sources: list[dict[str, str]] = []
    for line in logical_dockerfile_lines(dockerfile):
        tokens = shell_words(line)
        sources.extend(parse_git_clone_sources(tokens, used))
        sources.extend(parse_archive_sources(tokens, used))
    if root is not None and target is not None:
        sources.extend(load_source_overrides(root, target))
    return dedupe_sources(sources)


def copy_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"), dirs_exist_ok=False)


def materialize_repo(repo: dict[str, str], target: str, commit: str, root: Path) -> dict[str, Any]:
    artifacts_root = root / "artifacts" / "fuzzbench-target-sources" / target
    artifacts_root.mkdir(parents=True, exist_ok=True)
    local = artifacts_root / repo["dest"]
    result: dict[str, Any] = dict(repo)
    result.setdefault("kind", "git")
    result["artifact_path"] = str(local)
    if local.exists() and not (local / ".git").exists():
        result["clone_status"] = "path_exists_not_git"
        result["materialize_status"] = "path_exists_not_git"
        return result
    if (local / ".git").exists():
        proc = run(["git", "-C", str(local), "fetch", "--all", "--tags", "--prune"])
        result["clone_status"] = "fetched" if proc.returncode == 0 else "fetch_failed"
        result["materialize_status"] = result["clone_status"]
        if proc.returncode != 0:
            result["error"] = (proc.stderr or proc.stdout).strip()[-1000:]
            return result
    else:
        proc = run(["git", "clone", repo["url"], str(local)])
        result["clone_status"] = "cloned" if proc.returncode == 0 else "clone_failed"
        result["materialize_status"] = result["clone_status"]
        if proc.returncode != 0:
            result["error"] = (proc.stderr or proc.stdout).strip()[-1000:]
            return result
    if commit:
        proc = run(["git", "-C", str(local), "checkout", "--detach", commit])
        if proc.returncode == 0:
            result["checkout_status"] = "checked_out_commit"
        else:
            result["checkout_status"] = "commit_not_found_kept_head"
            result["checkout_error"] = (proc.stderr or proc.stdout).strip()[-1000:]
    else:
        result["checkout_status"] = "kept_head_no_commit"
    result["checked_out_commit"] = git_head(local)
    return result


def copy_extracted_archive(extract_root: Path, local: Path) -> None:
    entries = [p for p in extract_root.iterdir() if p.name not in {"__MACOSX"}]
    source = entries[0] if len(entries) == 1 and entries[0].is_dir() else extract_root
    if local.exists():
        shutil.rmtree(local)
    shutil.copytree(source, local, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"), dirs_exist_ok=False)


def materialize_archive(repo: dict[str, str], target: str, root: Path) -> dict[str, Any]:
    artifacts_root = root / "artifacts" / "fuzzbench-target-sources" / target
    artifacts_root.mkdir(parents=True, exist_ok=True)
    local = artifacts_root / repo["dest"]
    result: dict[str, Any] = dict(repo)
    result["kind"] = "archive"
    result["artifact_path"] = str(local)
    if local.is_dir() and any(local.rglob("*")):
        result["materialize_status"] = "cached"
        return result
    try:
        with tempfile.TemporaryDirectory(prefix="hgb-source-", dir=str(artifacts_root)) as tmp_s:
            tmp = Path(tmp_s)
            archive_path = tmp / "source.archive"
            urllib.request.urlretrieve(repo["url"], archive_path)
            extract_root = tmp / "extract"
            extract_root.mkdir()
            if zipfile.is_zipfile(archive_path):
                with zipfile.ZipFile(archive_path) as zf:
                    zf.extractall(extract_root)
            else:
                with tarfile.open(archive_path) as tf:
                    try:
                        tf.extractall(extract_root, filter="data")
                    except TypeError:
                        tf.extractall(extract_root)
            copy_extracted_archive(extract_root, local)
        result["materialize_status"] = "extracted"
    except Exception as exc:  # noqa: BLE001 - record best-effort source acquisition errors.
        result["materialize_status"] = "archive_failed"
        result["error"] = str(exc)[-1000:]
    return result


def materialize_source(repo: dict[str, str], target: str, commit: str, root: Path) -> dict[str, Any]:
    if repo.get("kind") == "archive":
        return materialize_archive(repo, target, root)
    return materialize_repo(repo, target, commit, root)


def likely_reference_harness(path: Path, root: Path) -> bool:
    rel = path.relative_to(root).as_posix()
    lower_rel = f"/{rel.lower()}"
    name = path.name.lower()
    suffix = path.suffix.lower()
    source_exts = {".c", ".cc", ".cpp", ".cxx"}
    header_exts = {".h", ".hh", ".hpp", ".hxx"}
    path_hint = any(
        token in lower_rel
        for token in ("/fuzz/", "/fuzzer/", "/fuzzers/", "/oss-fuzz/", "/test/fuzz", "/tests/fuzz")
    )
    source_name_hint = any(
        fnmatch.fnmatch(name, pat)
        for pat in ("*fuzz*.c", "*fuzz*.cc", "*fuzz*.cpp", "*fuzzer*.c", "*fuzzer*.cc", "*fuzzer*.cpp")
    )
    header_name_hint = suffix in header_exts and any(token in name for token in ("fuzz", "fuzzer"))
    if suffix in source_exts and (path_hint or source_name_hint):
        return True
    return header_name_hint and path_hint


def strip_reference_harnesses(source_full: Path, source_input: Path, reference_dir: Path, strip: bool, source_label: str = "source_full") -> list[str]:
    removed: list[str] = []
    if not source_full.exists():
        return removed
    for path in source_full.rglob("*"):
        if not path.is_file() or not likely_reference_harness(path, source_full):
            continue
        rel = path.relative_to(source_full)
        ref_target = reference_dir / rel
        ref_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, ref_target)
        removed.append(f"{source_label}/{rel.as_posix()}")
        if strip:
            input_path = source_input / rel
            if input_path.exists():
                input_path.unlink()
    return sorted(removed)


def copy_selected_docs(source_full: Path, docs_dir: Path) -> int:
    if not source_full.exists():
        return 0
    copied = 0
    patterns = ("README*", "readme*", "CHANGELOG*", "docs")
    for repo_dir in [p for p in source_full.iterdir() if p.is_dir()]:
        for item in repo_dir.iterdir():
            if not any(fnmatch.fnmatch(item.name, pat) for pat in patterns):
                continue
            rel = item.relative_to(source_full)
            dst = docs_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            try:
                if item.is_dir():
                    copy_tree(item, dst)
                else:
                    shutil.copy2(item, dst)
                copied += 1
            except OSError:
                continue
    return copied


def copy_seeds_and_dicts(benchmark_dir: Path, seeds_dir: Path, dictionary_dir: Path) -> tuple[int, int]:
    seed_count = 0
    dictionary_count = 0
    seed_names = {"seeds", "seed", "corpus"}
    for path in benchmark_dir.rglob("*"):
        if path.is_dir() and (path.name in seed_names or path.name.endswith("_seed_corpus")):
            dst = seeds_dir / path.relative_to(benchmark_dir)
            copy_tree(path, dst)
        elif path.is_file() and path.suffix in {".dict", ".options"}:
            dst = dictionary_dir / path.relative_to(benchmark_dir)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dst)
    if seeds_dir.exists():
        seed_count = sum(1 for p in seeds_dir.rglob("*") if p.is_file())
    if dictionary_dir.exists():
        dictionary_count = sum(1 for p in dictionary_dir.rglob("*") if p.is_file())
    return seed_count, dictionary_count



def ensure_package_build_script(benchmark_copy: Path) -> str:
    build_sh = benchmark_copy / "build.sh"
    if build_sh.is_file():
        build_sh.chmod(build_sh.stat().st_mode | 0o111)
        return "present"
    third_party = benchmark_copy / "third_party" / "build.sh"
    if third_party.is_file():
        build_sh.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "SCRIPT_DIR=\"$(cd -- \"$(dirname -- \"${BASH_SOURCE[0]}\")\" && pwd)\"\n"
            "exec bash \"$SCRIPT_DIR/third_party/build.sh\" \"$@\"\n",
            encoding="utf-8",
        )
        build_sh.chmod(0o755)
        return "wrapped_third_party_build_sh"
    build_sh.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf 'FuzzBench benchmark did not include a top-level build.sh; target build is unavailable for this package.\\n' >&2\n"
        "exit 127\n",
        encoding="utf-8",
    )
    build_sh.chmod(0o755)
    return "missing_stubbed_soft_skip"

def count_source_files(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for p in path.rglob("*") if p.is_file() and p.suffix.lower() in SOURCE_EXTS)


def count_named_files(path: Path, name: str) -> int:
    if not path.exists():
        return 0
    return sum(1 for p in path.rglob(name) if p.is_file())


def write_summary(output: Path, manifest: dict[str, Any]) -> None:
    lines = [
        "# HarnessGenBench Target Package",
        "",
        f"- Target: `{manifest['target']}`",
        f"- Project: `{manifest.get('project', '')}`",
        f"- Fuzz target: `{manifest.get('fuzz_target', '')}`",
        f"- FuzzBench commit: `{manifest.get('fuzzbench_commit', 'unknown')}`",
        f"- Source status: `{manifest.get('source_status', 'unknown')}`",
        f"- Source layout: `{manifest.get('source_layout', 'full')}`",
        f"- Source repositories: `{len(manifest.get('source_repos', []))}`",
        f"- Source files: `{manifest.get('source_file_count', 0)}`",
        f"- CMake files: `{manifest.get('cmake_file_count', 0)}`",
        f"- Compile databases: `{manifest.get('compile_commands_count', 0)}`",
        f"- Reference harness files stripped/copied: `{len(manifest.get('reference_harness_files', []))}`",
        f"- Seed files: `{manifest.get('seed_count', 0)}`",
        f"- Dictionary/options files: `{manifest.get('dictionary_count', 0)}`",
        f"- Build script status: `{manifest.get('build_script_status', 'unknown')}`",
        "",
    ]
    if manifest.get("source_status") == "benchmark_only":
        lines.append("No source fetch commands were parsed from the FuzzBench Dockerfile, so the package contains benchmark files only.")
    elif manifest.get("source_status") == "partial":
        lines.append("At least one source repository could not be materialized or copied. Downstream generators should soft-skip if source input is insufficient.")
    elif manifest.get("source_layout") == "compact":
        lines.append("Source repositories were materialized in the artifact cache and copied only to `source_input/`; `source_full/` is omitted to keep the workspace compact.")
    else:
        lines.append("Source repositories were materialized under `source_full/` and copied to `source_input/` for generator input.")
    (output / "HGB_TARGET_SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def package_target(root: Path, target: str, output: Path, layout: str = "compact") -> Path:
    if layout not in {"compact", "full"}:
        raise SystemExit(f"unknown target package layout: {layout}")
    resolved = resolve_target(root, target)
    benchmark_dir = Path(resolved["benchmark_dir"])
    if not benchmark_dir.is_dir():
        raise SystemExit(f"missing FuzzBench benchmark directory: {benchmark_dir}")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "logs").mkdir(parents=True, exist_ok=True)
    for dirname in ("source_input", "reference_harnesses", "docs", "seeds", "dictionary"):
        path = output / dirname
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True, exist_ok=True)
    source_full = output / "source_full"
    if layout == "full":
        if source_full.exists():
            shutil.rmtree(source_full)
        source_full.mkdir(parents=True, exist_ok=True)
    elif source_full.exists():
        shutil.rmtree(source_full)
    benchmark_copy = output / "fuzzbench_benchmark"
    copy_tree(benchmark_dir, benchmark_copy)
    build_script_status = ensure_package_build_script(benchmark_copy)
    repos = parse_clone_repos(benchmark_copy / "Dockerfile", root, target)
    materialized: list[dict[str, Any]] = []
    source_root = output / ("source_full" if layout == "full" else "source_input")
    for repo in repos:
        record = materialize_source(repo, target, resolved.get("commit", ""), root)
        materialized.append(record)
        local = Path(record.get("artifact_path", ""))
        if record.get("materialize_status") in {"cloned", "fetched", "cached", "extracted"} and local.is_dir():
            package_dst = source_root / repo["dest"]
            try:
                copy_tree(local, package_dst)
                record["copy_status"] = "copied_to_package" if layout == "full" else "copied_to_source_input"
                record["package_path"] = package_dst.relative_to(output).as_posix()
            except OSError as exc:
                record["copy_status"] = "copy_failed"
                record["copy_error"] = str(exc)
    (output / "source_repos.json").write_text(json.dumps(materialized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if layout == "full" and any((output / "source_full").rglob("*")):
        copy_tree(output / "source_full", output / "source_input")
    strip = os.environ.get("HGB_TARGET_STRIP_REFERENCE_HARNESS", "1") != "0"
    source_label = "source_full" if layout == "full" else "source_input"
    reference_files = strip_reference_harnesses(source_root, output / "source_input", output / "reference_harnesses", strip, source_label=source_label)
    copy_selected_docs(source_root, output / "docs")
    seed_count, dictionary_count = copy_seeds_and_dicts(benchmark_copy, output / "seeds", output / "dictionary")
    source_file_count = count_source_files(output / "source_input")
    cmake_file_count = count_named_files(output / "source_input", "CMakeLists.txt")
    compile_commands_count = count_named_files(output / "source_input", "compile_commands.json")
    copied_statuses = {"copied_to_package", "copied_to_source_input"}
    if not repos:
        source_status = "benchmark_only"
    elif all(r.get("copy_status") in copied_statuses for r in materialized):
        source_status = "materialized"
    else:
        source_status = "partial"
    manifest = {
        "schema_version": 1,
        "target": target,
        "source": "fuzzbench",
        "fuzzbench_commit": resolved.get("fuzzbench_commit", "unknown"),
        "benchmark_dir": str(benchmark_dir),
        "project": resolved.get("project", ""),
        "fuzz_target": resolved.get("fuzz_target", ""),
        "commit": resolved.get("commit", ""),
        "commit_date": resolved.get("commit_date", ""),
        "source_layout": layout,
        "source_status": source_status,
        "source_repos": materialized,
        "source_artifact_paths": sorted({str(r.get("artifact_path", "")) for r in materialized if r.get("artifact_path")}),
        "source_file_count": source_file_count,
        "cmake_file_count": cmake_file_count,
        "compile_commands_count": compile_commands_count,
        "source_input_dir": "source_input",
        "source_full_dir": "source_full" if layout == "full" else "",
        "reference_harness_dir": "reference_harnesses",
        "reference_harness_files": reference_files,
        "seed_count": seed_count,
        "dictionary_count": dictionary_count,
        "build_script_status": build_script_status,
        "created_at": now_iso(),
    }
    (output / "target_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_summary(output, manifest)
    return output


def main(argv: list[str] | None = None) -> int:
    root = find_repo_root()
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    validate_parser = sub.add_parser("validate")
    validate_parser.add_argument("--soft", action="store_true")
    resolve_parser = sub.add_parser("resolve")
    resolve_parser.add_argument("target")
    resolve_parser.add_argument("--json", action="store_true", dest="as_json")
    package_parser = sub.add_parser("package")
    package_parser.add_argument("target")
    package_parser.add_argument("--output", required=True)
    package_parser.add_argument("--layout", choices=("compact", "full"), default=os.environ.get("HGB_TARGET_PACKAGE_LAYOUT", "compact"))
    args = parser.parse_args(argv)

    if args.command == "list":
        for target in enabled_targets(load_registry(root)):
            print(target)
        return 0
    if args.command == "validate":
        return validate(root, soft=args.soft)
    if args.command == "resolve":
        resolved = resolve_target(root, args.target)
        if args.as_json:
            print(json.dumps(resolved, indent=2, sort_keys=True))
        else:
            for key in ("name", "project", "fuzz_target", "commit", "commit_date", "benchmark_dir", "fuzzbench_commit"):
                print(f"{key}: {resolved.get(key, '')}")
        return 0
    if args.command == "package":
        output = package_target(root, args.target, Path(args.output), layout=args.layout)
        print(output)
        return 0
    raise SystemExit(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
