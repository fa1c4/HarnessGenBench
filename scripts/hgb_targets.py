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
HARNESS_SOURCE_EXTS = {".c", ".cc", ".cpp", ".cxx"}
SELECTED_REFERENCE_SUBDIR = "selected"
HARNESS_STOP_TOKENS = {
    "fuzz",
    "fuzzer",
    "fuzzing",
    "target",
    "oss",
    "ossfuzz",
    "read",
    "decode",
    "parser",
    "parse",
    "http",
    "both",
    "send",
    "convert",
    "shape",
    "link",
}
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
GIT_CLONE_REVISION_OPTIONS = {"-b", "--branch"}
# ``captured_unpinned`` is a concrete commit observed while packaging an
# upstream recipe that omitted a revision. It is reproducible for this HGB
# run, while manifest metadata still exposes that it was not benchmark-pinned.
REPRODUCIBLE_REVISION_STATUSES = {"resolved", "resolved_url", "captured_unpinned"}
# The historical Savannah mirror was retired. The GitHub mirror retains the
# submodule history required by text-rendering-tests.
LEGACY_SUBMODULE_URL_REWRITES = {
    "git://git.sv.nongnu.org/freetype/freetype2.git": "https://github.com/freetype/freetype.git",
    "https://git.sv.nongnu.org/freetype/freetype2.git": "https://github.com/freetype/freetype.git",
}
PROJECT_REPO_ALIASES = {
    # FuzzBench project names are normally the repository basename.  These
    # historical projects are the exceptions in the bundled target set.
    "lcms": {"littlecms"},
    "proj4": {"proj"},
    "php": {"phpsrc"},
}


class PackageSplitError(RuntimeError):
    """The target package cannot be split into generator/evaluator halves."""


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


def _load_docker_common_module(name: str):
    """Load a docker/common/<name>.py module by path (stdlib-only helper)."""
    import importlib.util

    root = find_repo_root()
    path = root / "docker" / "common" / f"{name}.py"
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(name, str(path))
    if not spec or not spec.loader:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


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


def registry_target_sets(registry: dict[str, Any]) -> dict[str, Any]:
    target_sets = registry.get("target_sets", {})
    return target_sets if isinstance(target_sets, dict) else {}


def target_set_names(registry: dict[str, Any]) -> list[str]:
    return sorted(registry_target_sets(registry))


def targets_for_set(registry: dict[str, Any], target_set: str = "all") -> list[str]:
    if target_set in {"", "all"}:
        return enabled_targets(registry)
    target_sets = registry_target_sets(registry)
    raw_set = target_sets.get(target_set)
    if raw_set is None:
        available = ", ".join(["all", *target_set_names(registry)])
        raise SystemExit(f"unknown target set: {target_set}; available sets: {available}")
    raw_targets = raw_set.get("targets", raw_set) if isinstance(raw_set, dict) else raw_set
    if not isinstance(raw_targets, list):
        raise SystemExit(f"target set is not a list: {target_set}")
    enabled = set(enabled_targets(registry))
    selected = [str(target) for target in raw_targets]
    unknown = [target for target in selected if target not in enabled]
    if unknown:
        raise SystemExit(f"target set {target_set} references disabled or unknown targets: {', '.join(unknown)}")
    return selected


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
    for set_name in target_set_names(registry):
        try:
            selected = targets_for_set(registry, set_name)
        except SystemExit as exc:
            errors.append(str(exc))
            continue
        if len(selected) != len(set(selected)):
            errors.append(f"target set {set_name} contains duplicate target names")
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


def docker_instruction(line: str) -> tuple[str, str]:
    """Return an upper-case Dockerfile instruction and its argument text."""
    match = re.match(r"^([A-Za-z]+)\s+(.*)$", line.strip())
    if not match:
        return "", ""
    return match.group(1).upper(), match.group(2).strip()


_DOCKER_VARIABLE_RE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")


def substitute_docker_variables(value: str, variables: dict[str, str]) -> str:
    """Expand Docker-style variables with values known from ARG/ENV only."""

    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        # Preserve unknown values: an empty replacement would silently turn an
        # unresolved source URL into a different URL.
        return variables.get(name, match.group(0))

    return _DOCKER_VARIABLE_RE.sub(replace, value)


def update_docker_variables(instruction: str, argument: str, variables: dict[str, str]) -> None:
    """Apply the ARG/ENV forms needed to resolve deterministic source URLs."""
    if instruction == "ARG":
        name, separator, value = argument.partition("=")
        name = name.strip()
        if name and separator:
            variables[name] = substitute_docker_variables(value.strip(), variables)
        return
    if instruction != "ENV":
        return
    try:
        words = shlex.split(argument, posix=True)
    except ValueError:
        words = argument.split()
    if not words:
        return
    if "=" not in words[0]:
        if len(words) > 1:
            variables[words[0]] = substitute_docker_variables(" ".join(words[1:]), variables)
        return
    for word in words:
        name, separator, value = word.partition("=")
        if name and separator:
            variables[name] = substitute_docker_variables(value, variables)


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
        revision = ""
        while j < len(tokens):
            token = tokens[j]
            if token in SHELL_OPS:
                break
            if token.startswith("-"):
                opt = token.split("=", 1)[0]
                if "=" not in token and opt in GIT_CLONE_OPTIONS_WITH_ARG and j + 1 < len(tokens):
                    if opt in GIT_CLONE_REVISION_OPTIONS:
                        revision = tokens[j + 1]
                    j += 2
                else:
                    if opt in GIT_CLONE_REVISION_OPTIONS and "=" in token:
                        revision = token.split("=", 1)[1]
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
            repo = {"kind": "git", "url": url, "dest": dest, "source": "Dockerfile"}
            if raw_dest:
                repo["docker_dest"] = raw_dest
            if revision:
                repo["revision"] = revision
                repo["revision_source"] = "dockerfile_git_clone_branch"
            repos.append(repo)
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


def archive_extract_dir_name(url: str) -> str:
    """Return the conventional top-level directory for an archive URL."""

    name = url.split("?", 1)[0].rstrip("/").split("/")[-1]
    for suffix in (".tar.gz", ".tar.xz", ".tar.bz2", ".tar.zst", ".tar", ".tgz", ".zip"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return name or "source"


def parse_archive_sources(tokens: list[str], used: set[str]) -> list[dict[str, str]]:
    repos: list[dict[str, str]] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in {"curl", "wget"}:
            url = ""
            j = i + 1
            while j < len(tokens) and tokens[j] not in SHELL_OPS:
                candidate = tokens[j].rstrip(".,")
                if archive_url(candidate):
                    url = candidate
                j += 1
            if url:
                # Docker's default ``tar xf`` creates a directory named from
                # the archive, not from an earlier ``cd`` in a parenthesized
                # build group. Keeping that stale directory was the cause of
                # the shifted m4/autoconf/automake snapshots for libxslt.
                dest = normalize_repo_name(url, archive_extract_dir_name(url), used)
                repos.append({"kind": "archive", "url": url, "dest": dest, "source": "Dockerfile"})
            i = max(j, i + 1)
            continue
        i += 1
    return repos


def _docker_workdir_name(value: str) -> str:
    return docker_path_basename(value).lower()


def _repo_matches_workdir(repo: dict[str, str], workdir: str) -> bool:
    if not workdir:
        return False
    expected = _docker_workdir_name(workdir)
    candidates = {
        _docker_workdir_name(str(repo.get("dest", ""))),
        _docker_workdir_name(str(repo.get("docker_dest", ""))),
    }
    return expected in candidates


def _git_revision_argument(tokens: list[str], start: int) -> str:
    """Return the first revision argument after checkout/reset options."""
    index = start
    while index < len(tokens) and tokens[index] not in SHELL_OPS:
        token = tokens[index]
        if token == "--":
            index += 1
            if index < len(tokens) and tokens[index] not in SHELL_OPS:
                return tokens[index]
            return ""
        if not token.startswith("-"):
            return token
        index += 1
    return ""


def apply_git_checkout_revisions(
    tokens: list[str], repos: list[dict[str, str]], default_workdir: str = ""
) -> None:
    """Attach explicit ``git checkout``/``git reset --hard`` revisions."""
    workdir = default_workdir
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "cd" and index + 1 < len(tokens):
            workdir = tokens[index + 1]
            index += 2
            continue
        if token != "git":
            index += 1
            continue
        command_index = index + 1
        command_workdir = workdir
        if command_index < len(tokens) and tokens[command_index] == "-C" and command_index + 1 < len(tokens):
            command_workdir = tokens[command_index + 1]
            command_index += 2
        if command_index >= len(tokens) or tokens[command_index] not in {"checkout", "reset"}:
            index += 1
            continue
        command = tokens[command_index]
        revision = _git_revision_argument(tokens, command_index + 1)
        if command == "reset" and "--hard" not in tokens[command_index + 1 :]:
            revision = ""
        if revision:
            for repo in repos:
                if _repo_matches_workdir(repo, command_workdir):
                    repo["revision"] = revision
                    repo["revision_source"] = f"dockerfile_git_{command}"
        index = command_index + 1


def canonical_repo_identifiers(value: str) -> set[str]:
    raw = value.rstrip("/").split("/")[-1]
    raw = raw.removesuffix(".git")
    normalized = re.sub(r"[^a-z0-9]+", "", raw.lower())
    identifiers = {normalized} if normalized else set()
    if normalized.endswith("src") and len(normalized) > 3:
        identifiers.add(normalized[:-3])
    return identifiers


def attribute_source_revisions(repos: list[dict[str, str]], project: str, benchmark_commit: str) -> None:
    """Assign the benchmark revision only to the primary project repository."""
    project_id = re.sub(r"[^a-z0-9]+", "", project.lower())
    aliases = PROJECT_REPO_ALIASES.get(project_id, set())
    primary_indexes: list[int] = []
    for index, repo in enumerate(repos):
        if repo.get("kind") == "archive":
            continue
        identifiers = set()
        for value in (str(repo.get("dest", "")), str(repo.get("docker_dest", "")), str(repo.get("url", ""))):
            identifiers.update(canonical_repo_identifiers(value))
        if project_id in identifiers or bool(identifiers & aliases):
            primary_indexes.append(index)
    for index, repo in enumerate(repos):
        repo["is_primary_project"] = index in primary_indexes
        if repo.get("kind") == "archive":
            repo.setdefault("revision", str(repo.get("url", "")))
            repo.setdefault("revision_source", "archive_url")
        elif index in primary_indexes and benchmark_commit and len(primary_indexes) == 1:
            repo["revision"] = benchmark_commit
            repo["revision_source"] = "benchmark.yaml.commit"
        elif not repo.get("revision"):
            repo["revision_source"] = "unresolved"
    if len(primary_indexes) > 1:
        for index in primary_indexes:
            repos[index]["primary_project_match"] = "ambiguous"


def revision_is_resolved(revision: str) -> bool:
    return bool(revision) and "$" not in revision


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
        record = {"kind": kind, "url": url, "dest": dest, "source": "metadata/fuzzbench_source_overrides.json"}
        for key in ("revision", "revision_source", "docker_dest", "clone_branch"):
            if entry.get(key):
                record[key] = str(entry[key])
        normalized.append(record)
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
    variables: dict[str, str] = {}
    workdir = ""
    for line in logical_dockerfile_lines(dockerfile):
        instruction, argument = docker_instruction(line)
        if instruction in {"ARG", "ENV"}:
            update_docker_variables(instruction, argument, variables)
            continue
        expanded_argument = substitute_docker_variables(argument, variables)
        if instruction == "WORKDIR":
            workdir = expanded_argument
            continue
        if instruction != "RUN":
            continue
        tokens = shell_words(f"RUN {expanded_argument}")
        sources.extend(parse_git_clone_sources(tokens, used))
        sources.extend(parse_archive_sources(tokens, used))
        apply_git_checkout_revisions(tokens, sources, workdir)
    if root is not None and target is not None:
        overrides = load_source_overrides(root, target)
        # An override is authoritative for an archive whose Docker command
        # extracts into a non-standard directory (SQLite). Do not retain the
        # inferred duplicate under a different destination.
        override_urls = {(entry["kind"], entry["url"]) for entry in overrides}
        sources = [entry for entry in sources if (entry.get("kind"), entry.get("url")) not in override_urls]
        sources.extend(overrides)
    return dedupe_sources(sources)


def copy_tree(src: Path, dst: Path) -> None:
    """Replace ``dst`` with a symlink-preserving copy of ``src``.

    Source projects such as systemd contain symlinks.  ``copytree`` defaults to
    dereferencing them, which can escape the copied tree or turn a link into a
    stale host-dependent file.  Copy into a sibling first so failed copies
    leave an existing package intact.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{dst.name}.tmp-", dir=str(dst.parent)))
    temporary.rmdir()
    backup = Path(tempfile.mkdtemp(prefix=f".{dst.name}.old-", dir=str(dst.parent)))
    backup.rmdir()
    moved_existing = False
    installed = False

    def exists_or_link(path: Path) -> bool:
        return path.exists() or path.is_symlink()

    def remove_path(path: Path) -> None:
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.exists():
            shutil.rmtree(path)

    try:
        shutil.copytree(
            src,
            temporary,
            symlinks=True,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
            dirs_exist_ok=False,
        )
        if exists_or_link(dst):
            os.replace(dst, backup)
            moved_existing = True
        os.replace(temporary, dst)
        installed = True
    finally:
        if not installed and moved_existing and exists_or_link(backup):
            if exists_or_link(dst):
                remove_path(dst)
            os.replace(backup, dst)
        if exists_or_link(temporary):
            remove_path(temporary)
        if installed and exists_or_link(backup):
            remove_path(backup)


def normalize_legacy_submodule_urls(local: Path, result: dict[str, Any]) -> bool:
    """Rewrite insecure/unavailable git:// submodules to HTTPS in the cache.

    The rewrite is local to the disposable artifact checkout. Provenance keeps
    both URLs so package consumers can see that the transport, not the commit,
    was normalized.
    """

    gitmodules = local / ".gitmodules"
    try:
        original = gitmodules.read_text(encoding="utf-8")
    except OSError as exc:
        result["submodule_url_rewrite_error"] = str(exc)
        return False

    rewrites: list[dict[str, str]] = []

    def replace(match: re.Match[str]) -> str:
        prefix, url = match.group(1), match.group(2)
        replacement = LEGACY_SUBMODULE_URL_REWRITES.get(url)
        if not replacement:
            replacement = "https://" + url[len("git://") :] if url.startswith("git://") else url
        if replacement != url:
            rewrites.append({"original": url, "replacement": replacement})
        return prefix + replacement

    rewritten = re.sub(r"(?m)^(\s*url\s*=\s*)([^\s#]+)", replace, original)
    if not rewrites:
        return True
    try:
        gitmodules.write_text(rewritten, encoding="utf-8")
    except OSError as exc:
        result["submodule_url_rewrite_error"] = str(exc)
        return False
    result["submodule_url_rewrites"] = rewrites
    sync = run(["git", "-C", str(local), "submodule", "sync", "--recursive"])
    if sync.returncode == 0:
        result["submodule_url_sync_status"] = "synchronized"
        return True
    result["submodule_url_sync_status"] = "sync_failed"
    result["submodule_url_sync_error"] = (sync.stderr or sync.stdout).strip()[-1000:]
    return False


def materialize_submodules(local: Path, result: dict[str, Any]) -> bool:
    """Populate pinned git submodules required by a checked-out project."""

    if not (local / ".gitmodules").is_file():
        result["submodule_status"] = "not_present"
        return True
    if not normalize_legacy_submodule_urls(local, result):
        result["submodule_status"] = "url_normalization_failed"
        result["materialize_status"] = "submodule_update_failed"
        return False
    proc = run(["git", "-C", str(local), "submodule", "update", "--init", "--recursive"])
    if proc.returncode == 0:
        result["submodule_status"] = "initialized_recursive"
        return True
    result["submodule_status"] = "update_failed"
    result["submodule_error"] = (proc.stderr or proc.stdout).strip()[-1000:]
    result["materialize_status"] = "submodule_update_failed"
    return False


def materialize_repo(repo: dict[str, str], target: str, commit: str, root: Path) -> dict[str, Any]:
    artifacts_root = root / "artifacts" / "fuzzbench-target-sources" / target
    artifacts_root.mkdir(parents=True, exist_ok=True)
    local = artifacts_root / repo["dest"]
    result: dict[str, Any] = dict(repo)
    result.setdefault("kind", "git")
    result["artifact_path"] = str(local)
    revision = str(repo.get("revision") or commit or "").strip()
    capture_unpinned = not revision_is_resolved(revision)
    result["requested_revision"] = revision
    result.setdefault("revision_source", "legacy_commit_argument" if commit else "unresolved")
    if capture_unpinned:
        result["revision_source"] = "captured_unpinned_head"
    if local.exists() and not (local / ".git").exists():
        result["clone_status"] = "path_exists_not_git"
        result["materialize_status"] = "path_exists_not_git"
        result["revision_status"] = "unavailable"
        return result
    if (local / ".git").exists():
        proc = run(["git", "-C", str(local), "fetch", "--all", "--tags", "--prune"])
        result["clone_status"] = "fetched" if proc.returncode == 0 else "fetch_failed"
        result["materialize_status"] = result["clone_status"]
        if proc.returncode != 0:
            result["error"] = (proc.stderr or proc.stdout).strip()[-1000:]
            if any(p for p in local.rglob("*") if p.is_file() and ".git" not in p.parts):
                result["materialize_status"] = "fetch_failed_using_cached_checkout"
                result["cache_fallback"] = True
            else:
                result["revision_status"] = "unavailable"
                return result
    else:
        clone_command = ["git", "clone"]
        clone_branch = str(repo.get("clone_branch") or "").strip()
        if clone_branch:
            clone_command.extend(["--branch", clone_branch])
            result["clone_branch"] = clone_branch
        clone_command.extend([repo["url"], str(local)])
        proc = run(clone_command)
        result["clone_status"] = "cloned" if proc.returncode == 0 else "clone_failed"
        result["materialize_status"] = result["clone_status"]
        if proc.returncode != 0:
            result["error"] = (proc.stderr or proc.stdout).strip()[-1000:]
            result["revision_status"] = "unavailable"
            return result
    if capture_unpinned:
        captured = git_head(local)
        if captured == "unknown":
            result["checkout_status"] = "capture_failed"
            result["revision_status"] = "unavailable"
            result["materialize_status"] = "capture_failed"
            return result
        proc = run(["git", "-C", str(local), "checkout", "--detach", captured])
        if proc.returncode == 0:
            result["revision"] = captured
            result["captured_revision"] = captured
            result["checkout_status"] = "captured_unpinned_commit"
            result["revision_status"] = "captured_unpinned"
            result["source_reproducibility"] = "captured_at_package_time"
            if not materialize_submodules(local, result):
                result["revision_status"] = "unavailable"
        else:
            result["checkout_status"] = "capture_checkout_failed"
            result["checkout_error"] = (proc.stderr or proc.stdout).strip()[-1000:]
            result["revision_status"] = "unavailable"
            result["materialize_status"] = "capture_checkout_failed"
        result["checked_out_commit"] = git_head(local)
        return result

    proc = run(["git", "-C", str(local), "checkout", "--detach", revision])
    if proc.returncode == 0:
        result["checkout_status"] = "checked_out_revision"
        result["revision_status"] = "resolved"
        if not materialize_submodules(local, result):
            result["revision_status"] = "unavailable"
    else:
        result["checkout_status"] = "checkout_failed"
        result["checkout_error"] = (proc.stderr or proc.stdout).strip()[-1000:]
        result["revision_status"] = "unavailable"
        result["materialize_status"] = "checkout_failed"
    result["checked_out_commit"] = git_head(local)
    return result


def copy_extracted_archive(extract_root: Path, local: Path) -> None:
    entries = [p for p in extract_root.iterdir() if p.name not in {"__MACOSX"}]
    source = entries[0] if len(entries) == 1 and entries[0].is_dir() else extract_root
    copy_tree(source, local)


def materialize_archive(repo: dict[str, str], target: str, root: Path) -> dict[str, Any]:
    artifacts_root = root / "artifacts" / "fuzzbench-target-sources" / target
    artifacts_root.mkdir(parents=True, exist_ok=True)
    local = artifacts_root / repo["dest"]
    result: dict[str, Any] = dict(repo)
    result["kind"] = "archive"
    result["artifact_path"] = str(local)
    result["requested_revision"] = str(repo.get("revision") or repo.get("url") or "")
    result.setdefault("revision_source", "archive_url")
    if not revision_is_resolved(result["requested_revision"]):
        result["revision_status"] = "unresolved"
        result["materialize_status"] = "revision_unresolved"
        return result
    if local.is_dir() and any(local.rglob("*")):
        result["materialize_status"] = "cached"
        result["revision_status"] = "resolved_url"
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
        result["revision_status"] = "resolved_url"
    except Exception as exc:  # noqa: BLE001 - record best-effort source acquisition errors.
        result["materialize_status"] = "archive_failed"
        result["error"] = str(exc)[-1000:]
        result["revision_status"] = "unavailable"
    return result


def materialize_source(repo: dict[str, str], target: str, commit: str, root: Path) -> dict[str, Any]:
    if repo.get("kind") == "archive":
        return materialize_archive(repo, target, root)
    return materialize_repo(repo, target, commit, root)


def _dynamic_branch_variable(repo: dict[str, str]) -> str:
    destination = str(repo.get("docker_dest") or "")
    match = re.search(r"\$(?:\{)?([A-Za-z_][A-Za-z0-9_]*)", destination)
    return match.group(1) if match else ""


def expand_dynamic_branch_sources(
    repos: list[dict[str, str]], materialized: list[dict[str, Any]]
) -> list[dict[str, str]]:
    """Expand Docker clone destinations such as ``project.$branch``.

    Some FuzzBench recipes keep a branch list in a separately cloned source
    repository. Capturing each branch head lets sealed verification remove the
    live shell loop while preserving the source layout native ``build.sh``
    expects (libjpeg-turbo).
    """

    dynamic = [repo for repo in repos if _dynamic_branch_variable(repo)]
    if not dynamic:
        return []
    values: list[str] = []
    for record in materialized:
        artifact = Path(str(record.get("artifact_path") or ""))
        if not artifact.is_dir():
            continue
        for branch_file in sorted(artifact.rglob("branches.txt")):
            try:
                lines = branch_file.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for raw in lines:
                branch = raw.split("#", 1)[0].strip()
                if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", branch) and branch not in values:
                    values.append(branch)
    if not values:
        return []

    used = {str(repo.get("dest", "")) for repo in repos if not _dynamic_branch_variable(repo)}
    expanded: list[dict[str, str]] = []
    for repo in dynamic:
        variable = _dynamic_branch_variable(repo)
        raw_destination = str(repo.get("docker_dest") or repo.get("dest") or "")
        for branch in values:
            docker_destination = raw_destination.replace(f"${{{variable}}}", branch).replace(f"${variable}", branch)
            entry = dict(repo)
            entry["dest"] = normalize_repo_name(str(repo["url"]), docker_destination, used)
            entry["docker_dest"] = docker_destination
            entry["clone_branch"] = branch
            entry["dynamic_branch"] = branch
            entry["source"] = "Dockerfile_dynamic_branch"
            if branch != "main":
                entry.pop("revision", None)
                entry["revision_source"] = "captured_dynamic_branch_head"
                entry["is_primary_project"] = False
            expanded.append(entry)
    return expanded


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



def _norm_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def harness_hint_tokens(*values: str) -> list[str]:
    tokens: list[str] = []
    for value in values:
        for token in re.split(r"[^A-Za-z0-9]+", value or ""):
            token = token.lower()
            if len(token) < 2 or token in HARNESS_STOP_TOKENS:
                continue
            if token not in tokens:
                tokens.append(token)
    return tokens


def _all_name_tokens(*values: str) -> list[str]:
    tokens: list[str] = []
    for value in values:
        for token in re.split(r"[^A-Za-z0-9]+", value or ""):
            token = token.lower()
            if token and token not in tokens:
                tokens.append(token)
    return tokens


def _project_alias_norms(project: str) -> set[str]:
    aliases = {_norm_token(project)}
    for token in _all_name_tokens(project):
        aliases.add(_norm_token(token))
    project_norm = _norm_token(project)
    if project_norm.endswith("4"):
        aliases.add(project_norm[:-1])
    if project_norm == "openthread":
        aliases.add("ot")
    return {alias for alias in aliases if alias}


def _project_path_score(rel: Path, project: str) -> int:
    aliases = _project_alias_norms(project)
    if not aliases or not rel.parts:
        return 0
    top = _norm_token(rel.parts[0])
    if any(top == alias or top.startswith(alias) or alias.startswith(top) for alias in aliases):
        return 150
    return -160


def _selected_harness_alias_norms(target: str, fuzz_target: str, project: str, build_stems: set[str]) -> set[str]:
    project_aliases = _project_alias_norms(project)
    generic = {"fuzz", "fuzzer", "target", "oss", "ossfuzz"}
    aliases: set[str] = set()
    for value in (target, fuzz_target, *sorted(build_stems)):
        parts = _all_name_tokens(value, Path(value).stem)
        if not parts:
            continue
        candidate_sets = [
            parts,
            [part for part in parts if _norm_token(part) not in project_aliases],
            [part for part in parts if _norm_token(part) not in project_aliases and part not in generic],
        ]
        for candidate in candidate_sets:
            if not candidate:
                continue
            joined = "".join(candidate)
            aliases.add(_norm_token(joined))
            if "fuzz" in candidate:
                aliases.add(_norm_token("".join("fuzzer" if part == "fuzz" else part for part in candidate)))
            if "fuzzer" in candidate:
                aliases.add(_norm_token("".join("fuzz" if part == "fuzzer" else part for part in candidate)))
    return {alias for alias in aliases if len(alias) >= 3}


def _for_loop_values(build_text: str) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for match in re.finditer(r"\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+([^;\n]+)", build_text):
        var = match.group(1)
        raw_values = [unquote(part.strip()) for part in match.group(2).split() if part.strip()]
        values[var] = [value for value in raw_values if value and not value.startswith("$")]
    return values


def _clean_build_source_ref(ref: str) -> str:
    ref = unquote(ref.strip().strip("\\"))
    for prefix in ("${SRC}/", "$SRC/", "${WORK}/", "$WORK/", "./"):
        if ref.startswith(prefix):
            ref = ref[len(prefix):]
    while ref.startswith("../"):
        ref = ref[3:]
    return ref.strip("/")


def _source_ref_matches_target(ref: str, target_tokens: list[str], target_norms: set[str]) -> bool:
    rel = _clean_build_source_ref(ref).lower()
    name = Path(rel).name.lower()
    stem = Path(name).stem
    norm_stem = _norm_token(stem)
    norm_rel = _norm_token(rel)
    if not rel or Path(rel).suffix.lower() not in HARNESS_SOURCE_EXTS:
        return False
    if "fuzz" in rel or "fuzzer" in rel:
        return True
    if stem in {"target", "ossfuzz"}:
        return True
    if norm_stem in target_norms:
        return True
    return any(token and token in norm_rel for token in target_tokens)


def selected_build_hints(build_sh: Path, target: str, fuzz_target: str) -> tuple[set[str], set[str]]:
    if not build_sh.is_file():
        return set(), set()
    text = build_sh.read_text(encoding="utf-8", errors="replace")
    tokens = harness_hint_tokens(target, fuzz_target)
    target_norms = {_norm_token(value) for value in (target, fuzz_target, *tokens) if value}
    build_hint_norms = {_norm_token(value) for value in (target, fuzz_target) if value}
    refs: set[str] = set()
    stems: set[str] = set()

    source_ref_re = re.compile(r"(?:\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/|\.\.?/|[A-Za-z0-9_.-]+/)?[A-Za-z0-9_./{}$-]+\.(?:c|cc|cpp|cxx)\b")
    for match in source_ref_re.finditer(text):
        ref = _clean_build_source_ref(match.group(0))
        if "$" not in ref and _source_ref_matches_target(ref, tokens, target_norms):
            refs.add(ref.lower())
            stems.add(Path(ref).stem.lower())

    loop_values = _for_loop_values(text)
    for var, values in loop_values.items():
        var_pattern = re.compile(rf"[A-Za-z0-9_./{{}}$-]*\$(?:\{{{re.escape(var)}\}}|{re.escape(var)})[A-Za-z0-9_./{{}}$-]*\.(?:c|cc|cpp|cxx)\b")
        for match in var_pattern.finditer(text):
            template = _clean_build_source_ref(match.group(0))
            for value in values:
                value_norm = _norm_token(value)
                if value_norm not in target_norms and value not in {"fuzz", "fuzzer"}:
                    continue
                expanded = template.replace(f"${{{var}}}", value).replace(f"${var}", value)
                if _source_ref_matches_target(expanded, tokens, target_norms):
                    refs.add(expanded.lower())
                    stems.add(Path(expanded).stem.lower())

    for match in re.finditer(r"\b[A-Za-z0-9_./-]*(?:fuzz|fuzzer)[A-Za-z0-9_./-]*\b", text, re.I):
        hint = match.group(0).strip("./")
        if not hint or hint.lower() in {"fuzzers", "fuzzer", "fuzz"}:
            continue
        hint_name = Path(hint).name.lower()
        hint_norm = _norm_token(hint_name)
        if any(norm and (norm in hint_norm or hint_norm in norm) for norm in build_hint_norms):
            stems.add(hint_name)
    return refs, stems


def _candidate_score(
    path: Path,
    rel: Path,
    root: Path,
    target: str,
    fuzz_target: str,
    project: str,
    build_refs: set[str],
    build_stems: set[str],
    benchmark_local: bool,
) -> int:
    rel_s = rel.as_posix()
    rel_l = rel_s.lower()
    name_l = path.name.lower()
    stem_l = path.stem.lower()
    norm_stem = _norm_token(stem_l)
    norm_rel = _norm_token(rel_s)
    tokens = harness_hint_tokens(target, fuzz_target)
    target_norms = {_norm_token(value) for value in (target, fuzz_target, *tokens) if value}
    alias_norms = _selected_harness_alias_norms(target, fuzz_target, project, build_stems)
    score = 0
    if rel_l in build_refs or any(rel_l.endswith(ref) for ref in build_refs):
        score += 420
    if stem_l in build_stems or name_l in build_stems:
        score += 240
    if norm_stem in alias_norms:
        score += 300
    elif any(alias and alias in norm_stem for alias in alias_norms):
        score += 140
    if norm_stem in target_norms:
        score += 180
    for norm in target_norms:
        if norm and norm in norm_stem:
            score += 120
        elif norm and norm in norm_rel:
            score += 70
    for token in tokens:
        if token == stem_l:
            score += 140
        elif token in stem_l:
            score += 90
        elif token in rel_l:
            score += 35
    if stem_l in {"target", "ossfuzz"} and benchmark_local:
        score += 120
    if benchmark_local:
        score += 30
    else:
        score += _project_path_score(rel, project)
    try:
        if likely_reference_harness(path, root):
            score += 140
    except ValueError:
        pass
    if any(part.lower() in {"seed", "seeds", "testcases", "corpus"} for part in rel.parts):
        score -= 200
    if not benchmark_local and "fuzz" not in rel_l and "fuzzer" not in rel_l:
        score -= 80
    return score


def _copy_selected_reference_file(path: Path, root: Path, label: str, selected_dir: Path) -> str | None:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return None
    dst = selected_dir / label / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, dst)
    return f"{label}/{rel.as_posix()}"


def copy_selected_reference_harnesses(
    benchmark_dir: Path,
    source_root: Path,
    reference_dir: Path,
    target: str,
    fuzz_target: str,
    project: str,
    source_label: str,
) -> list[str]:
    selected_dir = reference_dir / SELECTED_REFERENCE_SUBDIR
    selected_dir.mkdir(parents=True, exist_ok=True)
    build_refs, build_stems = selected_build_hints(benchmark_dir / "build.sh", target, fuzz_target)
    candidates: list[tuple[int, Path, Path, str, bool]] = []

    roots: list[tuple[Path, str, bool]] = []
    if benchmark_dir.is_dir():
        roots.append((benchmark_dir, "fuzzbench_benchmark", True))
    if source_root.is_dir():
        roots.append((source_root, source_label, False))

    for root, label, benchmark_local in roots:
        for candidate in sorted(root.rglob("*")):
            if not candidate.is_file() or candidate.suffix.lower() not in HARNESS_SOURCE_EXTS:
                continue
            try:
                rel = candidate.relative_to(root)
            except ValueError:
                continue
            if benchmark_local and any(part in {"seeds", "testcases", "corpus"} for part in rel.parts):
                continue
            score = _candidate_score(candidate, rel, root, target, fuzz_target, project, build_refs, build_stems, benchmark_local)
            if benchmark_local:
                source_count = sum(1 for p in root.rglob("*") if p.is_file() and p.suffix.lower() in HARNESS_SOURCE_EXTS)
                if source_count == 1:
                    score += 120
            if score >= 80:
                candidates.append((score, candidate, root, label, benchmark_local))

    if not candidates:
        return []
    candidates.sort(key=lambda item: (-item[0], item[3], item[1].as_posix()))
    top_score = candidates[0][0]
    threshold = max(80, top_score - 40)
    copied: list[str] = []
    seen: set[str] = set()
    for score, candidate, root, label, _benchmark_local in candidates:
        if score < threshold or len(copied) >= 8:
            break
        rel_label = _copy_selected_reference_file(candidate, root, label, selected_dir)
        if rel_label and rel_label not in seen:
            seen.add(rel_label)
            copied.append(rel_label)
    return copied


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



def exclude_synthetic_build_script_from_docker_context(benchmark_copy: Path) -> None:
    """Keep a package-only build wrapper out of the native Docker context.

    Some FuzzBench Dockerfiles first copy a project's native build.sh into
    $SRC and later use ``COPY * $SRC``.  A package stub at the context root
    would overwrite that native script (libpng is one example).
    """
    dockerignore = benchmark_copy / ".dockerignore"
    rule = "/build.sh"
    existing = dockerignore.read_text(encoding="utf-8") if dockerignore.exists() else ""
    if rule in {line.strip() for line in existing.splitlines()}:
        return
    suffix = "" if not existing or existing.endswith("\n") else "\n"
    dockerignore.write_text(
        existing + suffix + "# HarnessGenBench: package-only build wrapper\n" + rule + "\n",
        encoding="utf-8",
    )


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
        exclude_synthetic_build_script_from_docker_context(benchmark_copy)
        return "wrapped_third_party_build_sh"
    build_sh.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "printf 'FuzzBench benchmark did not include a top-level build.sh; target build is unavailable for this package.\\n' >&2\n"
        "exit 127\n",
        encoding="utf-8",
    )
    build_sh.chmod(0o755)
    exclude_synthetic_build_script_from_docker_context(benchmark_copy)
    return "missing_stubbed_soft_skip"


def source_status_for_records(records: list[dict[str, Any]]) -> str:
    """Return materialized only when every copied source has a resolved ref."""
    if not records:
        return "benchmark_only"
    copied_statuses = {"copied_to_package", "copied_to_source_input"}
    if all(
        record.get("copy_status") in copied_statuses
        and record.get("revision_status") in REPRODUCIBLE_REVISION_STATUSES
        for record in records
    ):
        return "materialized"
    return "partial"


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
        f"- Selected reference harness files: `{manifest.get('selected_reference_harness_count', 0)}`",
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


def package_target(root: Path, target: str, output: Path, layout: str = "compact", require_split: bool = False) -> Path:
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
    attribute_source_revisions(repos, resolved.get("project", ""), resolved.get("commit", ""))
    materialized: list[dict[str, Any]] = []
    source_root = output / ("source_full" if layout == "full" else "source_input")

    def materialize_and_copy(repo: dict[str, str]) -> None:
        record = materialize_source(repo, target, "", root)
        materialized.append(record)
        local = Path(record.get("artifact_path", ""))
        if (
            record.get("materialize_status") in {"cloned", "fetched", "cached", "extracted", "fetch_failed_using_cached_checkout"}
            and record.get("revision_status") in REPRODUCIBLE_REVISION_STATUSES
            and local.is_dir()
        ):
            package_dst = source_root / repo["dest"]
            try:
                copy_tree(local, package_dst)
                record["copy_status"] = "copied_to_package" if layout == "full" else "copied_to_source_input"
                record["package_path"] = package_dst.relative_to(output).as_posix()
            except OSError as exc:
                record["copy_status"] = "copy_failed"
                record["copy_error"] = str(exc)

    static_repos = [repo for repo in repos if not _dynamic_branch_variable(repo)]
    dynamic_repos = [repo for repo in repos if _dynamic_branch_variable(repo)]
    for repo in static_repos:
        materialize_and_copy(repo)
    expanded_dynamic_repos = expand_dynamic_branch_sources(dynamic_repos, materialized)
    if dynamic_repos and not expanded_dynamic_repos:
        # Keep a provenance record rather than silently dropping a source when
        # the branch-list repository could not be materialized.
        for repo in dynamic_repos:
            materialize_and_copy(repo)
    else:
        for repo in expanded_dynamic_repos:
            materialize_and_copy(repo)
    (output / "source_repos.json").write_text(json.dumps(materialized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if layout == "full" and any((output / "source_full").rglob("*")):
        copy_tree(output / "source_full", output / "source_input")
    strip = os.environ.get("HGB_TARGET_STRIP_REFERENCE_HARNESS", "1") != "0"
    source_label = "source_full" if layout == "full" else "source_input"
    selected_reference_files = copy_selected_reference_harnesses(
        benchmark_copy,
        source_root,
        output / "reference_harnesses",
        target,
        resolved.get("fuzz_target", ""),
        resolved.get("project", ""),
        source_label,
    )
    reference_files = strip_reference_harnesses(source_root, output / "source_input", output / "reference_harnesses", strip, source_label=source_label)
    copy_selected_docs(source_root, output / "docs")
    seed_count, dictionary_count = copy_seeds_and_dicts(benchmark_copy, output / "seeds", output / "dictionary")
    source_file_count = count_source_files(output / "source_input")
    cmake_file_count = count_named_files(output / "source_input", "CMakeLists.txt")
    compile_commands_count = count_named_files(output / "source_input", "compile_commands.json")
    source_fallback_statuses = sorted({str(r.get("materialize_status", "")) for r in materialized if r.get("cache_fallback")})
    source_revision_statuses = sorted({str(r.get("revision_status", "")) for r in materialized})
    captured_unpinned_sources = [
        {
            "dest": str(record.get("dest", "")),
            "url": str(record.get("url", "")),
            "commit": str(record.get("captured_revision") or record.get("revision") or ""),
        }
        for record in materialized
        if record.get("revision_status") == "captured_unpinned"
    ]
    source_status = source_status_for_records(materialized)
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
        "source_fallback_statuses": source_fallback_statuses,
        "source_revision_statuses": source_revision_statuses,
        "captured_unpinned_sources": captured_unpinned_sources,
        "source_repos": materialized,
        "source_artifact_paths": sorted({str(r.get("artifact_path", "")) for r in materialized if r.get("artifact_path")}),
        "source_file_count": source_file_count,
        "cmake_file_count": cmake_file_count,
        "compile_commands_count": compile_commands_count,
        "source_input_dir": "source_input",
        "source_full_dir": "source_full" if layout == "full" else "",
        "reference_harness_dir": "reference_harnesses",
        "reference_harness_files": reference_files,
        "selected_reference_harness_dir": f"reference_harnesses/{SELECTED_REFERENCE_SUBDIR}",
        "selected_reference_harness_files": selected_reference_files,
        "selected_reference_harness_count": len(selected_reference_files),
        "seed_count": seed_count,
        "dictionary_count": dictionary_count,
        "build_script_status": build_script_status,
        "synthetic_build_script_excluded_from_docker_context": build_script_status != "present",
        "created_at": now_iso(),
    }
    (output / "target_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_summary(output, manifest)
    _apply_package_split(output, manifest, target, resolved.get("fuzz_target", ""), require_split=require_split)
    return output


def _apply_package_split(
    output: Path,
    manifest: dict[str, Any],
    target: str,
    fuzz_target: str,
    *,
    require_split: bool = False,
) -> None:
    """Create the generator_input/evaluator_only physical split (beta plan §3).

    The monolithic layout is preserved for backwards compatibility; the split
    is what blind-project generators mount.  ``target_manifest.generator.json``
    omits every reference-harness field so a blind generator cannot read the
    exact target harness answer.

    When ``require_split`` is true (reproduction-delta / blind harness
    generators), a split failure is fail-closed: the exception is re-raised so
    the caller writes an ``infra_failure`` result instead of leaving a
    monolithic package that would leak reference harnesses to the generator.
    A reference canary is embedded in the evaluator-only half and asserted to
    be absent from ``generator_input/``.
    """
    if os.environ.get("HGB_TARGET_DISABLE_SPLIT", "0") == "1":
        if require_split:
            raise PackageSplitError(
                "target package split is required (reproduction-delta/blind) but HGB_TARGET_DISABLE_SPLIT=1 is set"
            )
        return
    hgb_target_package = _load_docker_common_module("hgb_target_package")
    if hgb_target_package is None:
        if require_split:
            raise PackageSplitError("hgb_target_package module unavailable; cannot create required split")
        return
    native_harness: dict[str, Any] | None = None
    target_harness_mod = _load_docker_common_module("ckgfuzzer_target_harness")
    if target_harness_mod is not None:
        try:
            harness = target_harness_mod.select_native_harness(output, fuzz_target)
            native_harness = {
                "selected_reference": harness.selected_reference,
                "container_destination": harness.container_destination,
                "language": harness.language,
                "source_suffix": harness.source_suffix,
                "selection_reason": harness.selection_reason,
            }
        except Exception:
            native_harness = None
    try:
        hgb_target_package.split_package(
            output,
            native_harness=native_harness,
            require_split=require_split,
        )
    except Exception as exc:
        if require_split:
            raise
        (output / "logs" / "split_error.log").write_text(
            f"target package split failed: {exc}\n", encoding="utf-8"
        )
        return
    # Fail-closed canary audit: the evaluator-only reference harnesses carry a
    # canary token that must never appear under generator_input/.
    generator_input = output / "generator_input"
    canary = os.environ.get("HGB_REF_CANARY", "")
    if canary and generator_input.is_dir():
        audit = hgb_target_package.audit_generator_input(generator_input)
        if not audit["clean"]:
            raise PackageSplitError(
                f"generator_input leaked reference-harness tokens after split: {audit['hits']}"
            )


def main(argv: list[str] | None = None) -> int:
    root = find_repo_root()
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    list_parser = sub.add_parser("list")
    list_parser.add_argument("target_set", nargs="?", default="all")
    list_parser.add_argument("--sets", action="store_true", help="list available named target sets")
    validate_parser = sub.add_parser("validate")
    validate_parser.add_argument("--soft", action="store_true")
    resolve_parser = sub.add_parser("resolve")
    resolve_parser.add_argument("target")
    resolve_parser.add_argument("--json", action="store_true", dest="as_json")
    package_parser = sub.add_parser("package")
    package_parser.add_argument("target")
    package_parser.add_argument("--output", required=True)
    package_parser.add_argument("--layout", choices=("compact", "full"), default=os.environ.get("HGB_TARGET_PACKAGE_LAYOUT", "compact"))
    package_parser.add_argument("--require-split", action="store_true",
                                help="fail closed if the generator_input/evaluator_only split cannot be created")
    args = parser.parse_args(argv)

    if args.command == "list":
        registry = load_registry(root)
        if args.sets:
            for name in target_set_names(registry):
                print(name)
            return 0
        for target in targets_for_set(registry, args.target_set):
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
        require_split = args.require_split
        # Infer require_split for blind-project harness generators when not
        # explicitly set (reproduction-zeta / reproduction-epsilon /
        # reproduction-delta fail-closed contract).
        if not require_split:
            baseline_profile = os.environ.get("HGB_BASELINE_PROFILE", "")
            baseline_protocol = os.environ.get("HGB_BASELINE_PROTOCOL", "")
            if baseline_protocol == "blind-project" and (
                os.environ.get("HGB_TARGET_REQUIRE_SPLIT", "0") == "1"
                or baseline_profile in ("reproduction-delta", "reproduction-epsilon", "reproduction-zeta")
            ):
                require_split = True
        try:
            output = package_target(root, args.target, Path(args.output), layout=args.layout, require_split=require_split)
        except PackageSplitError as exc:
            # Write an infra_failure result.json so the host runner can surface
            # the fail-closed split failure instead of mounting a monolithic
            # package that would leak reference harnesses to the generator.
            out_dir = Path(args.output).resolve()
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "logs").mkdir(parents=True, exist_ok=True)
            result = {
                "schema_version": 2,
                "generator": os.environ.get("HGB_GENERATOR", ""),
                "task_family": "harness_generator",
                "profile": os.environ.get("HGB_BASELINE_PROFILE", ""),
                "protocol": os.environ.get("HGB_BASELINE_PROTOCOL", ""),
                "target": args.target,
                "applicability": "applicable",
                "status": "infra_failure",
                "reason": f"target_split_failed: {exc}",
                "error": {"reason_code": "target_split_failed", "detail": str(exc)},
                "stages": {},
                "method_variant": os.environ.get("HGB_BASELINE_PROFILE", ""),
                "excluded_from_aggregate": True,
            }
            (out_dir / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"infra_failure: target_split_failed: {exc}", file=sys.stderr)
            return 3
        print(output)
        return 0
    raise SystemExit(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
