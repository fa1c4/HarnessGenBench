#!/usr/bin/env python3
"""Build, fuzz, and measure MAGMA targets with the MAGMA-native toolchain.

The MAGMA checkout provides two fuzzer integrations used here:

* ``libfuzzer_asan`` -- clang-15 + ASan + libFuzzer campaign binary.
* ``llvm_cov``      -- clang + profile instrumentation + standalone replay
                       driver that writes LCOV coverage for a saved corpus.

Each subcommand runs inside the target image built from
``$HGB_MAGMA_ROOT/docker/Dockerfile``; the image already contains the fetched,
patched target repository, so a rebuild only re-runs the fuzzer's
``instrument.sh`` after an optional harness overlay.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MAGMA_ROOT = Path(os.environ.get("HGB_MAGMA_ROOT", "/data/zym/magma-directed"))
METADATA = ROOT / "metadata/magma_targets.yaml"


def load_targets() -> dict[str, dict]:
    data = yaml.safe_load(METADATA.read_text(encoding="utf-8"))
    return data["targets"]


def image_tag(target: str, fuzzer: str) -> str:
    return f"hgb-magma-{target}-{fuzzer}:latest"


def harness_path(target: str, spec: dict) -> str:
    base = "/magma/targets" if spec["harness_base"] == "target_src" else f"/magma/targets/{target}/repo"
    return f"{base}/{target}/src/{spec['harness']}" if spec["harness_base"] == "target_src" \
        else f"{base}/{spec['harness']}"


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    print("+", " ".join(command), flush=True)
    return subprocess.run(command, check=False, **kwargs)


def build_image(args: argparse.Namespace, spec: dict) -> int:
    tag = image_tag(args.target, args.fuzzer)
    if not args.force and run(["docker", "image", "inspect", tag],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0:
        print(f"image already present: {tag}")
        return 0
    log = Path(args.log) if args.log else ROOT / f"workspace/magma/builds/{args.target}.{args.fuzzer}.build.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8") as handle:
        code = subprocess.run(
            ["docker", "build", "-f", "docker/Dockerfile",
             "--build-arg", f"target_name={args.target}",
             "--build-arg", f"fuzzer_name={args.fuzzer}",
             "-t", tag, "."],
            cwd=MAGMA_ROOT, stdout=handle, stderr=subprocess.STDOUT, check=False).returncode
    print(f"build exit={code} log={log}")
    return code


def container(args: argparse.Namespace, spec: dict, script: str,
              mounts: list[Path]) -> int:
    command = ["docker", "run", "--rm", "--init", "--user", "root",
               "-e", f"HOST_UID={os.getuid()}", "-e", f"HOST_GID={os.getgid()}",
               "--entrypoint", "/bin/bash"]
    for path in mounts:
        command += ["-v", f"{path}:{path}"]
    command += [image_tag(args.target, args.fuzzer), "-lc", script]
    return run(command).returncode


def rebuild(args: argparse.Namespace, spec: dict) -> int:
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    harness = Path(args.harness).resolve() if args.harness else None
    mounts = [work] + ([harness.parent] if harness else [])
    target_path = harness_path(args.target, spec)
    lines = ["set -e"]
    if harness:
        lines.append(f"cp {harness} {target_path}")
    lines += [
        "cd /magma",
        f"/magma/fuzzers/{args.fuzzer}/instrument.sh > {work}/build.log 2>&1 || "
        f"{{ echo instrument failed; tail -40 {work}/build.log; exit 1; }}",
        f"cp /magma_out/{spec['program']} {work}/",
        f"chown -R $HOST_UID:$HOST_GID {work}",
        f"printf '%s\\n' {work}",
    ]
    script = "\n".join(lines)
    code = container(args, spec, script, mounts)
    print(f"rebuild exit={code}")
    return code


def campaign(args: argparse.Namespace, spec: dict) -> int:
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    seeds = Path(args.seeds).resolve() if args.seeds else None
    binary_path = Path(args.binary).resolve() if args.binary else out / spec["program"]
    mounts = [out] + ([seeds] if seeds else []) + ([binary_path.parent] if binary_path.is_file() else [])
    binary = f"/magma_out/{spec['program']}"
    binary_copy = (f"cp {binary_path} {binary}" if binary_path.is_file()
                   else f"cp {out}/{spec['program']} {binary} 2>/dev/null || true")
    source = f"{seeds}/." if seeds else f"{spec['corpus']}/."
    script = f"""set -e
mkdir -p /tmp/corpus {out}/crashes
cp -a {source} /tmp/corpus/ 2>/dev/null || true
{binary_copy}
cd /tmp
ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:abort_on_error=0 \\
set +e
timeout {args.seconds}s {binary} -rss_limit_mb=100 -fork=1 -ignore_timeouts=1 \\
  -ignore_crashes=1 -ignore_ooms=1 -artifact_prefix={out}/crashes/ /tmp/corpus \\
  > {out}/campaign.log 2>&1
code=$?
set -e
echo "campaign exit=$code"
cp -a /tmp/corpus {out}/final_corpus
echo "corpus_files=$(find {out}/final_corpus -type f | wc -l) crashes=$(find {out}/crashes -type f | wc -l)"
chown -R $HOST_UID:$HOST_GID {out}
"""
    return container(args, spec, script, mounts)


def coverage(args: argparse.Namespace, spec: dict) -> int:
    corpus = Path(args.corpus).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    harness = Path(args.harness).resolve() if args.harness else None
    mounts = [corpus, out] + ([harness.parent] if harness else [])
    target_path = harness_path(args.target, spec)
    lines = ["set -e"]
    if harness:
        lines.append(f"cp {harness} {target_path}")
    lines += [
        "cd /magma",
        f"/magma/fuzzers/llvm_cov/instrument.sh > {out}/coverage_build.log 2>&1 || "
        f"{{ tail -40 {out}/coverage_build.log; exit 1; }}",
        f"binary=/magma_out/{spec['program']}",
        "mkdir -p /tmp/prof",
        f"find {corpus} -maxdepth 1 -type f -print0 | xargs -0 -r -n 400 sh -c "
        f"'LLVM_PROFILE_FILE=/tmp/prof/%p.profraw $0 \"$@\"' $binary "
        f"> {out}/replay.log 2>&1 || true",
        "/usr/bin/llvm-profdata-9 merge -sparse /tmp/prof/*.profraw -o /tmp/merged.profdata",
        f"/usr/bin/llvm-cov-9 export -format=lcov $binary -instr-profile=/tmp/merged.profdata "
        f"> {out}/coverage.lcov",
        f"echo lcov_lines=$(wc -l < {out}/coverage.lcov)",
        f"chown -R $HOST_UID:$HOST_GID {out}",
    ]
    code = container(args, spec, "\n".join(lines), mounts)
    if code == 0 and (out / "coverage.lcov").is_file():
        summary = summarize(out / "coverage.lcov", spec["project_root"],
                            target_path, args.target)
        (out / "coverage.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n",
                                           encoding="utf-8")
        print(json.dumps(summary, indent=2))
    return code


def summarize(lcov: Path, project_root: str, harness: str, target: str) -> dict:
    """Count executed project lines, excluding the harness and MAGMA support."""
    current = ""
    files: dict[str, dict[str, int]] = {}
    for raw in lcov.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw.startswith("SF:"):
            current = raw[3:].strip()
            continue
        if not current or not raw.startswith("DA:"):
            continue
        if not current.startswith(project_root) or current == harness:
            continue
        fields = raw[3:].split(",")
        if len(fields) < 2 or not fields[0].isdigit() or not fields[1].isdigit():
            continue
        entry = files.setdefault(current, {"total": 0, "covered": 0})
        entry["total"] += 1
        if int(fields[1]) > 0:
            entry["covered"] += 1
    total = sum(entry["total"] for entry in files.values())
    covered = sum(entry["covered"] for entry in files.values())
    return {
        "target": target,
        "covered_lines": covered,
        "total_lines": total,
        "percent": round(100.0 * covered / total, 4) if total else 0.0,
        "source_files": len(files),
        "project_root": project_root,
        "harness_excluded": harness,
        "files": {name: entry for name, entry in sorted(files.items())},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--fuzzer", default="libfuzzer_asan",
                        choices=("libfuzzer", "libfuzzer_asan", "llvm_cov"))
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build-image")
    build.add_argument("--force", action="store_true")
    build.add_argument("--log", default="")

    rebuild_parser = sub.add_parser("rebuild")
    rebuild_parser.add_argument("--work", required=True)
    rebuild_parser.add_argument("--harness", default="")

    camp = sub.add_parser("campaign")
    camp.add_argument("--out", required=True)
    camp.add_argument("--seconds", type=int, default=86400)
    camp.add_argument("--seeds", default="")
    camp.add_argument("--binary", default="")

    cov = sub.add_parser("coverage")
    cov.add_argument("--corpus", required=True)
    cov.add_argument("--out", required=True)
    cov.add_argument("--harness", default="")

    args = parser.parse_args()
    spec = load_targets()[args.target]
    if args.command == "build-image":
        return build_image(args, spec)
    if args.command == "rebuild":
        return rebuild(args, spec)
    if args.command == "campaign":
        return campaign(args, spec)
    if args.command == "coverage":
        return coverage(args, spec)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
