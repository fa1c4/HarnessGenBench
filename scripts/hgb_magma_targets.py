#!/usr/bin/env python3
"""Build MAGMA benchmark dirs and split target packages for HarnessGenBench.

For every MAGMA target the script materializes a self-contained Docker build
context (``workspace/magma/benchmarks/<target>``) from the already-built native
image, then derives the HGB split package
(``workspace/magma/targets/magma_<target>/pkg``):

* ``generator_input`` -- project source tree (MAGMA-patched, harness included),
  seeds, and generator-visible manifests.
* ``evaluator_only``  -- FuzzBench-style benchmark copy (Dockerfile/build.sh),
  the exact native harness path, and the reference harness for audit/control.

The benchmark's ``build.sh`` reuses the target's MAGMA build recipe with only
path replacements, so candidate builds link against exactly the source and
library layout the native evaluator uses.  A small sed normalizes the
OSS-Fuzz-Gen symbol namespace (``OSS_FUZZ_<project>_*`` -> ``<project>_*``)
before compiling generated harnesses.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAGMA = ROOT / "workspace/magma"
BENCH_ROOT = MAGMA / "benchmarks"
PKG_ROOT = MAGMA / "targets"

IMAGE = "hgb-magma-{target}-libfuzzer_asan:latest"

# dest: directory name used both inside /src and by the official OSS-Fuzz
# project WORKDIR (so the Introspector overlay lands in the right place).
# extras: paths copied from /magma/targets/<target> besides repo contents.
TARGETS: dict[str, dict] = {
    "libpng": {
        "dest": "libpng",
        "program": "libpng_read_fuzzer",
        "harness": "contrib/oss-fuzz/libpng_read_fuzzer.cc",
        "entry_api": 'png_create_read_struct',
        "entry_signature": 'png_structp png_create_read_struct(png_const_charp, png_voidp, png_error_ptr, png_error_ptr)',
        "language": "c",
        "deps": ["make", "autoconf", "automake", "libtool", "zlib1g-dev"],
        "source_url": "https://github.com/pnggroup/libpng.git",
        "build_timeout": 1800,
    },
    "libsndfile": {
        "dest": "libsndfile",
        "program": "sndfile_fuzzer",
        "harness": "ossfuzz/sndfile_fuzzer.cc",
        "entry_api": 'sf_open_virtual',
        "entry_signature": 'SNDFILE *sf_open_virtual(SF_VIRTUAL_IO *sfvirtual, int mode, SF_INFO *sfinfo, void *user_data)',
        "language": "c",
        "deps": [
            "make", "autoconf", "autogen", "automake", "libtool", "pkg-config",
            "libasound2-dev", "libflac-dev", "libogg-dev", "libvorbis-dev",
            "libopus-dev", "libmp3lame-dev", "libmpg123-dev",
        ],
        "source_url": "https://github.com/libsndfile/libsndfile.git",
        "build_timeout": 1800,
    },
    "libtiff": {
        "dest": "libtiff",
        "program": "tiff_read_rgba_fuzzer",
        "harness": "contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc",
        "entry_api": 'TIFFStreamOpen',
        "entry_signature": 'TIFF *TIFFStreamOpen(const char *filename, std::ostream *os)',
        "language": "c++",
        "deps": [
            "make", "autoconf", "automake", "libtool", "cmake", "nasm",
            "zlib1g-dev", "liblzma-dev", "libjpeg-turbo8-dev",
        ],
        "extras": ["src"],
        "source_url": "https://gitlab.com/libtiff/libtiff.git",
        "build_timeout": 2400,
    },
    "libxml2": {
        "dest": "libxml2",
        "program": "libxml2_xml_read_memory_fuzzer",
        "harness": "src/libxml2_xml_read_memory_fuzzer.cc",
        "entry_api": 'xmlReadMemory',
        "entry_signature": 'xmlDocPtr xmlReadMemory(const char *buffer, int size, const char *URL, const char *encoding, int options)',
        "language": "c",
        "deps": [
            "make", "autoconf", "automake", "libtool", "pkg-config",
            "zlib1g-dev", "liblzma-dev",
        ],
        "extras": ["src"],
        "source_url": "https://github.com/GNOME/libxml2.git",
        "build_timeout": 1800,
    },
    "lua": {
        "dest": "lua",
        "program": "fuzz_lua",
        "harness": "src/fuzz_lua.c",
        "entry_api": 'luaL_loadbufferx',
        "entry_signature": 'int luaL_loadbufferx(lua_State *L, const char *buff, size_t sz, const char *name, const char *mode)',
        "language": "c",
        "deps": ["make", "libreadline-dev"],
        "extras": ["src"],
        "source_url": "https://github.com/lua/lua.git",
        "build_timeout": 1800,
    },
    "openssl": {
        "dest": "openssl",
        "program": "x509",
        "harness": "fuzz/x509.c",
        "entry_api": 'd2i_X509',
        "entry_signature": 'X509 *d2i_X509(X509 **a, const unsigned char **in, long len)',
        "language": "c",
        "deps": ["make", "autoconf", "automake", "libtool"],
        "extras": ["configrc"],
        "source_url": "https://github.com/openssl/openssl.git",
        "build_timeout": 3600,
    },
    "php": {
        "dest": "php-src",
        "program": "parser",
        "harness": "sapi/fuzzer/fuzzer-parser.c",
        "entry_api": 'zend_compile_file',
        "entry_signature": 'zend_op_array *zend_compile_file(zend_file_handle *file_handle, int type)',
        "language": "c",
        "deps": [
            "make", "autoconf", "automake", "libtool", "bison", "re2c",
            "pkg-config", "libicu-dev",
        ],
        "extras": ["configrc"],
        "source_url": "https://github.com/php/php-src.git",
        "build_timeout": 3600,
    },
    "poppler": {
        "dest": "poppler",
        "program": "pdf_fuzzer",
        "harness": "src/pdf_fuzzer.cc",
        "entry_api": 'load_from_raw_data',
        "entry_signature": 'poppler::document *load_from_raw_data(const char *data, int size)',
        "language": "c++",
        "deps": [
            "make", "autoconf", "automake", "libtool", "pkg-config", "cmake",
            "zlib1g-dev", "libjpeg-dev", "libopenjp2-7-dev", "libpng-dev",
            "libcairo2-dev", "libtiff-dev", "liblcms2-dev", "libboost-dev",
        ],
        "extras": ["src", "configrc", "freetype2"],
        "source_url": "https://gitlab.freedesktop.org/poppler/poppler.git",
        "build_timeout": 3600,
    },
    "sqlite3": {
        "dest": "sqlite3",
        "program": "sqlite3_fuzz",
        "harness": "test/ossfuzz.c",
        "entry_api": 'sqlite3_exec',
        "entry_signature": 'int sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void*,int,char**,char**), void *arg, char **errmsg)',
        "language": "c",
        "deps": ["make", "autoconf", "automake", "libtool", "tcl", "zlib1g-dev"],
        "source_url": "https://github.com/sqlite/sqlite.git",
        "build_timeout": 1800,
    },
}

NORMALIZE = """# Normalize the OSS-Fuzz-Gen symbol namespace (OSS_FUZZ_<project>_*) to the
# plain project API before compiling. Harnesses from the other generators are
# already unprefixed and are left untouched.
harness={harness!r}
sed -i -E -e 's/\\bOSS_FUZZ_([A-Za-z_])/\\1/g' \\
          -e '/^[[:space:]]*#define[[:space:]]+[A-Za-z0-9_]*PREFIX[[:space:]]*$/d' "$harness"
"""

DOCKERFILE = """FROM gcr.io/oss-fuzz-base/base-builder@sha256:87ca1e9e19235e731fac8de8d1892ebe8d55caf18e7aa131346fc582a2034fdd

RUN apt-get update && apt-get install -y \\
    {deps}

COPY source_input/ /src/
COPY build.sh /src/build.sh
ADD seeds /opt/seeds

WORKDIR /src/{dest}
"""


def log(message: str) -> None:
    print(f"[hgb-magma] {message}", flush=True)


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, **kwargs)


def image_target_dir(target: str, path: str) -> bool:
    probe = run(
        ["docker", "run", "--rm", "--entrypoint", "/bin/bash", IMAGE.format(target=target),
         "-lc", f"test -e /magma/targets/{target}/{path}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return probe.returncode == 0


def extract_sources(target: str, spec: dict) -> Path:
    """Materialize source_input/<dest> from the native image."""
    benchmark = BENCH_ROOT / target
    dest_dir = benchmark / "source_input" / spec["dest"]
    marker = benchmark / ".source_extracted"
    if marker.is_file() and dest_dir.is_dir():
        log(f"{target}: source already extracted")
        return dest_dir

    benchmark.mkdir(parents=True, exist_ok=True)
    create = run(
        ["docker", "create", "--entrypoint", "/bin/true", IMAGE.format(target=target)],
        stdout=subprocess.PIPE, text=True,
    )
    container = create.stdout.strip()
    tmp = Path(tempfile.mkdtemp(prefix=f"hgb-magma-{target}-"))
    try:
        # Repo working tree -> source_input/<dest>.
        run(["docker", "cp", f"{container}:/magma/targets/{target}/repo/.", str(tmp / "repo")])
        if dest_dir.exists():
            shutil.rmtree(dest_dir)
        dest_dir.mkdir(parents=True)
        _merge_tree(tmp / "repo", dest_dir)
        for extra in spec.get("extras", []):
            source = tmp / "extra" / extra
            source.parent.mkdir(parents=True, exist_ok=True)
            if extra == "freetype2":
                run(["docker", "cp", f"{container}:/magma/targets/{target}/{extra}", str(source)])
            else:
                run(["docker", "cp", f"{container}:/magma/targets/{target}/{extra}", str(source)])
            destination = dest_dir / extra
            if destination.exists():
                shutil.rmtree(destination) if destination.is_dir() else destination.unlink()
            if source.is_dir():
                shutil.copytree(source, destination, symlinks=True)
            else:
                shutil.copy2(source, destination)
        _strip_git(dest_dir)
        (benchmark / "build.sh").write_text(adapt_build_script(target, spec), encoding="utf-8")
        (benchmark / "Dockerfile").write_text(
            DOCKERFILE.format(deps=" ".join(spec["deps"]), dest=spec["dest"]), encoding="utf-8"
        )
        marker.write_text("ok\n", encoding="utf-8")
    finally:
        run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL)
        shutil.rmtree(tmp, ignore_errors=True)
    log(f"{target}: source extracted ({dest_dir})")
    return dest_dir


def _merge_tree(source: Path, destination: Path) -> None:
    for child in source.iterdir():
        target = destination / child.name
        if child.is_dir() and not child.is_symlink():
            shutil.copytree(child, target, symlinks=True)
        else:
            shutil.copy2(child, target, follow_symlinks=False)


def _strip_git(root: Path) -> None:
    for path in root.rglob(".git"):
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)


def adapt_build_script(target: str, spec: dict) -> str:
    """Reuse the MAGMA target build recipe with source snapshot paths."""
    original = (Path("/data/zym/magma-directed") / "targets" / target / "build.sh").read_text()
    if "# HGB MAGMA benchmark build script" not in original:
        lines = original.splitlines()
        while lines and lines[0].startswith("#!"):
            lines.pop(0)
        body = "\n".join(lines)
        body = body.replace('"$TARGET/repo"', '"$TARGET"')
        body = body.replace("$TARGET/repo", "$TARGET")
        body = body.replace('"${TARGET}/repo"', '"${TARGET}"')
        body = body.replace("${TARGET}/repo", "${TARGET}")
        body = "\n".join(lines)
        header = (
            "#!/bin/bash\n"
            "# HGB MAGMA benchmark build script (generated by hgb_magma_targets.py).\n"
            "set -ex\n"
            f'export TARGET="${{SRC}}/{spec["dest"]}"\n'
            'export FUZZER="${TARGET}"\n'
            'export OUT="${OUT:-/out}"\n'
            # MAGMA recipes are written for `set -e` (not `set -u`); provide
            # empty defaults so the sealed compile environment never trips an
            # unbound-variable abort. The fuzzer engine is linked explicitly at
            # the target link line ($LIB_FUZZING_ENGINE), never through LIBS.
            'export LDFLAGS="${LDFLAGS:-}"\n'
            'export LIBS="${LIBS:-}"\n'
            'export REQUIRE_GET_BITCODE="${REQUIRE_GET_BITCODE:-}"\n'
            'export REQUIRE_COPY_BITCODE="${REQUIRE_COPY_BITCODE:-}"\n'
        )
        # Drop the original set -ex / shebang lines but keep comments and body.
        keep = original.splitlines()
        while keep and (keep[0].startswith("#!") or keep[0].strip() in {"set -ex", "set -e"}):
            keep.pop(0)
        body = "\n".join(keep)
        body = body.replace('"$TARGET/repo"', '"$TARGET"')
        body = body.replace("$TARGET/repo", "$TARGET")
        body = body.replace('"${TARGET}/repo"', '"${TARGET}"')
        body = body.replace("${TARGET}/repo", "${TARGET}")
        harness = spec["harness"]
        normalize = NORMALIZE.format(harness=harness)
        # Insert normalization after the export block, before any build step.
        adapted = header + normalize + body + "\n"
        return adapted
    return original


def seed_corpus(target: str, spec: dict) -> None:
    """Copy the MAGMA seed corpus into the benchmark context."""
    benchmark = BENCH_ROOT / target
    seeds = benchmark / "seeds"
    if seeds.is_dir() and any(seeds.iterdir()):
        return
    container = run(
        ["docker", "create", "--entrypoint", "/bin/true", IMAGE.format(target=target)],
        stdout=subprocess.PIPE, text=True,
    ).stdout.strip()
    try:
        seeds.mkdir(parents=True, exist_ok=True)
        run(["docker", "cp",
             f"{container}:/magma/targets/{target}/corpus/{spec['program']}/.",
             str(seeds)])
    finally:
        run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL)


def write_benchmark_metadata(target: str, spec: dict, head_commit: str) -> None:
    benchmark = BENCH_ROOT / target
    (benchmark / "benchmark.yaml").write_text(
        f"project: {target if target != 'lua' else 'lua'}\n"
        f"fuzz_target: {spec['program']}\n"
        f"commit: {head_commit}\n"
        "source: magma\n",
        encoding="utf-8",
    )


def make_package(target: str, spec: dict, head_commit: str) -> Path:
    """Derive the HGB split package from the benchmark dir."""
    benchmark = BENCH_ROOT / target
    pkg = PKG_ROOT / f"magma_{target}" / "pkg"
    if pkg.exists():
        shutil.rmtree(pkg)
    gen = pkg / "generator_input"
    evl = pkg / "evaluator_only"
    gen.mkdir(parents=True)
    evl.mkdir(parents=True)
    dest = spec["dest"]
    harness_rel = spec["harness"]
    source_root = benchmark / "source_input"
    # Generator-visible source tree (hard links keep the package compact).
    run(["cp", "-al", str(source_root), str(gen / "source_input")])
    for name in ("seeds", "docs"):
        src = benchmark / name
        if src.is_dir():
            run(["cp", "-al", str(src), str(gen / name)])
        else:
            (gen / name).mkdir()
    (gen / "build_metadata").mkdir()
    (pkg / "seeds").mkdir()
    run(["cp", "-al", str(benchmark / "seeds") + "/.", str(pkg / "seeds")])
    # benchmark copy used by the sealed evaluator context.
    comp = evl / "benchmark_copy"
    comp.mkdir()
    for name in ("Dockerfile", "build.sh", "benchmark.yaml"):
        shutil.copy2(benchmark / name, comp / name)
    run(["cp", "-al", str(benchmark / "seeds"), str(comp / "seeds")])
    # Reference harness (evaluator-only) and selected copy.
    rel_parent = Path(harness_rel).parent
    ref = evl / "reference_harnesses" / dest / rel_parent
    ref.mkdir(parents=True, exist_ok=True)
    sel = evl / "selected_reference_harnesses" / "source_input" / dest / rel_parent
    sel.mkdir(parents=True, exist_ok=True)
    harness_src = benchmark / "source_input" / dest / harness_rel
    shutil.copy2(harness_src, ref / Path(harness_rel).name)
    shutil.copy2(harness_src, sel / Path(harness_rel).name)
    (pkg / "reference_harnesses" / dest / rel_parent).mkdir(parents=True, exist_ok=True)
    shutil.copy2(harness_src, pkg / "reference_harnesses" / dest / rel_parent / Path(harness_rel).name)

    native_dest = f"/src/{dest}/{harness_rel}"
    native = {
        "container_destination": native_dest,
        "native_harness_destination": native_dest,
        "native_harness_path": f"source_input/{dest}/{harness_rel}",
        "selected_reference": f"source_input/{dest}/{harness_rel}",
        "selection_reason": "magma source snapshot path",
        "language": spec["language"],
        "source_suffix": Path(harness_rel).suffix,
    }
    (evl / "native_harness_path.json").write_text(json.dumps(native, indent=2) + "\n")
    (evl / "evaluator_manifest.json").write_text(json.dumps({
        "benchmark_copy_dir": "benchmark_copy",
        "native_harness_path_file": "native_harness_path.json",
        "protocol_visibility": "evaluator_only",
        "reference_harnesses_dir": "reference_harnesses",
        "selected_reference_harnesses_dir": "selected_reference_harnesses",
        "target_manifest_file": "target_manifest.evaluator.json",
    }, indent=2) + "\n")
    (evl / "reference_canary.txt").write_text("HGB_REF_CANARY_none\n")

    seed_count = sum(1 for p in (benchmark / "seeds").iterdir() if p.is_file())
    base_manifest = {
        "benchmark_dir": str(comp),
        "build_script_status": "magma_native",
        "captured_unpinned_sources": [],
        "commit": head_commit,
        "commit_date": "",
        "compile_commands_count": 0,
        "created_at": "",
        "dictionary_count": 0,
        "fuzz_target": spec["program"],
        "fuzzbench_commit": "",
        "native_harness_destination": native_dest,
        "native_harness_path": f"source_input/{dest}/{harness_rel}",
        "project": target,
        "protocol_visibility": "generator_input_only",
        "reference_harness_dir": "reference_harnesses",
        "reference_harness_files": [f"source_input/{dest}/{harness_rel}"],
        "schema_version": 1,
        "seed_count": seed_count,
        "seeds_dir": "seeds",
        "selected_reference_harness_count": 1,
        "selected_reference_harness_dir": "reference_harnesses/selected",
        "selected_reference_harness_files": [f"source_input/{dest}/{harness_rel}"],
        "source": "magma",
        "source_artifact_paths": [],
        "source_fallback_statuses": [],
        "source_file_count": sum(1 for p in (gen / "source_input").rglob("*") if p.is_file()),
        "source_full_dir": "",
        "source_input_dir": "source_input",
        "source_layout": "compact",
        "source_repos": [],
        "source_revision_statuses": ["resolved"],
        "source_status": "materialized",
        "synthetic_build_script_excluded_from_docker_context": True,
        "target": f"magma_{target}",
        "language": spec["language"],
    }
    generator_manifest = dict(base_manifest)
    generator_manifest["benchmark_dir"] = str(benchmark)
    ev_manifest = dict(base_manifest)
    ev_manifest["protocol_visibility"] = "evaluator_only"
    (gen / "target_manifest.json").write_text(json.dumps(generator_manifest, indent=2) + "\n")
    (gen / "target_manifest.generator.json").write_text(json.dumps(generator_manifest, indent=2) + "\n")
    (evl / "target_manifest.evaluator.json").write_text(json.dumps(ev_manifest, indent=2) + "\n")
    (pkg / "target_manifest.json").write_text(json.dumps(ev_manifest, indent=2) + "\n")
    repos = [{
        "dest": dest,
        "is_primary_project": True,
        "kind": "git",
        "package_path": f"source_input/{dest}",
        "revision": head_commit,
        "checked_out_commit": head_commit,
        "revision_status": "resolved",
        "checkout_status": "checked_out_revision",
        "clone_status": "fetched",
        "copy_status": "copied_to_source_input",
        "materialize_status": "fetched",
        "requested_revision": head_commit,
        "revision_source": "magma_setup_commit",
        "source": "magma",
        "submodule_status": "not_present",
        "url": spec["source_url"],
        "artifact_path": "",
    }]
    (gen / "source_repos.json").write_text(json.dumps(repos, indent=2) + "\n")
    (gen / "build_metadata" / "source_repos.json").write_text(json.dumps(repos, indent=2) + "\n")
    (pkg / "source_repos.json").write_text(json.dumps(repos, indent=2) + "\n")
    declared = {
        "schema_version": 1,
        "target": f"magma_{target}",
        "source": "results/magma_harness_apis.md",
        "apis": [{
            "name": spec["entry_api"],
            "return_type": "",
            "params": [],
            "signature": spec["entry_signature"],
        }],
    }
    (gen / "declared_api.json").write_text(json.dumps(declared, indent=2) + "\n")
    (pkg / "declared_api.json").write_text(json.dumps(declared, indent=2) + "\n")
    (gen / "generator_manifest.json").write_text(json.dumps({
        "schema_version": 1,
        "target": f"magma_{target}",
        "project": target,
        "fuzz_target": spec["program"],
        "language": spec["language"],
        "source_input_dir": "source_input",
        "entry_api": spec["entry_api"],
        "entry_signature": spec["entry_signature"],
        "task_family": "harness_generator",
    }, indent=2) + "\n")
    return pkg


def head_commit(target: str) -> str:
    """Read the prepared repo HEAD from the image (before stripping .git)."""
    out = run(
        ["docker", "run", "--rm", "--entrypoint", "/bin/bash", IMAGE.format(target=target),
         "-lc", "git -C /magma/targets/%s/repo rev-parse HEAD 2>/dev/null || true" % target],
        stdout=subprocess.PIPE, text=True,
    ).stdout.strip()
    return out or "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="*", default=sorted(TARGETS))
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    if args.force:
        for target in (args.targets or sorted(TARGETS)):
            shutil.rmtree(BENCH_ROOT / target, ignore_errors=True)
            shutil.rmtree(PKG_ROOT / f"magma_{target}", ignore_errors=True)
    for target in args.targets or sorted(TARGETS):
        spec = TARGETS[target]
        commit = head_commit(target)
        log(f"{target}: repo HEAD {commit}")
        extract_sources(target, spec)
        seed_corpus(target, spec)
        write_benchmark_metadata(target, spec, commit)
        pkg = make_package(target, spec, commit)
        log(f"{target}: package {pkg}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
