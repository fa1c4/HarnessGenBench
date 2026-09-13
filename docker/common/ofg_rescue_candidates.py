#!/usr/bin/env python3
"""Rescue staged OSS-Fuzz-Gen candidates before independent evaluation.

Applies ONLY deterministic, audited repairs that mirror upstream
OSS-Fuzz-Gen's own canonical fixers (llm_toolkit/code_fixer.collect_specific_fixes):

1. Strip LLM response pollution (leading ``<solution>``/``<reasoning>`` XML
   tags and markdown code fences). A leading tag alone provokes a cascade of
   spurious compiler errors (e.g. glibc ``__u_char`` in sys/types.h).
2. C++ candidates: append ``extern "C"`` before ``LLVMFuzzerTestOneInput``
   when missing (upstream ``append_extern_c``), ensure ``<cstdint>`` and
   ``<cstdlib>`` (upstream ``insert_cstdint``/``insert_cstdlib``).
3. A small per-target rescue map for common LLM declaration omissions
   (e.g. openssl_x509 uses ``libctx`` without declaring it).

Every applied change is recorded in ``rescue_audit.json`` next to the staged
candidates so the repair is fully transparent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

CPP_EXTS = {".cc", ".cpp", ".cxx"}
C_EXTS = {".c", ".h"}

XML_TAG_RE = re.compile(
    r"^\s*</?(solution|reasoning|thinking|analysis|response|answer|code)>"
    r"\s*(?:\[[^\]]*\])?\s*$",
    flags=re.I,
)

FENCE_RE = re.compile(r"^\s*(```+|\*\*\*+)\s*(?:c\+\+|cpp|cc|c|rust|python)?\s*$")


def strip_pollution(text: str) -> tuple[str, list[str]]:
    """Strip leading XML tags/fences; report what was removed."""
    fixes: list[str] = []
    lines = text.splitlines()
    while lines:
        line = lines[0]
        stripped = line.strip()
        if not stripped:
            # Blank lines between pollution markers are fine to keep.
            if fixes:
                break
            lines.pop(0)
            continue
        if XML_TAG_RE.match(stripped):
            fixes.append(f"stripped_xml_tag:{stripped[:40]}")
            lines.pop(0)
            continue
        if FENCE_RE.match(stripped):
            fixes.append("stripped_markdown_fence")
            lines.pop(0)
            continue
        break
    if fixes:
        return "\n".join(lines) + ("\n" if text.endswith("\n") else ""), fixes
    return text, fixes


def append_extern_c(text: str) -> tuple[str, bool]:
    """Upstream append_extern_c: extern "C" before the fuzzer entry."""
    if re.search(r'extern\s+"C"\s+int\s+LLVMFuzzerTestOneInput', text):
        return text, False
    pattern = r"(?<![\w\"])int\s+LLVMFuzzerTestOneInput\s*\(([^)]*)\)"
    if not re.search(pattern, text):
        return text, False
    new = re.sub(pattern, r'extern "C" int LLVMFuzzerTestOneInput(\1)', text)
    return new, new != text


def insert_cstdint(text: str) -> tuple[str, bool]:
    if "#include <cstdint>" in text or "#include <stdint.h>" in text:
        return text, False
    return "#include <cstdint>\n" + text, True


def insert_cstdlib(text: str) -> tuple[str, bool]:
    if "#include <cstdlib>" in text or "#include <stdlib.h>" in text:
        return text, False
    return "#include <cstdlib>\n" + text, True


# ---------------------------------------------------------------------------
# Per-target rescues for common LLM declaration omissions. Each rule is a
# (regex_evidence, replacement) pair applied only when the evidence matches.
# ---------------------------------------------------------------------------


def _declare_openssl_ctx(text: str) -> tuple[str, bool]:
    """Insert declarations for libctx/propq when used but never declared."""
    if not re.search(r"\blibctx\b", text) and not re.search(r"\bpropq\b", text):
        return text, False
    changed = False
    decls = ""
    if re.search(r"\blibctx\b", text) and not re.search(
        r"OSSL_LIB_CTX\s*\*\s*libctx|OSSL_LIB_CTX\s+libctx", text
    ):
        decls += "    OSSL_LIB_CTX *libctx = NULL;\n"
        changed = True
    if re.search(r"\bpropq\b", text) and not re.search(
        r"const\s+char\s*\*\s*propq|char\s*\*\s*propq", text
    ):
        decls += "    const char *propq = NULL;\n"
        changed = True
    if not changed:
        return text, False
    # Insert right after the fuzzer entry opening brace.
    m = re.search(r"(LLVMFuzzerTestOneInput\s*\([^)]*\)\s*\{)\n", text)
    if not m:
        return text, False
    text = text[: m.end()] + decls + text[m.end():]
    return text, True


TARGET_RESCUES: dict[str, list[dict[str, Any]]] = {
    "openssl_x509": [
        {
            "name": "declare_libctx_propq",
            "apply": _declare_openssl_ctx,
        },
    ],
}


def rescue_file(path: Path, *, target: str, language: str) -> dict[str, Any]:
    """Apply deterministic rescues to one candidate file."""
    before = path.read_text(encoding="utf-8", errors="replace")
    fixes: list[str] = []
    text, strip_fixes = strip_pollution(before)
    fixes.extend(strip_fixes)

    is_cpp = path.suffix.lower() in CPP_EXTS or language == "c++"
    if is_cpp:
        new, applied = append_extern_c(text)
        if applied:
            fixes.append("append_extern_c")
            text = new
        for fn, label in ((insert_cstdint, "insert_cstdint"), (insert_cstdlib, "insert_cstdlib")):
            new, applied = fn(text)
            if applied:
                fixes.append(label)
                text = new

    rules = TARGET_RESCUES.get(target, [])
    for rule in rules:
        fn = rule.get("apply")
        if fn is None:
            continue
        new, applied = fn(text)
        if applied:
            fixes.append(rule.get("name", "target_rescue"))
            text = new

    if text != before:
        path.write_text(text, encoding="utf-8")
    return {
        "path": str(path),
        "fixes": fixes,
        "sha256_before": hashlib.sha256(before.encode()).hexdigest()[:16],
        "sha256_after": hashlib.sha256(text.encode()).hexdigest()[:16],
        "changed": text != before,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates-dir", required=True)
    parser.add_argument("--target", default="")
    parser.add_argument("--language", default="c++", choices=("c", "c++"))
    parser.add_argument("--audit-out", default="")
    args = parser.parse_args()

    candidates = Path(args.candidates_dir)
    if not candidates.is_dir():
        print("rescue: candidates dir missing", file=sys.stderr)
        return 1

    records = []
    for p in sorted(candidates.iterdir()):
        if not p.is_file() or p.suffix.lower() not in (CPP_EXTS | C_EXTS):
            continue
        records.append(rescue_file(p, target=args.target, language=args.language))

    changed = sum(1 for r in records if r["changed"])
    for r in records:
        if r["changed"]:
            print(f"ofg_rescue: {Path(r['path']).name}: {', '.join(r['fixes'])}")
    audit = {
        "target": args.target,
        "language": args.language,
        "candidates": records,
        "changed_count": changed,
    }
    audit_path = Path(args.audit_out) if args.audit_out else candidates / "rescue_audit.json"
    audit_path.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"ofg_rescue_done: {len(records)} candidates, {changed} repaired")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
