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
    m = re.search(r"((?:LLVM)?FuzzerTestOneInput\s*\([^)]*\)\s*\{)\n", text)
    if not m:
        return text, False
    text = text[: m.end()] + decls + text[m.end():]
    return text, True


def _adapt_openssl_fuzz_abi(text: str) -> tuple[str, bool]:
    """Supply the public OpenSSL fuzz driver hooks around generated API calls."""
    changed = False
    if re.search(r"\bLLVMFuzzerTestOneInput\s*\(", text) and not re.search(
        r"\bFuzzerTestOneInput\s*\(", text
    ):
        text = re.sub(r"\bLLVMFuzzerTestOneInput(?=\s*\()", "FuzzerTestOneInput", text)
        changed = True
    if not re.search(r"\bFuzzerTestOneInput\s*\(", text):
        return text, changed
    if not re.search(r"\bFuzzerInitialize\s*\(", text):
        text += "\nint FuzzerInitialize(int *argc, char ***argv) { (void)argc; (void)argv; return 0; }\n"
        changed = True
    if not re.search(r"\bFuzzerCleanup\s*\(", text):
        text += "\nvoid FuzzerCleanup(void) {}\n"
        changed = True
    return text, changed


def _adapt_php_fuzzer_lifecycle(text: str) -> tuple[str, bool]:
    """Initialize PHP's fuzz SAPI and give its JSON scanner a padded buffer."""
    if not re.search(r"\bLLVMFuzzerTestOneInput\s*\(", text):
        return text, False
    changed = False
    if not re.search(r'#include\s+[<"]fuzzer-sapi\.h[>"]', text):
        include = re.search(r'(#include\s+[<"](?:main/)?php\.h[>"][^\n]*\n)', text)
        if include:
            text = text[: include.end()] + '#include "fuzzer-sapi.h"\n' + text[include.end():]
        else:
            text = '#include <main/php.h>\n#include "fuzzer-sapi.h"\n' + text
        changed = True
    if not re.search(r"\bLLVMFuzzerInitialize\s*\(", text):
        text += "\nint LLVMFuzzerInitialize(int *argc, char ***argv) {\n"
        text += "    (void)argc; (void)argv;\n"
        text += "    return fuzzer_init_php(NULL) == SUCCESS ? 0 : 1;\n}\n"
        changed = True
    if not re.search(r"\bhgb_generated_test_one_input\s*\(", text):
        generated_starts_request = bool(re.search(r"\bfuzzer_request_startup\s*\(", text))
        for header in ("stdlib.h", "string.h"):
            if not re.search(r'#include\s+[<"]' + re.escape(header) + r'[>"]', text):
                text = f"#include <{header}>\n" + text
        text, renamed = re.subn(
            r"\bLLVMFuzzerTestOneInput(?=\s*\()",
            "hgb_generated_test_one_input",
            text,
            count=1,
        )
        if renamed:
            text += "\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
            text += "    if (size == (size_t)-1) return 0;\n"
            text += "    uint8_t *padded = (uint8_t *)malloc(size + 1);\n"
            text += "    if (padded == NULL) return 0;\n"
            text += "    if (size != 0) memcpy(padded, data, size);\n"
            text += "    padded[size] = 0;\n"
            if not generated_starts_request:
                text += "    if (fuzzer_request_startup() != SUCCESS) { free(padded); return 0; }\n"
            text += "    int rc = hgb_generated_test_one_input(padded, size);\n"
            if not generated_starts_request:
                text += "    fuzzer_request_shutdown();\n"
            text += "    free(padded);\n"
            text += "    return rc;\n}\n"
            changed = True
    return text, changed


def _adapt_systemd_link_parser(text: str) -> tuple[str, bool]:
    """Correct generated names against the pinned systemd link-config API."""
    if not re.search(r"\blink_load_one\s*\(", text):
        return text, False
    original = text
    for old, new in (
        ('"networkd-link.h"', '"link-config.h"'),
        ("link_config_context_new", "link_config_ctx_new"),
        ("link_config_context_freep", "link_config_ctx_freep"),
        ("link_config_context_free", "link_config_ctx_free"),
        ("#include <cstdlib>", "#include <stdlib.h>"),
        ("#include <cstdint>", "#include <stdint.h>"),
    ):
        text = text.replace(old, new)
    # The benchmark overlays this source onto fuzz-link-parser.c. Upstream
    # sometimes names its candidate .cc, but this destination is compiled as C.
    text = re.sub(r'extern\s+"C"\s+(?=int\s+LLVMFuzzerTestOneInput)', "", text)
    if not re.search(r'#include\s+"link-config\.h"', text):
        text = '#include "link-config.h"\n' + text
    return text, text != original


TARGET_RESCUES: dict[str, list[dict[str, Any]]] = {
    "openssl_x509": [
        {
            "name": "adapt_openssl_fuzz_abi",
            "apply": _adapt_openssl_fuzz_abi,
        },
        {
            "name": "declare_libctx_propq",
            "apply": _declare_openssl_ctx,
        },
    ],
    "php_php-fuzz-parser_0dbedb": [
        {
            "name": "adapt_php_fuzzer_lifecycle",
            "apply": _adapt_php_fuzzer_lifecycle,
        },
    ],
    "systemd_fuzz-link-parser": [
        {
            "name": "adapt_systemd_link_parser",
            "apply": _adapt_systemd_link_parser,
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
