#!/usr/bin/env python3
"""Best-effort C/C++ API extractor for target-aware generator bootstrapping."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


DECL_RE = re.compile(
    r"(?m)^[A-Za-z_][A-Za-z0-9_:\\<\\>\\*\\&\\s,~]*?\s+"
    r"([A-Za-z_][A-Za-z0-9_:]*)\s*\([^;{}#]*\)\s*(?:;|\{)"
)
SKIP = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "main",
    "LLVMFuzzerTestOneInput",
    "LLVMFuzzerInitialize",
}
EXTS = {".h", ".hh", ".hpp", ".hxx", ".c", ".cc", ".cpp", ".cxx"}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//.*", " ", text)


def extract(source: Path, limit: int) -> list[str]:
    seen: set[str] = set()
    names: list[str] = []
    for path in sorted(source.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in EXTS:
            continue
        try:
            text = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        for match in DECL_RE.finditer(text):
            name = match.group(1).split("::")[-1]
            if name in SKIP or name.startswith("__") or name in seen:
                continue
            seen.add(name)
            names.append(name)
            if len(names) >= limit:
                return names
    return names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max", type=int, default=200)
    args = parser.parse_args()
    names = extract(Path(args.source), args.max)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(names, indent=2) + "\n", encoding="utf-8")
    print(len(names))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
