#!/usr/bin/env python3
"""Best-effort C/C++ API extractor for target-aware generator bootstrapping."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any


DECL_RE = re.compile(
    r"(?m)^[ \t]*(?!#)"
    r"([A-Za-z_][A-Za-z0-9_:\<\>\*\&\s,~]*?)\s+"
    r"([A-Za-z_][A-Za-z0-9_:]*)\s*\(([^;{}#]*)\)\s*(?:;|\{)"
)
SKIP = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "main",
    "void",
    "LLVMFuzzerTestOneInput",
    "LLVMFuzzerInitialize",
}
EXTS = {".h", ".hh", ".hpp", ".hxx", ".c", ".cc", ".cpp", ".cxx"}


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//.*", " ", text)


def split_params(params: str) -> list[str]:
    params = params.strip()
    if not params or params == "void":
        return []
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for char in params:
        if char in "(<[":
            depth += 1
        elif char in ")>]" and depth > 0:
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if current:
        parts.append("".join(current).strip())
    return [part for part in parts if part]


def parse_param(param: str) -> dict[str, str]:
    param = " ".join(param.replace("\n", " ").split())
    if param == "...":
        return {"name": "", "type": "..."}
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?$", param)
    if not match:
        return {"name": "", "type": param}
    name = match.group(1)
    type_part = param[: match.start(1)].rstrip()
    if not type_part or name in {"const", "volatile", "struct", "enum", "union"}:
        return {"name": "", "type": param}
    return {"name": name, "type": type_part}


def valid_name(name: str) -> bool:
    short = name.split("::")[-1]
    if short in SKIP or short.startswith("__"):
        return False
    if short.upper() == short and len(short) > 2:
        return False
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_:]*$", name))


def make_record(name: str, return_type: str, params: str, path: Path | None = None, source: Path | None = None) -> dict[str, Any]:
    short_name = name.split("::")[-1]
    parsed_params = [parse_param(param) for param in split_params(params)]
    signature = f"{return_type.strip() or 'int'} {name}({params.strip()})"
    record: dict[str, Any] = {
        "name": short_name,
        "return_type": return_type.strip() or "int",
        "params": parsed_params,
        "signature": signature,
    }
    if path is not None:
        try:
            record["path"] = str(path.relative_to(source)) if source else str(path)
        except ValueError:
            record["path"] = str(path)
    return record


def source_files(source: Path) -> list[Path]:
    return [path for path in sorted(source.rglob("*")) if path.is_file() and path.suffix.lower() in EXTS]


def ctags_records(source: Path, limit: int) -> list[dict[str, Any]]:
    ctags = shutil.which("ctags")
    if not ctags:
        return []
    cmd = [
        ctags,
        "--output-format=json",
        "--languages=C,C++",
        "--kinds-C=f",
        "--kinds-C++=f",
        "--fields=+S",
        "-R",
        "-f",
        "-",
        str(source),
    ]
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, check=False, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0 and not proc.stdout.strip():
        return []

    seen: set[str] = set()
    records: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = str(item.get("name", ""))
        short_name = name.split("::")[-1]
        if not valid_name(name) or short_name in seen:
            continue
        signature = str(item.get("signature", "()"))
        params = signature.strip()[1:-1] if signature.startswith("(") and signature.endswith(")") else ""
        typeref = str(item.get("typeref", ""))
        return_type = typeref.split(":", 1)[1] if ":" in typeref else "int"
        path = Path(str(item.get("path", ""))) if item.get("path") else None
        records.append(make_record(name, return_type, params, path, source))
        seen.add(short_name)
        if len(records) >= limit:
            return records
    return records


def regex_records(source: Path, limit: int) -> list[dict[str, Any]]:
    seen: set[str] = set()
    records: list[dict[str, Any]] = []
    for path in source_files(source):
        try:
            text = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        for match in DECL_RE.finditer(text):
            return_type, name, params = match.groups()
            short_name = name.split("::")[-1]
            if not valid_name(name) or short_name in seen:
                continue
            seen.add(short_name)
            records.append(make_record(name, return_type, params, path, source))
            if len(records) >= limit:
                return records
    return records


def extract_details(source: Path, limit: int) -> list[dict[str, Any]]:
    records = ctags_records(source, limit)
    if records:
        return records[:limit]
    return regex_records(source, limit)


def extract(source: Path, limit: int) -> list[str]:
    return [record["name"] for record in extract_details(source, limit)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max", type=int, default=200)
    parser.add_argument("--details", action="store_true", help="write detailed API records instead of only names")
    args = parser.parse_args()
    data = extract_details(Path(args.source), args.max) if args.details else extract(Path(args.source), args.max)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(len(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
