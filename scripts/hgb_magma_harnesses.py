#!/usr/bin/env python3
"""Extract each MAGMA target's first harness API.

The harness is the target's primary libFuzzer program (first entry in the
MAGMA ``configrc`` PROGRAMS list).  We isolate ``LLVMFuzzerTestOneInput`` (or
``main`` for standalone drivers), list call expressions in source order, drop
language/libc/library-local helpers, and keep the calls whose identifier is
declared by the target project's own headers.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Calls that are language/runtime/standard-library plumbing, never the target API.
GENERIC = {
    # control flow / operators written as calls
    "if", "for", "while", "switch", "return", "sizeof", "alignof", "decltype",
    "static_cast", "reinterpret_cast", "const_cast", "dynamic_cast",
    "new", "delete", "throw", "catch", "operator",
    # std / C runtime
    "memcpy", "memmove", "memset", "memcmp", "strlen", "strcmp", "strncmp",
    "strcpy", "strncpy", "strdup", "malloc", "calloc", "realloc", "free",
    "abort", "assert", "printf", "fprintf", "sprintf", "snprintf", "puts",
    "exit", "atoi", "atol", "strtol", "strtoul", "strtod", "fopen", "fclose",
    "fread", "fwrite", "fseek", "ftell", "open", "close", "read", "write",
    "lseek", "mmap", "munmap", "getpid", "time", "clock", "rand", "srand",
    "min", "max", "std", "begin", "end", "size", "data", "push_back",
    "reserve", "resize", "clear", "empty", "insert", "erase", "emplace_back",
    "make_unique", "make_shared", "shared_ptr", "unique_ptr", "vector",
    "string", "basic_string", "allocator", "construct", "destroy",
    "LLVMFuzzerTestOneInput", "LLVMFuzzerInitialize", "LLVMFuzzerMutate",
}
COMMENT_OR_STRING = re.compile(
    r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'", re.S)
CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
DEFINITION = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{")
DECL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*;")


def strip_comments(text: str) -> str:
    return COMMENT_OR_STRING.sub(" ", text)


def function_body(text: str, name: str) -> str:
    """Return the balanced brace body that follows ``name(...)``."""
    match = re.search(rf"\b{re.escape(name)}\s*\([^;{{}}]*\)\s*\{{", text)
    if not match:
        return ""
    start = text.find("{", match.start())
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1:index]
    return text[start + 1:]


def header_declarations(repo: Path, limit: int = 4000) -> set[str]:
    """Collect function names declared by the project's headers."""
    names: set[str] = set()
    candidates = [path for path in repo.rglob("*")
                  if path.suffix in {".h", ".hh", ".hpp", ".hxx"}
                  and path.is_file()
                  and "/.git/" not in str(path)
                  and "/test/" not in str(path) and "/tests/" not in str(path)
                  and "/third_party/" not in str(path)]
    for path in candidates[:limit]:
        try:
            text = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        for match in DECL.finditer(text):
            names.add(match.group(1))
    return names


def source_definition_names(repo: Path, limit: int = 4000) -> set[str]:
    names: set[str] = set()
    candidates = [path for path in repo.rglob("*")
                  if path.suffix in {".c", ".cc", ".cpp", ".cxx"}
                  and path.is_file() and "/.git/" not in str(path)]
    for path in candidates[:limit]:
        try:
            text = strip_comments(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        for match in DEFINITION.finditer(text):
            names.add(match.group(1))
    return names


INPUT_TOKENS = ("data", "size", "buf", "input", "bytes", "len", "length")
SETUP_PATTERN = re.compile(
    r"(SetErrorHandler|SetWarningHandler|set_debug_error_function|initialize|_init$|^init|"
    r"set_.*_function|newstate|_malloc$)", re.I)


def call_arguments(body: str, open_paren: int) -> str:
    depth = 0
    for index in range(open_paren, len(body)):
        if body[index] == "(":
            depth += 1
        elif body[index] == ")":
            depth -= 1
            if depth == 0:
                return body[open_paren + 1:index]
    return ""


def input_variables(body: str) -> set[str]:
    return set(INPUT_TOKENS)


def first_api(harness: Path, repo: Path) -> dict:
    text = strip_comments(harness.read_text(encoding="utf-8", errors="replace"))
    for entry_name in ("LLVMFuzzerTestOneInput", "FuzzerTestOneInput", "main"):
        body = function_body(text, entry_name)
        if body:
            break
    if not body:
        return {"harness": str(harness), "error": "no fuzzer entry point"}
    declarations = header_declarations(repo)
    definitions = source_definition_names(repo)
    local = source_definition_names(harness.parent, limit=200)
    symbols = (declarations | definitions) - local
    variables = input_variables(body)
    calls = []
    for match in CALL.finditer(body):
        name = match.group(1)
        if name in GENERIC:
            continue
        line = body[:match.start()].count("\n") + 1
        args = call_arguments(body, match.end() - 1)
        touches_input = any(re.search(rf"(?<![.>-])\b{re.escape(var)}\b", args)
                            for var in variables)
        calls.append({"name": name, "offset": match.start(), "line": line,
                      "args": args.strip()[:160], "touches_input": touches_input,
                      "project_header": name in declarations,
                      "project_definition": name in definitions,
                      "project_symbol": name in symbols})
    project_calls = [call for call in calls if call["project_symbol"]]
    entry = next((call for call in project_calls if call["touches_input"]), None)
    if entry is None:
        entry = next((call for call in project_calls
                      if not SETUP_PATTERN.search(call["name"])), None)
    return {
        "harness": str(harness),
        "entry_point": "LLVMFuzzerTestOneInput/FuzzerTestOneInput/main",
        "first_project_call": project_calls[0] if project_calls else None,
        "entry_project_call": entry or (project_calls[0] if project_calls else None),
        "first_calls": calls[:12],
        "project_calls": project_calls[:8],
        "declaration_count": len(declarations),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True,
                        help="JSON list of {target, program, harness, repo}")
    parser.add_argument("--output", type=Path,
                        default=ROOT / "workspace/magma/harness_apis.json")
    args = parser.parse_args()
    spec = json.loads(args.spec.read_text(encoding="utf-8"))
    results = {}
    for item in spec:
        harness = Path(item["harness"])
        repo = Path(item["repo"])
        if not harness.is_file() or not repo.is_dir():
            results[item["target"]] = {"target": item["target"], "program": item["program"],
                                       "error": f"missing harness={harness} repo={repo}"}
            print(f"{item['target']}: missing harness/repo", flush=True)
            continue
        result = first_api(harness, repo)
        result.update(target=item["target"], program=item["program"], repo=str(repo))
        results[item["target"]] = result
        first = result.get("first_project_call") or {}
        entry = result.get("entry_project_call") or {}
        print(f"{item['target']:10s} {item['program']:30s} first={first.get('name', '?'):28s} "
              f"entry={entry.get('name', '?'):28s} ({len(result.get('project_calls', []))} project calls)",
              flush=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
