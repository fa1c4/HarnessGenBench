#!/usr/bin/env python3
"""Recover selected C/C++ API snippets when CKGFuzzer extraction is incomplete."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
SKIPPED_DIRS = {".git", "build", "out", "work"}


def _short_name(name: str) -> str:
    return name.split("::")[-1]


def _matching_delimiter(text: str, start: int, opening: str, closing: str) -> int:
    depth = 0
    quote = ""
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index
    return -1


def _is_knr_declaration_block(text: str) -> bool:
    """Recognize the old-style declarations between ``)`` and ``{``.

    K&R parameters routinely include pointer declarators (``Bytef *dest``),
    which the previous regex rejected.  This deliberately accepts normal C
    declaration tokens while excluding statements and preprocessor content.
    """
    declarations = [part.strip() for part in text.split(";") if part.strip()]
    if not declarations:
        return False
    for declaration in declarations:
        if any(token in declaration for token in ("{", "}", "(", ")", "=", "#")):
            return False
        if not re.search(r"[A-Za-z_][A-Za-z0-9_]*\s*(?:\[[^]\n]*\])?$", declaration):
            return False
    return True


def _tree_sitter_function_snippet(text: str, api_name: str) -> str:
    """Use the installed C++ grammar when available, including K&R C input."""
    try:
        from tree_sitter import Language, Parser
    except ImportError:
        return ""
    grammar_candidates = [
        Path(value)
        for value in (
            os.environ.get("CKGFUZZER_TREE_SITTER_CPP_LIBRARY", ""),
            "/opt/hgb/artifacts/ckgfuzzer/fuzzing_llm_engine/codetext/parser/tree-sitter/cpp.so",
        )
        if value
    ]
    grammar = next((candidate for candidate in grammar_candidates if candidate.is_file()), None)
    if grammar is None:
        return ""
    try:
        parser = Parser()
        language = Language(str(grammar), "cpp")
        if hasattr(parser, "set_language"):
            parser.set_language(language)
        else:
            parser.language = language
        tree = parser.parse(text.encode("utf-8", errors="replace"))
    except Exception:
        return ""

    name = _short_name(api_name)
    nodes = [tree.root_node]
    while nodes:
        node = nodes.pop()
        if node.type == "function_definition":
            snippet = text.encode("utf-8", errors="replace")[node.start_byte : node.end_byte].decode(
                "utf-8", errors="replace"
            )
            signature = snippet[: snippet.find("{")]
            if re.search(
                r"\b(?:[A-Za-z_][A-Za-z0-9_]*::)*" + re.escape(name) + r"(?:\s*<[^(){};]*>)?\s*\(",
                signature,
            ):
                return snippet
        nodes.extend(reversed(node.children))
    return ""


def function_snippet(text: str, api_name: str) -> str:
    """Return a complete definition, including C K&R and C++ templates."""
    name = _short_name(api_name)
    pattern = re.compile(
        r"(?ms)(?:^[ \t]*template\s*<[^{};]*>\s*\n)*"
        r"^[ \t]*(?!#|//|/\*)[^;{}\n]*\b(?:[A-Za-z_][A-Za-z0-9_]*::)*"
        + re.escape(name)
        + r"(?:\s*<[^(){};]*>)?\s*\("
    )
    for match in pattern.finditer(text):
        open_paren = text.find("(", match.start(), match.end())
        close_paren = _matching_delimiter(text, open_paren, "(", ")")
        if close_paren < 0:
            continue
        brace = text.find("{", close_paren + 1, min(len(text), close_paren + 4096))
        if brace < 0:
            continue
        between = text[close_paren + 1 : brace]
        compact = between.strip()
        if ";" in compact:
            if not _is_knr_declaration_block(between):
                continue
        elif compact and not re.fullmatch(
            r"(?:const|noexcept|override|final|throw\s*\([^)]*\)|&|&&|\s)+", compact
        ):
            continue
        end = _matching_delimiter(text, brace, "{", "}")
        if end >= 0:
            return text[match.start() : end + 1]
    # CodeQL metadata is preferred by recover_selected_api_code. If its
    # source text is incomplete and the lexical fallback cannot identify a
    # definition, use the real tree-sitter parser as the final recovery tier.
    return _tree_sitter_function_snippet(text, api_name)

def macro_generated_snippet(text: str, api_name: str) -> str:
    """Return the ASN.1 macro context for APIs generated by OpenSSL macros."""
    short_name = _short_name(api_name)
    if "_" not in short_name:
        return ""
    type_name = short_name.rsplit("_", 1)[0]
    pattern = re.compile(
        r"(?m)^[ \t]*(?:DECLARE|IMPLEMENT)_ASN1_[A-Z_]*FUNCTIONS[^\n]*\(\s*"
        + re.escape(type_name)
        + r"(?:\s*[,)]).*"
    )
    match = pattern.search(text)
    if not match:
        return ""
    return "/* HGB recovered macro-generated API context for " + short_name + ". */\n" + match.group(0)


def declaration_snippet(text: str, api_name: str) -> str:
    """Return a usable declaration when a definition is macro-generated."""
    name = _short_name(api_name)
    pattern = re.compile(
        r"(?m)^[ \t]*(?!#)[^{};\n]*\b(?:[A-Za-z_][A-Za-z0-9_]*::)*"
        + re.escape(name)
        + r"\s*\([^{};]*\)\s*;"
    )
    match = pattern.search(text)
    if not match:
        return ""
    return "/* HGB recovered declaration; definition is macro-generated or unavailable. */\n" + match.group(0)


def _source_files(source_root: Path, max_files: int) -> list[Path]:
    files: list[Path] = []
    for path in sorted(source_root.rglob("*")):
        if any(part in SKIPPED_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES:
            files.append(path)
            if len(files) >= max_files:
                break
    return files


def recover_selected_api_code(
    src_api_data: dict[str, Any],
    api_list: list[str],
    source_root: str,
    max_files: int,
) -> tuple[dict[str, str], list[str]]:
    """Recover snippets from CodeQL, then source definitions, then declarations."""
    requested_by_short: dict[str, list[str]] = {}
    for requested in api_list:
        requested_by_short.setdefault(_short_name(requested), []).append(requested)

    recovered: dict[str, str] = {}
    for src_value in src_api_data.get("src", {}).values():
        for api in src_value.get("fn_def_list", []):
            name = str(api.get("fn_meta", {}).get("identifier", ""))
            code = str(api.get("fn_code", ""))
            if not code:
                continue
            for requested in requested_by_short.get(_short_name(name), []):
                recovered[requested] = code

    missing = [name for name in api_list if name not in recovered]
    root = Path(source_root)
    if not missing or not root.is_dir():
        return recovered, missing

    source_texts: list[str] = []
    for path in _source_files(root, max(1, max_files)):
        try:
            if path.stat().st_size > 4 * 1024 * 1024:
                continue
            source_texts.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue

    # Prefer bodies globally. A declaration in an early header must not hide a
    # later K&R/template definition in the implementation tree.
    for text in source_texts:
        for name in list(missing):
            snippet = function_snippet(text, name)
            if snippet:
                recovered[name] = snippet
                missing.remove(name)
        if not missing:
            break
    if missing:
        for text in source_texts:
            for name in list(missing):
                snippet = macro_generated_snippet(text, name)
                if snippet:
                    recovered[name] = snippet
                    missing.remove(name)
            if not missing:
                break
    if missing:
        for text in source_texts:
            for name in list(missing):
                snippet = declaration_snippet(text, name)
                if snippet:
                    recovered[name] = snippet
                    missing.remove(name)
            if not missing:
                break
    return recovered, missing
