#!/usr/bin/env python3
"""Ranking helpers for HGB OSS-Fuzz-Gen benchmark API selection."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

BAD_PATH_PARTS = (
    '/test/', '/tests/', '/testing/', '/example/', '/examples/', '/sample/',
    '/samples/', '/demo/', '/demos/', '/benchmark/', '/bench/', '/perf/',
    '/doc/examples/', '/third_party/', '/googletest/', '/gtest/', '/gmock/',
    '/oss-fuzz/infra/', '/infra/indexer/', '/contrib/', '.tar.', '.zip/',
    'libarchive-',
)
BAD_TYPE_RE = re.compile(
    r'\b(BOOL|DWORD|HANDLE|HMODULE|HINSTANCE|LARGE_INTEGER|LPVOID|HRESULT)\b|'
    r'Matcher\s*<|testing::|::testing\b|gtest|gmock',
)
GENERIC_NAMES = {
    'a', 'abort', 'add', 'begin', 'build', 'check', 'clean', 'cleanup',
    'close', 'copy', 'create', 'delete', 'display', 'doextension', 'error',
    'finish', 'get', 'init', 'initialize', 'main', 'open', 'parse', 'print',
    'process', 'read', 'run', 'set', 'setup', 'start', 'test', 'update',
    'write',
}
BANNED_API_NAMES = {
    'calloc', 'fclose', 'fdopen', 'fflush', 'fopen', 'fprintf', 'fread',
    'free', 'fseek', 'ftell', 'fwrite', 'malloc', 'memcmp', 'memcpy',
    'memmove', 'memset', 'printf', 'puts', 'realloc', 'rewind', 'snprintf',
    'sprintf', 'strcasecmp', 'strcat', 'strchr', 'strcmp', 'strcpy',
    'strdup', 'strlen', 'strncmp', 'strncpy', 'strstr', 'vfprintf',
}
BANNED_API_PREFIXES = ('java_',)
BANNED_SIGNATURE_RE = re.compile(
    r'^\s*(?:return|typedef)\b|\(\s*\*|\bJNIEXPORT\b|'
    r'\bgoogle::protobuf\b|^\s*(?:public|private|protected)\s*:',
    re.I,
)
BANNED_RETURN_TYPES = {'public:', 'private:', 'protected:'}
STOP_TOKENS = {
    'fuzz', 'fuzzer', 'fuzzing', 'target', 'ossfuzz', 'oss', 'read', 'decode',
    'parser', 'parse', 'http', 'both', 'send', 'convert', 'shape', 'link',
}



REFERENCE_SOURCE_EXTS = {'.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp', '.hxx'}
REFERENCE_CALL_SKIP = GENERIC_NAMES | BANNED_API_NAMES | {
    'alignas', 'alignof', 'asm', 'auto', 'bool', 'break', 'case', 'catch',
    'char', 'class', 'const', 'const_cast', 'continue', 'decltype', 'default',
    'delete', 'do', 'double', 'dynamic_cast', 'else', 'enum', 'explicit',
    'extern', 'false', 'float', 'for', 'friend', 'goto', 'if', 'inline', 'int',
    'long', 'namespace', 'new', 'noexcept', 'nullptr', 'operator', 'private',
    'protected', 'public', 'register', 'reinterpret_cast', 'return', 'short',
    'signed', 'sizeof', 'static', 'static_cast', 'struct', 'switch', 'template',
    'this', 'throw', 'true', 'try', 'typedef', 'typeid', 'typename', 'union',
    'unsigned', 'using', 'virtual', 'void', 'volatile', 'while',
    'LLVMFuzzerTestOneInput', 'LLVMFuzzerInitialize',
}


def strip_reference_noise(text: str) -> str:
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
    text = re.sub(r'//.*', ' ', text)
    text = re.sub(r'"(?:\\.|[^"\\])*"', ' ', text)
    text = re.sub(r"'(?:\\.|[^'\\])*'", ' ', text)
    return text


def load_reference_calls(reference_dir: str | Path | None, max_bytes: int = 1_000_000) -> set[str]:
    if not reference_dir:
        return set()
    root = Path(reference_dir)
    if not root.exists():
        return set()
    calls: set[str] = set()
    remaining = max_bytes
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.suffix.lower() not in REFERENCE_SOURCE_EXTS:
            continue
        if remaining <= 0:
            break
        try:
            text = path.read_text(encoding='utf-8', errors='replace')[:remaining]
        except OSError:
            continue
        remaining -= len(text)
        for match in re.finditer(r'\b([A-Za-z_][A-Za-z0-9_:]*)\s*\(', strip_reference_noise(text)):
            name = match.group(1).split('::')[-1]
            if not name or name in REFERENCE_CALL_SKIP or name.startswith('__'):
                continue
            calls.add(name.lower())
    return calls


def split_hint_tokens(*values: str) -> list[str]:
    tokens: list[str] = []
    for value in values:
        for token in re.split(r'[^A-Za-z0-9]+', value or ''):
            token = token.lower()
            if len(token) < 3 or token in STOP_TOKENS:
                continue
            if token not in tokens:
                tokens.append(token)
    return tokens


def load_reference_text(reference_dir: str | Path | None, max_bytes: int = 1_000_000) -> str:
    if not reference_dir:
        return ''
    root = Path(reference_dir)
    if not root.exists():
        return ''
    parts: list[str] = []
    remaining = max_bytes
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.suffix.lower() not in {'.c', '.cc', '.cpp', '.cxx', '.h', '.hpp', '.hh'}:
            continue
        if remaining <= 0:
            break
        try:
            text = path.read_text(encoding='utf-8', errors='replace')[:remaining]
        except OSError:
            continue
        parts.append(text)
        remaining -= len(text)
    return '\n'.join(parts).lower()


def _record_text(record: dict[str, Any]) -> str:
    fields = [
        str(record.get('name') or ''),
        str(record.get('signature') or ''),
        str(record.get('return_type') or record.get('return-type') or ''),
        str(record.get('path') or ''),
    ]
    for param in record.get('params') or []:
        if isinstance(param, dict):
            fields.append(str(param.get('type') or ''))
            fields.append(str(param.get('name') or ''))
        else:
            fields.append(str(param))
    return ' '.join(fields)


def reject_reason(record: dict[str, Any]) -> str:
    name = str(record.get('name') or '').split('::')[-1]
    signature = str(record.get('signature') or '')
    path = ('/' + str(record.get('path') or '').replace('\\', '/').lower()).replace('//', '/')
    text = _record_text(record)
    name_l = name.lower()
    signature_l = signature.lower().strip()
    return_type_l = str(record.get('return_type') or record.get('return-type') or '').lower().strip()
    if not name and not signature:
        return 'empty_api_candidate'
    if len(name) == 1:
        return 'generic_single_letter_api'
    if name_l in BANNED_API_NAMES:
        return 'generic_runtime_or_io_api'
    if any(name_l.startswith(prefix) for prefix in BANNED_API_PREFIXES):
        return 'jni_or_language_binding_api'
    if return_type_l in BANNED_RETURN_TYPES:
        return 'cxx_constructor_or_access_label'
    if name_l in {'failure', 'fail', 'error'} and 'inline' in signature_l:
        return 'inline_helper_api'
    if BANNED_SIGNATURE_RE.search(signature):
        return 'callback_wrapper_or_inline_expression'
    if BAD_TYPE_RE.search(text):
        return 'unsupported_or_test_only_type'
    for part in BAD_PATH_PARTS:
        if part in path:
            return 'irrelevant_source_path'
    return ''


def score_record(
    record: dict[str, Any],
    *,
    project: str = '',
    target_name: str = '',
    fuzz_target: str = '',
    reference_text: str = '',
) -> tuple[int, list[str]] | None:
    reason = reject_reason(record)
    if reason:
        return None

    name = str(record.get('name') or '').split('::')[-1]
    name_l = name.lower()
    signature_l = str(record.get('signature') or '').lower()
    path_l = str(record.get('path') or '').replace('\\', '/').lower()
    project_hint_tokens = split_hint_tokens(project)
    raw_target_tokens = split_hint_tokens(target_name, fuzz_target)
    target_tokens = [
        token for token in raw_target_tokens if token not in project_hint_tokens
    ]
    project_tokens = [
        token for token in project_hint_tokens if token not in target_tokens
    ]
    if not target_tokens:
        target_tokens = raw_target_tokens or project_tokens
        project_tokens = [] if target_tokens else project_tokens
    score = 0
    reasons: list[str] = []

    if reference_text and name_l:
        if re.search(rf'\b{re.escape(name_l)}\s*\(', reference_text):
            score += 300
            reasons.append('called_by_harness')
        elif re.search(rf'\b{re.escape(name_l)}\b', reference_text):
            score += 120
            reasons.append('mentioned_by_harness')
    for token in target_tokens:
        if token == name_l:
            score += 150
            reasons.append(f'target_name_exact:{token}')
        elif token in name_l:
            score += 100
            reasons.append(f'target_name:{token}')
        if token and token in signature_l:
            score += 45
            reasons.append(f'target_signature:{token}')
        if token and token in path_l:
            score += 15
            reasons.append(f'target_path:{token}')
    for token in project_tokens:
        if token == name_l:
            score += 20
            reasons.append(f'project_name_exact:{token}')
        elif token in name_l:
            score += 10
            reasons.append(f'project_name:{token}')
        if token and token in signature_l:
            score += 10
            reasons.append(f'project_signature:{token}')
        if token and token in path_l:
            score += 10
            reasons.append(f'project_path:{token}')

    if path_l.endswith(('.h', '.hh', '.hpp', '.hxx')):
        score += 25
        reasons.append('header_decl')
    if path_l.endswith(('.c', '.cc', '.cpp', '.cxx')):
        score += 10
        reasons.append('source_decl')
    if name_l in GENERIC_NAMES:
        score -= 120
        reasons.append('generic_name')
    if name_l.startswith('_zn') and not reasons:
        score -= 40
        reasons.append('mangled_without_target_hint')
    if len(name_l) <= 3:
        score -= 30
        reasons.append('short_name')
    score -= min(path_l.count('/'), 20)
    return score, reasons


def rank_records(
    records: list[dict[str, Any]],
    *,
    project: str = '',
    target_name: str = '',
    fuzz_target: str = '',
    reference_dir: str | Path | None = None,
    keep_rejected: bool = False,
) -> list[dict[str, Any]]:
    reference_text = load_reference_text(reference_dir)
    ranked: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        item = dict(record)
        scored = score_record(
            item,
            project=project,
            target_name=target_name,
            fuzz_target=fuzz_target,
            reference_text=reference_text,
        )
        if scored is None:
            item['_hgb_reject_reason'] = reject_reason(item) or 'rejected'
            item['_hgb_original_index'] = index
            rejected.append(item)
            continue
        score, reasons = scored
        item['_hgb_score'] = score
        item['_hgb_score_reasons'] = reasons
        item['_hgb_original_index'] = index
        ranked.append(item)
    ranked.sort(key=lambda item: (-int(item.get('_hgb_score', 0)), int(item.get('_hgb_original_index', 0))))
    if keep_rejected and not ranked:
        return rejected
    return ranked
