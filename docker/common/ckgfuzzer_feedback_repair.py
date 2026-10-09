#!/usr/bin/env python3
"""Repair an upstream CKGFuzzer driver using its real FuzzBench build error.

Only generator-visible source headers are supplied to the model. The repaired
driver remains a model-generated CKGFuzzer candidate and is evaluated by the
same independent harness evaluator as the original driver.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from pathlib import Path


def compiler_feedback(log: str, limit: int = 9000) -> str:
    lines = log.splitlines()
    markers = ("error:", "fatal error:", "undefined reference", "undefined symbol", "No such file")
    hits = [i for i, line in enumerate(lines) if any(m in line for m in markers)]
    if not hits:
        return log[-limit:]
    selected: set[int] = set()
    for i in hits[-12:]:
        selected.update(range(max(0, i - 2), min(len(lines), i + 3)))
    return "\n".join(lines[i] for i in sorted(selected))[-limit:]


def visible_headers(candidate: str, source_root: Path, limit: int = 36000) -> str:
    names = re.findall(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', candidate, re.M)
    snippets: list[str] = []
    seen: set[Path] = set()
    if not source_root.is_dir():
        return ""
    wanted = {Path(name).name for name in names if Path(name).suffix.lower() in {".h", ".hh", ".hpp", ".hxx"}}
    matches: dict[str, list[Path]] = {name: [] for name in wanted}
    for path in source_root.rglob("*"):
        if path.name in wanted and len(matches[path.name]) < 2:
            matches[path.name].append(path)
    for name in names:
        for path in matches.get(Path(name).name, []):
            if path in seen or not path.is_file() or path.stat().st_size > 150000:
                continue
            seen.add(path)
            snippet = f"\n// Project header: {path.relative_to(source_root)}\n" + path.read_text(errors="replace")[:20000]
            if sum(map(len, snippets)) + len(snippet) > limit:
                return "".join(snippets)
            snippets.append(snippet)
    joined = "".join(snippets)
    proto_names = {Path(name).name.replace(".pb.h", ".proto")
                   for name in re.findall(r'#\s*include\s*[<"]([^>"]+\.pb\.h)[>"]', joined)}
    if proto_names:
        for path in source_root.rglob("*.proto"):
            if path.name in proto_names and path.is_file():
                snippet = f"\n// Project protobuf schema for generated header: {path.relative_to(source_root)}\n" + path.read_text(errors="replace")[:10000]
                if len(joined) + len(snippet) <= limit:
                    joined += snippet
                break
    return joined


def extract_code(response: str) -> str:
    blocks = re.findall(r"```(?:c\+\+|cpp|c|cc)?\s*\n(.*?)```", response, re.I | re.S)
    code = max(blocks, key=len) if blocks else response
    code = code.strip() + "\n"
    if "LLVMFuzzerTestOneInput" not in code or "#include" not in code:
        raise ValueError("model reply did not contain a complete fuzz driver")
    return code


def has_cpp_only_syntax_for_c_target(code: str) -> bool:
    guarded = re.sub(
        r'#\s*(?:ifdef\s+__cplusplus|if\s+defined\s*\(\s*__cplusplus\s*\))\s*\n'
        r'\s*extern\s+"C"\s*\n\s*#\s*endif', '', code,
    )
    return bool(re.search(r'extern\s+"C"|\bstd::|\breinterpret_cast\s*<|\bstatic_cast\s*<', guarded))


def adapt_public_fuzz_driver_abi(code: str, source_root: Path, native_destination: str) -> tuple[str, bool]:
    """Use OpenSSL's generator-visible fuzz/driver.c entrypoint contract."""
    if not native_destination.endswith("/fuzz/x509.c"):
        return code, False
    driver = source_root / "openssl/fuzz/driver.c"
    if not driver.is_file():
        return code, False
    public_contract = driver.read_text(errors="replace")
    if "return FuzzerTestOneInput(buf, len)" not in public_contract or "int LLVMFuzzerTestOneInput" not in public_contract:
        return code, False
    changed = False
    if re.search(r"\bLLVMFuzzerTestOneInput\s*\(", code) and not re.search(r"\bFuzzerTestOneInput\s*\(", code):
        code = re.sub(r"\bLLVMFuzzerTestOneInput\b", "FuzzerTestOneInput", code)
        changed = True
    if not re.search(r"\bFuzzerInitialize\s*\(", code):
        code += "\nint FuzzerInitialize(int *argc, char ***argv) { (void)argc; (void)argv; return 0; }\n"
        changed = True
    if not re.search(r"\bFuzzerCleanup\s*\(", code):
        code += "\nvoid FuzzerCleanup(void) {}\n"
        changed = True
    return code, changed


def repair(candidate: Path, build_log: Path, source_root: Path, output_dir: Path,
           api_selection: Path | None = None, native_destination: str = "",
           feedback_kind: str = "compiler") -> Path:
    from openai import OpenAI
    import hgb_llm_trace

    source = candidate.read_text(errors="replace")
    feedback = compiler_feedback(build_log.read_text(errors="replace"))
    headers = visible_headers(source, source_root)
    selected_names: list[str] = []
    if api_selection and api_selection.is_file():
        selected_names = [str(name) for name in json.loads(api_selection.read_text()).get("selected_api_names", [])]
    # A generated explanation can mention an API in a comment without
    # calling it. Preserve actual project calls, not those prose mentions.
    source_without_comments = re.sub(r"/\*.*?\*/|//[^\n]*", "", source, flags=re.S)
    original_calls = [name for name in selected_names if re.search(
        r"\b" + re.escape(name.split("::")[-1]) + r"\s*\(", source_without_comments)]
    native_c = Path(native_destination).suffix.lower() == ".c" or (
        not native_destination and bool(re.search(r"\.c:\d+:\d+:\s*(?:fatal\s+)?error:", feedback))
    )
    model = os.environ.get("CKGFUZZER_LLM_MODEL") or os.environ.get("HGB_LLM_MODEL") or os.environ.get("MODEL")
    key = os.environ.get("CKGFUZZER_API_KEY") or os.environ.get("HGB_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY") or os.environ.get("API_KEY")
    base = os.environ.get("CKGFUZZER_BASE_URL") or os.environ.get("HGB_LLM_BASE_URL") or os.environ.get("OPENAI_BASE_URL") or os.environ.get("BASE_URL")
    if not model or not key or not base:
        raise ValueError("CKGFuzzer chat model, key, or base URL is missing")
    language_rule = ("The target compiles the overlaid fuzz driver as C11. Return C source only: omit extern \"C\" "
                     "or guard it with #ifdef __cplusplus, and avoid "
                     "C++ headers, templates, namespaces, std::, and C++ casts.\n") if native_c else ""
    if feedback_kind not in {"compiler", "sanitizer_smoke"}:
        raise ValueError(f"unsupported feedback kind: {feedback_kind}")
    diagnostic_intro = (
        "Repair this CKGFuzzer-generated driver using the independent sanitizer smoke failure. "
        "Fix the actual runtime initialization or memory misuse. The real selected project APIs must still run "
        "on valid nonempty inputs; do not avoid the crash by returning before all project API calls. "
        if feedback_kind == "sanitizer_smoke" else
        "Repair this CKGFuzzer-generated driver using the independent FuzzBench compiler diagnostics. "
    )
    prompt = (
        diagnostic_intro +
        "Return the complete C/C++ source only. Keep LLVMFuzzerTestOneInput and derive API inputs from its data. "
        "Call real project symbols declared by project headers. Do not stub, mock, redefine, or reimplement "
        "project APIs or classes. Do not include nonexistent headers. Keep the driver's intended API coverage. "
        "A generated .pb.h header may be provided by the project build when its .proto schema is in the source tree.\n"
        + language_rule
        +
        f"The original candidate calls these selected project APIs, and the repair must still call them: {original_calls}.\n\n"
        f"{'Sanitizer smoke diagnostics' if feedback_kind == 'sanitizer_smoke' else 'Compiler diagnostics'}:\n{feedback}\n\nGenerated driver:\n{source[:24000]}\n\n"
        f"Generator-visible project headers (if found):\n{headers}"
    )
    client = OpenAI(api_key=key, base_url=base, timeout=float(os.environ.get("CKGFUZZER_LLM_REQUEST_TIMEOUT_SECONDS", "900")), max_retries=0)
    kwargs = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0}
    max_attempts = max(1, int(os.environ.get("CKGFUZZER_LLM_MAX_RETRIES", "3")))
    output_dir.mkdir(parents=True, exist_ok=True)
    repair_attempt_count = 0
    for attempt in range(max_attempts):
        try:
            reply = hgb_llm_trace.trace_call(
                lambda: client.chat.completions.create(**kwargs),
                stage="ckgfuzzer-feedback-repair", provider=os.environ.get("HGB_LLM_PROVIDER_RESOLVED", ""),
                operation="chat.completions.create", model=model, request=kwargs,
            )
        except Exception:
            if attempt + 1 >= max_attempts:
                raise
            hgb_llm_trace.record_retry(stage="ckgfuzzer-feedback-repair")
            time.sleep(min(30, 2 ** attempt))
            continue
        repair_attempt_count += 1
        hgb_llm_trace.record_driver_fix(stage="ckgfuzzer-feedback-repair")
        (output_dir / "repair_attempts.json").write_text(json.dumps({"count": repair_attempt_count}) + "\n")
        try:
            code = extract_code(reply.choices[0].message.content or "")
            if native_c and has_cpp_only_syntax_for_c_target(code):
                raise ValueError("target compiles the driver as C; C++ syntax remains")
            code_without_comments = re.sub(r"/\*.*?\*/|//[^\n]*", "", code, flags=re.S)
            missing_calls = [name for name in original_calls if not re.search(r"\b" + re.escape(name.split("::")[-1]) + r"\s*\(", code_without_comments)]
            if missing_calls:
                raise ValueError(f"model repair dropped required project API calls: {missing_calls}")
            code, abi_adapted = adapt_public_fuzz_driver_abi(code, source_root, native_destination)
            if abi_adapted:
                hgb_llm_trace.record_driver_fix(stage="ckgfuzzer-public-fuzz-abi")
            break
        except ValueError as exc:
            if attempt + 1 >= max_attempts:
                raise
            hgb_llm_trace.record_retry(stage="ckgfuzzer-feedback-repair")
            kwargs["messages"].append({"role": "user", "content": f"The previous revision was rejected: {exc}. Preserve every required real project API call and return the full corrected driver source."})
    output = output_dir / ("ckg_repaired_" + candidate.name)
    output.write_text(code)
    (output_dir / "repair_provenance.json").write_text(json.dumps({
        "source_candidate": str(candidate), "compiler_log": str(build_log),
        "output_candidate": str(output), "model": model,
        "native_destination": native_destination,
        "feedback_kind": feedback_kind,
        "public_fuzz_abi_adapted": abi_adapted,
        "repair_attempt_count": repair_attempt_count,
    }, indent=2) + "\n")
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--build-log", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--api-selection", type=Path)
    parser.add_argument("--native-destination", default="")
    parser.add_argument("--feedback-kind", choices=("compiler", "sanitizer_smoke"), default="compiler")
    args = parser.parse_args()
    print(repair(args.candidate, args.build_log, args.source_root, args.output_dir,
                 args.api_selection, args.native_destination, args.feedback_kind))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
