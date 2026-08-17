#!/usr/bin/env python3
"""API reachability checking for generated fuzz drivers.

The evaluator must confirm that at least one intended project API actually
executes during smoke or corpus replay.  Intended APIs come from the CKGFuzzer
generation plan/API combination -- never from the reference harness.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable


class ReachabilityError(RuntimeError):
    """Raised when intended APIs cannot be determined."""


def extract_intended_apis(plan: dict[str, Any] | str | Path) -> list[str]:
    """Return the intended API names from a CKGFuzzer generation plan.

    Accepts a parsed dict, a JSON string, or a path to a JSON file.  Looks for
    common plan shapes: ``api_combination``, ``api_list``, ``planned_apis``,
    ``selected_apis``, or a top-level list of API dicts/strings.
    """

    if isinstance(plan, (str, Path)):
        path = Path(plan)
        if path.is_file():
            try:
                plan = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ReachabilityError(f"cannot parse plan JSON {plan}: {exc}") from exc
        else:
            try:
                plan = json.loads(str(plan))
            except json.JSONDecodeError as exc:
                raise ReachabilityError(f"cannot parse plan JSON: {exc}") from exc

    if isinstance(plan, list):
        return _normalize_api_list(plan)
    if not isinstance(plan, dict):
        raise ReachabilityError("plan is not a dict or list")

    for key in ("api_combination", "planned_apis", "selected_apis", "api_list", "apis"):
        value = plan.get(key)
        if isinstance(value, list) and value:
            return _normalize_api_list(value)
        if isinstance(value, dict) and value:
            # api_combination can be keyed by group id -> list of apis
            nested: list[Any] = []
            for item in value.values():
                if isinstance(item, list):
                    nested.extend(item)
                else:
                    nested.append(item)
            if nested:
                return _normalize_api_list(nested)
    # Fallback: any ``api``/``name`` fields in a flat structure.
    flat = []
    for entry in plan.get("candidates", []) if isinstance(plan.get("candidates"), list) else []:
        if isinstance(entry, dict):
            for key in ("api", "name", "function"):
                if entry.get(key):
                    flat.append(entry[key])
    if flat:
        return _normalize_api_list(flat)
    raise ReachabilityError("could not find intended APIs in generation plan")


def _normalize_api_list(items: Iterable[Any]) -> list[str]:
    out: list[str] = []
    for item in items:
        if isinstance(item, str):
            name = item.strip()
            if name:
                out.append(name)
        elif isinstance(item, dict):
            for key in ("api", "name", "function", "symbol"):
                value = item.get(key)
                if isinstance(value, str) and value.strip():
                    out.append(value.strip())
                    break
    return out


def _strip_signature(name: str) -> str:
    return name.split("(", 1)[0].strip()


def _symbol_names(symbol: str) -> set[str]:
    """Return comparable API names from a raw/qualified/mangled symbol."""

    raw = _strip_signature(symbol.strip())
    if not raw:
        return set()
    names = {raw}
    # Demangled C++ and qualified C names.
    for sep in ("::", "."):
        if sep in raw:
            last = raw.rsplit(sep, 1)[-1]
            if last:
                names.add(last)
    # Some OSS-Fuzz builds rename public project symbols with a stable prefix
    # during sanitizer/link isolation, while coverage still reports the renamed
    # symbol. Preserve the original and add the public API spelling.
    for prefix in ("OSS_FUZZ_",):
        if raw.startswith(prefix) and len(raw) > len(prefix):
            names.add(raw[len(prefix):])
    # Itanium C++ ABI mangling stores identifiers as length-prefixed
    # components, e.g. _ZN6bloaty10BloatyMainERK... -> bloaty, BloatyMain.
    mangled = raw
    if mangled.startswith("_Z"):
        i = 2
        if i < len(mangled) and mangled[i] == "N":
            i += 1
        while i < len(mangled):
            if mangled[i] == "E":
                break
            match = re.match(r"(\d+)", mangled[i:])
            if not match:
                i += 1
                continue
            length = int(match.group(1))
            i += len(match.group(1))
            if length <= 0 or i + length > len(mangled):
                break
            component = mangled[i:i + length]
            if component:
                names.add(component)
            i += length
    return names


def reached_apis_from_trace(trace: dict[str, Any] | str | Path, intended: list[str]) -> list[str]:
    """Return the subset of intended APIs that appear in a dynamic trace.

    ``trace`` may be a dict with ``executed_functions``/``covered_functions``,
    a JSON file/string, or a plain text symbol/coverage trace.
    """

    executed: set[str] = set()
    if isinstance(trace, (str, Path)):
        path = Path(trace)
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    for key in ("executed_functions", "covered_functions", "functions", "symbols"):
                        value = data.get(key)
                        if isinstance(value, list):
                            executed.update(_normalize_api_list(value))
                elif isinstance(data, list):
                    executed.update(_normalize_api_list(data))
            except json.JSONDecodeError:
                # Treat as a plain text symbol trace: one symbol per line.
                for line in text.splitlines():
                    token = line.strip().split()[0] if line.strip() else ""
                    if token:
                        executed.add(token)
        else:
            for line in str(trace).splitlines():
                token = line.strip().split()[0] if line.strip() else ""
                if token:
                    executed.add(token)
    elif isinstance(trace, dict):
        for key in ("executed_functions", "covered_functions", "functions", "symbols"):
            value = trace.get(key)
            if isinstance(value, list):
                executed.update(_normalize_api_list(value))
    intended_names: dict[str, set[str]] = {}
    for name in intended:
        clean = _strip_signature(name) if name else ""
        if clean:
            intended_names[clean] = _symbol_names(clean)
    executed_names: set[str] = set()
    for symbol in executed:
        executed_names.update(_symbol_names(symbol))
    return sorted(
        intended_name
        for intended_name, aliases in intended_names.items()
        if aliases & executed_names
    )


def check_reachability(intended: list[str], trace: dict[str, Any] | str | Path) -> dict[str, Any]:
    """Return a reachability report dict.

    ``reached`` is True iff at least one intended API executed dynamically.
    """
    reached = reached_apis_from_trace(trace, intended)
    return {
        "intended_apis": intended,
        "reached_apis": reached,
        "reached": len(reached) > 0,
        "reached_count": len(reached),
    }


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Check API reachability")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--trace", required=True)
    args = parser.parse_args()
    intended = extract_intended_apis(args.plan)
    result = check_reachability(intended, args.trace)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["reached"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
