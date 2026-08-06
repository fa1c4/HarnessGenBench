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
    intended_set = {name.split("(")[0].strip() for name in intended if name}
    return sorted(intended_set & executed)


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
