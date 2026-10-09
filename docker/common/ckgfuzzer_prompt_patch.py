#!/usr/bin/env python3
"""Keep upstream CKGFuzzer prompts anchored to the real project library.

The upstream generator remains responsible for API planning, driver generation,
and compilation repair. This patch only tells those model steps to avoid
reimplementing project symbols inside the driver, which can otherwise make a
mock harness compile while bypassing the actual library.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


GENERATOR_REL = Path("fuzzing_llm_engine/roles/fuzz_generator.py")
FIXER_REL = Path("fuzzing_llm_engine/roles/compilation_fix_agent.py")
GENERATOR_ANCHOR = '            "I will provide the API combination, headers, API source code, and API summary below.\\n"'
GENERATOR_RULE = (
    '            "12. Call the real project library symbols. Do not define, stub, mock, or reimplement a project API '
    'or project class inside the fuzz driver.\\n"\n'
    '            "13. Use declarations from actual project headers; do not invent API names, signatures, or type '
    'definitions to make the driver compile.\\n"\n'
    '            "14. Include only project headers that exist in the supplied source tree; an invented include path '
    'will fail the independent project build.\\n"\n'
    '            "15. Put extern \\"C\\" for LLVMFuzzerTestOneInput inside a #ifdef __cplusplus / #endif guard so the same driver also compiles as C.\\n"\n'
)
FIXER_ANCHOR = '        "8. Add brief comments explaining your changes.\\n"'
FIXER_RULE = (
    '        "9. Keep calls to the real project library. Do not add project API stubs, mock classes, or replacement '
    'definitions to silence compiler or linker errors.\\n"\n'
)
DRIVER_FALLBACK_ANCHOR = "            if api_list_proc:\n                fuzz_driver_generation_response = self.fuzz_driver_generation"
DRIVER_FALLBACK_RULE = (
    "            # CodeQL can recover a callable body even when summary extraction\n"
    "            # did not populate the matching file bucket. Keep the planned API.\n"
    "            if not api_list_proc:\n"
    "                for api in api_list:\n"
    "                    body = api_code.get(api)\n"
    "                    if body:\n"
    "                        api_list_proc.append(api)\n"
    "                        api_info += f'\\n{api}:\\n{body}'\n"
)


def patch_file(path: Path, anchor: str, rule: str, expected_count: int) -> bool:
    source = path.read_text(encoding="utf-8")
    if rule.strip() in source:
        return False
    found = source.count(anchor)
    if found != expected_count:
        raise ValueError(f"{path}: expected {expected_count} prompt anchors, found {found}")
    path.write_text(source.replace(anchor, rule + anchor), encoding="utf-8")
    return True


def patch_artifact(root: Path) -> dict[str, bool]:
    paths = ((GENERATOR_REL, GENERATOR_ANCHOR, GENERATOR_RULE),
             (FIXER_REL, FIXER_ANCHOR, FIXER_RULE))
    for rel, anchor, rule in paths:
        source = (root / rel).read_text(encoding="utf-8")
        if rule.strip() not in source and source.count(anchor) != 2:
            raise ValueError(f"{rel}: upstream prompt shape changed")
    result = {str(rel): patch_file(root / rel, anchor, rule, 2) for rel, anchor, rule in paths}
    generator = root / GENERATOR_REL
    result["driver_summary_fallback"] = patch_file(generator, DRIVER_FALLBACK_ANCHOR, DRIVER_FALLBACK_RULE, 1)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args()
    print(json.dumps(patch_artifact(args.artifact), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
