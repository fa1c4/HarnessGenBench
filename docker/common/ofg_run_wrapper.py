#!/usr/bin/env python3
"""Run upstream OSS-Fuzz-Gen with HGB-local compatibility shims."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def env_bool(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", default="/opt/hgb/artifacts/oss-fuzz-gen")
    parser.add_argument("upstream_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    upstream_args = list(args.upstream_args)
    if upstream_args and upstream_args[0] == "--":
        upstream_args = upstream_args[1:]

    artifact = Path(args.artifact).resolve()
    sys.path.insert(0, str(artifact))
    os.chdir(artifact)

    import run_all_experiments  # pylint: disable=import-error,import-outside-toplevel

    if env_bool("OFG_SKIP_COVERAGE_GAINS", "1"):

        def _skip_coverage_gains(*_args, **_kwargs):
            return None

        class _NoopProcess:
            def __init__(self, *_args, **_kwargs):
                pass

            def start(self) -> None:
                pass

            def kill(self) -> None:
                pass

        run_all_experiments.extend_report_with_coverage_gains = _skip_coverage_gains
        run_all_experiments.extend_report_with_coverage_gains_process = _skip_coverage_gains
        run_all_experiments._process_total_coverage_gain = lambda: {}
        run_all_experiments.Process = _NoopProcess

    sys.argv = ["run_all_experiments.py", *upstream_args]
    result = run_all_experiments.main()
    return int(result or 0)


if __name__ == "__main__":
    raise SystemExit(main())
