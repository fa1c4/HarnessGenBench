#!/usr/bin/env bash
set -euo pipefail
# Minimal FuzzBench build recipe for offline evaluator tests.
cc -c "$SRC/project/sample.c" -o "$WORK/sample.o" 2>/dev/null || true
cc "$SRC/project/native.c" -o "$OUT/fuzz_target" 2>/dev/null || true
