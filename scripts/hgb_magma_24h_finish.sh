#!/usr/bin/env bash
# Finish the 24 h matrix: coverage replay for every trial, then render the
# five-trial table with mean +/- stdev and crashes.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/hgb_magma_24h.py \
  --manifest workspace/magma/selection_24h.json \
  --batch magma24h2 --phase coverage --workers 150
python3 scripts/hgb_magma_baselines_5times.py --batch magma24h2 --min-trials 5
