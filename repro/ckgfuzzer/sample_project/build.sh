#!/usr/bin/env bash
set -euo pipefail
cc -Wall -Wextra -I. sample.c test_usage/example_usage.c -o /tmp/hgb_sample_usage
/tmp/hgb_sample_usage
