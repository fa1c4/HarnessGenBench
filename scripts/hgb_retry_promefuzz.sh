#!/usr/bin/env bash
# Retry the remaining valuable PromeFuzz targets until every target evaluates.
#
# Gates on BOTH Docker container starts and the local TEI embedding service so a
# dead daemon or an exited embedding container cannot waste a whole round.
set -uo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."
[[ -f configs/set_api_key_ds.sh ]] || { printf 'missing configs/set_api_key_ds.sh\n' >&2; exit 2; }
source configs/set_api_key_ds.sh
export HGB_API_KEY_CONFIG="$PWD/configs/set_api_key_ds.sh"
export HGB_SKIP_IMAGE_PREFLIGHT=1
export PROME_FUZZ_EVAL_MAX_CANDIDATES=4

TARGETS="${HGB_RETRY_TARGETS:-freetype2_ftfuzzer,libxml2_xml,openssl_x509,php_php-fuzz-parser_0dbedb,systemd_fuzz-link-parser}"
image="hgb-promefuzz:655d2d98fc30"
embedding_container="hgb-local-embedding"
log="${HGB_PROME_RETRY_LOG:-workspace/promefuzz_final.log}"
lock="workspace/promefuzz/.retry_runner.lock"

exec 8>"$lock"
flock -n 8 || { echo "another retry runner is active" >>"$log"; exit 0; }

log_line() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$log"; }

unresolved_targets() {
  python3 - "$TARGETS" <<'PY'
import glob
import json
import sys

pending = []
for target in filter(None, sys.argv[1].split(',')):
    evaluated = False
    for path in glob.iglob('workspace/promefuzz/' + target + '/*/metadata.json'):
        try:
            with open(path, encoding='utf-8') as handle:
                if json.load(handle).get('status') == 'evaluated':
                    evaluated = True
                    break
        except (OSError, ValueError):
            continue
    if not evaluated:
        pending.append(target)
print(','.join(pending))
PY
}

docker_ok() {
  timeout 40 docker run --rm --pull=never --entrypoint /bin/true "$image" >/dev/null 2>&1
}

embedding_ok() {
  curl -fsS --max-time 5 http://127.0.0.1:18080/health >/dev/null 2>&1
}

wait_services() {
  local attempt=0
  while :; do
    attempt=$((attempt + 1))
    if ! embedding_ok; then
      timeout 60 docker start "$embedding_container" >/dev/null 2>&1 || true
    fi
    if embedding_ok && docker_ok; then
      log_line "services healthy (poll $attempt)"
      return 0
    fi
    (( attempt % 20 == 0 )) && log_line "waiting for services (docker/embedding) poll $attempt"
    sleep 30
  done
}

round=0
remaining="$(unresolved_targets)"
log_line "runner started; unresolved=$remaining"
while [[ -n "$remaining" ]]; do
  round=$((round + 1))
  log_line "round $round: waiting for services; targets=$remaining"
  if ! wait_services; then log_line "services never healthy; abort"; exit 1; fi
  runid="final_r${round}_$(date -u +%Y%m%dT%H%M%SZ)"
  log_line "round $round: launching matrix $runid"
  HGB_SKIP_IMAGE_PREFLIGHT=1 PROME_FUZZ_EVAL_MAX_CANDIDATES=4 \
    bash scripts/hgb_generate_matrix.sh \
      --generators promefuzz \
      --targets "$remaining" \
      --parallel-worker 5 \
      --profile alpha \
      --protocol blind-project \
      --run-id "$runid" >>"$log" 2>&1
  mdir="workspace/matrix/$runid"
  retry_delay=300
  if [[ -f "$mdir/matrix.tsv" ]]; then
    while IFS=$'\t' read -r g t st ws meta summary; do
      [[ "$g" == "generator" || -z "$g" ]] && continue
      reason="$(python3 - "$meta" <<'PY'
import json,sys
try:
    reason = json.load(open(sys.argv[1])).get('reason', '')
except (OSError, ValueError):
    reason = ''
print(' '.join(str(reason).split())[:300])
PY
)"
      if [[ "${st,,} ${reason,,}" == *rate_limit* || "${st,,} ${reason,,}" == *"rate limit"* || "${st,,} ${reason,,}" == *quota* || "${st,,} ${reason,,}" == *"429"* ]]; then
        retry_delay=1800
      fi
      log_line "round $round result: $t=$st reason=$reason"
    done < <(tail -n +2 "$mdir/matrix.tsv")
  fi
  # Matrix parents can be interrupted after children write metadata but before
  # their TSV rows are collected. Use completed per-target metadata as the
  # source of truth, and never treat a header-only matrix as success.
  remaining="$(unresolved_targets)"
  if [[ -z "$remaining" ]]; then log_line "round $round: all remaining targets evaluated"; break; fi
  log_line "round $round: still failing -> $remaining; sleeping ${retry_delay}s before retry"
  sleep "$retry_delay"
done
log_line "runner finished after $round round(s); remaining=$remaining"
