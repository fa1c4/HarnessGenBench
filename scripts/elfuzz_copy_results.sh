#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

extract_json_string() {
  local key="$1"
  local file="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$file" | head -n 1
}

extract_stage_code() {
  local key="$1"
  local file="$2"
  sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p" "$file" | head -n 1
}

container_running() {
  local name="$1"
  [[ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)" == "true" ]]
}

stage_code_from_run() {
  local run_dir="$1"
  local stage="$2"
  local metadata_file="$run_dir/metadata.json"
  local code=""
  if [[ -f "$metadata_file" ]]; then
    code="$(extract_stage_code "$stage" "$metadata_file")"
  fi
  if [[ -z "$code" && -f "$run_dir/logs/$stage.exit" ]]; then
    code="$(cat "$run_dir/logs/$stage.exit")"
  fi
  [[ -n "$code" ]] || code="unknown"
  printf '%s' "$code"
}

top_failure_reason() {
  local run_dir="$1"
  local stages=(setup download hf_config synth produce seed_cov afl copy_to_host)
  local stage code log_file
  for stage in "${stages[@]}"; do
    code="$(stage_code_from_run "$run_dir" "$stage")"
    if [[ "$code" != "0" && "$code" != "unknown" && "$code" != "not_run" ]]; then
      if [[ "$code" == "124" ]]; then
        printf 'stage %s timed out with exit code 124' "$stage"
        return
      fi
      log_file="$run_dir/logs/$stage.log"
      if [[ -f "$log_file" ]]; then
        if grep -qiE 'hugging|HF_TOKEN|token|401|403|unauthorized|model|tgi|download|zenodo|no space|storage|docker|permission|error|failed|traceback' "$log_file"; then
          grep -iE 'hugging|HF_TOKEN|token|401|403|unauthorized|model|tgi|download|zenodo|no space|storage|docker|permission|error|failed|traceback' "$log_file" | head -n 1
        else
          tail -n 1 "$log_file"
        fi
      else
        printf 'stage %s failed with exit code %s' "$stage" "$code"
      fi
      return
    fi
  done
  printf 'none'
}

copy_from_container() {
  local root="$1"
  local container="$2"
  local target="$3"
  local host_tmp="$root/${HGB_RESULTS_DIR:-results}/elfuzz/host-tmp"
  local command_text

  command_text='
set -euo pipefail
export ELFUZZ_TARGET="'"$target"'"
rm -rf /tmp/host/hgb-elfuzz-export
mkdir -p /tmp/host/hgb-elfuzz-export
cd /home/appuser/elmfuzz
for dir in analysis/rq1/results analysis/rq2/results analysis/rq3/results plot/fig plot/table evaluation/elmfuzzers evaluation/alt_elmfuzzers evaluation/nocomp_fuzzers evaluation/noinf_fuzzers evaluation/nospl_fuzzers extradata/produce_info extradata/evolution_record; do
  if [ -d "$dir" ]; then
    find "$dir" -maxdepth 4 -type f \( -name "*.xlsx" -o -name "*.csv" -o -name "*.txt" -o -name "*.log" -o -name "*.tar.xz" -o -name "*.tar.zst" \) -size -50M -exec cp --parents {} /tmp/host/hgb-elfuzz-export/ \;
  fi
done
if [ -d "preset/$ELFUZZ_TARGET" ]; then
  find "preset/$ELFUZZ_TARGET" -path "*/seeds/*" -type f \( -name "*.py" -o -name "*.rs" -o -name "*.cc" -o -name "*.c" \) -size -5M -exec cp --parents {} /tmp/host/hgb-elfuzz-export/ \;
fi
find /tmp/host/hgb-elfuzz-export -type f | sort > /tmp/host/hgb-elfuzz-export/manifest.txt
'
  if container_running "$container"; then
    docker exec "$container" bash -lc "$command_text" >/dev/null 2>&1 || true
  fi
  [[ -d "$host_tmp/hgb-elfuzz-export" ]] || return 1
}

main() {
  local root run_dir export_dir summary_file metadata_file image repo_digests container target
  local setup_status download_status synth_status produce_status seed_cov_status afl_status
  local failed_stages top_failure copied_count host_tmp timestamp
  local stages=(setup restart_after_setup download hf_config synth produce seed_cov afl copy_to_host)
  local stage code

  root="$(repo_root)"
  load_env
  require_cmd docker

  run_dir="${1:-}"
  if [[ -z "$run_dir" ]]; then
    run_dir="$(find "$root/${HGB_RESULTS_DIR:-results}/elfuzz" -maxdepth 1 -type d -name 'smoke_*' 2>/dev/null | sort | tail -n 1 || true)"
  fi
  [[ -n "$run_dir" ]] || run_dir="$root/${HGB_RESULTS_DIR:-results}/elfuzz"
  [[ "$run_dir" = /* ]] || run_dir="$root/$run_dir"

  metadata_file="$run_dir/metadata.json"
  image="${ELFUZZ_IMAGE:-ghcr.io/osuseclab/elfuzz:25.08.0}"
  container="${ELFUZZ_CONTAINER:-elfuzz-hgb}"
  target="${ELFUZZ_TARGET:-jsoncpp}"
  repo_digests="$(docker image inspect -f '{{join .RepoDigests ","}}' "$image" 2>/dev/null || true)"
  if [[ -f "$metadata_file" ]]; then
    image="$(extract_json_string image "$metadata_file")"
    container="$(extract_json_string container "$metadata_file")"
    target="$(extract_json_string target "$metadata_file")"
    repo_digests="$(extract_json_string repo_digests "$metadata_file")"
  fi
  [[ -n "$image" ]] || image="${ELFUZZ_IMAGE:-ghcr.io/osuseclab/elfuzz:25.08.0}"
  [[ -n "$container" ]] || container="${ELFUZZ_CONTAINER:-elfuzz-hgb}"
  [[ -n "$target" ]] || target="${ELFUZZ_TARGET:-jsoncpp}"

  copy_from_container "$root" "$container" "$target" || true

  timestamp="$(make_timestamp)"
  export_dir="$root/${HGB_RESULTS_DIR:-results}/elfuzz/export_$timestamp"
  ensure_dir "$export_dir"
  host_tmp="$root/${HGB_RESULTS_DIR:-results}/elfuzz/host-tmp"
  if [[ -d "$host_tmp/hgb-elfuzz-export" ]]; then
    cp -a "$host_tmp/hgb-elfuzz-export/." "$export_dir/"
  elif [[ -d "$run_dir/artifacts/hgb-elfuzz-smoke" ]]; then
    cp -a "$run_dir/artifacts/hgb-elfuzz-smoke/." "$export_dir/"
  fi
  copied_count="$(find "$export_dir" -type f 2>/dev/null | wc -l | tr -d ' ')"

  setup_status="$(stage_code_from_run "$run_dir" setup)"
  download_status="$(stage_code_from_run "$run_dir" download)"
  synth_status="$(stage_code_from_run "$run_dir" synth)"
  produce_status="$(stage_code_from_run "$run_dir" produce)"
  seed_cov_status="$(stage_code_from_run "$run_dir" seed_cov)"
  afl_status="$(stage_code_from_run "$run_dir" afl)"

  failed_stages=""
  for stage in "${stages[@]}"; do
    code="$(stage_code_from_run "$run_dir" "$stage")"
    if [[ "$code" != "0" && "$code" != "unknown" ]]; then
      failed_stages="${failed_stages} $stage=$code"
    fi
  done
  [[ -n "$failed_stages" ]] || failed_stages=" none"
  top_failure="$(top_failure_reason "$run_dir")"

  summary_file="$export_dir/HGB_SUMMARY.md"
  {
    printf '# HarnessGenBench ELFuzz Summary\n\n'
    printf -- '- Source run directory: `%s`\n' "$run_dir"
    printf -- '- Export directory: `%s`\n' "$export_dir"
    printf -- '- Image: `%s`\n' "$image"
    printf -- '- Image digest: `%s`\n' "${repo_digests:-unknown}"
    printf -- '- Container: `%s`\n' "$container"
    printf -- '- Target: `%s`\n' "$target"
    printf -- '- Setup status: `%s`\n' "$setup_status"
    printf -- '- Download status: `%s`\n' "$download_status"
    printf -- '- Synthesis status: `%s`\n' "$synth_status"
    printf -- '- Seed production status: `%s`\n' "$produce_status"
    printf -- '- Seed coverage status: `%s`\n' "$seed_cov_status"
    printf -- '- AFL++ status: `%s`\n' "$afl_status"
    printf -- '- Copied report/artifact files: %s\n' "$copied_count"
    printf -- '- Failed stages:%s\n' "$failed_stages"
    printf -- '- Top failure reason: %s\n' "$top_failure"
    printf '\n## Copied Files\n\n'
    find "$export_dir" -type f 2>/dev/null | sort | sed "s#^$export_dir/##" | head -100 | sed 's/^/- `/' | sed 's/$/`/'
  } >"$summary_file"

  if [[ -d "$run_dir" ]]; then
    cp "$summary_file" "$run_dir/HGB_SUMMARY.md" 2>/dev/null || true
  fi

  log "Wrote $summary_file"
}

main "$@"
