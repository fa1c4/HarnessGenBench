import os
import subprocess
from pathlib import Path


def test_elfuzz_target_adapter_uses_live_source_and_manifest_driven_workflow() -> None:
    entrypoint = Path("docker/elfuzz/entrypoint.sh").read_text(encoding="utf-8")
    pipeline = Path("docker/common/elfuzz_target_pipeline.py").read_text(encoding="utf-8")

    assert "find_elfuzz_project_root" in entrypoint
    assert "/home/appuser/elmfuzz" in entrypoint
    assert "patch_elfuzz_sibling_paths" in entrypoint
    assert "ELFUZZ_HOST_SHARED_DIR" in entrypoint
    assert "elfuzz_target_pipeline.py full" in entrypoint
    assert "task_family" in pipeline
    assert "input_generator" in pipeline
    assert "rq1.afl" in pipeline
    assert "synthesis/fuzzer_programs" in pipeline
    assert "generated_inputs/produced" in pipeline
    assert "campaign/queue" in pipeline


def test_elfuzz_runner_mounts_a_private_sibling_container_directory() -> None:
    common = Path("scripts/lib/common.sh").read_text(encoding="utf-8")
    matrix = Path("scripts/hgb_generate_matrix.sh").read_text(encoding="utf-8")

    assert "elfuzz_shared_dir" in common
    assert "ELFUZZ_TGI_CACHE_DIR" in common
    assert "host.docker.internal:host-gateway" in common
    assert "serializing ELFuzz targets" in matrix
    assert "active_parallel_worker=1" in matrix
    assert "generator_supports_target" in matrix
    assert "record_not_applicable_target" in matrix
    assert matrix.index('if preflight_generator "$generator"; then') < matrix.index('prepare_shared_target_packages "${eligible_targets[@]}"')


def test_image_build_reports_layerdb_collision_without_auto_pruning() -> None:
    common = Path("scripts/lib/common.sh").read_text(encoding="utf-8")

    assert "Docker image storage has a layerdb collision" in common
    assert "HGB will not prune or alter /data/docker automatically" in common
    assert "HGB_RETRY_DOCKER_LAYERDB_BUILD" in common
    assert "hgb_previous_docker_layerdb_collision_log" in common


def test_layerdb_collision_guard_skips_a_repeat_build(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    command = r'''source scripts/lib/common.sh
docker() {
  case "$1" in
    info) return 0 ;;
    build)
      printf '%s\n' 'failed to register layer: layerdb file exists'
      return 37
      ;;
    image) return 1 ;;
  esac
  return 0
}
first=0
second=0
hgb_build_image elfuzz elfuzz "$PWD" >/dev/null || first=$?
hgb_build_image elfuzz elfuzz "$PWD" >/dev/null || second=$?
[[ "$first" == "37" ]]
[[ "$second" == "75" ]]
'''
    result = subprocess.run(
        ["bash", "-c", command],
        cwd=repo_root,
        env=os.environ | {"HGB_WORKSPACE_DIR": str(tmp_path / "workspace")},
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stderr.count("Docker build failed for") == 1
    assert "was skipped after a prior layerdb collision" in result.stderr
