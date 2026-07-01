.PHONY: check clone artifacts docker-build docker-smoke \
  docker-build-oss-fuzz-gen smoke-oss-fuzz-gen \
  docker-build-ckgfuzzer smoke-ckgfuzzer \
  docker-build-promefuzz smoke-promefuzz \
  docker-build-elfuzz smoke-elfuzz \
  docker-build-g2fuzz smoke-g2fuzz \
  targets target-smoke generate generate-dry-run generate-matrix

check:
	bash scripts/env_check.sh

clone artifacts:
	bash scripts/clone_artifacts.sh

docker-build: docker-build-oss-fuzz-gen docker-build-ckgfuzzer docker-build-promefuzz docker-build-elfuzz docker-build-g2fuzz

docker-smoke: smoke-oss-fuzz-gen smoke-ckgfuzzer smoke-promefuzz smoke-elfuzz smoke-g2fuzz

docker-build-oss-fuzz-gen:
	bash scripts/oss_fuzz_gen_setup.sh

smoke-oss-fuzz-gen:
	bash scripts/oss_fuzz_gen_smoke.sh

docker-build-ckgfuzzer:
	bash scripts/ckgfuzzer_setup.sh

smoke-ckgfuzzer:
	bash scripts/ckgfuzzer_smoke.sh

docker-build-promefuzz:
	bash scripts/promefuzz_build_docker.sh

smoke-promefuzz:
	bash scripts/promefuzz_smoke_pugixml.sh

docker-build-elfuzz:
	bash scripts/elfuzz_pull_image.sh

smoke-elfuzz:
	bash scripts/elfuzz_smoke_jsoncpp.sh

docker-build-g2fuzz:
	bash scripts/g2fuzz_setup.sh

smoke-g2fuzz:
	bash scripts/g2fuzz_generate_seeds.sh || true
	bash scripts/g2fuzz_smoke_afl.sh || true

targets:
	bash scripts/hgb_targets.sh list

target-smoke:
	bash scripts/hgb_target_smoke.sh $(TARGET)

generate:
	bash scripts/hgb_generate_harness.sh --generator $(GENERATOR) --target $(TARGET)

generate-dry-run:
	bash scripts/hgb_generate_harness.sh --generator $(GENERATOR) --target $(TARGET) --dry-run

generate-matrix:
	bash scripts/hgb_generate_matrix.sh --generators $(GENERATORS) --targets $(TARGETS)
