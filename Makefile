.PHONY: check clone artifacts docker-build docker-smoke \
  docker-build-oss-fuzz-gen smoke-oss-fuzz-gen \
  docker-build-ckgfuzzer smoke-ckgfuzzer \
  docker-build-promefuzz smoke-promefuzz \
  docker-build-elfuzz smoke-elfuzz \
  docker-build-g2fuzz smoke-g2fuzz

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
