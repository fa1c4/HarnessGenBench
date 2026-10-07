# Target package preparation and reuse

Target preparation reuses a completed compatible package, including across
matrix run IDs. The cache defaults to `workspace/target-package-cache/` under
the configured workspace. Set `HGB_TARGET_PACKAGE_CACHE_DIR` to override it.

Compatibility includes the target, requested source revisions, benchmark
recipe metadata, packaging implementation, layout, profile/protocol, and
reference-isolation settings. Published manifests record the exact captured
source revisions. Benchmark files are checked by path, type, size, and
modification time; changing a recipe invalidates reuse. Source checkouts are
treated as acquisition caches, rather than editable package inputs.

Source revisions are frozen when a package is built. Reusing a package does
not fetch repositories, copy source trees, or advance unpinned upstream
branches. To refresh sources and build a new package version:

```sh
bash scripts/hgb_generate_matrix.sh --generators promefuzz --targets valuable \
  --run-id next-run --force-target-packages

bash scripts/hgb_prepare_target.sh --target jsoncpp_jsoncpp_fuzzer \
  --output workspace/targets/jsoncpp --force
```

Preparation logs whether each package was reused or rebuilt. Its stdout is
the immutable version directory; `--output` becomes a relative alias to that
version. Matrix workers keep the version directory so a later preparation
cannot redirect their inputs. Per-target locking serializes source acquisition
and packaging, including concurrent requests for different layouts.

Builds run in a staging directory. A completion marker is written only after
the build, and checked against the manifest and required package roots.
Interrupted builds are not reusable, and failed replacements preserve the
previous version. Old versions and replaced legacy directories are retained
because running containers may still use them; remove them only after their
consumers have finished. Existing legacy packages have no completion marker
and are rebuilt once rather than trusted as cache entries.

In compact packages, `generator_input/source_input/` is the single physical
generator source tree. The legacy top-level `source_input` path is a relative
alias. Docs, seeds, and dictionaries use the same arrangement. The source tree
remains independent of the artifact checkout, and references remain in the
evaluator half. Full packages retain the old independent-copy layout.
