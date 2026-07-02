#!/usr/bin/env bash
set -euo pipefail

artifact=/opt/hgb/artifacts/promefuzz
python=/opt/hgb/venv/bin/python
workspace=/workspace

fix_workspace_permissions() {
  if [[ -n "${HGB_HOST_UID:-}" && -n "${HGB_HOST_GID:-}" ]] && command -v chown >/dev/null 2>&1; then
    chown -R "${HGB_HOST_UID}:${HGB_HOST_GID}" "$workspace" 2>/dev/null || true
  fi
}
trap fix_workspace_permissions EXIT
mode="${1:-smoke-pugixml}"
mkdir -p "$workspace/logs" "$workspace/artifacts" /run/hgb
json_escape() { local v="${1:-}"; v="${v//\\/\\\\}"; v="${v//\"/\\\"}"; v="${v//$'\n'/\\n}"; printf '%s' "$v"; }
count_files() { local d="$1"; shift || true; [[ -d "$d" ]] || { printf '0'; return 0; }; find "$d" "$@" 2>/dev/null | wc -l | tr -d ' '; }
commit() { git -C "$artifact" rev-parse HEAD 2>/dev/null || printf unknown; }
promefuzz_processors_ready() {
  [[ -x "$1/build/bin/preprocessor" && -x "$1/build/bin/cgprocessor" ]]
}
compile_db_has_entries() {
  local db="$1"
  [[ -f "$db" ]] || return 1
  python3 - "$db" <<'PY_COMPILE_DB_CHECK' >/dev/null 2>&1
import json
import sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.exit(1)
sys.exit(0 if isinstance(data, list) and len(data) > 0 else 1)
PY_COMPILE_DB_CHECK
}
write_synthetic_compile_db() {
  local db="$1" language="$2" project="$3"
  mkdir -p "$(dirname "$db")"
  python3 - "$db" "$language" "$project" <<'PY_SYNTHETIC_COMPILE_DB'
import json
import shlex
import sys
from pathlib import Path

db, language, project = sys.argv[1:4]
root = Path("/target/source_input")
source_exts = {".c", ".cc", ".cpp", ".cxx"}
header_exts = {".h", ".hh", ".hpp", ".hxx"}
ignored_parts = {
    ".git",
    ".hg",
    ".svn",
    "build",
    "cmake-build-debug",
    "cmake-build-release",
    "out",
    "workspace",
}
include_dirs: list[Path] = []

def add_include(path: Path) -> None:
    if path.exists() and path.is_dir() and path not in include_dirs:
        include_dirs.append(path)

add_include(root)
if project:
    add_include(root / project)
    add_include(root / project / "include")
    add_include(root / project / "src")
for child in (root.rglob("*") if root.exists() else []):
    if not child.is_dir():
        continue
    if any(part in ignored_parts for part in child.parts):
        continue
    if child.name in {"include", "inc", "src"}:
        add_include(child)
for header in (root.rglob("*") if root.exists() else []):
    if len(include_dirs) >= 120:
        break
    if header.is_file() and header.suffix.lower() in header_exts:
        if not any(part in ignored_parts for part in header.parts):
            add_include(header.parent)

include_args = [f"-I{path}" for path in include_dirs]
entries = []
for source in sorted(root.rglob("*") if root.exists() else []):
    if not source.is_file() or source.suffix.lower() not in source_exts:
        continue
    if any(part in ignored_parts for part in source.parts):
        continue
    suffix = source.suffix.lower()
    is_c = suffix == ".c" and language == "c"
    compiler = "clang" if is_c else "clang++"
    std = "-std=c11" if is_c else "-std=c++17"
    args = [compiler, std, "-D_FORTIFY_SOURCE=0", *include_args, "-c", str(source), "-o", "/tmp/hgb-promefuzz-null.o"]
    entries.append({
        "directory": str(source.parent),
        "file": str(source),
        "arguments": args,
        "command": shlex.join(args),
    })
Path(db).write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
print(len(entries))
PY_SYNTHETIC_COMPILE_DB
}
write_config() {
  local cfg=/run/hgb/promefuzz_config.toml
  if [[ -f "$artifact/config.template.toml" ]]; then
    cp "$artifact/config.template.toml" "$cfg"
  else
    printf '[llm]\n' >"$cfg"
  fi
  cat >>"$cfg" <<EOF

# HarnessGenBench runtime-only LLM configuration. Not mounted to host.
[llm.hgb_cloud]
llm_type = "openai"
base_url = "${OPENAI_BASE_URL:-${BASE_URL:-https://api.openai.com/v1}}"
api_key = "${OPENAI_API_KEY:-${API_KEY:-}}"
model = "${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
EOF
  printf '%s\n' "$cfg"
}
summary() {
  local status="$1" code="$2" reason="$3"
  {
    printf '# HarnessGenBench PromeFuzz Summary\n\n'
    printf -- '- Run directory: `%s`\n' "$workspace"
    printf -- '- Upstream commit: `%s`\n' "$(commit)"
    printf -- '- Target: `pugixml`\n'
    printf -- '- Status: `%s`\n' "$status"
    printf -- '- Exit code: `%s`\n' "$code"
    printf -- '- API key present: `%s`\n' "$([[ -n "${OPENAI_API_KEY:-${API_KEY:-}}" ]] && printf true || printf false)"
    printf -- '- Generated fuzz-driver count: %s\n' "$(count_files "$workspace" -type f \( -name 'fuzz_driver_*.c' -o -name 'fuzz_driver_*.cc' -o -name 'fuzz_driver_*.cpp' \))"
    printf -- '- Top failure reason: %s\n' "$reason"
    printf '\n## Logs\n\n'
    find "$workspace/logs" -type f 2>/dev/null | sort | sed "s#^$workspace/##" | sed 's/^/- `/' | sed 's/$/`/'
  } >"$workspace/HGB_SUMMARY.md"
}
metadata() {
  local status="$1" code="$2" reason="$3" cfg="$4"
  {
    printf '{\n'
    printf '  "fuzzer": "promefuzz",\n'
    printf '  "status": "%s",\n' "$(json_escape "$status")"
    printf '  "upstream_commit": "%s",\n' "$(json_escape "$(commit)")"
    printf '  "target": "pugixml",\n'
    printf '  "api_key_present": %s,\n' "$([[ -n "${OPENAI_API_KEY:-${API_KEY:-}}" ]] && printf true || printf false)"
    printf '  "runtime_config": "%s",\n' "$(json_escape "$cfg")"
    printf '  "exit_code": %s,\n' "$code"
    printf '  "reason": "%s",\n' "$(json_escape "$reason")"
    printf '  "command_file": "%s",\n' "$(json_escape "$workspace/command.txt")"
    printf '  "log_file": "%s"\n' "$(json_escape "$workspace/logs/run.log")"
    printf '}\n'
  } >"$workspace/metadata.json"
}

if [[ "$mode" == "generate-target" ]]; then
  # shellcheck source=/opt/hgb/bin/target_contract.sh
  source /opt/hgb/bin/target_contract.sh
  export HGB_GENERATOR="${HGB_GENERATOR:-promefuzz}"
  export HGB_GENERATOR_ARTIFACT_DIR="$artifact"
  export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
  export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
  export OPENAI_MODEL="${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
  export PROME_FUZZ_SKIP_BAD_DOCS="${PROME_FUZZ_SKIP_BAD_DOCS:-1}"
  export NLTK_DATA="${NLTK_DATA:-/opt/hgb/nltk_data}"
  mkdir -p "$workspace/logs" "$workspace/generated_harnesses" "$workspace/promefuzz_out" /run/hgb/promefuzz
  hgb_require_target_package
  target_name="${HGB_TARGET:-$(hgb_target_manifest_value target)}"
  project="${HGB_TARGET_PROJECT:-$(hgb_target_manifest_value project)}"
  safe_target="$(printf '%s' "$target_name" | sed 's/[^A-Za-z0-9_]/_/g')"
  language="c++"
  if find /target/source_input -type f \( -name '*.c' -o -name '*.h' \) 2>/dev/null | grep -q . && ! find /target/source_input -type f \( -name '*.cc' -o -name '*.cpp' -o -name '*.cxx' -o -name '*.hpp' \) 2>/dev/null | grep -q .; then
    language="c"
  fi
  config=/run/hgb/promefuzz/config.toml
  libraries=/run/hgb/promefuzz/libraries.toml
  cat >"$config" <<EOF_PROMEFUZZ_CONFIG
[comprehender]
embedding_llm = "hgb_embedding"
comprehension_llm = "hgb_cloud"

[generator]
generation_llm = "hgb_cloud"

[analyzer]
analysis_llm = "hgb_cloud"

[llm]
default_llm = "hgb_cloud"
validate_llm = false
enable_log = true

[llm.hgb_cloud]
llm_type = "openai"
base_url = "${OPENAI_BASE_URL:-https://api.openai.com/v1}"
api_key = "${OPENAI_API_KEY:-}"
model = "${OPENAI_MODEL:-}"
temperature = 0.0
max_tokens = -1
timeout = 80
retry_times = 3

[llm.hgb_embedding]
llm_type = "${PROME_FUZZ_EMBEDDING_LLM_TYPE:-mock}"
host = "${PROME_FUZZ_EMBEDDING_HOST:-localhost}"
port = ${PROME_FUZZ_EMBEDDING_PORT:-11434}
base_url = "${PROME_FUZZ_EMBEDDING_BASE_URL:-${OPENAI_BASE_URL:-https://api.openai.com/v1}}"
api_key = "${PROME_FUZZ_EMBEDDING_API_KEY:-${OPENAI_API_KEY:-}}"
model = "${PROME_FUZZ_EMBEDDING_MODEL:-hgb-hash-embedding}"
temperature = 0.0
max_tokens = ${PROME_FUZZ_EMBEDDING_MAX_TOKENS:--1}
timeout = ${PROME_FUZZ_EMBEDDING_TIMEOUT:-60}
retry_times = ${PROME_FUZZ_EMBEDDING_RETRY_TIMES:-3}
EOF_PROMEFUZZ_CONFIG
  compile_db="$workspace/promefuzz_build/compile_commands.json"
  preserved_compile_db="$workspace/compile_commands.json"
  compile_db_for_metadata="$compile_db"
  mkdir -p "$workspace/promefuzz_build"
  cmake_src="$(find /target/source_input -name CMakeLists.txt -type f -printf '%h\n' 2>/dev/null | sort | head -n 1 || true)"
  if [[ -n "$cmake_src" ]]; then
    cmake -S "$cmake_src" -B "$workspace/promefuzz_build" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON >"$workspace/logs/cmake.log" 2>&1 || true
  fi
  if ! compile_db_has_entries "$compile_db" && [[ "${HGB_PROMEFUZZ_TRY_FUZZBENCH_BUILD:-1}" == "1" ]] && command -v bear >/dev/null 2>&1; then
    mkdir -p "$workspace/promefuzz_build/src" "$workspace/promefuzz_build/out" "$workspace/promefuzz_build/work"
    cp -a /target/source_input/. "$workspace/promefuzz_build/src/" 2>/dev/null || true
    (cd "$workspace/promefuzz_build" && SRC="$workspace/promefuzz_build/src" OUT="$workspace/promefuzz_build/out" WORK="$workspace/promefuzz_build/work" bear -- bash /target/fuzzbench_benchmark/build.sh) >"$workspace/logs/bear.log" 2>&1 || true
    if [[ -f "$workspace/promefuzz_build/compile_commands.json" && "$workspace/promefuzz_build/compile_commands.json" != "$compile_db" ]]; then
      cp "$workspace/promefuzz_build/compile_commands.json" "$compile_db" 2>/dev/null || true
    fi
  fi
  if ! compile_db_has_entries "$compile_db"; then
    synthetic_count="$(write_synthetic_compile_db "$compile_db" "$language" "$project" 2>/dev/null || printf '0')"
    printf 'Wrote synthetic compile_commands.json with %s entries for /target/source_input.\n' "$synthetic_count" >>"$workspace/logs/cmake.log"
  fi
  if compile_db_has_entries "$compile_db"; then
    cp "$compile_db" "$preserved_compile_db" 2>/dev/null || true
    compile_db_for_metadata="$preserved_compile_db"
  fi
  cat >"$libraries" <<EOF_PROMEFUZZ_LIBS
[$safe_target]
language = "$language"
header_paths = ["/target/source_input", "/target/source_input/$project/include", "/target/source_input/$project/include/json"]
compile_commands_path = "$compile_db"
document_paths = ["/target/docs"]
document_has_api_usage = true
output_path = "$workspace/promefuzz_out/$safe_target"
source_paths = ["/target/source_input", "/target/source_input/$project/src/lib_json"]
exclude_paths = ["/target/source_input/$project/example"]
driver_headers = ["/target/source_input/$project/include/json/json.h"]
driver_build_args = ["-I/target/source_input/$project/include"]
consumer_build_args = ["-I/target/source_input/$project/include"]
EOF_PROMEFUZZ_LIBS
  printf 'PromeFuzz config: %s\nPromeFuzz libraries: %s\n' "$config" "$libraries" >"$workspace/command.txt"
  if ! compile_db_has_entries "$compile_db"; then
    cp "$libraries" "$workspace/promefuzz_libraries.toml" 2>/dev/null || true
    if [[ "${HGB_SAVE_MODE:-compact}" == "compact" ]]; then
      rm -rf "$workspace/promefuzz_build" "$workspace/promefuzz_out"
    fi
    hgb_soft_skip needs_compile_commands 'PromeFuzz requires a non-empty compile_commands.json; CMake, Bear/FuzzBench build replay, and synthetic fallback did not produce one. Inspect cmake.log and bear.log.' harness_generator
  fi
  if [[ "${HGB_DRY_RUN:-0}" == "1" ]]; then
    cp "$libraries" "$workspace/promefuzz_libraries.toml" 2>/dev/null || true
    if [[ "${HGB_SAVE_MODE:-compact}" == "compact" ]]; then
      rm -rf "$workspace/promefuzz_build" "$workspace/promefuzz_out"
    fi
    hgb_write_common_metadata dry_run_ok 'dry run prepared PromeFuzz config and compile_commands.json' 0 harness_generator
    hgb_write_common_summary dry_run_ok 'dry run prepared PromeFuzz config and compile_commands.json' harness_generator
    exit 0
  fi
  if ! hgb_api_key_present; then
    printf 'OPENAI_API_KEY is not set; PromeFuzz target generation skipped.\n' >"$workspace/logs/run.log"
    hgb_write_common_metadata missing_api_key 'OPENAI_API_KEY is not set' 2 harness_generator
    hgb_write_common_summary missing_api_key 'OPENAI_API_KEY is not set' harness_generator
    exit 2
  fi
  runtime_artifact=/run/hgb/promefuzz/artifact
  rm -rf "$runtime_artifact"
  mkdir -p "$runtime_artifact"
  cp -a "$artifact/." "$runtime_artifact/"
  python3 - "$runtime_artifact" <<'PY_PROMEFUZZ_LOCAL_RAG_PATCH'
from pathlib import Path
import sys
root = Path(sys.argv[1])
rag_py = root / "src/llm/rag.py"
utils_py = root / "src/utils.py"
if rag_py.exists():
    text = rag_py.read_text()
    start = text.find("    def add_document(self, document: Path):")
    end = text.find("    def add_webpage(self, url: str):", start)
    if start != -1 and end != -1 and "PROME_FUZZ_SKIP_BAD_DOCS" not in text[start:end]:
        robust_add_document = '    def add_document(self, document: Path):\n        """\n        Add a local document to the retriever, skipping unusable documents in HGB mode.\n        """\n        skip_bad = os.environ.get("PROME_FUZZ_SKIP_BAD_DOCS", "1") != "0"\n        document = Path(document)\n        if self.is_in_database(document):\n            logger.warning(f"Document {document} already exists in the retriever")\n            return\n        if skip_bad:\n            try:\n                if not document.is_file() or document.stat().st_size == 0:\n                    logger.warning(f"Skipping empty or missing document {document}")\n                    return\n                max_bytes = int(os.environ.get("PROME_FUZZ_MAX_DOC_BYTES", "5242880") or "0")\n                if max_bytes > 0 and document.stat().st_size > max_bytes:\n                    logger.warning(f"Skipping large document {document} ({document.stat().st_size} bytes)")\n                    return\n            except OSError as exc:\n                logger.warning(f"Skipping unreadable document {document}: {exc}")\n                return\n\n        from src.utils import ProgressTitle\n\n        with ProgressTitle(f"Loading document {document}..."):\n            try:\n                suffix = document.suffix.lower()\n                if suffix == ".pdf":\n                    loader = UnstructuredPDFLoader(str(document), mode="elements", strategy="fast")\n                    docs = loader.load()\n                elif suffix in [".html", ".htm"]:\n                    loader = UnstructuredHTMLLoader(str(document), mode="elements", strategy="fast")\n                    docs = loader.load()\n                else:\n                    loader = TextLoader(document, autodetect_encoding=True)\n                    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200, add_start_index=True)\n                    docs = loader.load_and_split(splitter)\n            except Exception as exc:\n                if skip_bad:\n                    logger.warning(f"Skipping document {document}: {exc}")\n                    return\n                raise\n\n            docs = filter_complex_metadata(docs)\n            docs = [doc for doc in docs if getattr(doc, "page_content", "").strip()]\n            if not docs:\n                logger.warning(f"Skipping document {document}: no non-empty chunks")\n                return\n            self.vector_store.add_documents(docs)\n\n        self._add_to_document_list(document)\n\n'
        text = text[:start] + robust_add_document + text[end:]
    if "class LocalHashEmbeddings" not in text:
        marker = "\n\nclass OllamaRetriever(RAGRetriever):\n"
        local_code = '''

class LocalHashEmbeddings:
    def __init__(self, dimensions: int = 384):
        self.dimensions = int(dimensions or 384)

    def _embed(self, text: str) -> list[float]:
        import hashlib
        vec = [0.0] * self.dimensions
        tokens = str(text or "").split() or [str(text or "")]
        for token in tokens:
            digest = hashlib.sha256(token.encode("utf-8", "ignore")).digest()
            idx = int.from_bytes(digest[:4], "little") % self.dimensions
            sign = 1.0 if digest[4] & 1 else -1.0
            vec[idx] += sign
        norm = sum(v * v for v in vec) ** 0.5 or 1.0
        return [v / norm for v in vec]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed(text) for text in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)


class LocalRetriever(RAGRetriever):
    def __init__(self, dimensions: int = 384, database_path: Path = None):
        embedding_client = LocalHashEmbeddings(dimensions)
        self.vector_store = Chroma(
            embedding_function=embedding_client,
            persist_directory=str(database_path.resolve()) if database_path else None,
            client_settings=chromadb_config.Settings(anonymized_telemetry=False),
        )
        self.database_path = database_path
        self._load_document_list()
'''
        if marker in text:
            text = text.replace(marker, local_code + marker, 1)
        rag_py.write_text(text)
if utils_py.exists():
    text = utils_py.read_text()
    old = '''    else:\n        raise ValueError(f"Unsupported LLM type: {llm_type}")\n\n    # create database path\n'''
    new = '''    elif llm_type in ("mock", "local", "hash"):\n        selected_llm.setdefault("dimensions", 384)\n    else:\n        raise ValueError(f"Unsupported LLM type: {llm_type}")\n\n    # create database path\n'''
    if old in text and 'llm_type in ("mock", "local", "hash")' not in text:
        text = text.replace(old, new, 1)
    old = '''    elif llm_type == LLM.LLM_TYPES.OPENAI.value:\n        rag_retriever = RAG.OpenAIRetriever(\n            selected_llm["base_url"],\n            selected_llm["api_key"],\n            selected_llm["model"],\n            selected_llm["max_tokens"],\n            database_path=database_path,\n        )\n\n    logger.success(f"The RAG retriever {llm_name} has been setup.")\n'''
    new = '''    elif llm_type == LLM.LLM_TYPES.OPENAI.value:\n        rag_retriever = RAG.OpenAIRetriever(\n            selected_llm["base_url"],\n            selected_llm["api_key"],\n            selected_llm["model"],\n            selected_llm["max_tokens"],\n            database_path=database_path,\n        )\n    elif llm_type in ("mock", "local", "hash"):\n        rag_retriever = RAG.LocalRetriever(\n            int(selected_llm.get("dimensions", 384)),\n            database_path=database_path,\n        )\n\n    logger.success(f"The RAG retriever {llm_name} has been setup.")\n'''
    if old in text and 'RAG.LocalRetriever' not in text:
        text = text.replace(old, new, 1)
    utils_py.write_text(text)
knowledge_py = root / "src/comprehender/knowledge.py"
if knowledge_py.exists():
    ktext = knowledge_py.read_text()
    if "import os\n" not in ktext:
        ktext = ktext.replace("from pathlib import Path\n", "from pathlib import Path\nimport os\n", 1)
    old = '                except Exception as e:\n                    logger.critical(f"Failed to load document {doc}: {e}")\n                    exit(1)\n'
    new = '                except Exception as e:\n                    if os.environ.get("PROME_FUZZ_SKIP_BAD_DOCS", "1") != "0":\n                        logger.warning(f"Skipping document {doc}: {e}")\n                        continue\n                    logger.critical(f"Failed to load document {doc}: {e}")\n                    exit(1)\n'
    if old in ktext and "PROME_FUZZ_SKIP_BAD_DOCS" not in ktext:
        ktext = ktext.replace(old, new, 1)
    knowledge_py.write_text(ktext)
preprocess_py = root / "cli/preprocess.py"
if preprocess_py.exists():
    text = preprocess_py.read_text()
    if "import os\n" not in text:
        text = text.replace("import json\n", "import json\nimport os\n", 1)
    old = """    api = api_extractor.extract(pool_size=pool_size)
    api.dump(out_path / "api.pkl")"""
    new = """    api = api_extractor.extract(pool_size=pool_size)
    max_apis = int(os.environ.get("PROME_FUZZ_MAX_APIS", "16") or "0")
    if max_apis > 0 and api.count > max_apis:
        def _hgb_api_rank(func):
            text = " ".join(str(getattr(func, attr, "")) for attr in ("header", "name", "loc", "decl_loc")).lower()
            penalty = 0
            for token in ("/test", "/tests", "/example", "/examples", "test::", "testing"):
                if token in text:
                    penalty += 10
            return (penalty, len(str(getattr(func, "name", ""))), str(getattr(func, "name", "")), str(getattr(func, "loc", "")))
        before = api.count
        api.funcs = sorted(api.funcs, key=_hgb_api_rank)[:max_apis]
        logger.info(f"Limiting API functions from {before} to {api.count} for HGB integration. Set PROME_FUZZ_MAX_APIS=0 to disable.")
    api.dump(out_path / "api.pkl")"""
    if old in text and "PROME_FUZZ_MAX_APIS" not in text:
        text = text.replace(old, new, 1)
    preprocess_py.write_text(text)
PY_PROMEFUZZ_LOCAL_RAG_PATCH
  if ! promefuzz_processors_ready "$runtime_artifact"; then
    printf 'PromeFuzz processor binaries are missing under %s/build/bin. Rebuild the image so docker/promefuzz/Dockerfile runs setup.sh.\n' "$runtime_artifact" >"$workspace/logs/processor.log"
    hgb_soft_skip missing_processor_binaries 'PromeFuzz processor binaries are missing; rebuild the PromeFuzz image so setup.sh runs during docker build' harness_generator
  fi
  cfg_flag=-c
  if ! (cd "$runtime_artifact" && "$python" PromeFuzz.py --help 2>/dev/null | grep -q -- ' -c'); then
    cfg_flag=--config
  fi
  stages=(preprocess comprehend generate stats)
  : >"$workspace/command.txt"
  code=0
  failed_stage=none
  for stage in "${stages[@]}"; do
    stage_args=("$python" PromeFuzz.py "$cfg_flag" "$config" -F "$libraries" "$stage")
    if [[ "$stage" == "comprehend" ]]; then
      stage_args+=(--task "${PROME_FUZZ_COMPREHEND_TASK:-funcpurp}")
    fi
    printf '%q ' "${stage_args[@]}" >>"$workspace/command.txt"; printf '\n' >>"$workspace/command.txt"
    stage_code=0
    (cd "$runtime_artifact" && timeout "${HGB_GENERATION_TIMEOUT_SECONDS:-900}" "${stage_args[@]}") >"$workspace/logs/${stage}.log" 2>&1 || stage_code=$?
    if [[ "$stage" == "stats" ]]; then
      continue
    fi
    if [[ "$stage" == "preprocess" && "$stage_code" -eq 0 ]]; then
      api_json="$workspace/promefuzz_out/$safe_target/preprocessor/api.json"
      api_count_after_preprocess="$($python - "$api_json" <<'PY_PROME_API_COUNT'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    print(0)
    raise SystemExit
if isinstance(data, list):
    print(len(data))
elif isinstance(data, dict):
    funcs = data.get("funcs") or data.get("functions") or data
    print(len(funcs) if hasattr(funcs, "__len__") else 0)
else:
    print(0)
PY_PROME_API_COUNT
)"
      if [[ "${api_count_after_preprocess:-0}" == "0" ]]; then
        hgb_soft_skip promefuzz_no_api_candidates 'PromeFuzz preprocess completed but extracted zero API functions; skipping comprehension/generation' harness_generator
      fi
    fi
    if [[ "$stage_code" -ne 0 ]]; then
      code="$stage_code"
      failed_stage="$stage"
      break
    fi
  done
  n=0
  while IFS= read -r generated; do
    n=$((n + 1))
    cp "$generated" "$workspace/generated_harnesses/${n}_$(basename "$generated")" 2>/dev/null || true
  done < <(find "$workspace/promefuzz_out" "$runtime_artifact" -type f \( -name '*fuzz*.c' -o -name '*fuzz*.cc' -o -name '*fuzz*.cpp' -o -name 'fuzz_driver_*' \) 2>/dev/null | sort)
  status=completed
  reason=none
  if [[ "$code" -ne 0 ]]; then
    status=failed
    reason="PromeFuzz $failed_stage stage exited $code"
    stage_log="$workspace/logs/${failed_stage}.log"
    if [[ -f "$stage_log" ]]; then
      if grep -qi 'localhost.*11434\|port=11434\|/api/embeddings.*Connection refused' "$stage_log"; then
        reason='PromeFuzz embedding service is unavailable at localhost:11434; start Ollama or set PROME_FUZZ_EMBEDDING_LLM_TYPE/base/model/API key'
      elif grep -q 'openai.NotFoundError: Error code: 404\|Error code: 404' "$stage_log"; then
        reason='PromeFuzz embedding API returned 404; set PROME_FUZZ_EMBEDDING_MODEL and embedding base/API key to a compatible embeddings endpoint'
      elif grep -qi 'Expected Embeddings to be non-empty\|no non-empty chunks\|Skipping document' "$stage_log"; then
        reason='promefuzz_no_usable_docs: PromeFuzz comprehension had no usable non-empty documentation chunks after filtering bad docs'
      elif grep -qi 'pdfminer\|partition_pdf\|Failed to load document.*pdf' "$stage_log"; then
        reason='PromeFuzz PDF document parsing failed; rebuild the image with pdfminer.six or skip bad docs with PROME_FUZZ_SKIP_BAD_DOCS=1'
      elif grep -qi 'nltk\|punkt_tab\|averaged_perceptron' "$stage_log"; then
        reason='PromeFuzz NLTK data is unavailable; rebuild the image so NLTK data is downloaded at docker build time'
      elif grep -qi 'Comprehension not done yet' "$stage_log"; then
        reason='promefuzz_no_api_candidates: PromeFuzz comprehension produced no completed API comprehension records'
      fi
    fi
  fi
  generated_harness_count="$(count_files "$workspace/generated_harnesses" -type f)"
  if [[ "$code" -ne 0 && "${generated_harness_count:-0}" -gt 0 ]]; then
    status=partial_completed
    reason="PromeFuzz $failed_stage stage exited $code after producing $generated_harness_count harness candidates"
  fi
  if [[ "${HGB_SAVE_MODE:-compact}" == "compact" ]]; then
    rm -rf "$workspace/promefuzz_build" "$workspace/promefuzz_out"
  fi
  extra=$(printf '  "libraries_file": "%s",\n  "compile_commands_path": "%s",\n  "command_file": "%s",\n  "failed_stage": "%s"' "$(hgb_json_escape "$libraries")" "$(hgb_json_escape "$compile_db_for_metadata")" "$(hgb_json_escape "$workspace/command.txt")" "$(hgb_json_escape "$failed_stage")")
  hgb_write_common_metadata "$status" "$reason" "$code" harness_generator "$extra"
  hgb_write_common_summary "$status" "$reason" harness_generator
  exit "$code"
fi
[[ "$mode" == "smoke-pugixml" || "$mode" == "smoke" ]] || { echo "unknown mode: $mode" >&2; exit 64; }
export OPENAI_API_KEY="${OPENAI_API_KEY:-${API_KEY:-}}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-${BASE_URL:-}}"
export OPENAI_MODEL="${OPENAI_MODEL:-${MODEL:-gpt-4o-mini}}"
cfg="$(write_config)"
(cd "$artifact" && ("$python" PromeFuzz.py --help || python3 PromeFuzz.py --help)) >"$workspace/logs/help.txt" 2>&1 || true
printf 'PromeFuzz runtime config: /run/hgb/promefuzz_config.toml (not mounted)\n' >"$workspace/command.txt"
if [[ -z "$OPENAI_API_KEY" ]]; then
  printf 'OPENAI_API_KEY is not set; PromeFuzz pugixml smoke not launched.\n' >"$workspace/logs/run.log"
  metadata missing_api_key 2 'OPENAI_API_KEY is not set' "$cfg"
  summary missing_api_key 2 'OPENAI_API_KEY is not set'
  exit 2
fi
code=0
(cd "$artifact" && timeout "${PROMEFUZZ_STAGE_TIMEOUT_SECONDS:-600}" "$python" PromeFuzz.py --config "$cfg" --help) >"$workspace/logs/run.log" 2>&1 || code=$?
status=completed; reason=none
[[ "$code" -eq 0 ]] || { status=failed; reason="PromeFuzz command exited $code"; }
metadata "$status" "$code" "$reason" "$cfg"
summary "$status" "$code" "$reason"
exit "$code"
