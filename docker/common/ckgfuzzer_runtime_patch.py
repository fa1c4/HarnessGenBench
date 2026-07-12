#!/usr/bin/env python3
"""Apply deterministic HarnessGenBench fixes to the pinned CKGFuzzer artifact."""

from __future__ import annotations

import argparse
import ast
from pathlib import Path


def _replace_functions(source: str, name: str, replacement: str) -> str:
    tree = ast.parse(source)
    matches = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]
    if not matches:
        raise ValueError(f"could not find top-level function {name}")
    lines = source.splitlines(keepends=True)
    replacement_lines = replacement.rstrip() + "\n\n"
    for node in sorted(matches, key=lambda item: item.lineno, reverse=True):
        if node.end_lineno is None:
            raise ValueError(f"function {name} has no end line")
        lines[node.lineno - 1 : node.end_lineno] = [replacement_lines]
    return "".join(lines)


def _replace_in_functions(source: str, name: str, old: str, new: str) -> str:
    """Replace text only within named top-level functions."""
    tree = ast.parse(source)
    matches = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]
    if not matches:
        raise ValueError(f"could not find top-level function {name}")
    lines = source.splitlines(keepends=True)
    changed = False
    for node in sorted(matches, key=lambda item: item.lineno, reverse=True):
        if node.end_lineno is None:
            raise ValueError(f"function {name} has no end line")
        body = "".join(lines[node.lineno - 1 : node.end_lineno])
        if old not in body:
            continue
        lines[node.lineno - 1 : node.end_lineno] = [body.replace(old, new)]
        changed = True
    if not changed:
        raise ValueError(f"could not find expected text in function {name}")
    return "".join(lines)


def _write_if_changed(path: Path, source: str) -> bool:
    old = path.read_text(encoding="utf-8")
    if old == source:
        return False
    path.write_text(source, encoding="utf-8")
    return True


def patch_code_base(path: Path) -> bool:
    source = path.read_text(encoding="utf-8")
    replacement = '''def fix_file_path(file_path):
    """Resolve portable or stale cached paths against the current source tree."""
    source_root = os.environ.get("CKGFUZZER_SOURCE_ROOT", "").rstrip("/")
    if not source_root:
        return file_path
    portable_prefix = "@HGB_CKG_SOURCE@"
    normalized = str(file_path).replace("\\\\", "/")
    if normalized == portable_prefix:
        return source_root
    if normalized.startswith(portable_prefix + "/"):
        return os.path.join(source_root, normalized[len(portable_prefix) + 1:])
    marker = "/source_code/"
    if marker in normalized:
        tail = normalized.split(marker, 1)[1]
        if "/" in tail:
            return os.path.join(source_root, tail.split("/", 1)[1])
    return file_path
'''
    source = _replace_functions(source, "fix_file_path", replacement)
    return _write_if_changed(path, source)


def patch_preproc(path: Path) -> bool:
    source = path.read_text(encoding="utf-8")
    combine_replacement = '''def combine_call_graph(src_api_file_path):
    """Combine only selected, unique edges while enforcing a hard row bound."""
    import csv

    api_list_path = os.path.join(src_api_file_path, "api_list.json")
    with open(api_list_path, "r", encoding="utf-8") as f:
        api_list = set(json.load(f))
    csv_folder_path = os.path.join(src_api_file_path, "codebase/call_graph")
    api_combine_dir = os.path.join(src_api_file_path, "api_combine")
    os.makedirs(api_combine_dir, exist_ok=True)
    output_path = os.path.join(api_combine_dir, "combined_call_graph.csv")
    max_edges = max(1, int(os.environ.get("CKGFUZZER_MAX_GRAPH_EDGES", "50000") or "50000"))
    csv_files = []
    if os.path.isdir(csv_folder_path):
        for file_name in sorted(os.listdir(csv_folder_path)):
            if not file_name.endswith(".csv"):
                continue
            api_name = file_name.split("@")[-1].split("_call_graph")[0]
            if api_name in api_list:
                csv_files.append(os.path.join(csv_folder_path, file_name))

    default_header = [
        "caller", "callee", "caller_src", "callee_src",
        "start_body_start_line", "start_body_end_line",
        "end_body_start_line", "end_body_end_line",
        "caller_signature", "caller_parameter_string",
        "caller_return_type", "caller_return_type_inferred",
        "callee_signature", "callee_parameter_string",
        "callee_return_type", "callee_return_type_inferred",
    ]
    fieldnames = None
    seen = set()
    written = 0
    with open(output_path, "w", encoding="utf-8", newline="") as output:
        writer = None
        for csv_path in csv_files:
            with open(csv_path, "r", encoding="utf-8", errors="replace", newline="") as source_file:
                reader = csv.DictReader(source_file)
                if not reader.fieldnames:
                    continue
                if fieldnames is None:
                    fieldnames = list(reader.fieldnames)
                    writer = csv.DictWriter(output, fieldnames=fieldnames)
                    writer.writeheader()
                for row in reader:
                    edge_key = (
                        row.get("caller", ""), row.get("callee", ""),
                        row.get("caller_src", ""), row.get("callee_src", ""),
                    )
                    if edge_key in seen:
                        continue
                    seen.add(edge_key)
                    writer.writerow({key: row.get(key, "") for key in fieldnames})
                    written += 1
                    if written >= max_edges:
                        break
            if written >= max_edges:
                break
        if fieldnames is None:
            csv.writer(output).writerow(default_header)
    print(f"Wrote {written} unique selected call-graph edges to {output_path}")
    return output_path
'''
    extract_replacement = '''def extract_fn_code(src_api_file_path):
    """Extract selected API bodies, with a bounded source fallback for macros."""
    import re

    api_list_path = os.path.join(src_api_file_path, "api_list.json")
    with open(api_list_path, "r", encoding="utf-8") as f:
        api_list = json.load(f)
    api_code_path = os.path.join(src_api_file_path, "src/src_api_code.json")
    os.makedirs(os.path.dirname(api_code_path), exist_ok=True)
    with open(os.path.join(src_api_file_path, "codebase/api/src_api.json"), "r", encoding="utf-8") as f:
        src_api_data = json.load(f)

    import sys
    if "/opt/hgb/bin" not in sys.path:
        sys.path.insert(0, "/opt/hgb/bin")
    from ckgfuzzer_api_recovery import recover_selected_api_code

    source_root = os.environ.get("CKGFUZZER_SOURCE_ROOT", "")
    max_files = max(1, int(os.environ.get("CKGFUZZER_SOURCE_FALLBACK_MAX_FILES", "5000") or "5000"))
    api_code_dict, missing = recover_selected_api_code(src_api_data, api_list, source_root, max_files)
    with open(api_code_path, "w", encoding="utf-8") as f:
        json.dump(api_code_dict, f, indent=2, sort_keys=True, ensure_ascii=False)
    api_combine_dir = os.path.join(src_api_file_path, "api_combine")
    os.makedirs(api_combine_dir, exist_ok=True)
    shutil.copy2(api_code_path, os.path.join(api_combine_dir, os.path.basename(api_code_path)))
    print(f"Resolved {len(api_code_dict)} selected APIs; unresolved: {missing}")
    return

    api_code_dict = {}
    for src_value in src_api_data.get("src", {}).values():
        for api in src_value.get("fn_def_list", []):
            api_name = api.get("fn_meta", {}).get("identifier", "")
            if api_name in api_list:
                api_code_dict[api_name] = api.get("fn_code", "")

    source_root = os.environ.get("CKGFUZZER_SOURCE_ROOT", "")
    max_files = max(1, int(os.environ.get("CKGFUZZER_SOURCE_FALLBACK_MAX_FILES", "5000") or "5000"))

    def function_snippet(text, api_name):
        pattern = re.compile(
            r"(?ms)^[^;{}]*\\b" + re.escape(api_name) + r"\\s*\\([^;{}]*\\)\\s*\\{"
        )
        match = pattern.search(text)
        if not match:
            return ""
        brace = text.find("{", match.start())
        depth = 0
        for index in range(brace, len(text)):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    return text[match.start():index + 1]
        return ""

    missing = [api_name for api_name in api_list if api_name not in api_code_dict]
    if missing and source_root and os.path.isdir(source_root):
        checked = 0
        for root, dirs, files in os.walk(source_root):
            dirs[:] = sorted(d for d in dirs if d not in {".git", "build", "out", "work"})
            for file_name in sorted(files):
                if not file_name.endswith((".c", ".cc", ".cpp", ".cxx")):
                    continue
                checked += 1
                if checked > max_files:
                    break
                path = os.path.join(root, file_name)
                try:
                    if os.path.getsize(path) > 4 * 1024 * 1024:
                        continue
                    text = open(path, "r", encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                for api_name in list(missing):
                    snippet = function_snippet(text, api_name)
                    if snippet:
                        api_code_dict[api_name] = snippet
                        missing.remove(api_name)
                if not missing:
                    break
            if checked > max_files or not missing:
                break

    with open(api_code_path, "w", encoding="utf-8") as f:
        json.dump(api_code_dict, f, indent=2, sort_keys=True, ensure_ascii=False)
    api_combine_dir = os.path.join(src_api_file_path, "api_combine")
    os.makedirs(api_combine_dir, exist_ok=True)
    shutil.copy2(api_code_path, os.path.join(api_combine_dir, os.path.basename(api_code_path)))
    print(f"Resolved {len(api_code_dict)} selected APIs; unresolved: {missing}")
'''
    source = _replace_functions(source, "combine_call_graph", combine_replacement)
    source = _replace_functions(source, "extract_fn_code", extract_replacement)
    return _write_if_changed(path, source)


def patch_kg(path: Path) -> bool:
    source = path.read_text(encoding="utf-8")
    marker = "def getCodeCallKGGraph("
    helper = '''def _hgb_read_bounded_call_graph(path):
    max_rows = max(1, int(os.environ.get("CKGFUZZER_MAX_GRAPH_EDGES", "50000") or "50000"))
    chunks = []
    seen_rows = 0
    for chunk in pd.read_csv(path, chunksize=min(max_rows, 10000), low_memory=False):
        chunk = chunk.drop_duplicates(subset=["caller", "callee", "caller_src", "callee_src"])
        remaining = max_rows - seen_rows
        if remaining <= 0:
            break
        chunk = chunk.head(remaining)
        chunks.append(chunk)
        seen_rows += len(chunk)
        if seen_rows >= max_rows:
            break
    if not chunks:
        return pd.read_csv(path, nrows=0, low_memory=False)
    result = pd.concat(chunks, ignore_index=True)
    result = result.drop_duplicates(subset=["caller", "callee", "caller_src", "callee_src"])
    logger.info(f"Loaded {len(result)} bounded unique call-graph edges from {path}")
    return result.head(max_rows)


'''
    if "def _hgb_read_bounded_call_graph(" not in source:
        source = source.replace(marker, helper + marker, 1)
    source = source.replace("df = pd.read_csv(method_call_csv_file)", "df = _hgb_read_bounded_call_graph(method_call_csv_file)", 1)
    source = source.replace("methods_in_codebase = [ ]", "methods_in_codebase = set()", 1)
    source = source.replace("methods_in_codebase.append(method_name)", "methods_in_codebase.add(method_name)")
    source = source.replace("ids_in_graph = []", "ids_in_graph = set()", 1)
    source = source.replace("ids_in_graph.append(", "ids_in_graph.add(")
    return _write_if_changed(path, source)


def _docker_run_source() -> str:
    return '''def docker_run(run_args, print_output=True, architecture='x86_64'):
  """Run a nested Docker command with a bounded timeout and explicit status."""
  platform = 'linux/arm64' if architecture == 'aarch64' else 'linux/amd64'
  command = ['docker', 'run', '--rm', '--privileged', '--shm-size=2g', '--platform', platform]
  if sys.stdin.isatty() and sys.stdout.isatty():
    command.append('-i')
  command.extend(run_args)
  logger.info('Running: %s.', _get_command_string(command))
  timeout_seconds = max(1, int(os.environ.get('CKGFUZZER_DOCKER_ACTION_TIMEOUT_SECONDS', '600') or '600'))
  try:
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout_seconds, check=False)
  except subprocess.TimeoutExpired as exc:
    output = (exc.stdout or b'').decode('utf-8', errors='replace') if isinstance(exc.stdout, bytes) else str(exc.stdout or '')
    return f"INFRA_ERROR: nested docker run timed out after {timeout_seconds}s\\n{output}"
  output = completed.stdout.decode('utf-8', errors='replace')
  if completed.returncode != 0:
    return f"ERROR: nested docker run exited {completed.returncode}\\n{output}"
  return output or "HGB_COMMAND_OK"
'''


def patch_check_gen_fuzzer(path: Path) -> bool:
    source = path.read_text(encoding="utf-8")
    docker_exec = '''def docker_exec_command(run_args, project_name, print_output=True):
  """Run a nested Docker exec with a timeout and preserved return code."""
  command = ['docker', 'exec', '-u', 'root']
  if sys.stdin.isatty() and sys.stdout.isatty():
    command.extend(['-i', '-t'])
  command.append(project_name + "_check")
  command.extend(run_args)
  timeout_seconds = max(1, int(os.environ.get('CKGFUZZER_DOCKER_ACTION_TIMEOUT_SECONDS', '600') or '600'))
  try:
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout_seconds, check=False)
  except subprocess.TimeoutExpired as exc:
    output = (exc.stdout or b'').decode('utf-8', errors='replace') if isinstance(exc.stdout, bytes) else str(exc.stdout or '')
    return f"INFRA_ERROR: nested docker exec timed out after {timeout_seconds}s\\n{output}"
  output = completed.stdout.decode('utf-8', errors='replace')
  if completed.returncode != 0:
    return f"ERROR: nested docker exec exited {completed.returncode}\\n{output}"
  return output or "HGB_COMMAND_OK"
'''
    check_exists = '''def _check_fuzzer_exists(project, fuzzer_name, architecture='x86_64'):
  """Check the mounted output directly; do not pull or start another image."""
  fuzzer_path = os.path.join(project.out, fuzzer_name)
  if os.path.isfile(fuzzer_path):
    return True
  logger.error(f'{fuzzer_name} does not exist at {fuzzer_path}. Please build it first.')
  return False
'''
    docker_build = '''def docker_build(build_args):
  """Run docker build with the configured nested action timeout."""
  command = ['docker', 'build']
  command.extend(build_args)
  logger.info('Running: %s.', _get_command_string(command))
  timeout_seconds = max(1, int(os.environ.get('CKGFUZZER_DOCKER_ACTION_TIMEOUT_SECONDS', '600') or '600'))
  try:
    completed = subprocess.run(command, timeout=timeout_seconds, check=False)
  except subprocess.TimeoutExpired:
    logger.error('Docker build timed out after %ss.', timeout_seconds)
    return False
  if completed.returncode != 0:
    logger.error('Docker build failed with exit code %s.', completed.returncode)
    return False
  return True
'''
    source = _replace_functions(source, "docker_exec_command", docker_exec)
    source = _replace_functions(source, "_check_fuzzer_exists", check_exists)
    source = _replace_functions(source, "docker_run", _docker_run_source())
    source = _replace_functions(source, "docker_build", docker_build)
    # ``start_docker_check_compilation_impl`` returns a bool, whereas our
    # patched docker_run returns a status string. Keep the string check in the
    # one caller that consumes docker_run; a global substitution changes the
    # Docker-start boolean branch and calls ``.startswith`` on it.
    source = _replace_in_functions(
        source,
        "build_fuzzers_impl",
        "if not result:\n    logger.error('Building fuzzers failed.')",
        "if not result or result.startswith(('ERROR:', 'INFRA_ERROR:')):\n    logger.error('Building fuzzers failed: %s', result)",
    )
    source = source.replace(
        "if not _check_fuzzer_exists(args.project, args.fuzzer_name):\n    return False",
        "if not _check_fuzzer_exists(args.project, args.fuzzer_name):\n    return f'INFRA_ERROR: fuzzer binary {args.fuzzer_name} is missing'",
    )
    return _write_if_changed(path, source)


def patch_run_fuzzer(path: Path) -> bool:
    source = path.read_text(encoding="utf-8")
    source = source.replace("        self.failed_builds = []", "        self.failed_builds = []\n        self.successful_builds = []", 1)
    source = source.replace("            logger.info(f\"Successfully built fuzzer {fuzz_driver_file}\")", "            logger.info(f\"Successfully built fuzzer {fuzz_driver_file}\")\n            self.successful_builds.append(fuzz_driver_file)")
    old = '''            if "ERROR" in run_fuzzer_result:
                logger.info("Crash detected. Analyzing...")'''
    new = '''            if run_fuzzer_result.startswith("INFRA_ERROR:"):
                logger.error(f"Fuzzer infrastructure failed: {run_fuzzer_result}")
                self.failed_builds.append(fuzz_driver_file)
                return
            if "ERROR" in run_fuzzer_result:
                logger.info("Crash detected. Analyzing...")'''
    source = source.replace(old, new)
    old_nested = '''                        if "ERROR" in run_fuzzer_result:
                            logger.info("Crash detected. Analyzing...")'''
    new_nested = '''                        if run_fuzzer_result.startswith("INFRA_ERROR:"):
                            logger.error(f"Fuzzer infrastructure failed: {run_fuzzer_result}")
                            self.failed_builds.append(fuzz_driver_file)
                            return
                        if "ERROR" in run_fuzzer_result:
                            logger.info("Crash detected. Analyzing...")'''
    source = source.replace(old_nested, new_nested)
    return _write_if_changed(path, source)



def patch_fuzzing(path: Path) -> bool:
    source = path.read_text(encoding="utf-8")
    # Candidate verification is performed by HarnessGenBench after generation
    # in the native FuzzBench build context. Skipping upstream checking must
    # also avoid starting its nested-Docker verifier container.
    source = _replace_in_functions(
        source,
        "start_docker_for_check_compilation",
        "def start_docker_for_check_compilation(project_dir, project_name):\n",
        "def start_docker_for_check_compilation(project_dir, project_name):\n"
        "    if os.environ.get(\"HGB_CKG_EXTERNAL_VERIFIER\") == \"1\":\n"
        "        logger.info(\"Using HarnessGenBench external candidate verifier.\")\n"
        "        return True\n",
    )
    return _write_if_changed(path, source)


_DIRECT_CALL_GRAPH_QUERY = '''import cpp

predicate directCall(Function caller, Function callee) {
  exists(FunctionCall call |
    call.getEnclosingFunction() = caller and
    call.getTarget() = callee
  )
}

predicate selectedRoot(Function function) {
  function.hasName("ENTRY_FNC")
}

from Function start, Function end, Location start_loc, Location end_loc
where
  selectedRoot(start) and
  directCall(start, end) and
  start_loc = start.getLocation() and
  end_loc = end.getLocation()
select
  start as caller,
  end as callee,
  start.getFile() as caller_src,
  end.getFile() as callee_src,
  start_loc.getStartLine() as start_body_start_line,
  start_loc.getEndLine() as start_body_end_line,
  end_loc.getStartLine() as end_body_start_line,
  end_loc.getEndLine() as end_body_end_line,
  start.getName() as caller_signature,
  start.getParameterString() as caller_parameter_string,
  start.getType() as caller_return_type,
  start.getUnspecifiedType() as caller_return_type_inferred,
  end.getName() as callee_signature,
  end.getParameterString() as callee_parameter_string,
  end.getType() as callee_return_type,
  end.getUnspecifiedType() as callee_return_type_inferred
'''


def patch_call_graph_assets(root: Path) -> list[Path]:
    query_dir = root / "docker_shared/qlpacks/cpp_queries"
    changed: list[Path] = []
    for name in ("extract_call_graph_template.ql", "extract_call_graph_template_fast.ql"):
        path = query_dir / name
        if path.is_file() and _write_if_changed(path, _DIRECT_CALL_GRAPH_QUERY):
            changed.append(path)
    shell_path = query_dir / "extract_call_graph.sh"
    if shell_path.is_file():
        source = shell_path.read_text(encoding="utf-8")
        source = source.replace(
            'if codeql query run "$QUERY" --database="$dbbase" --output="$outputfile"; then',
            'if timeout "${CKGFUZZER_CODEQL_QUERY_TIMEOUT_SECONDS:-600}" codeql query run "$QUERY" --database="$dbbase" --output="$outputfile"; then',
        )
        source = source.replace(
            '        echo "BQRS file successfully converted to CSV: $csv_output"',
            '        echo "BQRS file successfully converted to CSV: $csv_output"\n        touch "${outputfile%.bqrs}.ok"',
        )
        if _write_if_changed(shell_path, source):
            changed.append(shell_path)
    return changed



def apply_runtime_patches(root: Path) -> list[Path]:
    targets = (
        (root / "fuzzing_llm_engine/rag/code_base.py", patch_code_base),
        (root / "fuzzing_llm_engine/repo/preproc.py", patch_preproc),
        (root / "fuzzing_llm_engine/rag/kg.py", patch_kg),
        (root / "fuzzing_llm_engine/utils/check_gen_fuzzer.py", patch_check_gen_fuzzer),
        (root / "fuzzing_llm_engine/roles/run_fuzzer.py", patch_run_fuzzer),
        (root / "fuzzing_llm_engine/fuzzing.py", patch_fuzzing),
    )
    changed: list[Path] = []
    for path, patcher in targets:
        if not path.is_file():
            raise FileNotFoundError(path)
        if patcher(path):
            changed.append(path)
    changed.extend(patch_call_graph_assets(root))
    return changed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    args = parser.parse_args()
    try:
        changed = apply_runtime_patches(args.artifact)
    except (OSError, SyntaxError, ValueError) as exc:
        print(f"ckgfuzzer_runtime_patch: {exc}")
        return 1
    for path in changed:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
