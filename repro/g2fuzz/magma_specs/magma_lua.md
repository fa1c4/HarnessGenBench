# G2Fuzz MAGMA target: `lua`

- MAGMA target: `lua`, program `fuzz_lua`
- Format: Lua source chunk (loaded with `luaL_loadbufferx`)
- Method profile: extension (no upstream G2Fuzz program-map entry).
- Generator focus: assignments, table/string literals, functions, closures,
  varargs, control flow, metatables/metamethods, coroutines, error handling,
  long-bracket strings/comments, and syntactically valid fragments that stress
  the parser.
