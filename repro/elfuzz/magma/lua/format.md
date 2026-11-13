# Lua source input format for MAGMA `lua`

The target is `fuzz_lua` (MAGMA's `src/fuzz_lua.c`), which loads the input as a
Lua chunk through `luaL_loadbufferx` (the committed entry API).

Characteristics worth covering:

* local/global assignments, arithmetic, string and table literals
* function definitions, calls, closures, and varargs
* control flow: `if`/`elseif`/`else`, `while`, `repeat`, numeric and generic
  `for`
* metatables and metamethods, coroutines, `pcall`/`error`
* long bracket strings and comments (`[[ ... ]]`, `--[[ ... ]]`)
* syntactically valid fragments that stress the parser rather than execute

The initial seed program returns a small valid chunk.  ELFuzz mutates the
generator program, not the target harness.
