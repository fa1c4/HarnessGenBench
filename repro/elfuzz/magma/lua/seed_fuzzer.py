"""Seed fuzzer program for the MAGMA lua corpus generator.

ELFuzz evolves input-producing fuzzer programs; this program is the initial
seed.  It uses the deterministic random source ELFuzz supplies so the first
generation already spans several valid chunks instead of emitting one
constant string.  The native MAGMA harness (`fuzz_lua`) is kept fixed.
"""
from __future__ import annotations


def _byte(rng) -> int:
    value = rng.read(1)
    if isinstance(value, (bytes, bytearray)):
        return value[0] if value else 0
    return int(value) % 256


def _pick(rng, items):
    return items[_byte(rng) % len(items)]


_VALUES = [
    "1",
    "0x2a",
    "3.5",
    "1e3",
    '"text"',
    "'x'",
    "{1, 2, 3}",
    '{a = 1, b = "two"}',
    "true",
    "false",
    "nil",
    "tostring(42)",
]
_BLOCKS = [
    "local t = {1, 2, x = \"y\"}\nfor i = 1, #t do print(t[i]) end\n",
    "local function f(a, ...) return a + select('#', ...) end\nprint(f(1, 2, 3))\n",
    "local mt = {__index = function(_, k) return k end}\nlocal o = setmetatable({}, mt)\nprint(o.foo)\n",
    "local s = 0\nfor i = 1, 10 do s = s + i end\nprint(s)\n",
    "local ok, err = pcall(function() error({code = 7}) end)\nprint(ok, type(err))\n",
    "local co = coroutine.create(function(x) coroutine.yield(x + 1) end)\nprint(coroutine.resume(co, 41))\n",
    "local s = [[long bracket]] .. [[ text]]\n--[[ block\ncomment ]]\nprint(#s)\n",
    "local a <const> = 1\nlocal <close> h = io.tmpfile()\nprint(a)\n",
]


def generate_input(rng, output):
    parts = ["local v = " + _pick(rng, _VALUES) + "\n", _pick(rng, _BLOCKS)]
    for _ in range(_byte(rng) % 3):
        parts.append(_pick(rng, _BLOCKS))
    parts.append("return v\n")
    output.write("".join(parts).encode())
