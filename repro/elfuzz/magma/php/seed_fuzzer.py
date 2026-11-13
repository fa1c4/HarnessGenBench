"""Seed fuzzer program for the MAGMA php corpus generator.

ELFuzz evolves input-producing fuzzer programs; this program is the initial
seed.  It uses the deterministic random source ELFuzz supplies so the first
generation already spans several valid PHP files instead of emitting one
constant string.  The native MAGMA harness (`parser`) is kept fixed.
"""
from __future__ import annotations


def _byte(rng) -> int:
    value = rng.read(1)
    if isinstance(value, (bytes, bytearray)):
        return value[0] if value else 0
    return int(value) % 256


def _pick(rng, items):
    return items[_byte(rng) % len(items)]


_VALUES = ["1", "0x2a", "3.5", '"text"', "'x'", "true", "null", "[1, 2, 3]", "['a' => 1]"]
_STATEMENTS = [
    "$x = %s;\n",
    "echo %s;\n",
    "if (%s) { echo 1; } else { echo 0; }\n",
    "foreach ([1, 2, 3] as $v) { echo $v; }\n",
    "function f(int $a = 1): int { return $a + 1; }\n",
    "class C { public function m(): string { return 'm'; } }\n",
    "try { throw new RuntimeException('x'); } catch (Throwable $e) { echo $e->getMessage(); }\n",
    "switch (1) { case 1: echo 'one'; break; default: echo 'other'; }\n",
    "echo match (1) { 1 => 'one', default => 'other' };\n",
    "$s = <<<TXT\nheredoc $x\nTXT;\n",
    "declare(strict_types=1);\n",
    "namespace N { function f() { return __FUNCTION__; } }\n",
]


def generate_input(rng, output):
    parts = ["<?php\n"]
    for _ in range(1 + _byte(rng) % 4):
        stmt = _pick(rng, _STATEMENTS)
        if "%s" in stmt:
            stmt = stmt % (stmt.count("%s") * (_pick(rng, _VALUES),))
        parts.append(stmt)
    parts.append("?>\n")
    output.write("".join(parts).encode())
