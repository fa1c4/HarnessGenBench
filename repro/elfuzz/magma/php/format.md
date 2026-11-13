# PHP source input format for MAGMA `php`

The target is `parser` (MAGMA's `sapi/fuzzer/fuzzer-parser.c`), which compiles
the input as PHP source (`zend_compile_file` is the committed entry API).

Characteristics worth covering:

* the `<?php` opening tag and inline HTML outside it
* variables, arrays, function/class/namespace declarations, closures
* control flow and exception handling (`try`/`catch`/`finally`)
* string interpolation, heredoc/nowdoc syntax, comments
* attributes, match expressions, named arguments, enums
* syntactically valid but semantically odd fragments that stress the parser

The initial seed program returns a small valid PHP file.  ELFuzz mutates the
generator program, not the target harness.
