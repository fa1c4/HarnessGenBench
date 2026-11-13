# G2Fuzz MAGMA target: `php`

- MAGMA target: `php`, program `parser`
- Format: PHP source file compiled by `zend_compile_file`
- Method profile: extension (no upstream G2Fuzz program-map entry).
- Generator focus: `<?php` blocks, variables/arrays, function/class/namespace
  declarations, closures, control flow, exceptions, match expressions, named
  arguments, heredoc/nowdoc, attributes, and parser-stressing but valid syntax.
