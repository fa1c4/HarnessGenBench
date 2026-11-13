# SQL input format for MAGMA `sqlite3`

The target is `sqlite3_fuzz` (MAGMA's `test/ossfuzz.c`), which executes the
input as a sequence of SQL statements (`sqlite3_exec` is the committed entry
API).

Characteristics worth covering:

* DDL: `CREATE TABLE`/`INDEX`/`VIEW`/`TRIGGER`, including `WITHOUT ROWID`
* DML: `INSERT`, `UPDATE`, `DELETE`, `REPLACE`, UPSERT
* queries: joins, subqueries, CTEs (`WITH`), window functions, aggregates
* expressions, casts, collations, `LIKE`/`GLOB`, JSON functions
* transactions, `PRAGMA` statements, `ATTACH`/`DETACH`
* multiple statements separated by semicolons

The initial seed program returns a short valid SQL script.  ELFuzz mutates the
generator program, not the target harness.
