# G2Fuzz MAGMA target: `sqlite3`

- MAGMA target: `sqlite3`, program `sqlite3_fuzz`
- Format: SQL script executed by `sqlite3_exec`
- Method profile: extension (no upstream G2Fuzz program-map entry).
- Generator focus: DDL (CREATE TABLE/INDEX/VIEW/TRIGGER), DML (INSERT/UPDATE/
  DELETE/REPLACE/UPSERT), joins/subqueries/CTEs/window functions, expressions,
  casts, collations, JSON functions, PRAGMA statements, transactions, and
  multiple statements per input.
