# sqlite3_ossfuzz format

Inputs are SQL statement sequences accepted by SQLite: CREATE/INSERT/SELECT/UPDATE/DELETE, expressions, pragmas, and transactions. Uses the upstream-native ELFuzz sqlite3 adapter bound to the pinned FuzzBench sqlite3_ossfuzz binary.
