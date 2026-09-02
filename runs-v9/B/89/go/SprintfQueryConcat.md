## Verdict

Exploitable. Confidence: high.

- **CWE**: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'))
- **Location**: `SprintfQueryConcat.go`, line 18 (`h.DB.QueryRow(query)`), fed by the concatenation at line 16

## Source

`username := r.URL.Query().Get("username")` (line 14) - the `username` query-string parameter of the incoming HTTP request, fully attacker-controlled.

## Fix

**Vulnerable code:**

```go
query := fmt.Sprintf("SELECT id, email, role FROM users WHERE username = '%s'", username)
row := h.DB.QueryRow(query)
```

`username` is interpolated directly into the SQL string literal via `fmt.Sprintf`. An attacker who sends `username=' OR '1'='1` (or a payload closing the quote and appending a `UNION SELECT` / boolean condition) changes the query's logic rather than supplying a value for it.

**Fixed code:**

```go
query := "SELECT id, email, role FROM users WHERE username = ?"
row := h.DB.QueryRow(query, username)
```

## Explanation

The fix replaces string interpolation with a parameterized query: the SQL text is now a static literal, and `username` is passed as a separate argument to `QueryRow`. `database/sql` sends the value to the driver out-of-band from the query text, so it is always bound as a literal value for the `username` column and can no longer alter the query's structure, regardless of quotes, comments, or SQL keywords it contains. This is the primary defence per the CWE-89 Go guidance; no allowlist step is needed here because `username` is used only as a bound value, not as an identifier (table/column name or sort direction).

Assumption: the target driver was not identifiable from the snippet (only `database/sql` is imported, no driver import visible). The fix uses `?`, the MySQL/SQLite placeholder convention; if the underlying driver is PostgreSQL, the placeholder should be `$1` instead. This does not change the fix mechanism, only the placeholder syntax.

## Behaviour changes

None. `h.DB.QueryRow(query, username)` still returns a `*sql.Row` handled identically by the existing `row.Scan(&id, &email, &role)` and not-found error path (line 22-25); the query still selects the same columns for the same matching semantics (exact equality on `username`), and no output produced or discarded by the sink changes.
