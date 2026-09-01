## Verdict

CONFIRMED. SQL injection via string concatenation. User-controlled `username` parameter is interpolated directly into the SQL query string using `fmt.Sprintf`, allowing attackers to inject SQL metacharacters and manipulate query logic.

## Source

Line 14: `username := r.URL.Query().Get("username")`

Untrusted query parameter from HTTP request.

## Fix

Replace line 16–18:

**Vulnerable:**
```go
query := fmt.Sprintf("SELECT id, email, role FROM users WHERE username = '%s'", username)
row := h.DB.QueryRow(query)
```

**Fixed:**
```go
query := "SELECT id, email, role FROM users WHERE username = ?"
row := h.DB.QueryRow(query, username)
```

For PostgreSQL drivers, substitute `$1` for `?`:
```go
query := "SELECT id, email, role FROM users WHERE username = $1"
row := h.DB.QueryRow(query, username)
```

## Explanation

The fixed code uses parameterized query syntax with a placeholder (`?` or `$1`) in the SQL string and passes the user value as a separate argument to `QueryRow()`. The database driver treats the parameter as data, never as executable SQL syntax. This eliminates the injection vector; SQL metacharacters in `username` such as `'` or `--` are escaped automatically by the driver and cannot alter query structure.

The fix preserves the original contract: `QueryRow()` still returns a `*Row` for scanning results, and error handling remains unchanged.

## Behaviour changes

- Injection characters in `username` are now literal string values, not SQL syntax.
- Performance is neutral or improved: prepared statements are reusable and reduce parse overhead.
- No change to application logic or error handling.
- The fix is compatible with all Go database drivers (`github.com/lib/pq` for PostgreSQL, MySQL drivers, SQLite, etc.); use the corresponding placeholder syntax for each driver.
