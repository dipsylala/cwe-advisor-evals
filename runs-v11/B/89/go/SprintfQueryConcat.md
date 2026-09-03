## Verdict

Exploitable. Untrusted username from the URL query string is concatenated directly into the SQL query via `fmt.Sprintf`, allowing an attacker to inject SQL commands.

## Source

`r.URL.Query().Get("username")` at line 14 — user-controlled input from URL query parameter.

## Fix

**Vulnerable code (line 16-18):**
```go
query := fmt.Sprintf("SELECT id, email, role FROM users WHERE username = '%s'", username)
// SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
row := h.DB.QueryRow(query)
```

**Fixed code:**
```go
query := "SELECT id, email, role FROM users WHERE username = ?"
row := h.DB.QueryRow(query, username)
```

## Explanation

The vulnerability is eliminated by replacing string concatenation with parameterized queries. Instead of interpolating the `username` variable into the SQL string via `fmt.Sprintf`, the fixed code uses a placeholder (`?`) in the query string and passes the username as a separate parameter to `QueryRow()`. The Go database driver treats the parameter as data, not executable SQL, so metacharacters like single quotes are escaped automatically and cannot manipulate query logic. This is Go's standard defence against SQL injection and works with all `database/sql` drivers (MySQL, PostgreSQL, SQLite).

## Behaviour changes

None. The `QueryRow()` call now receives the query and parameter separately instead of a pre-concatenated string. The driver executes the same logical query but with the parameter value safely bound, and `Scan()` retrieves results identically. No changes to return values, error handling, or result processing are required.
