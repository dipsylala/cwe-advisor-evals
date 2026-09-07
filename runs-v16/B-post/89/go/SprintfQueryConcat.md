## Verdict

**Exploitable.** The `username` parameter from the HTTP request (line 14) flows directly into SQL via `fmt.Sprintf` concatenation (line 16), reaching `h.DB.QueryRow()` (line 18) without parameterization. An attacker can inject SQL syntax to alter the query logic, bypass authentication, or extract unauthorized data.

## Source

`r.URL.Query().Get("username")` at line 14 returns untrusted user input from the URL query string.

## Fix

Replace lines 16-18:

```go
query := fmt.Sprintf("SELECT id, email, role FROM users WHERE username = '%s'", username)
// SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
row := h.DB.QueryRow(query)
```

With:

```go
query := "SELECT id, email, role FROM users WHERE username = ?"
row := h.DB.QueryRow(query, username)
```

## Explanation

The fix replaces string concatenation with Go's `database/sql` parameterized query syntax. The `?` placeholder tells the driver to treat the second argument (`username`) as data, not executable SQL. The driver escapes the value appropriately for the target database, preventing interpretation of special characters such as single quotes or SQL keywords as query structure. This closes the injection vector regardless of the input content.

## Behaviour changes

The query execution cost and latency remain identical. Return values and error handling are unchanged—`QueryRow` still returns a `*sql.Row` with the same `Scan` interface. The application's visible behaviour is unaffected; only the internal mechanism for preventing injection changes.
