## Verdict

**Confirmed SQL Injection via string concatenation (CWE-89).** The `username` parameter from the URL query is directly interpolated into the SQL query string using `fmt.Sprintf` without sanitization, then passed to `db.QueryRow()`. An attacker can inject SQL syntax by providing a username like `' OR '1'='1` to bypass authentication or retrieve unauthorized data.

## Source

The vulnerability originates at line 14 in `GetUserByName()`:
```go
username := r.URL.Query().Get("username")
```

The `username` parameter is read from an untrusted URL query string and flows directly into the SQL query construction on line 16:
```go
query := fmt.Sprintf("SELECT id, email, role FROM users WHERE username = '%s'", username)
```

Line 18 executes this concatenated query:
```go
row := h.DB.QueryRow(query)
```

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

The fix replaces string concatenation with parameterized query syntax. Instead of interpolating the `username` into the query string, a `?` placeholder is used as a value marker, and the username is passed as a separate parameter argument to `QueryRow()`. The `database/sql` driver automatically treats the parameter as data, not executable SQL code, preventing injection. This is the standard safe pattern for Go's `database/sql` with MySQL/SQLite drivers; PostgreSQL drivers would use `$1` instead of `?`.

## Behaviour changes

- The SQL query text no longer contains the username value; it is passed out-of-band as a parameter to the database driver.
- The `QueryRow()` call now passes two arguments: the static query string and the username parameter.
- Return type and error handling remain unchanged; `row.Scan()` works identically with parameterized and concatenated queries.
- Database result set content is unchanged; the fix only affects how the query is transmitted to the database.
- No additional library dependencies required; `database/sql` has full support for this pattern.
