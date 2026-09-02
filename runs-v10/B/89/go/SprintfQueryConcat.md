## Verdict

Exploitable. An attacker can inject SQL by providing input like `' OR '1'='1` or `'; DELETE FROM users; --` in the `username` query parameter, allowing them to bypass authentication, extract unauthorized data, or execute arbitrary commands.

## Source

Line 14: `username := r.URL.Query().Get("username")` - untrusted user input from the URL query parameter flows directly into the SQL query string without sanitization.

## Fix

**Vulnerable code (lines 16-18):**
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

The vulnerability occurs because `username` is directly interpolated into the SQL query string using `fmt.Sprintf`. This allows an attacker to inject SQL syntax (quotes, boolean operators, comments, etc.) to manipulate the query logic. The fix replaces string concatenation with Go's `database/sql` parameterized query mechanism: the `?` placeholder in the query string is replaced with a value passed as a separate argument to `QueryRow()`, ensuring the username is always treated as literal data and never as executable SQL code. The database driver handles proper escaping transparently.

## Behaviour changes

None. The fix preserves the original behaviour entirely:
- `QueryRow()` still returns a single `*sql.Row` object for the calling code to scan
- `row.Scan(&id, &email, &role)` works identically - same column mapping, same error handling
- Error returns from `row.Scan()` are unchanged (still triggers the 404 response)
- The HTTP response content and format are identical
- The only change is the mechanism of parameter passing, which is internal to the database driver and transparent to the caller
