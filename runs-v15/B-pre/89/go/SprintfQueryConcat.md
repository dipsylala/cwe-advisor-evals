## Verdict

**Confirmed**. The code is vulnerable to SQL injection via unsanitized user input concatenated into a query string.

## Source

The `username` parameter is extracted from an untrusted HTTP query string on line 14:

```
username := r.URL.Query().Get("username")
```

An attacker controls this value entirely.

## Fix

Replace string concatenation with parameterized queries. Use a placeholder (`?`) for the data value and pass the username as a separate argument to `QueryRow`:

```go
query := "SELECT id, email, role FROM users WHERE username = ?"
row := h.DB.QueryRow(query, username)
```

This replaces lines 16–18 of the original code. The database driver treats the username as data, never as query structure, preventing injection regardless of its content.

## Explanation

The original code builds the SQL query by interpolating user input into the query string via `fmt.Sprintf`. This allows an attacker to inject SQL syntax—for example, providing `username = ' OR '1'='1` produces the query `WHERE username = '' OR '1'='1'`, which bypasses authentication.

Parameterized queries (prepared statements) separate query structure from data. The `?` placeholder instructs the database driver to treat the following argument as a data value only. The driver handles escaping internally and ensures the value cannot alter query logic. This is Go's standard defence against SQL injection and is built into `database/sql` without additional dependencies.

## Behaviour changes

- **Functional impact**: None for legitimate inputs. The query executes identically and returns the same results.
- **Security impact**: Injection attacks are eliminated. Payloads like `' OR '1'='1` or `'; DROP TABLE users; --` are stored and compared as literal strings.
- **API impact**: None. The code still uses `database/sql.DB.QueryRow()` and `Scan()` in the same way.
- **Dependencies**: None. Parameterized queries are a core feature of `database/sql`.
