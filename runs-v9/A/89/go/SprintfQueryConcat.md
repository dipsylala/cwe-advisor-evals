## Verdict

Confirmed. The query string is built with `fmt.Sprintf` by directly interpolating an attacker-controlled HTTP query parameter into a SQL string literal, then executed as-is. This is classic SQL injection.

## Source

`username := r.URL.Query().Get("username")` (line 14) - user-controlled value read from the `username` query string parameter of the incoming HTTP request.

## Fix

```go
func (h *UserHandler) GetUserByName(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	row := h.DB.QueryRow(
		"SELECT id, email, role FROM users WHERE username = ?",
		username,
	)

	var id int
	var email, role string
	if err := row.Scan(&id, &email, &role); err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	fmt.Fprintf(w, "id=%d email=%s role=%s", id, email, role)
}
```

(If `h.DB` is a driver that uses positional dollar placeholders, e.g. `lib/pq` or `pgx` for PostgreSQL, use `$1` instead of `?`.)

## Explanation

The vulnerable code builds the SQL statement with `fmt.Sprintf("... WHERE username = '%s'", username)`, splicing the raw `username` value directly inside a quoted string literal. Because `username` comes straight from `r.URL.Query().Get("username")` with no escaping or validation, an attacker can supply a value such as `' OR '1'='1' --` (or a subquery/UNION payload) to break out of the intended string literal and alter the query's logic, potentially bypassing the lookup entirely or exfiltrating data outside the `users` table.

The fix removes the string-building step entirely and passes the query to `sql.DB.QueryRow` as a parameterized statement: the literal SQL text uses a placeholder (`?` for MySQL-style drivers, `$1` for PostgreSQL-style drivers) and `username` is passed as a separate argument. `database/sql` sends the query and its parameters to the driver separately, so the driver binds the value as data rather than as part of the SQL grammar - it can no longer change the query's structure no matter what characters it contains. This also removes the need for any manual escaping or input sanitization, which is fragile and easy to bypass compared to parameterization.

No other behavior changes: the same query is executed, the same columns are scanned, and the not-found and success paths are unchanged.
