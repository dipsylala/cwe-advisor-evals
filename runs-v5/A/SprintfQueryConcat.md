## Verdict

Confirmed. `GetUserByName` builds a SQL query by interpolating the raw `username` query parameter into the statement string with `fmt.Sprintf`, then executes that string with `h.DB.QueryRow`. An attacker fully controls `username` via the URL query string, so they can inject SQL through the unescaped `'%s'` literal (e.g. terminate the string literal and append arbitrary conditions or stacked clauses), affecting the query's logic and results.

## Source

`username := r.URL.Query().Get("username")` (line 14) - untrusted, attacker-controlled HTTP query parameter.

## Fix

```go
func (h *UserHandler) GetUserByName(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	query := "SELECT id, email, role FROM users WHERE username = ?"
	row := h.DB.QueryRow(query, username)

	var id int
	var email, role string
	if err := row.Scan(&id, &email, &role); err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	fmt.Fprintf(w, "id=%d email=%s role=%s", id, email, role)
}
```

## Explanation

The fix replaces string concatenation with a parameterized query. The SQL text now contains a placeholder (`?`, the parameter marker `database/sql` uses for MySQL-family drivers; use `$1` for `lib/pq`/`pgx` or `:name`/positional binds per the specific driver in use) instead of the interpolated value, and `username` is passed as a separate argument to `QueryRow`. The database driver sends the query and the value separately and binds the value as data, so it can never be reinterpreted as SQL syntax regardless of what characters it contains (quotes, semicolons, comment sequences, etc.). This removes the injection vector entirely rather than trying to escape or filter the input, which is the correct primary defense for this class of finding - `fmt.Sprintf` (or any manual string building) should never be used to construct SQL text from external input.
