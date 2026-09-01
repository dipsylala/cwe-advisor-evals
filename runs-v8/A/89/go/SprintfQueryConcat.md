## Verdict

SQL injection vulnerability confirmed. The `username` parameter from the HTTP request is embedded directly into the SQL query string without sanitization or parameterization, allowing an attacker to inject arbitrary SQL.

## Source

Line 14: `username := r.URL.Query().Get("username")` — untrusted user input from the query string.

Line 16: `query := fmt.Sprintf("SELECT id, email, role FROM users WHERE username = '%s'", username)` — the username is interpolated directly into the SQL query string.

Line 18: `row := h.DB.QueryRow(query)` — the malformed query is executed against the database.

## Fix

Replace the string-concatenated query with a parameterized query:

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

Change line 16 from string formatting to a placeholder query, and pass `username` as a separate argument to `QueryRow()`.

## Explanation

Parameterized queries (prepared statements) separate the SQL command structure from user data. The `?` placeholder tells the database driver to treat the corresponding argument as data only, never as executable SQL. This eliminates the injection vector entirely—even if `username` contains SQL metacharacters like `' OR '1'='1`, they are transmitted to the database as literal string values, not parsed as query syntax.

`database/sql.DB.QueryRow()` accepts the query string and any number of parameter values as separate arguments. The driver handles all escaping and type conversion internally, ensuring the data cannot be misinterpreted as code.
