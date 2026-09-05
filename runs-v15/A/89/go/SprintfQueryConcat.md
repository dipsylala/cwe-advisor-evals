## Verdict
Confirmed. The code constructs a SQL query by concatenating unsanitized user input directly into the query string, enabling SQL injection.

## Source
Line 16: `query := fmt.Sprintf("SELECT id, email, role FROM users WHERE username = '%s'", username)`

The `username` parameter originates from the HTTP request query string (line 14) without validation or escaping. When this query is executed on line 18, an attacker can inject arbitrary SQL syntax by supplying a crafted username like `' OR '1'='1` or `'; DROP TABLE users; --`.

## Fix
Replace the string concatenation with a parameterized query:

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
Parameterized queries (prepared statements) separate SQL code from data by using placeholders (`?` in Go's `database/sql` package). The database driver handles proper quoting and escaping of the parameter value, preventing the user input from being interpreted as SQL syntax. This is the standard and only reliable defense against SQL injection in Go. The placeholder syntax is agnostic to the underlying database; the driver translates `?` to the appropriate syntax for the target database (e.g., `$1` for PostgreSQL, `?` for MySQL/SQLite).
