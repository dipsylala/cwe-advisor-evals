## Verdict
**Confirmed**: SQL injection vulnerability. The `username` parameter from the HTTP query string is directly concatenated into the SQL query without parameterization, allowing an attacker to inject arbitrary SQL commands.

## Source
The vulnerability originates at line 14, where the untrusted `username` parameter is extracted from the HTTP request URL query string: `username := r.URL.Query().Get("username")`. This value flows directly into the SQL query construction without any input validation or parameterization.

## Fix
Replace the string concatenation approach with a parameterized query using `?` placeholders:

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
The original code uses `fmt.Sprintf` to interpolate the `username` parameter directly into the SQL query string. This allows an attacker to break out of the intended query structure by submitting input like `' OR '1'='1` or `'; DROP TABLE users; --`, fundamentally changing the SQL command's meaning and bypassing intended security controls.

The fix uses parameterized queries (prepared statements), where the query template and user-supplied values are sent separately to the database driver. The database treats the placeholder value (`?`) and the argument (`username`) as a data value only, never as executable SQL syntax. This prevents the attacker from injecting commands regardless of the input content.

This approach is the standard defense for SQL injection in Go's `database/sql` package. The `QueryRow(query, args...)` method binds arguments using the driver's parameterization mechanism, ensuring safe handling of any user input.
