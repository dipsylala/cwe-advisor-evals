## Verdict

Real SQL injection vulnerability. The username parameter from the HTTP request is directly concatenated into the SQL query string using `fmt.Sprintf`, allowing attackers to inject SQL syntax (e.g., `' OR '1'='1`) to bypass authentication or extract unauthorized data.

## Source

HTTP request URL query parameter `username` at line 14, passed without validation or parameterization into SQL query construction at line 16.

## Fix

Replace string concatenation with parameterized query syntax. Pass the username as a separate parameter to `QueryRow()` instead of interpolating it into the query string.

### File: SprintfQueryConcat.go

```go
package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

type UserHandler struct {
	DB *sql.DB
}

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

The fix replaces `fmt.Sprintf` with parameterized query syntax. The query string now uses `?` as a placeholder for the username value. The username is passed as a separate argument to `QueryRow()` instead of being interpolated into the query string. This ensures that the database driver treats the username as data, not as executable SQL code. The `?` placeholder is the standard Go `database/sql` syntax for MySQL and SQLite drivers; PostgreSQL would use `$1` instead, but the common `?` form works with MySQL/SQLite which are typical for this pattern.

The rest of the function remains unchanged: `Scan()` correctly populates the three variables, and error handling is preserved.

## Behaviour changes

None. The query logic, result handling, and HTTP response are identical. Only the mechanism of passing the parameter changes: from unsafe string concatenation to safe parameterized execution.
