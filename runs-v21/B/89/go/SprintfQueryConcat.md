## Verdict

The finding is a confirmed SQL injection vulnerability. Untrusted user input from the URL query parameter is interpolated into a SQL query string using `fmt.Sprintf()`, allowing an attacker to inject malicious SQL operators and logic.

## Source

- **Type**: Untrusted HTTP query parameter
- **Origin**: `username := r.URL.Query().Get("username")` at line 14
- **Path**: HTTP request → query parameter → string concatenation → SQL query → database execution

## Fix

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

The original code built the SQL query by concatenating the untrusted `username` parameter directly into the query string using `fmt.Sprintf()`. This allowed an attacker to inject SQL operators (e.g., `' OR '1'='1`) that would be parsed as part of the query structure rather than treated as data.

The fix replaces the string concatenation pattern with a parameterized query using Go's `database/sql` placeholder syntax (`?`). The username is now passed as a separate argument to `db.QueryRow()` instead of being interpolated into the query string. This ensures the database driver treats the username as a literal string value in a data context, not as executable SQL code.

The `?` placeholder is database-agnostic in Go and works with MySQL, SQLite, and other drivers. PostgreSQL users would use `$1` instead, but the principle is identical: separate the query structure from the data values.

## Behaviour changes

- The query string is now static (`SELECT id, email, role FROM users WHERE username = ?`) rather than built dynamically
- The `username` parameter is bound separately via the variadic argument list to `QueryRow()`
- Malicious payloads such as `' OR '1'='1` are now treated as literal strings in the SQL comparison, not as SQL operators
- No functional change to legitimate use cases—the query returns the same results for valid usernames
- Error handling and return value behavior remain unchanged
