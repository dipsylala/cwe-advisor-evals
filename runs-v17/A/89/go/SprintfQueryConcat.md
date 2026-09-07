## Verdict

CONFIRMED. The code constructs SQL queries through string concatenation with user-supplied input, allowing SQL injection.

## Source

Line 16 constructs the query using `fmt.Sprintf` with the untrusted `username` parameter:
```go
query := fmt.Sprintf("SELECT id, email, role FROM users WHERE username = '%s'", username)
```

An attacker can inject SQL syntax (e.g., `' OR '1'='1`) to alter the query's meaning and bypass authentication or extract unauthorized data.

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

The fix replaces string concatenation with parameterized query construction. Instead of embedding the username directly into the SQL string, the query uses a `?` placeholder. The `QueryRow` method receives both the query template and the parameter separately, ensuring the database driver treats the username as data, not executable SQL syntax.

Go's `database/sql` package automatically escapes parameters according to the underlying database's requirements, preventing the attacker from injecting SQL metacharacters. This is the standard defense against SQL injection across all databases supported by Go (MySQL, PostgreSQL, SQLite, etc.).

Key change: `fmt.Sprintf` with embedded user input → parameterized query with separate argument binding.
