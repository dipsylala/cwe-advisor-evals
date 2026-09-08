## Verdict
CONFIRMED. The vulnerability is a classic SQL injection caused by direct string concatenation of unsanitized user input into a SQL query.

## Source
Line 16 constructs the query using `fmt.Sprintf()` with the `username` parameter from `r.URL.Query().Get("username")` directly interpolated into the SQL string. An attacker can inject SQL metacharacters and commands by providing a malicious username value (e.g., `' OR '1'='1`).

Line 18 executes this untrusted query string via `h.DB.QueryRow()`, making it the sink where the injection takes effect.

## Fix

### File: SprintfQueryConcat.go

```go
package main

import (
	"database/sql"
	"net/http"
	"fmt"
)

type UserHandler struct {
	DB *sql.DB
}

func (h *UserHandler) GetUserByName(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	row := h.DB.QueryRow("SELECT id, email, role FROM users WHERE username = ?", username)

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
The fix replaces string concatenation with a parameterized query. Instead of using `fmt.Sprintf()` to build the query string, the code now passes the SQL query with a `?` placeholder and provides the username as a separate argument to `QueryRow()`. The database driver treats the parameter as data, not executable SQL, preventing injection attacks. This is the standard defense for SQL injection in Go's `database/sql` package.
