## Verdict

Confirmed. `GetUserByName` builds the SQL statement with `fmt.Sprintf`, splicing the raw `username` query parameter directly into the string literal, then executes the result with `h.DB.QueryRow(query)`. A value such as `' OR '1'='1` or a stacked/UNION payload changes the query's logic or exfiltrates data outside the `users` table, because the database receives attacker-controlled text as part of the SQL grammar rather than as a literal value.

## Source

`username := r.URL.Query().Get("username")` on line 14 of `SprintfQueryConcat.go` - an untrusted HTTP query parameter - flows unmodified into `fmt.Sprintf` on line 16 and then into `h.DB.QueryRow(query)` on line 18, the sink identified by the finding.

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

The fix replaces string-built SQL with a parameterized query: the statement text is now a fixed literal containing a `?` placeholder, and `username` is passed to `database/sql`'s `QueryRow` as a separate argument. The `database/sql` driver sends the statement and the parameter to the server separately (or otherwise ensures the value is bound strictly as data), so the database can no longer interpret any characters in `username` - quotes, `--`, `;`, etc. - as SQL syntax. This closes the injection without changing the handler's behavior for legitimate usernames, and requires no new validation, escaping, or allowlist: the driver's placeholder binding is the complete, correct defense for this sink. (The `?` placeholder syntax shown here is for MySQL-family drivers; drivers such as `lib/pq` for PostgreSQL use positional `$1` placeholders instead - the binding mechanism and security guarantee are identical either way.)
