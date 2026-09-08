## Verdict

CONFIRMED. The code constructs a SQL statement via string concatenation with untrusted user input (`displayName` and `userID`) and executes it directly, enabling SQL injection attacks.

## Source

- Line 14: `userID := r.URL.Query().Get("user_id")` — untrusted URL parameter
- Line 15: `displayName := r.FormValue("display_name")` — untrusted form value
- Line 17: Both values are interpolated into a SQL string via `fmt.Sprintf`
- Line 19: The unsanitized query string is passed to `h.DB.Exec()`

## Fix

### File: DbExecConcat.go

```go
package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

type ProfileHandler struct {
	DB *sql.DB
}

func (h *ProfileHandler) UpdateDisplayName(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	displayName := r.FormValue("display_name")

	stmt := "UPDATE users SET display_name = ? WHERE id = ?"
	// SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
	result, err := h.DB.Exec(stmt, displayName, userID)
	if err != nil {
		http.Error(w, "failed to update display name", http.StatusInternalServerError)
		return
	}

	rows, err := result.RowsAffected()
	if err != nil || rows == 0 {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	fmt.Fprintf(w, "display name updated for user %s", userID)
}
```

## Explanation

Replace string concatenation with parameterized query syntax. The `?` placeholders separate the SQL structure from user-supplied values, ensuring the database driver handles escaping correctly and prevents SQL injection.

- Line 17: Changed `fmt.Sprintf` with embedded values to a plain SQL statement with `?` placeholders
- Line 19: Updated `Exec` call to pass values as separate arguments: `h.DB.Exec(stmt, displayName, userID)`

This mechanism guarantees that the values are treated as data, not as SQL code, regardless of their content.
