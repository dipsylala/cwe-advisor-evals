## Verdict

CONFIRMED: SQL injection via string concatenation. Both `userID` and `displayName` are untrusted user inputs directly interpolated into the SQL query using `fmt.Sprintf` at line 17, then executed at line 19. An attacker can inject SQL syntax through either parameter to manipulate the query logic.

## Source

- `userID`: `r.URL.Query().Get("user_id")` (line 14) — query string parameter, attacker-controlled
- `displayName`: `r.FormValue("display_name")` (line 15) — form field, attacker-controlled

Both values flow directly into `fmt.Sprintf` at line 17, building the query string.

## Fix

Replace the string concatenation with parameterized query syntax. Pass the values as separate arguments to `db.Exec()` instead of interpolating them into the query string.

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

The fix converts the query from a concatenated string to a parameterized query using placeholders. Line 17 changes from `fmt.Sprintf("UPDATE users SET display_name = '%s' WHERE id = %s", displayName, userID)` to `"UPDATE users SET display_name = ? WHERE id = ?"`, and line 18 passes the values as separate arguments to `h.DB.Exec(stmt, displayName, userID)`.

In Go's `database/sql`, the `?` placeholder marks where a value parameter should be substituted. The database driver ensures these parameters are safely bound as data, never as query syntax. This eliminates the injection risk: even if `displayName` or `userID` contains SQL metacharacters or syntax (e.g., `' OR '1'='1`), they are treated as literal string values, not as executable SQL.

## Behaviour changes

No functional changes. The query executes with the same logic:
- The UPDATE statement targets the same table, column, and WHERE clause.
- The values bound to the placeholders are identical to those in the original vulnerable code.
- Return values, error handling, and response messages remain unchanged.

The only change is the mechanism by which values are passed to the database — from string interpolation (unsafe) to parameterized binding (safe).
