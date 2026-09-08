## Verdict

The vulnerability at line 19 is confirmed: user-controlled input from `displayName` and `userID` are concatenated directly into the SQL query string via `fmt.Sprintf`, then passed to `h.DB.Exec()`. An attacker can inject SQL operators, conditions, or commands through either parameter.

## Source

Line 14-15: HTTP request parameters (`userID` from query string, `displayName` from form data) are obtained without validation.

Line 17: `fmt.Sprintf("UPDATE users SET display_name = '%s' WHERE id = %s", displayName, userID)` concatenates untrusted input directly into the SQL query string.

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

The fix replaces string concatenation with parameterized queries. Line 17 now uses `?` placeholders instead of interpolating values. Line 19 passes user input as separate arguments to `h.DB.Exec()`: the query string and two parameters (`displayName`, `userID`). The `database/sql` driver treats each parameter as pure data, not executable SQL, preventing injection. Placeholders are positional: the first `?` receives `displayName`, the second receives `userID`.

## Behaviour changes

The query execution is now safe against SQL injection. Query results are unchanged for legitimate input. The application behavior is identical for all valid user IDs and display names—no input validation changes or new constraints are introduced. The fix is a direct replacement of the unsafe string construction with parameterization and introduces no breaking changes.

