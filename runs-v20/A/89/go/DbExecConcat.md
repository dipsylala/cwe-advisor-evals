## Verdict
Confirmed. `userID` and `displayName` are both request-controlled (`r.URL.Query().Get("user_id")` and `r.FormValue("display_name")`) and are concatenated directly into a SQL string via `fmt.Sprintf`, which is then executed by `h.DB.Exec`. An attacker can break out of the quoted `display_name` value or inject through the unquoted `id` value to alter the query, read/modify unrelated rows, or run stacked statements depending on the driver.

## Source
`r.URL.Query().Get("user_id")` and `r.FormValue("display_name")` in `UpdateDisplayName` (DbExecConcat.go lines 14-15), flowing unmodified into the `fmt.Sprintf`-built query string on line 17 and executed at the `h.DB.Exec(stmt)` sink on line 19.

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

	result, err := h.DB.Exec("UPDATE users SET display_name = ? WHERE id = ?", displayName, userID)
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
The fix replaces the `fmt.Sprintf`-built query with a parameterized statement, passing `displayName` and `userID` as bind arguments to `h.DB.Exec` instead of interpolating them into the SQL text. The `database/sql` driver sends the query and its parameters separately, so the database treats both values strictly as data - any quotes, semicolons, or SQL keywords they contain cannot change the statement's structure, closing the injection while preserving the original update-by-id behavior. This uses the `?` placeholder syntax expected by `database/sql` drivers that follow the ordinal-question-mark convention (e.g. MySQL/SQLite); if the underlying driver is PostgreSQL, the placeholders should instead be `$1`, `$2` in argument order. No other behavior changes: the same rows-affected check and response messages are preserved.
