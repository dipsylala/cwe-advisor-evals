## Verdict
CONFIRMED

## Source
Line 17–19: SQL query constructed via string concatenation with user-supplied `displayName` and `userID` parameters, then passed to `h.DB.Exec()`.

```go
stmt := fmt.Sprintf("UPDATE users SET display_name = '%s' WHERE id = %s", displayName, userID)
result, err := h.DB.Exec(stmt)
```

An attacker can inject SQL through either parameter by supplying values like `' OR '1'='1` or `1 UNION SELECT ...`, allowing arbitrary database modification or disclosure.

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
The fix replaces string concatenation with a parameterized query using `?` placeholders. Arguments are passed separately to `Exec()`, ensuring the database driver treats them as data, not executable SQL syntax. This eliminates the injection vector regardless of input content: special characters like quotes, semicolons, and SQL keywords are automatically escaped and cannot alter query structure.
