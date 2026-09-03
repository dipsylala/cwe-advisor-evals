## Verdict
CWE-89 SQL Injection confirmed. The code constructs an SQL query by concatenating user-supplied input directly into the statement string without parameterization.

## Source
Lines 17-19 in DbExecConcat.go:
- Line 14: `userID` is read from query parameters without validation
- Line 15: `displayName` is read from form data without validation
- Line 17: Both values are interpolated directly into an SQL statement string using `fmt.Sprintf`
- Line 19: The unsanitized statement is executed via `h.DB.Exec(stmt)`

An attacker can supply `display_name` containing SQL metacharacters (e.g., `' OR '1'='1`) or `user_id` containing SQL fragments to rewrite the query and execute arbitrary database operations.

## Fix
Replace string concatenation with parameterized queries using `?` placeholders:

```go
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

The key change: move from `fmt.Sprintf("UPDATE ... '%s' ... %s", displayName, userID)` to `"UPDATE ... ? ... ?"` with values passed as separate arguments to `Exec()`.

## Explanation
Parameterized queries in Go's `database/sql` package treat the placeholder values as data, never as SQL syntax. The database driver handles escaping and ensures user input cannot alter the query structure.

When using `Exec(stmt, arg1, arg2)`, each `?` is replaced by a properly escaped version of the corresponding argument value. This prevents SQL injection because the attacker's input remains data, even if it contains quotes, semicolons, or other SQL keywords.

This approach is Go's idiomatic defence against SQL injection and works across all supported database drivers.
