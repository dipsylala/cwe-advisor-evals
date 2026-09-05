## Verdict
SQL injection vulnerability confirmed. User-supplied input from `displayName` and `userID` query parameters is directly concatenated into a SQL query string without parameterization, allowing attackers to inject arbitrary SQL commands.

## Source
Lines 14-19 in `DbExecConcat.go`:
```go
userID := r.URL.Query().Get("user_id")
displayName := r.FormValue("display_name")

stmt := fmt.Sprintf("UPDATE users SET display_name = '%s' WHERE id = %s", displayName, userID)
result, err := h.DB.Exec(stmt)
```

Both `userID` and `displayName` originate from untrusted request sources and are interpolated directly into the SQL string via `fmt.Sprintf`.

## Fix
Replace string concatenation with a parameterized query using Go's `database/sql` placeholder syntax:

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

## Explanation
The fix uses Go's parameterized query feature via `?` placeholders in the query string. The `Exec` method receives the SQL template and the parameter values separately, ensuring the database driver handles escaping and prevents interpretation of user input as SQL syntax. This is the primary defense against SQL injection in Go's `database/sql` package.
