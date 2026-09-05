## Verdict

Exploitable. User input from `r.URL.Query().Get("user_id")` and `r.FormValue("display_name")` flows directly into SQL via string concatenation at line 17, then executes at line 19 without parameterization. Both quoted (`displayName`) and unquoted (`userID`) contexts allow injection.

## Source

- `userID` from `r.URL.Query().Get("user_id")` (line 14)
- `displayName` from `r.FormValue("display_name")` (line 15)

Both are attacker-controlled HTTP request data with no validation before use.

## Fix

**Vulnerable code (line 17-19):**
```go
stmt := fmt.Sprintf("UPDATE users SET display_name = '%s' WHERE id = %s", displayName, userID)
result, err := h.DB.Exec(stmt)
```

**Fixed code:**
```go
stmt := "UPDATE users SET display_name = ? WHERE id = ?"
result, err := h.DB.Exec(stmt, displayName, userID)
```

## Explanation

Replace string concatenation with parameterized query placeholders (`?`). User-controlled values (`displayName`, `userID`) are now passed as separate arguments to `db.Exec()`, ensuring they are treated as data, not SQL syntax. This prevents both quoted injection (e.g., `' OR '1'='1`) and unquoted numeric injection (e.g., `1 OR 1=1`). The fix uses Go's `database/sql` built-in parameterization, which is safe across MySQL, SQLite, and other drivers that support `?` placeholders.

## Behaviour changes

None. The `db.Exec()` method signature, return type, and error handling remain identical. The query executes identically for legitimate input, and the fix preserves all existing contract properties (return value, error handling, row count retrieval).
