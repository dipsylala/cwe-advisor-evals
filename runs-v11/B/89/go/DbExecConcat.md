## Verdict

Exploitable. Both `userID` (line 14, from URL query parameter) and `displayName` (line 15, from form data) are untrusted inputs directly concatenated into an SQL query string via `fmt.Sprintf` (line 17), then executed without parameterization (line 19). An attacker can inject arbitrary SQL by crafting malicious values in either parameter.

## Source

- Line 14: `userID := r.URL.Query().Get("user_id")` — untrusted URL query parameter
- Line 15: `displayName := r.FormValue("display_name")` — untrusted form data

## Fix

**Vulnerable code (lines 17–19):**
```go
stmt := fmt.Sprintf("UPDATE users SET display_name = '%s' WHERE id = %s", displayName, userID)
// SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
result, err := h.DB.Exec(stmt)
```

**Fixed code:**
```go
stmt := "UPDATE users SET display_name = ? WHERE id = ?"
result, err := h.DB.Exec(stmt, displayName, userID)
```

## Explanation

The original code concatenates untrusted input directly into the SQL query using `fmt.Sprintf`, allowing SQL injection. The fix uses Go's `database/sql` parameterized query mechanism: the query text contains `?` placeholders where values belong, and those values are passed as separate arguments to `Exec()`. The database driver treats each argument as data, not as executable SQL code, making injection impossible regardless of input content.

## Behaviour changes

None. The fix preserves the original sink contract: `Exec()` still returns `sql.Result` and `error` with identical error handling and return-value usage. No parameters are added, omitted, or altered beyond the parameterization itself.
