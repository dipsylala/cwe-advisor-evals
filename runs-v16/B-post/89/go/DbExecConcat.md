## Verdict

Exploitable. Untrusted data from HTTP request parameters flows directly into SQL query string via `fmt.Sprintf`, allowing SQL injection at the `db.Exec()` sink.

## Source

1. `userID := r.URL.Query().Get("user_id")` (line 14) — attacker-controlled URL query parameter
2. `displayName := r.FormValue("display_name")` (line 15) — attacker-controlled form parameter

Both values reach the sink unvalidated.

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

The fix replaces string concatenation with parameterized query placeholders (`?`), moving untrusted values out of the query string and into separate arguments to `db.Exec()`. This ensures the database driver treats `displayName` and `userID` as data literals, not SQL syntax. An attacker cannot inject SQL commands through these parameters: a payload like `' OR '1'='1` is stored and compared as the literal string value, not executed as code.

## Behaviour changes

None. The original code's contract is preserved: `db.Exec()` still returns the same `sql.Result` and `error`, row counting and error handling remain unchanged, and the update operation produces identical results for all legitimate inputs.
