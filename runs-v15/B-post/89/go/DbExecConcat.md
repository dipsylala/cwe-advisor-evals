## Verdict

Exploitable. Attacker-controlled input from request parameters flows directly into SQL via string concatenation and is executed without parameterization.

## Source

- `userID` via `r.URL.Query().Get("user_id")` (line 14)
- `displayName` via `r.FormValue("display_name")` (line 15)

Both are untrusted request data.

## Fix

**Vulnerable code:**

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

Replace string concatenation with parameterized queries. Go's `database/sql` API accepts placeholders (`?` for MySQL/SQLite, `$1`/`$2` for PostgreSQL) and user input as separate arguments to `Exec()`. The database driver treats arguments as data values, not executable SQL code, preventing injection. This closes the vulnerability because a literal `'` character in `displayName` is stored as data, not interpreted as SQL syntax, and a numeric bypass like `1 OR 1=1` in `userID` is compared as a literal string value, not evaluated as a logical expression.

## Behaviour changes

None. The fix preserves the original function's contract: same return value, same error handling, same query semantics. The difference is that user input is now safely parameterized rather than concatenated into the query string.
