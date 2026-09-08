## Verdict

exploitable

- cwe_id: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'))
- location: `DbExecConcat.go`, line 19 (`h.DB.Exec(stmt)`)
- confidence: high

## Source

Two independent taint sources feed the sink:

- `r.URL.Query().Get("user_id")` (line 14) - attacker-controlled query string parameter, assigned to `userID`.
- `r.FormValue("display_name")` (line 15) - attacker-controlled form field, assigned to `displayName`.

Both flow unchanged into `fmt.Sprintf("UPDATE users SET display_name = '%s' WHERE id = %s", displayName, userID)` (line 17), which builds the query text via string interpolation, then straight into `h.DB.Exec(stmt)` (line 19) with no validation, escaping, or parameterization in between. `displayName` lands inside a quoted string literal (breakable with a single `'`) and `userID` lands in an unquoted numeric context (breakable with no quote needed at all, e.g. `1 OR 1=1`), so both parameters are independently exploitable.

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

The fix removes the `fmt.Sprintf`-built query string and replaces it with a static SQL statement that uses `?` placeholders for both values, passing `displayName` and `userID` as separate variadic arguments to `h.DB.Exec`. `database/sql` sends parameter values to the driver out-of-band from the query text, so the database always treats them as literal data - a `'` in `displayName` or an `OR 1=1` in `userID` can no longer alter the query's structure. Both taint sources are values bound into an `UPDATE ... SET x = ? WHERE id = ?` statement, not identifiers (no table/column/sort-direction is user-controlled here), so parameterization alone is the complete fix; no allowlist step is needed. `userID` is still used unchanged in the final `fmt.Fprintf` response line, which is an output write, not a SQL sink, so no further change is needed there.

## Behaviour changes

none - the sink's contract is preserved: `h.DB.Exec` still returns the same `(sql.Result, error)` pair, `RowsAffected()` and the "not found" / "failed" error paths are untouched, and the success response still echoes `userID`. The only substantive change is how the query text and its two values reach the driver (bound parameters vs. string interpolation); no argument was added, dropped, reordered, or given a different default, and no previously-discarded output is now surfaced.

**Verification**: `go vet ./...` against a scratch copy of the fixed file (with a minimal `go.mod`) completed with no diagnostics (exit 0). `go build` on that same scratch module fails with `function main is undeclared in the main package` - this is pre-existing and unrelated to the fix: the case fixture is a single `package main` file with no `main()` function, so it does not build standalone even before the change; it is meant to be compiled as part of a larger package. Every symbol the fixed code uses (`database/sql`, `fmt`, `net/http`, `h.DB.Exec`) is unchanged from the original file - no new import or API was introduced.

**Assumptions**: the placeholder syntax `?` is MySQL/SQLite-style; no driver import is present in the file to confirm which `database/sql` driver is in use. If the underlying driver is PostgreSQL, the placeholders must be positional (`$1`, `$2`) instead. This does not change the fix's structure, only the placeholder token, and is noted per the Go guidance's placeholder-syntax distinction.
