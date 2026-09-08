## Verdict

exploitable

- cwe_id: CWE-89
- location: SprintfQueryConcat.go, line 18 (sink), query built at line 16
- confidence: high

## Source

`r.URL.Query().Get("username")` (line 14) - the `username` query-string parameter from an incoming HTTP request, fully attacker-controlled and unvalidated.

## Fix

- library_recommendation: none - `database/sql` (standard library) already provides parameterized query support; no third-party library is needed for this fix.

### File: SprintfQueryConcat.go

```go
package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

type UserHandler struct {
	DB *sql.DB
}

func (h *UserHandler) GetUserByName(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	query := "SELECT id, email, role FROM users WHERE username = ?"
	row := h.DB.QueryRow(query, username)

	var id int
	var email, role string
	if err := row.Scan(&id, &email, &role); err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	fmt.Fprintf(w, "id=%d email=%s role=%s", id, email, role)
}
```

## Explanation

The original code built the SQL statement with `fmt.Sprintf("... WHERE username = '%s'", username)`, splicing the raw, attacker-controlled `username` value directly into the query text before handing it to `h.DB.QueryRow`; a value such as `' OR '1'='1' --` changes the query's logic and returns arbitrary rows. The fix keeps the sink (`h.DB.QueryRow`) and its two-value return contract (`*sql.Row`, whose error surfaces later through `row.Scan`) exactly as before, but replaces the interpolated literal with a `?` placeholder and passes `username` as a separate variadic argument. The database driver then binds `username` as a data value in the `username` column's context, never as SQL syntax, so no input can alter the query's structure. `?` is the placeholder syntax for the MySQL/SQLite family of `database/sql` drivers; the assumption below covers this choice since the driver package isn't shown in the file.

## Behaviour changes

none - the query still selects the same three columns filtered by an exact `username` match, `QueryRow` is still called once with the same downstream `Scan`/error-handling/response logic untouched, and the 404 response on no match and the `id=%d email=%s role=%s` success output are unchanged. The only difference is that `username` now arrives as a bound parameter instead of interpolated text, which is required to close the injection and introduces no functional change for legitimate (non-malicious) usernames.

- verification: `go vet` run against the fixed file in a scratch module (stdlib-only imports: `database/sql`, `fmt`, `net/http`) - exit code 0, no diagnostics.
- assumptions: the target driver's placeholder syntax is assumed to be `?` (MySQL/SQLite style) rather than PostgreSQL's `$1`, since the file imports only `database/sql` and no driver package is visible; if the underlying driver is `lib/pq`, `pgx`, or another `$`-style driver, the placeholder in the fixed query should be `$1` instead of `?`. This does not change `username`'s treatment as a bound parameter, only the placeholder token.
