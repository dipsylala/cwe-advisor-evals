## Verdict

- **cwe_id**: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command / SQL Injection)
- **location**: `SprintfQueryConcat.go`, line 18 (`h.DB.QueryRow(query)`), query built at line 16
- **verdict**: exploitable
- **confidence**: high

## Source

- **Source**: `r.URL.Query().Get("username")` (line 14) - the `username` query-string parameter from the incoming HTTP request, fully attacker-controlled.
- **Sink**: `h.DB.QueryRow(query)` (line 18) - executes the SQL text built at line 16.
- **Flow**: `username` is read directly from the request and passed unmodified into `fmt.Sprintf("SELECT id, email, role FROM users WHERE username = '%s'", username)` (line 16). The resulting string, with the attacker's value spliced into the middle of a quoted SQL literal, is handed straight to `QueryRow`. No validation, escaping, or parameterization occurs anywhere on this path, so a value such as `' OR '1'='1` or `' UNION SELECT ...--` alters the query's logic or structure.

**Sink contract** (`database/sql.DB.QueryRow`):
- **Returns**: a `*sql.Row`, whose `Scan` is called on the next line to populate `id`, `email`, `role`; on no matching row or scan error, `Scan` returns an error and the handler responds `404 user not found`.
- **Discards**: nothing beyond the single row's own error handling.
- **Implicit arguments**: none beyond the query string itself - `QueryRow` takes the query plus a variadic parameter list, currently empty.
- **Failure behaviour**: errors surface only through `row.Scan`'s return value, handled by the existing `if err != nil` branch.

## Fix

Vulnerable code (line 16-18):

```go
query := fmt.Sprintf("SELECT id, email, role FROM users WHERE username = '%s'", username)
// SAST FINDING: CWE-89 reported here. Sink is the next statement.
row := h.DB.QueryRow(query)
```

Fixed code:

```go
query := "SELECT id, email, role FROM users WHERE username = ?"
row := h.DB.QueryRow(query, username)
```

(Full corrected function for context - `SprintfQueryConcat.go`, not written to the shared fixture:)

```go
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

`fmt` remains imported and used (for `fmt.Fprintf` at the end of the function), so no import changes are needed.

## Explanation

The query text is now a static string with a placeholder (`?`) in place of the interpolated value, and `username` is passed as a separate argument to `QueryRow` rather than being spliced into the SQL. `database/sql` sends the query and the parameter to the driver independently, so the driver binds `username` strictly as the value of the `username` column comparison - it can never be interpreted as SQL syntax, regardless of quotes, comments, or keywords it contains. This removes the injection at its source: the string-formatting step that mixed untrusted data into query structure is gone, and `fmt.Sprintf` is no longer used to build SQL anywhere in this function.

**Assumption**: the placeholder syntax `?` (MySQL/SQLite style) was used since the concrete driver import isn't shown in this file. If the underlying driver is PostgreSQL (`lib/pq`, `pgx`), the placeholder must be positional instead: `... WHERE username = $1`. This does not change the fix's structure, only the placeholder token.

## Behaviour changes

- **Query text**: changed from a per-request interpolated string to a fixed string - required to remove the injection; the query's semantics (select `id, email, role` where `username` matches) are unchanged.
- **QueryRow arguments**: `username` moved from the query string into `QueryRow`'s variadic parameter list - this is the mechanism of the fix, not an incidental change; the driver now evaluates the same equality comparison the original SQL expressed, but as a bound parameter instead of literal text.
- **Returns, error handling, response body**: unchanged. `row.Scan`, the 404 path, and the `fmt.Fprintf` response are untouched, so the sink's contract (return value, discards, failure behaviour) is fully preserved.
- **none** beyond the above - no other difference between the original and fixed code.
