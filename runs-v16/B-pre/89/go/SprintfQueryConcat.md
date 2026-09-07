## Verdict

VULNERABLE. The code constructs an SQL query by concatenating untrusted user input from `r.URL.Query().Get("username")` directly into the query string using `fmt.Sprintf`. This allows an attacker to inject SQL fragments by providing payloads such as `' OR '1'='1` in the username parameter, which will be interpolated verbatim into the query and executed.

## Source

**File:** `evals/cases/89/go/SprintfQueryConcat/SprintfQueryConcat.go`
**Line:** 16–18

**Data flow:**
- Line 14: `username := r.URL.Query().Get("username")` — untrusted HTTP request parameter
- Line 16: `query := fmt.Sprintf("SELECT id, email, role FROM users WHERE username = '%s'", username)` — username interpolated directly into SQL string
- Line 18: `row := h.DB.QueryRow(query)` — interpolated query executed without parameterization

## Fix

Replace lines 16–18 with parameterized query syntax:

```go
query := "SELECT id, email, role FROM users WHERE username = ?"
row := h.DB.QueryRow(query, username)
```

**Full corrected function:**

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

## Explanation

The vulnerability exists because `fmt.Sprintf` concatenates the untrusted `username` parameter directly into the SQL query string. An attacker can craft a username value such as `admin' --` or `' OR '1'='1` that will be concatenated verbatim and alter the query logic:
- Input: `admin' --` produces query: `SELECT id, email, role FROM users WHERE username = 'admin' --'`
- Input: `' OR '1'='1` produces query: `SELECT id, email, role FROM users WHERE username = '' OR '1'='1'`

Both bypass authentication and authorization.

The fix uses Go's `database/sql` parameterized query mechanism: the query string contains a placeholder (`?`), and the username is passed as a separate argument to `QueryRow()`. The database driver ensures the value is treated as data only and cannot alter query structure, regardless of its content.

## Behaviour changes

**Before:** The application accepts and executes arbitrary SQL fragments in the username parameter, allowing attackers to extract data, modify queries, or perform other SQL operations.

**After:** The username parameter is treated as a literal string value. Special characters such as single quotes, semicolons, and SQL keywords are escaped or quoted by the database driver and have no syntactic meaning in the query. Payloads like `admin' --` and `' OR '1'='1` are compared as literal values, not interpreted as SQL syntax.
