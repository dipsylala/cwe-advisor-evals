## Verdict

The vulnerability is confirmed. User input from `r.URL.Query().Get("username")` is directly embedded into an SQL query string via `fmt.Sprintf()` without parameterization, creating a SQL injection sink at line 18.

## Source

```go
username := r.URL.Query().Get("username")
query := fmt.Sprintf("SELECT id, email, role FROM users WHERE username = '%s'", username)
row := h.DB.QueryRow(query)
```

The query string is constructed by concatenating untrusted user input directly into the SQL command. An attacker can inject SQL metacharacters (e.g., `' OR '1'='1` or `'; DROP TABLE users; --`) to alter query logic or structure.

## Fix

Replace string concatenation with parameterized query syntax using Go's `database/sql` placeholders:

```go
username := r.URL.Query().Get("username")
query := "SELECT id, email, role FROM users WHERE username = ?"
row := h.DB.QueryRow(query, username)
```

Pass the username as a separate argument to `QueryRow()` so the database driver handles escaping and treats it as data, not executable SQL.

## Explanation

Parameterized queries (prepared statements) separate SQL structure from data. The placeholder `?` tells the driver where user input goes, and the driver encodes it appropriately for the database without interpreting special characters as SQL syntax. This prevents injection regardless of the input content. Go's `database/sql` package applies this protection automatically when arguments are passed separately from the query string—the query template and arguments are never concatenated at the application level.
