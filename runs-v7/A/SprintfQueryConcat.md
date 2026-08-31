## Verdict

Confirmed SQL injection via string concatenation of unsanitized user input into a SQL query. The `fmt.Sprintf` construct on line 16 embeds the `username` parameter directly into the query string without escaping or parameterization.

## Source

Line 16 constructs the SQL query by concatenating user input:
```
query := fmt.Sprintf("SELECT id, email, role FROM users WHERE username = '%s'", username)
```

The `username` value comes from `r.URL.Query().Get("username")` on line 14, which is untrusted request data. An attacker can inject SQL by supplying input like `' OR '1'='1` to break out of the string context and inject arbitrary SQL clauses.

## Fix

Replace the string concatenation with a parameterized query:

```go
query := "SELECT id, email, role FROM users WHERE username = ?"
row := h.DB.QueryRow(query, username)
```

This separates the query structure from the data. The `?` placeholder tells the database driver to treat the second argument as a value, not as executable SQL. The driver handles escaping and type conversion automatically.

## Explanation

SQL injection occurs because user input is concatenated directly into the query string. The database parser sees the entire concatenated string as a SQL command and executes whatever injection the attacker included. Parameterized queries fix this by keeping data separate from command structure—the database receives the query template and the data as distinct inputs, so injection in the data cannot alter the command's structure.

Go's `database/sql` package uses `?` positional placeholders for parameterized queries across all drivers (PostgreSQL, MySQL, SQLite, etc.). Pass the values as additional arguments to `QueryRow()`, `Query()`, or `Exec()` after the query string.
