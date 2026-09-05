## Verdict

exploitable

## Source

Line 27: `category := r.URL.Query().Get("category")` — untrusted user input from HTTP query parameter

## Fix

**Vulnerable code (line 29):**
```go
query := fmt.Sprintf("SELECT id, name, category, price FROM products WHERE category = '%s'", category)
err := h.DB.Select(&products, query)
```

**Fixed code:**
```go
query := "SELECT id, name, category, price FROM products WHERE category = ?"
err := h.DB.Select(&products, query, category)
```

## Explanation

The vulnerability occurs because user input from `r.URL.Query().Get("category")` is concatenated directly into the SQL query string using `fmt.Sprintf`. An attacker can inject SQL metacharacters — for example, passing `category=' OR '1'='1` produces the query `WHERE category = '' OR '1'='1'`, which returns all products and bypasses the intended filter.

The fix replaces string concatenation with a parameterized query using a placeholder (`?`). The category value is now passed as a separate argument to `Select()`, where `sqlx` and the underlying `database/sql` driver treat it strictly as data, not executable SQL. This ensures SQL metacharacters in the category value cannot alter the query structure.

## Behaviour changes

none — `sqlx.DB.Select()` accepts placeholder syntax and variadic arguments for parameters in the same way `database/sql.DB.Query()` does. The query execution, result binding to the `products` slice, and error handling remain identical. The placeholder syntax (`?`) is portable across MySQL, SQLite, and other drivers supported by `sqlx`.
