## Verdict

**CWE-89 Confirmed**: SQL Injection via string concatenation of unsanitized user input into an SQL query.

## Source

Line 29 constructs an SQL query using `fmt.Sprintf` with direct string concatenation:

```
query := fmt.Sprintf("SELECT id, name, category, price FROM products WHERE category = '%s'", category)
```

The `category` parameter originates from untrusted user input via `r.URL.Query().Get("category")` on line 27 and flows directly into the query without any parameterization or escaping. An attacker can inject SQL metacharacters (e.g., `' OR '1'='1`) to alter the query's logic.

## Fix

Replace string concatenation with parameterized queries using sqlx's placeholder syntax:

```go
query := "SELECT id, name, category, price FROM products WHERE category = ?"
err := h.DB.Select(&products, query, category)
```

The `?` placeholder ensures the database driver treats `category` as a literal value, not executable SQL. The parameter is passed separately to `Select()` and safely escaped by the driver.

## Explanation

String concatenation bypasses the SQL parser's ability to distinguish code from data. Parameterized queries (prepared statements) enforce this distinction: the SQL structure is sent to the database first, then parameters are bound as data values only. This eliminates the injection vector regardless of the parameter's contents.

The fix uses sqlx's built-in parameterization, which is the standard defense for SQL injection across all Go database drivers (`database/sql`-compatible interfaces). No external sanitization or escaping is required when parameterized queries are used correctly.
