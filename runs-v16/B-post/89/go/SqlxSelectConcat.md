## Verdict

Exploitable. Untrusted user input flows directly into SQL query construction via string concatenation, allowing SQL injection attacks.

## Source

Line 27: `category := r.URL.Query().Get("category")` — user-supplied HTTP query parameter, untrusted and attacker-controlled.

## Fix

**Vulnerable code (line 29):**
```go
query := fmt.Sprintf("SELECT id, name, category, price FROM products WHERE category = '%s'", category)
```

**Fixed code:**
```go
query := "SELECT id, name, category, price FROM products WHERE category = ?"
```

Pass the `category` parameter separately to `Select()` on line 33:

**Vulnerable code (line 33):**
```go
err := h.DB.Select(&products, query)
```

**Fixed code:**
```go
err := h.DB.Select(&products, query, category)
```

## Explanation

The original code builds SQL by concatenating the user-supplied `category` parameter directly into the query string using `fmt.Sprintf`. An attacker can inject SQL by supplying payloads such as `' OR '1'='1` or `'; DROP TABLE products; --`, causing the query to execute unintended commands or bypass intended logic.

The fix uses sqlx's parameterized query mechanism: replace the string concatenation with a static query string containing a `?` placeholder, and pass the `category` value as a separate argument to the `Select()` method. This ensures the value is treated as opaque data rather than executable SQL code, preventing injection regardless of the input's content.

## Behaviour changes

None. The `Select()` method signature accepts variadic arguments for query parameters, so `Select(&products, query, category)` is compatible with the original method contract. The method populates the `products` slice and returns errors in exactly the same way; the only difference is that it is now safe from SQL injection.

**Verification:** Go syntax check passed (`go fmt` executed without errors).

**Assumptions:** The target database uses `?` as the parameter placeholder. Some databases (PostgreSQL) use `$1`, `$2`, etc.; consult the sqlx documentation for the specific database being used. The fix assumes the database driver in use is configured through the sqlx.DB connection string.
