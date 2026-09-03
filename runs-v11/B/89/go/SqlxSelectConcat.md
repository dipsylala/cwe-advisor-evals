## Verdict

exploitable

## Source

`r.URL.Query().Get("category")` at line 27 - untrusted HTTP query parameter flows directly into SQL query construction

## Fix

**Vulnerable code (line 29-33):**
```go
query := fmt.Sprintf("SELECT id, name, category, price FROM products WHERE category = '%s'", category)

var products []Product
err := h.DB.Select(&products, query)
```

**Fixed code:**
```go
query := "SELECT id, name, category, price FROM products WHERE category = ?"

var products []Product
err := h.DB.Select(&products, query, category)
```

## Explanation

The vulnerability is eliminated by converting the concatenated SQL string to a parameterized query with a `?` placeholder. User input is now passed as a separate argument to `h.DB.Select()` rather than interpolated into the query string. This ensures the category value is always treated as data, not executable SQL code, preventing an attacker from injecting SQL syntax. The sqlx library's `Select()` method handles parameter binding using the underlying `database/sql` driver, which safely encodes the value according to the appropriate SQL dialect.

## Behaviour changes

none
