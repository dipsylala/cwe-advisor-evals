## Verdict

The vulnerability is real and exploitable. The code directly concatenates an untrusted HTTP query parameter into a SQL query string using `fmt.Sprintf`, allowing an attacker to inject arbitrary SQL.

## Source

The untrusted data originates at line 27 with the HTTP query parameter:
```
category := r.URL.Query().Get("category")
```

This value flows directly into the query string construction at line 29:
```
query := fmt.Sprintf("SELECT id, name, category, price FROM products WHERE category = '%s'", category)
```

An attacker can provide a malicious value such as `category=' OR '1'='1` which will be incorporated directly into the SQL query, bypassing the intended WHERE clause logic.

## Fix

Replace the concatenated query construction with a parameterized query using sqlx's placeholder syntax:

**Vulnerable code (lines 29-33):**
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

The fix eliminates the SQL injection by using sqlx's parameterized query mechanism. The `?` placeholder is a marker where a parameter will be safely bound. The `category` value is passed as a separate argument to `Select()` rather than being interpolated into the query string. sqlx handles the parameter binding internally, ensuring the value is always treated as data, not as executable SQL code. Even if the category contains SQL metacharacters like `'`, `OR`, or `--`, they will be treated as literal string content and will not alter the query's logical structure. This approach is the standard safe pattern for the Go `database/sql` ecosystem and is supported by sqlx as a wrapper around it.

## Behaviour changes

The fix preserves the existing behavior of the application—the SELECT query still filters products by category and returns the same result set. The only change is that the category value is now safely parameterized and cannot be used to inject SQL. Error handling remains unchanged: the function still checks for errors from `Select()` and returns HTTP 500 on failure.
