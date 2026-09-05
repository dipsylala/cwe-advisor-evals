## Verdict
Confirmed SQL injection via string concatenation.

## Source
Line 27 obtains the `category` parameter from an untrusted HTTP query string without validation or sanitization.

## Fix
Replace the string concatenation on line 29 with a parameterized query using `?` placeholders, and pass the parameter to the query method:

```go
query := "SELECT id, name, category, price FROM products WHERE category = ?"
err := h.DB.Select(&products, query, category)
```

## Explanation
The original code uses `fmt.Sprintf` to inject the `category` value directly into the SQL query string. An attacker can supply a malicious value like `' OR '1'='1` to break out of the WHERE clause and alter the query logic. 

Parameterized queries separate the SQL structure from the data values. The `?` placeholder marks where a parameter goes, and the database driver handles escaping and type conversion, ensuring user input cannot be interpreted as SQL syntax. The sqlx library natively supports this pattern by accepting additional variadic arguments to `Select()` that bind to each placeholder in order.
