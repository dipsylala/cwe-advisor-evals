## Verdict

**Confirmed: SQL Injection via f-string concatenation**

Untrusted user input (`customer_id` from `request.args.get()`) flows directly into a SQL query via f-string formatting and is passed to `cursor.execute()` without parameterization. An attacker can inject arbitrary SQL by supplying values like `1 OR 1=1` or `1; DROP TABLE orders;--`.

## Source

**Taint source**: Line 9 — `customer_id = request.args.get("customer_id")`

User input from Flask's request query parameters is untrusted.

**Taint sink**: Line 16 — `cursor.execute(query)`

The `execute()` method with a tainted SQL string allows injection.

**Data flow**: Lines 9 → 14 → 16

The `customer_id` parameter is embedded into the query string via f-string interpolation on line 14, then executed on line 16.

## Fix

**Replace lines 14–16:**

```python
query = "SELECT id, item, total FROM orders WHERE customer_id = ?"
cursor.execute(query, (customer_id,))
```

The fix uses sqlite3's parameterized query syntax:
- The query string contains a `?` placeholder instead of the interpolated value
- The user-supplied `customer_id` is passed as a separate argument tuple to `execute()`
- sqlite3 treats the parameter as data, not query structure, preventing injection

## Explanation

Parameterized queries separate SQL structure from data. By using a `?` placeholder, the database driver itself handles escaping and parsing of the parameter, ensuring the value can never be interpreted as SQL code. This is the primary defence for SQL injection and is required by sqlite3's own documented secure coding pattern. The f-string approach treats the user input as part of the query syntax, which allows an attacker to inject operators, keywords, and logic. Manual escaping or string validation (such as checking for quote characters or SQL keywords) is ineffective and is not an alternative to parameterization.

## Behaviour changes

- **Untrusted input is now bound as data, not parsed as query structure**: `?` in sqlite3 binds values using the driver's internal parameterization mechanism, which is immune to SQL injection.
- **The query structure remains static and database-agnostic**: The query string no longer depends on the content of `customer_id`, so all payloads are treated identically as literal values.
- **No change to the result set or error handling**: The query still returns the same rows and raises the same exceptions on errors; only the injection surface is eliminated.
