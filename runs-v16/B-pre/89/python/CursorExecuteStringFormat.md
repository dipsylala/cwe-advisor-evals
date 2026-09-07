## Verdict

Exploitable. The `customer_id` parameter from `request.args.get()` is concatenated directly into a SQL query via an f-string at line 14 and executed without parameterization at line 16, allowing an attacker to inject arbitrary SQL.

## Source

`customer_id = request.args.get("customer_id")` at line 9. The value is untrusted user input from the HTTP request query string.

## Fix

**Vulnerable code (line 14-16):**
```python
query = f"SELECT id, item, total FROM orders WHERE customer_id = {customer_id}"
# SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
cursor.execute(query)
```

**Fixed code:**
```python
query = "SELECT id, item, total FROM orders WHERE customer_id = ?"
cursor.execute(query, (customer_id,))
```

## Explanation

The fix replaces the f-string concatenation with a static SQL query string containing a parameterized placeholder (`?`). The `customer_id` value is now passed as a separate tuple argument to `cursor.execute()`, which sqlite3 treats as data rather than query structure. This ensures that even if `customer_id` contains SQL metacharacters or complete SQL fragments (e.g., `' OR '1'='1`), they are escaped and treated as literal values in the query predicate, eliminating the injection vector.

## Behaviour changes

The `cursor.execute()` call now accepts two arguments instead of one: the query string and a tuple of parameter values. This is the documented sqlite3 parameterized-query interface and does not change the functional outcome—rows matching the authenticated `customer_id` are returned identically—but it changes the argument count passed to the method.
