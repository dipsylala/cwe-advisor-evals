## Verdict

exploitable

## Source

`customer_id` parameter from `request.args.get("customer_id")` (line 9) - untrusted HTTP query string input.

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

The vulnerability occurs because the untrusted `customer_id` parameter is concatenated directly into the SQL query string via an f-string (line 14), allowing an attacker to inject arbitrary SQL. An attacker could pass payloads like `1 OR 1=1` to bypass the WHERE clause or `1'; DROP TABLE orders; --` to execute destructive commands. The fix replaces the f-string with a parameterized query using sqlite3's `?` placeholder syntax. The user input is now passed as a separate parameter to `cursor.execute()`, ensuring the driver treats it as data rather than query structure. This eliminates the injection path while preserving the query logic and return values.

## Behaviour changes

None. The `execute()` method now accepts two arguments (query string and parameter tuple) instead of one. This is the correct and required usage of parameterized queries in sqlite3. The return value is identical, `fetchall()` produces the same rows, and the error handling behavior remains unchanged.
