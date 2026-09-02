## Verdict

Exploitable. The `customer_id` parameter from an untrusted user request is directly interpolated into the SQL query via an f-string without parameterization, allowing SQL injection.

## Source

Line 9: `customer_id = request.args.get("customer_id")` – untrusted user input from HTTP request parameter.

## Fix

**Vulnerable code (lines 14–16):**
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

The fix replaces the f-string concatenation with a parameterized query using sqlite3's `?` placeholder syntax. The untrusted `customer_id` value is now passed as a separate parameter to `cursor.execute()` in a tuple, rather than being embedded in the SQL string. This ensures the database driver treats the value as data, not as executable SQL, preventing attackers from injecting malicious SQL syntax. Parameterized queries are the primary defence against SQL injection and are the recommended pattern in all Python database libraries including sqlite3, psycopg2, and mysql-connector.

## Behaviour changes

The `cursor.execute()` call now receives two arguments instead of one: the query string and a tuple of parameter values. sqlite3's parameterized query mechanism automatically handles escaping and treats the parameter as a literal data value regardless of its content, so SQL metacharacters are neutralized. The query result and return value (`rows` from `cursor.fetchall()`) remain unchanged.
