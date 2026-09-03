## Verdict

Exploitable. The `customer_id` parameter is sourced from untrusted user input and directly interpolated into the SQL query via f-string formatting, allowing SQL injection attacks.

## Source

Line 9: `customer_id = request.args.get("customer_id")` - user-supplied HTTP request parameter, untrusted.

## Fix

**Vulnerable code (lines 14-16):**
```python
query = f"SELECT id, item, total FROM orders WHERE customer_id = {customer_id}"
# SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
cursor.execute(query)
```

**Fixed code:**
```python
query = "SELECT id, item, total FROM orders WHERE customer_id = ?"
# Safe: SQL structure is static; customer_id is passed as data via parameterized query
cursor.execute(query, (customer_id,))
```

## Explanation

The fix replaces the f-string SQL construction with a parameterized query using sqlite3's `?` placeholder syntax. The untrusted `customer_id` value is now passed as a separate parameter to `cursor.execute()` rather than embedded in the query string. This ensures the database driver treats `customer_id` strictly as data, not as executable SQL code, preventing the attacker from injecting additional SQL operators or logic. An attacker passing `1 OR 1=1` as `customer_id` will now search for a row with `customer_id` equal to the literal string `"1 OR 1=1"`, not modify the query logic.

## Behaviour changes

None. The parameterized query produces the same result set as the original for all valid inputs. The `cursor.execute(query, (customer_id,))` call returns a Cursor object identical to the original, and `fetchall()` retrieves rows unchanged. The database connection and transaction semantics remain identical.
