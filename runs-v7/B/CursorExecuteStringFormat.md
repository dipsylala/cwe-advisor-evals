## Verdict

**Exploitable: Yes**

The vulnerability is a classic SQL injection via untrusted user input directly interpolated into a SQL query string using Python f-string concatenation. The `customer_id` parameter from the HTTP request is incorporated directly into the query without parameterization.

## Source

Line 9: `customer_id = request.args.get("customer_id")`

User-controlled HTTP parameter, untrusted by default.

## Fix

**Vulnerable code (line 14-16):**
```python
query = f"SELECT id, item, total FROM orders WHERE customer_id = {customer_id}"
# SAST FINDING: CWE-89
cursor.execute(query)
```

**Fixed code:**
```python
query = "SELECT id, item, total FROM orders WHERE customer_id = ?"
cursor.execute(query, (customer_id,))
```

## Explanation

The fix replaces the f-string concatenation with a parameterized query using sqlite3's placeholder syntax (`?`). User input is now passed as a separate tuple argument to `cursor.execute()` instead of being embedded in the SQL string. This ensures the database driver treats `customer_id` as a data value only, preventing the attacker from manipulating query structure. An attacker providing input like `' OR '1'='1` will be safely treated as a literal string to match against the `customer_id` column, not as executable SQL syntax.

## Behaviour changes

- **Query execution**: Identical semantics - the query returns the same rows as before when `customer_id` is a valid integer or user ID.
- **Error handling**: Unchanged - invalid SQL still raises `sqlite3.DatabaseError`.
- **Return value**: Unchanged - `cursor.fetchall()` returns the same result set.
- **Implicit parameters**: No new implicit parameters; sqlite3 argument tuple syntax is explicit and portable.
- **Injection prevention**: Attack payloads like `' OR '1'='1`, `); DROP TABLE orders; --`, and Unicode variants are now neutralized by parameterization and cannot alter query logic.
