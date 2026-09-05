## Verdict

Confirmed SQL Injection vulnerability. User input (`term`) is directly concatenated into an SQL query string and passed to `cursor.execute()`, allowing an attacker to manipulate the query logic.

## Source

The `term` parameter in the `search_customers()` function receives untrusted user input from a client-side search operation. This parameter flows directly into the SQL query without any parameterization.

## Fix

Replace the string concatenation with a parameterized query using sqlite3's placeholder syntax:

**Before:**
```python
cursor.execute("SELECT id, name FROM customers WHERE name = '" + term + "'")
```

**After:**
```python
cursor.execute("SELECT id, name FROM customers WHERE name = ?", (term,))
```

## Explanation

The fix converts the vulnerable string concatenation to a parameterized query using sqlite3's `?` placeholder syntax. This ensures the `term` value is treated as data, not as executable SQL code. The value is passed as a separate argument to `cursor.execute()`, after the query string. This is the primary defence against SQL injection in Python's sqlite3 driver and is mandated by the CWE-89 remediation guidance.

The query structure remains identical, but the database driver now handles the escaping and value binding internally, eliminating the injection vector regardless of what string the `term` parameter contains.

## Behaviour changes

- Return value: `cursor.fetchall()` returns the same result set as before for legitimate inputs.
- Query results: SQL injection payloads like `' OR '1'='1` are now treated as literal string values, not as query syntax. They will not match any customer names unless a customer name exactly equals that string.
- Error handling: If an exception is raised during execution, it will be the same as before (no changes to failure behaviour).
