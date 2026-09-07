## Verdict

**Vulnerable.** The application concatenates untrusted input directly into an SQL query without using parameterized statements, allowing SQL injection attacks. Client-side escaping in the JavaScript layer does not prevent this vulnerability.

## Source

The `term` parameter passed to `search_customers()` originates from a URL query parameter, received by the server after client-side escaping. This parameter is untrusted at the server layer because:
1. Client-side escaping is bypassable - an attacker can send requests directly to the server
2. Even if the client properly escapes single quotes, this is not a sufficient defense against SQL injection in the presence of server-side string concatenation

## Fix

### File: search.py

```python
import sqlite3


def search_customers(term):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # Use parameterized query instead of string concatenation
    cursor.execute("SELECT id, name FROM customers WHERE name = ?", (term,))
    return cursor.fetchall()
```

## Explanation

The original code concatenates the user-supplied `term` parameter directly into the SQL query string:

```python
cursor.execute("SELECT id, name FROM customers WHERE name = '" + term + "'")
```

This allows an attacker to inject SQL syntax. For example, passing `term = "' OR '1'='1"` would construct the query `SELECT id, name FROM customers WHERE name = '' OR '1'='1'`, which returns all customers.

The fix replaces string concatenation with a parameterized query using sqlite3's positional placeholder syntax (`?`). The user input is now passed as a separate parameter to `cursor.execute()`:

```python
cursor.execute("SELECT id, name FROM customers WHERE name = ?", (term,))
```

With this approach, the database driver treats `term` as data, not as SQL code. The placeholder is replaced with the properly escaped value at execution time, preventing injection attacks regardless of the content of `term`.

## Behaviour changes

**Functional behavior:** Query results remain identical for legitimate inputs. The application continues to return all customers matching the provided search term.

**Security:** The fix eliminates the SQL injection vulnerability. Malicious payloads such as `' OR '1'='1'` or `'; DROP TABLE customers; --` are now treated as literal string values to search for, not as SQL syntax. An attacker cannot manipulate the query logic.

**No breaking changes:** The function signature and return type remain unchanged. The `cursor.fetchall()` call works identically with the parameterized query.
