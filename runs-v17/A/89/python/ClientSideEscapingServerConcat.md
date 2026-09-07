## Verdict
Confirmed SQL Injection (CWE-89). The `term` parameter is concatenated directly into the SQL query string without parameterization or escaping, allowing an attacker to inject arbitrary SQL code.

## Source
```python
cursor.execute("SELECT id, name FROM customers WHERE name = '" + term + "'")
```

## Fix
### File: search.py
```python
import sqlite3


def search_customers(term):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    # Fixed: Use parameterized query with placeholder
    cursor.execute("SELECT id, name FROM customers WHERE name = ?", (term,))
    return cursor.fetchall()
```

## Explanation
The vulnerability exists because user input (`term`) is directly concatenated into the SQL query string. An attacker can inject SQL code, such as `' OR '1'='1`, to alter the query logic and bypass authentication or extract unauthorized data.

The fix uses parameterized queries (prepared statements) with the `?` placeholder. The parameter is passed separately to `execute()` as a tuple, ensuring that the database driver properly escapes the value and treats it as data, not executable SQL. This is the standard defense against SQL injection in Python's `sqlite3` module and eliminates the injection vector entirely.
