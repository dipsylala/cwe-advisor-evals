## Verdict

Exploitable. The `term` parameter is untrusted input from the client, passed directly via string concatenation into the SQL query at line 9. An attacker can inject arbitrary SQL commands, for example: `' OR '1'='1` returns all rows, or `'; DROP TABLE customers; --` deletes the table.

## Source

The `term` parameter is untrusted input originating from the JavaScript client (search.js calls `/api/search?term=` with user-supplied input). The function `search_customers(term)` receives this value.

## Fix

### File: search.py

```python
import sqlite3


def search_customers(term):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()

    cursor.execute("SELECT id, name FROM customers WHERE name = ?", (term,))
    return cursor.fetchall()
```

## Explanation

The original code concatenates untrusted user input directly into the SQL query string using string concatenation: `"SELECT id, name FROM customers WHERE name = '" + term + "'"`. This allows attackers to break out of the string context and inject arbitrary SQL commands.

The fix uses parameterized queries with sqlite3's placeholder syntax (`?`). By passing `term` as a separate parameter (the tuple `(term,)`) to `cursor.execute()`, the database driver treats the value as data rather than executable SQL. Any special characters in the input, including single quotes, SQL keywords, and comments, are automatically escaped and treated as literal values. This eliminates SQL injection at the sink while preserving the intended query logic for legitimate input.

## Behaviour changes

None. When called with legitimate input (a customer name without SQL metacharacters), the parameterized query returns identical results to the original. The only observable change is that SQL injection attempts are now prevented—malicious payloads are treated as literal string values, not as SQL code.
