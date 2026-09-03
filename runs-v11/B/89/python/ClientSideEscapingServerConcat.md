## Verdict

**Finding confirmed as exploitable.** The server concatenates untrusted user input directly into a SQL query despite client-side escaping in the JavaScript layer. Client-side escaping is not a security control and provides no protection against attackers bypassing the client entirely.

## Source

User input enters via the `term` parameter to `search_customers(term)` in `search.py` line 4. The JavaScript client attempts client-side escaping by replacing single quotes and URL-encoding (lines 1-3 of `search.js`), but this provides no security guarantee on the server.

## Fix

**Original (vulnerable):**
```python
cursor.execute("SELECT id, name FROM customers WHERE name = '" + term + "'")
```

**Fixed:**
```python
cursor.execute("SELECT id, name FROM customers WHERE name = ?", (term,))
```

Replace string concatenation with a parameterized query using `?` placeholders. Pass the `term` value as a separate parameter tuple to `execute()`. The sqlite3 driver treats the parameter as data only, never as executable SQL.

## Explanation

The fix uses parameterized queries (prepared statements), which is the primary defence against SQL injection in Python. In sqlite3, the `?` placeholder marks where a parameter value goes, and parameters are passed as a tuple in the second argument to `execute()`. The driver automatically handles any special characters in the parameter value, treating it as literal data rather than SQL syntax. This eliminates the possibility of injected SQL operators or metacharacters changing the query's structure.

The client-side escaping in the JavaScript layer is bypassed if an attacker submits a request directly to the server, so the server must never rely on it. Parameterized queries are the equivalent security control applied server-side where it cannot be circumvented.

## Behaviour changes

- **Query semantics:** Unchanged - the query still selects customers by exact name match.
- **Return value:** Unchanged - `cursor.fetchall()` still returns all matching rows.
- **Error handling:** Unchanged - parameterized queries with sqlite3 raise the same exception types on error.
- **Performance:** Negligible impact; prepared statements may offer marginal benefits on repeated queries.
- **Explicit trust boundary:** The fix makes explicit that the server treats the input as untrusted data, not as pre-sanitized SQL.
