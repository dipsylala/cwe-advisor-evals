## Verdict

Exploitable. The `term` parameter flows from the HTTP request directly into a SQL query via string concatenation without parameterization, allowing SQL injection. Client-side escaping in search.js does not protect the server-side sink.

## Source

`search.js` line 3 sends the `term` parameter to the server via HTTP GET request (`/api/search?term=...`). The `search_customers(term)` function in `search.py` receives this untrusted input.

## Fix

**Vulnerable code (search.py, line 9):**
```python
cursor.execute("SELECT id, name FROM customers WHERE name = '" + term + "'")
```

**Fixed code:**
```python
cursor.execute("SELECT id, name FROM customers WHERE name = ?", (term,))
```

Replace the string concatenation with a parameterized query. The `?` placeholder holds the position for the untrusted `term` value, and `sqlite3` treats it as data, not query structure. Pass the value as a separate tuple argument to `execute()`.

## Explanation

Parameterized queries separate SQL structure from data: the query text defines the statement logic, and parameters are bound as data values only. This prevents the attacker from injecting SQL syntax. When using `sqlite3`, the `?` placeholder syntax and passing values as a tuple to `execute()` ensures the parameter is always treated as data. The client-side escaping in search.js is not a security control and must not be relied upon - the server must defend itself.

## Behaviour changes

None. The fix preserves the original query's behaviour: it still selects rows where the `name` column matches the `term` parameter, returns all matching rows via `fetchall()`, and raises an exception on database errors. Parameterization does not alter return values, error handling, or the underlying database contract.
