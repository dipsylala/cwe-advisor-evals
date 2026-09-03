## Verdict
SQL injection vulnerability confirmed. String concatenation directly into SQL query allows attacker-controlled input to alter query logic.

## Source
Line 9 in `search.py`:
```python
cursor.execute("SELECT id, name FROM customers WHERE name = '" + term + "'")
```

The `term` parameter is concatenated directly into the query string without parameterization or escaping. An attacker can close the string context with `'` and inject arbitrary SQL.

## Fix
Use parameterized query with placeholder:
```python
cursor.execute("SELECT id, name FROM customers WHERE name = ?", (term,))
```

Replace the string concatenation with a `?` placeholder and pass parameters separately as a tuple. SQLite's `sqlite3` module handles proper escaping and quoting automatically.

## Explanation
Parameterized queries separate SQL structure from data. The database engine parses the SQL template first, then treats parameter values as literal data only—not as executable SQL syntax. This prevents injected quotes or keywords from being interpreted as commands.

The `?` syntax is SQLite's standard placeholder for positional parameters. The second argument to `execute()` is a tuple of values corresponding to each placeholder, matching the order they appear in the query.

This approach works for all SQL injection entry points: WHERE clauses, ORDER BY, INSERT, UPDATE, DELETE, and any other context where untrusted input reaches the query string.
