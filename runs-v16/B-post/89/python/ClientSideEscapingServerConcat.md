## Verdict

Exploitable. The `term` parameter is concatenated directly into the SQL query using string concatenation, allowing an attacker to inject arbitrary SQL commands.

## Source

`term` parameter in `search_customers()` function (line 4, called from line 9).

## Fix

**Vulnerable code (line 9):**
```python
cursor.execute("SELECT id, name FROM customers WHERE name = '" + term + "'")
```

**Fixed code:**
```python
cursor.execute("SELECT id, name FROM customers WHERE name = ?", (term,))
```

## Explanation

The fix replaces string concatenation with parameterized query syntax. The `?` placeholder is sqlite3's parameter marker, and the second argument `(term,)` is a tuple of values bound to the placeholders. This ensures `term` is always treated as data, never as executable SQL. An attacker cannot inject SQL commands through the `term` parameter because the database driver parses the query structure first, then substitutes the bound value as literal data into the WHERE clause. The fix closes the SQL injection weakness by removing the concatenation that allowed query manipulation.

## Behaviour changes

None. The `cursor.execute()` call returns a cursor object in both cases, and `fetchall()` operates identically on the result. The query logic and return value are preserved. The only difference is how the parameter is passed: previously embedded in the string (vulnerable), now bound separately (safe).
