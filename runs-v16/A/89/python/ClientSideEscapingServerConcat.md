## Verdict
True Positive. The code contains an SQL injection vulnerability where user input is directly concatenated into a SQL query string without parameterization.

## Source
The vulnerability is in `search.py` line 9, where the `term` parameter is concatenated directly into the SQL query:

```python
cursor.execute("SELECT id, name FROM customers WHERE name = '" + term + "'")
```

The `term` parameter originates from untrusted user input passed through an HTTP request parameter.

## Fix
Replace string concatenation with parameterized queries using SQLite's parameter placeholders:

```python
cursor.execute("SELECT id, name FROM customers WHERE name = ?", (term,))
```

The `?` placeholder marks where the parameter value goes, and the second argument to `execute()` is a tuple containing the values to be safely substituted. SQLite's driver handles escaping and encoding automatically.

## Explanation
The vulnerable code concatenates user input directly into the SQL query string. Although the client-side JavaScript code attempts to escape single quotes, client-side sanitization is not a security control—an attacker can bypass the client entirely and submit arbitrary SQL directly to the server.

The correct fix is server-side parameterized queries (prepared statements), which are the standard SQL injection defense. With parameterized queries, the SQL structure is fixed and user input is treated as data, not SQL code. The database driver automatically handles all necessary escaping and encoding, preventing the user input from being interpreted as SQL commands regardless of its content.

The `cursor.execute()` method in Python's sqlite3 module supports parameter binding through the `?` placeholder syntax. The user data is passed separately in a tuple as the second argument, ensuring it cannot be misinterpreted as SQL code.
