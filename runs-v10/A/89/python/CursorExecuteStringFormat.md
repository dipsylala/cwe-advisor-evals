## Verdict
SQL injection vulnerability via string interpolation in SQL query construction.

## Source
Line 14 constructs a SQL query using an f-string that directly interpolates `customer_id` from user input:
```python
query = f"SELECT id, item, total FROM orders WHERE customer_id = {customer_id}"
```

An attacker can supply values like `1 OR 1=1` or `1; DROP TABLE orders; --` to execute arbitrary SQL commands.

## Fix
Replace string interpolation with parameterized queries. Use the `?` placeholder syntax and pass parameters separately to `execute()`:

```python
query = "SELECT id, item, total FROM orders WHERE customer_id = ?"
cursor.execute(query, (customer_id,))
```

This ensures user input is treated as data, not SQL code.

## Explanation
Python's `sqlite3.Cursor.execute()` supports parameterized queries where placeholders (`?` for sqlite3) separate SQL structure from data. The database driver handles escaping and type conversion automatically. This is the standard defense against SQL injection in Python — it applies across all database libraries (sqlite3, psycopg2, mysql-connector-python, etc.). String formatting (f-strings, `.format()`, or concatenation) leaves the application responsible for escaping, which is error-prone and unnecessary when parameterization is available.
