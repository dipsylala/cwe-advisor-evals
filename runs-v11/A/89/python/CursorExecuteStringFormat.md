## Verdict

Confirmed SQL injection vulnerability. The `customer_id` parameter from an HTTP request is directly interpolated into an SQL query string using an f-string, then passed to `cursor.execute()`. An attacker can inject arbitrary SQL by providing input like `1; DROP TABLE orders; --` or `1 UNION SELECT ...`.

## Source

```python
customer_id = request.args.get("customer_id")
conn = sqlite3.connect("shop.db")
cursor = conn.cursor()
query = f"SELECT id, item, total FROM orders WHERE customer_id = {customer_id}"
cursor.execute(query)
```

The vulnerability is on line 16: the query string is constructed with string interpolation rather than parameterized binding.

## Fix

```python
customer_id = request.args.get("customer_id")
conn = sqlite3.connect("shop.db")
cursor = conn.cursor()
query = "SELECT id, item, total FROM orders WHERE customer_id = ?"
cursor.execute(query, (customer_id,))
```

Replace the f-string query construction with a parameterized query using the `?` placeholder. Pass the user-supplied value as a separate tuple argument to `execute()`.

## Explanation

Parameterized queries (prepared statements) separate SQL structure from user data. The database driver treats the placeholder `?` as a marker for data, not as SQL syntax. The `customer_id` value is passed to the database as data only, never parsed as SQL code, eliminating the injection vector. This is the standard defence for SQL injection in Python's `sqlite3` module and works identically in `psycopg2`, `mysql.connector`, and other database drivers.
