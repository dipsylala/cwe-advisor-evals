## Verdict
Confirmed SQL injection at line 16. The query is constructed via string interpolation on line 14 using unsanitized user input from `request.args.get()`, enabling an attacker to modify query logic by injecting SQL syntax.

## Source
```python
customer_id = request.args.get("customer_id")

conn = sqlite3.connect("shop.db")
cursor = conn.cursor()

query = f"SELECT id, item, total FROM orders WHERE customer_id = {customer_id}"
# SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
cursor.execute(query)
```

## Fix
Replace lines 14-16 with parameterized query execution:

```python
cursor.execute("SELECT id, item, total FROM orders WHERE customer_id = ?", (customer_id,))
```

## Explanation
The original code concatenates user-supplied `customer_id` directly into the SQL query string using an f-string. This allows an attacker to inject arbitrary SQL syntax—for example, passing `customer_id = "1 OR 1=1"` to bypass the WHERE clause, or `"1; DROP TABLE orders; --"` to execute additional commands.

Parameterized queries (also called prepared statements) separate SQL structure from data by using placeholders (`?` in SQLite) and passing values separately to `cursor.execute()`. The database driver handles escaping automatically, preventing injection attacks regardless of the input content. This is the standard defense for SQL injection in Python with sqlite3.
