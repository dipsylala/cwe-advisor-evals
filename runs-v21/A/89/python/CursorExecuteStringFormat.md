## Verdict
CONFIRMED. The code uses f-string interpolation to embed untrusted user input (`customer_id` from request parameters) directly into an SQL query, enabling SQL injection.

## Source
Line 13 supplies untrusted user input:
```python
customer_id = request.args.get("customer_id")
```

Line 16 uses that input unsafely in an f-string to construct the SQL query:
```python
query = f"SELECT id, item, total FROM orders WHERE customer_id = {customer_id}"
```

The `customer_id` parameter is then executed as part of the query at line 17, allowing an attacker to inject arbitrary SQL.

## Fix

### File: CursorExecuteStringFormat.py

```python
from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.route("/orders")
def get_orders():
    customer_id = request.args.get("customer_id")

    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()

    query = "SELECT id, item, total FROM orders WHERE customer_id = ?"
    # SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
    cursor.execute(query, (customer_id,))

    rows = cursor.fetchall()
    conn.close()

    return {"orders": rows}
```

## Explanation
The vulnerability stems from concatenating user-supplied input into the SQL query string. The attacker can inject SQL metacharacters and operators to alter the query logic — for example, `customer_id = 1 OR 1=1` bypasses the WHERE clause entirely, or `1; DROP TABLE orders; --` executes destructive commands.

The fix uses parameterized queries (prepared statements) with the `?` placeholder syntax that sqlite3 supports. By passing the parameter separately as a tuple to `cursor.execute()`, the database driver treats `customer_id` as a value, not executable SQL syntax. The driver handles escaping and quoting automatically, preventing injection regardless of the input's content.

This is the primary defence for SQL injection in Python: always use parameterized queries instead of string interpolation or concatenation for any dynamic SQL query with untrusted input.
