## Verdict

SQL injection vulnerability confirmed at line 16. The query string is constructed using f-string interpolation with unsanitized user input from `request.args.get()`, allowing an attacker to inject arbitrary SQL commands.

## Source

Line 14-16 in CursorExecuteStringFormat.py:
```python
query = f"SELECT id, item, total FROM orders WHERE customer_id = {customer_id}"
cursor.execute(query)
```

The `customer_id` parameter is obtained directly from HTTP request arguments without any parameterization or validation.

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

    cursor.execute("SELECT id, item, total FROM orders WHERE customer_id = ?", (customer_id,))

    rows = cursor.fetchall()
    conn.close()

    return {"orders": rows}
```

## Explanation

The fix replaces the unsafe f-string concatenation with a parameterized query using SQLite's `?` placeholder syntax. The user-supplied `customer_id` is passed as a separate parameter tuple to `cursor.execute()`, not as part of the SQL string itself. This separation ensures that the database driver treats the value as data, not as executable SQL code, eliminating the injection vector. Any special SQL characters in the input will be automatically escaped and interpreted as literal data values.
