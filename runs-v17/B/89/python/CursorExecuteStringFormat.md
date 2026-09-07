## Verdict

SQL injection confirmed. Untrusted HTTP request parameter (`customer_id`) flows directly into SQL query via f-string interpolation, reaching `cursor.execute()` as executable query structure rather than data.

## Source

- **File**: CursorExecuteStringFormat.py
- **Line 9**: `customer_id = request.args.get("customer_id")` — source of untrusted input from HTTP request
- **Line 14**: `query = f"SELECT id, item, total FROM orders WHERE customer_id = {customer_id}"` — f-string embeds untrusted value into SQL query string
- **Line 16**: `cursor.execute(query)` — sink that executes the interpolated query

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
    cursor.execute(query, (customer_id,))

    rows = cursor.fetchall()
    conn.close()

    return {"orders": rows}
```

## Explanation

The fix replaces f-string interpolation with sqlite3's parameterized query syntax. The `?` placeholder separates SQL structure from data. By passing `(customer_id,)` as the second argument to `cursor.execute()`, the database driver treats it as a value, not executable SQL. Special characters and SQL keywords in `customer_id` are escaped automatically by the driver and cannot manipulate query logic, preventing SQL injection.

## Behaviour changes

- Query logic identical for valid numeric input
- Special characters and SQL metacharacters (quotes, dashes, comments) in `customer_id` are now safely treated as literal string values
- Malicious payloads like `' OR '1'='1` no longer alter query logic; they become literal WHERE clause predicates that return no rows
- Error handling preserved; database driver raises exceptions on invalid input as before
