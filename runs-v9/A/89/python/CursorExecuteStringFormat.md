## Verdict
Confirmed. The `customer_id` request parameter is interpolated directly into a SQL string via an f-string and passed to `cursor.execute()`, allowing SQL injection.

## Source
`customer_id = request.args.get("customer_id")` (line 9) — attacker-controlled value from the Flask request query string.

## Fix

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
The original code builds the query with an f-string, embedding `customer_id` straight into the SQL text (line 14) before handing it to `cursor.execute()` (line 16). Since `customer_id` comes unvalidated from `request.args`, a value such as `1 OR 1=1` or `1; DROP TABLE orders;--` changes the query's logic or structure instead of being treated as a single scalar value.

The fix replaces string interpolation with a parameterized query: the SQL text now contains a `?` placeholder, and the value is passed separately as a tuple in the second argument to `cursor.execute()`. `sqlite3`'s DB-API driver sends the query and the parameter to SQLite through separate channels, so the driver binds `customer_id` strictly as a data value for the `customer_id` column comparison — it can never be reinterpreted as SQL syntax, regardless of what characters it contains. This is the standard defense for SQL injection in Python's `sqlite3` module (and DB-API-compliant drivers generally): always use the driver's parameter-binding mechanism (`?` placeholders with `sqlite3`, or `%s` with psycopg2/MySQLdb) rather than building queries via f-strings, `%`-formatting, `.format()`, or string concatenation whenever a value originates from user input.
