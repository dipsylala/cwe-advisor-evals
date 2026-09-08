## Verdict

Confirmed. `customer_id` comes from `request.args.get("customer_id")` (an unvalidated query-string parameter) and is interpolated directly into a SQL string via an f-string, which is then passed to `cursor.execute()`. An attacker controls `customer_id` and can inject SQL syntax, altering the query's logic or exfiltrating data via `UNION`-based injection.

## Source

`request.args.get("customer_id")` in `get_orders()` (`CursorExecuteStringFormat.py`, line 9) — untrusted, attacker-controlled HTTP query parameter, flowing unmodified into the f-string built on line 14 and executed on line 16.

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

The vulnerability is the use of an f-string to build the SQL statement, which lets attacker-controlled text become part of the SQL grammar rather than staying data. The fix replaces the interpolated value with a `?` placeholder and passes `customer_id` as a parameter in the tuple argument to `cursor.execute()`. `sqlite3`'s DB-API binds parameters out-of-band from the query text, so the driver sends the value as data no matter what characters it contains — a value like `1 OR 1=1` or `1; DROP TABLE orders;--` is matched literally against the `customer_id` column instead of altering the query structure. No other behavior changes: the query still filters on equality against `customer_id`, and the response shape is unchanged. Parameterization is the correct primary defense here (rather than input validation or escaping) because it removes the possibility of the value being interpreted as SQL syntax entirely, regardless of its content.
