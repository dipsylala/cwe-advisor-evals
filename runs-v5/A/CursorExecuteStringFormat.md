## Verdict

Confirmed. `customer_id` comes from `request.args.get("customer_id")` (an unvalidated query-string parameter) and is interpolated directly into a SQL string via an f-string, which is then passed to `cursor.execute()`. An attacker controls this value fully and can inject SQL, e.g. `?customer_id=1 OR 1=1` or a `UNION SELECT` to exfiltrate other tables, or stacked/boolean-based payloads to read or modify unrelated data.

## Source

`request.args.get("customer_id")` in `get_orders()` (`CursorExecuteStringFormat.py`, line 9) — attacker-controlled HTTP query parameter, flows unvalidated into the f-string at line 14 and reaches the sink at line 16 (`cursor.execute(query)`).

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

The vulnerability is caused by building the SQL statement through string formatting (an f-string) instead of letting the database driver handle parameter substitution. Because `customer_id` is spliced directly into the query text, any SQL syntax the caller supplies becomes part of the command the database executes.

The fix replaces the f-string with a static query string containing a `?` placeholder and passes `customer_id` as a separate parameter tuple to `cursor.execute()`. `sqlite3`'s DB-API driver sends the query text and the parameter value to SQLite separately, so the value is always bound as literal data for the `customer_id` column comparison and can never be interpreted as SQL syntax, regardless of what characters it contains. This is the standard parameterized-query defense for SQL injection and requires no manual escaping or input filtering.
