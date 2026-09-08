## Verdict

exploitable

- CWE ID: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'))
- Location: `CursorExecuteStringFormat.py`, line 16 (sink), value built at line 14
- Confidence: high

## Source

`request.args.get("customer_id")` at line 9 - the `customer_id` query-string parameter from the Flask request, fully attacker-controlled and read with no validation or type coercion.

The value flows unmodified into an f-string at line 14 (`query = f"SELECT id, item, total FROM orders WHERE customer_id = {customer_id}"`) and that string is passed directly to `cursor.execute(query)` at line 16, the sink. There is no intervening check, cast, or allowlist, so the trace is direct source-to-sink with one assignment in between.

Sink contract (`sqlite3.Cursor.execute`): takes a SQL string plus an optional parameters argument; returns the cursor itself (the caller instead uses the pre-existing `cursor` object and calls `.fetchall()` on it separately); raises `sqlite3.OperationalError` on malformed SQL. Nothing is discarded, and the parameters argument is currently omitted entirely (that omission is exactly the defect - the query has no placeholders to bind against).

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

The query string is changed from an f-string that interpolates `customer_id` directly into the SQL text to a static string containing a `?` placeholder (the `sqlite3` driver's positional placeholder syntax), with `customer_id` passed as a separate parameter in a tuple to `cursor.execute()`. `sqlite3` sends the SQL text and the parameter to the database separately, so the value can never be interpreted as SQL syntax regardless of its content (e.g. `1 OR 1=1` or `1; DROP TABLE orders`) - this closes the injection at the primary-defence level called for by both the general and Python-specific CWE-89 guidance. No other logic changed: the same connection, cursor, `fetchall()`, and response shape are preserved.

## Behaviour changes

- SQLite applies the `orders.customer_id` column's affinity to a bound parameter in a comparison, so a numeric-looking string parameter (e.g. `"5"`) is compared the same way the unquoted literal `5` was before - no change for well-formed numeric input.
- If `customer_id` is absent from the query string, `request.args.get` returns `None` in both versions, but the two handle it differently: previously the f-string produced literal SQL `... = None`, which is invalid syntax and raised `sqlite3.OperationalError` (surfacing as a 500 error). With the parameterized query, `None` binds as SQL `NULL`, producing a valid query that returns zero rows, so the endpoint now responds 200 with `{"orders": []}` instead of raising. This is a side effect of removing the string-interpolation path, not an intentional behavior change, and is a strict improvement in robustness, but it is called out because the error-vs-empty-result distinction could matter to a caller that relied on the old failure mode.

## Verification

Ran `python -m py_compile` (uv-managed CPython 3.13.12 interpreter) against the fixed file in isolation: compiled with no syntax errors. No new imports, functions, or APIs were introduced beyond `sqlite3.Cursor.execute`'s existing two-argument form (SQL string, parameter sequence), which is part of the Python standard library's DB-API 2.0-conformant `sqlite3` module already imported in the file, so no dependency check was needed.
