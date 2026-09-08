## Verdict

Exploitable. The `customer_id` parameter from the user request is incorporated directly into the SQL query via f-string interpolation without any parameterization, allowing an attacker to inject arbitrary SQL code.

## Source

`customer_id` from `request.args.get("customer_id")` (line 9) - untrusted user-supplied query parameter.

## Fix

The vulnerability lies in building the SQL query with f-string interpolation, which embeds user input directly into the query string before execution. Replace the f-string with a parameterized query using sqlite3's `?` placeholder syntax.

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

The original code used an f-string (`f"...{customer_id}..."`) to build the SQL query, which means the `customer_id` value is interpolated into the query string before it is passed to `cursor.execute()`. This allows an attacker to inject SQL syntax by crafting a malicious `customer_id` parameter (e.g., `1 OR 1=1`). The fix replaces the f-string with a parameterized query using sqlite3's `?` placeholder. The actual `customer_id` value is now passed as a separate parameter tuple to `cursor.execute()`, ensuring the value is always treated as data rather than SQL code. This is the primary defence against SQL injection in Python's sqlite3 library.

## Behaviour changes

None. The parameterized query produces identical results to the original query for legitimate inputs. The `customer_id` parameter is treated as a data value in both cases; the only difference is that in the original code this treatment was unintended and unsafe, while in the fixed code it is enforced by the database driver. The number of rows returned and their contents are unchanged.

Verification: `python -m py_compile` passed on the fixed code.
