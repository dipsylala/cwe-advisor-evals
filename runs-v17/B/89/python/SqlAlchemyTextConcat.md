## Verdict

Exploitable. The user-supplied `date_filter` from the request query parameter flows untrusted from `request.args.get("since")` (line 32) directly into the SQL query via f-string interpolation on line 15-18, and reaches the execution sink `connection.execute(text(sql))` at line 24 without parameterization. An attacker can inject SQL code such as `2024-01-01' OR '1'='1` to manipulate query logic and access unauthorized data.

## Source

`request.args.get("since", "1970-01-01")` at line 32 of `orders_since_handler()`.

## Fix

### File: report_service.py

```python
"""Reporting endpoints backed by SQLAlchemy Core."""

from sqlalchemy import create_engine, text

engine = create_engine("postgresql+psycopg2://reports:reports@localhost/orders")


def get_orders_since(date_filter: str) -> list[dict]:
    """Return orders placed on or after the caller-supplied date filter.

    date_filter is expected to be an ISO-8601 date string (e.g. "2024-01-01")
    taken from a query parameter such as ?since=2024-01-01, but it is not
    validated before being embedded in the query below.
    """
    sql = text("""
        SELECT order_id, customer_id, total_cents, placed_at
        FROM orders
        WHERE placed_at >= :date_filter
        ORDER BY placed_at DESC
    """)

    with engine.connect() as connection:
        result = connection.execute(sql, {"date_filter": date_filter})
        rows = [dict(row._mapping) for row in result]

    return rows


def orders_since_handler(request) -> list[dict]:
    """HTTP handler: GET /reports/orders?since=<date>"""
    date_filter = request.args.get("since", "1970-01-01")
    return get_orders_since(date_filter)
```

## Explanation

The vulnerability was in lines 15-18 where the untrusted `date_filter` was directly interpolated into the SQL query using an f-string, allowing attackers to inject arbitrary SQL. The fix replaces this with SQLAlchemy's parameterized query mechanism: the SQL query now uses the `:date_filter` named placeholder syntax, and the untrusted value is passed separately as a parameter dict `{"date_filter": date_filter}` to the `execute()` method (line 24). This ensures the database driver treats the value as data, not as executable SQL code. The injection is now impossible because the parameter binding occurs at the driver level, completely separating query structure from user-supplied data.

## Behaviour changes

None. The function's return value, behavior, and contract with its caller remain identical. SQLAlchemy's `execute()` method accepts both the SQL object and a parameter dict, processes the bound parameters, and returns the same cursor-like result object that can be iterated as before. The row iteration on line 25 is unchanged.
