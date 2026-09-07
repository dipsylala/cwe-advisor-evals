## Verdict
CONFIRMED - CWE-89 (SQL Injection) via unparameterized user input embedded into SQL query at line 24.

## Source
The `date_filter` parameter originates from untrusted user input (HTTP query parameter at line 32) and is embedded directly into the SQL query via f-string interpolation (line 18), allowing an attacker to inject arbitrary SQL by breaking out of the string literal (e.g., `2024-01-01' OR '1'='1`).

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
        # SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
        result = connection.execute(sql, {"date_filter": date_filter})
        rows = [dict(row._mapping) for row in result]

    return rows


def orders_since_handler(request) -> list[dict]:
    """HTTP handler: GET /reports/orders?since=<date>"""
    date_filter = request.args.get("since", "1970-01-01")
    return get_orders_since(date_filter)
```

## Explanation
Replace f-string SQL construction with SQLAlchemy's parameter binding. The fix:

1. Wrap the SQL string with `text()` on line 15 (moved from line 24)
2. Replace the f-string interpolation with a named parameter placeholder `:date_filter` on line 18
3. Pass the parameter value as a dictionary to `connection.execute(sql, {"date_filter": date_filter})` on line 24

SQLAlchemy's parameter binding uses the database driver's native prepared statement mechanism, which treats the value as data rather than code. This prevents SQL injection regardless of the input content—quotes, semicolons, and SQL keywords in `date_filter` are escaped/handled safely by the driver.
