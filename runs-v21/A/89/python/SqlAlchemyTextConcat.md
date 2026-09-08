## Verdict
CONFIRMED: SQL injection via unparameterized user input in SQLAlchemy Core query.

## Source
Line 24 executes an SQL query constructed with f-string interpolation of an unsanitized `date_filter` parameter (line 32, from HTTP request). The vulnerability exists in lines 15-20 where the f-string embeds user input directly into the SQL string, and the sink is line 24 where this string is passed to `connection.execute(text(sql))`.

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
The original code constructed an SQL query using Python f-string interpolation, directly embedding the unsanitized `date_filter` parameter into the SQL string. This allows an attacker to inject arbitrary SQL by providing a malicious value (e.g., `?since=2024-01-01' OR '1'='1`).

The fix replaces f-string interpolation with SQLAlchemy's parameterized query mechanism:

1. Move the `text()` call outside the f-string so it wraps the static SQL template.
2. Replace the f-string placeholder `'{date_filter}'` with a named parameter `:date_filter`.
3. Pass the user input as a dictionary to `connection.execute()` as the second argument: `{"date_filter": date_filter}`.

SQLAlchemy Core's parameterized queries handle proper escaping and quoting of the parameter value at the driver level, preventing SQL injection regardless of the input content.
