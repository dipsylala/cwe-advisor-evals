## Verdict

Confirmed. `get_orders_since` builds the SQL statement with an f-string that splices the caller-supplied `date_filter` directly into the `WHERE placed_at >= '{date_filter}'` clause, then hands the resulting string to `text()` and executes it. Any value reaching this function - including via `orders_since_handler`, which passes the raw `since` query parameter with no validation - is interpreted as SQL, not as data. A value such as `2024-01-01' OR '1'='1` or a stacked/UNION payload breaks out of the intended string literal and lets an attacker alter the query's logic or exfiltrate arbitrary columns.

## Source

`orders_since_handler` reads `date_filter` from `request.args.get("since", "1970-01-01")` (line 32) - an HTTP query parameter - and passes it unchanged into `get_orders_since`, which formats it into the SQL string at line 18 and executes it at line 24.

## Fix

### File: report_service.py

```python
"""Reporting endpoints backed by SQLAlchemy Core."""

from sqlalchemy import create_engine, text

engine = create_engine("postgresql+psycopg2://reports:reports@localhost/orders")


def get_orders_since(date_filter: str) -> list[dict]:
    """Return orders placed on or after the caller-supplied date filter.

    date_filter is expected to be an ISO-8601 date string (e.g. "2024-01-01")
    taken from a query parameter such as ?since=2024-01-01. It is passed as a
    bound parameter rather than being embedded in the query string.
    """
    sql = text(
        """
        SELECT order_id, customer_id, total_cents, placed_at
        FROM orders
        WHERE placed_at >= :date_filter
        ORDER BY placed_at DESC
        """
    )

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

The query text is now a static string containing the named placeholder `:date_filter`; `date_filter` is no longer interpolated into it at all. SQLAlchemy's `Connection.execute(statement, parameters)` sends the statement and the parameter dict to the DB-API driver separately, so the driver binds `date_filter` as a literal value for comparison against `placed_at` - it can never be parsed as SQL syntax, regardless of quotes, comment sequences, or `OR`/`UNION` payloads it contains. This preserves the original behavior for legitimate ISO-8601 date strings (and, being a bound parameter rather than a stripped/escaped value, does not reject or alter any well-formed input) while eliminating the injection: `text()` with named parameters is the standard SQLAlchemy Core pattern for parameterized raw SQL, so no additional library or schema change is needed. No allowlist or format validation was added on top, since the bound parameter already closes the injection and the endpoint's accepted date format is not otherwise being constrained by this change.
