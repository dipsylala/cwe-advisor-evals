## Verdict

**Confirmed SQL Injection (CWE-89)** in SQLAlchemy Core code. User-controlled query parameter flows directly into f-string interpolation, allowing arbitrary SQL injection. Fix closes the vulnerability by converting to parameterized queries.

## Source

**Vulnerable code chain:**
1. Line 32: Untrusted source: `request.args.get("since", "1970-01-01")` — HTTP query parameter with no validation
2. Line 8: Parameter passed to function: `get_orders_since(date_filter: str)`
3. Line 18: Interpolated into f-string: `WHERE placed_at >= '{date_filter}'`
4. Line 24: Executed without parameterization: `connection.execute(text(sql))`

**Exploitation scenario:** Attacker supplies `?since=2024-01-01' OR '1'='1` to bypass the WHERE clause and return all orders, or `?since=2024-01-01'; TRUNCATE orders; --` to destroy data.

## Fix

### File: report_service.py

```python
"""Reporting endpoints backed by SQLAlchemy Core."""

from sqlalchemy import create_engine, text

engine = create_engine("postgresql+psycopg2://reports:reports@localhost/orders")


def get_orders_since(date_filter: str) -> list[dict]:
    """Return orders placed on or after the caller-supplied date filter.

    date_filter is expected to be an ISO-8601 date string (e.g. "2024-01-01")
    taken from a query parameter such as ?since=2024-01-01.
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

The original code constructed SQL by embedding untrusted `date_filter` directly into an f-string, which SQLAlchemy passed to the database driver as-is. The fix replaces f-string interpolation with SQLAlchemy's parameterized query syntax:

1. **SQL string changed** (line 15–20): Replaced f-string with a raw SQL string using the `:date_filter` named placeholder
2. **Parameter binding added** (line 24): `connection.execute()` now receives a dict mapping `date_filter` to its value as a second argument
3. **Interpolation removed** (line 15): `text()` is no longer wrapped around an f-string; the template string is built without user data

SQLAlchemy's `text()` with named parameters (`:name` syntax) is translated to the underlying driver's parameterized form. Since the connection uses psycopg2 (`postgresql+psycopg2://`), SQLAlchemy internally converts `:date_filter` to psycopg2's `%(date_filter)s` or binds via the driver's prepared-statement API, ensuring the value is escaped at the driver level and cannot alter query structure.

The untrusted `date_filter` now flows as a **data value only**, not as part of the SQL string. Injection payloads like `' OR '1'='1` or `; DROP TABLE` are treated as literal string content and harmlessly compared against the `placed_at` column.

## Behaviour changes

**Returns:** Identical. The query still returns the same rows from the `orders` table.

**Discards:** None. The `result._mapping` dict conversion is unchanged.

**Arguments left implicit:** None introduced. The `connection.execute()` call's signature already accepted a second positional parameter for bindings; the original code simply did not use it.

**Failure behaviour:** Unchanged when injection payloads are supplied. Before the fix, malformed injection syntax (e.g., unbalanced quotes) would have caused a database parse error; after the fix, those same malformed strings are safely bound as literal values and produce no query results (the `placed_at` column never matches a malformed date string). Valid ISO-8601 dates and injection attempts alike are now bound as data; neither alters the query structure.

**No unintended side effects:** The fix does not suppress errors, change transaction scope, alter row ordering, or modify the return type. The function contract is preserved.
