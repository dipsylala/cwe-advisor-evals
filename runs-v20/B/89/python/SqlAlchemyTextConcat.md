## Verdict

Confirmed. `get_orders_since()` builds a raw SQL string with an f-string, embedding `date_filter` directly into the `WHERE` clause, then wraps it in SQLAlchemy's `text()` and executes it with no bound parameters. An attacker-controlled `since` query parameter reaches the database as literal SQL text.

## Source

`orders_since_handler(request)` reads `date_filter = request.args.get("since", "1970-01-01")` from the HTTP request's query string (line 32) - attacker-controlled, no validation - and passes it straight into `get_orders_since(date_filter)` (line 33).

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
    sql = text(
        """
        SELECT order_id, customer_id, total_cents, placed_at
        FROM orders
        WHERE placed_at >= :date_filter
        ORDER BY placed_at DESC
    """
    )

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

The vulnerable code used an f-string to splice `date_filter` into the SQL text before handing it to `text()`, so the value became part of the query's syntax - a payload such as `2024-01-01' OR '1'='1` or a stacked/UNION statement would be interpreted as SQL rather than data. The fix keeps the query as a single static `text()` construct with a named bind parameter, `:date_filter`, and passes the untrusted value in the parameters dict as the second argument to `connection.execute()`. SQLAlchemy forwards this to the psycopg2 driver as a separate, out-of-band parameter, so the database always treats it as a data value for the `placed_at >= ...` comparison and never as query structure, regardless of its contents. No other behavior changes: the same single comparison against `placed_at`, the same column list, ordering, and row-to-dict conversion are preserved.

Sink contract check: `connection.execute()` still returns a `CursorResult` that is iterated the same way (`row._mapping`) to build the returned list of dicts; nothing previously returned is discarded, and no new argument is defaulted or omitted - the only added argument is the bind-parameter dict itself, which is required to carry the value that used to be inlined. Failure behavior is unchanged: a malformed or type-incompatible `date_filter` still raises from the driver/database at `execute()` time, same as before.

Every name introduced by the fix - `text()` with a colon-prefixed bind parameter and `connection.execute(statement, params_dict)` - is standard SQLAlchemy Core API already in use in this file (`text` is already imported) and matches the language guidance's documented pattern (`cwe/89/python/INDEX.md`, "SQLAlchemy `text()` with interpolated values" is the taint sink; the safe form binds parameters instead). The file was compiled with `python -m py_compile` against a scratch copy and it compiled cleanly with no diagnostics.

## Behaviour changes

None expected. The query still selects the same columns, applies the same single `placed_at >= <value>` filter, and returns rows in the same order and shape. Passing `date_filter` as a bound parameter instead of an inlined string literal means Postgres/psycopg2 infer its type from the comparison context (as it does for a literal), so a well-formed ISO-8601 date string behaves identically; a malformed value now fails as a parameter-binding/type error at the database rather than producing a malformed SQL string, which is the intended effect of closing the injection rather than a functional regression.
