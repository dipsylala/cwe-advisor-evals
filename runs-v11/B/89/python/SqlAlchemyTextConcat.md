## Verdict

Exploitable. The untrusted `date_filter` parameter is concatenated directly into the SQL string via an f-string, allowing an attacker to inject arbitrary SQL.

## Source

`date_filter` originates from an HTTP query parameter (`?since=<date>`) at line 32 in `orders_since_handler()`:
```
date_filter = request.args.get("since", "1970-01-01")
```

The parameter is passed untrusted and unevaluated to `get_orders_since(date_filter)`.

## Sink

`connection.execute(text(sql))` at line 24. The SQL string is built with untrusted data interpolated via an f-string (lines 15-20), then passed to SQLAlchemy's `text()` and executed.

## Fix

**Vulnerable code:**
```python
def get_orders_since(date_filter: str) -> list[dict]:
    """Return orders placed on or after the caller-supplied date filter.

    date_filter is expected to be an ISO-8601 date string (e.g. "2024-01-01")
    taken from a query parameter such as ?since=2024-01-01, but it is not
    validated before being embedded in the query below.
    """
    sql = f"""
        SELECT order_id, customer_id, total_cents, placed_at
        FROM orders
        WHERE placed_at >= '{date_filter}'
        ORDER BY placed_at DESC
    """

    with engine.connect() as connection:
        # SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
        result = connection.execute(text(sql))
        rows = [dict(row._mapping) for row in result]

    return rows
```

**Fixed code:**
```python
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
```

## Explanation

The fix replaces f-string interpolation with SQLAlchemy's parameterized query mechanism. The SQL string now uses a named placeholder (`:date_filter`) instead of embedding the untrusted value directly. The `date_filter` parameter is passed separately to `execute()` as a dictionary of bound parameters (`{"date_filter": date_filter}`). This ensures that the database driver treats the value strictly as data, not as executable SQL code, preventing SQL injection regardless of the input content. The `text()` function is applied to the query itself rather than to an f-string, making the parameterization explicit.

## Behaviour changes

None. The query executes with the same semantics: it binds the caller-supplied date to the `WHERE` clause as a comparison value. The return type and structure remain unchanged. SQLAlchemy's parameter binding handles type conversion and escaping transparently, matching the original query's contract.
