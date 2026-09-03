## Verdict
Confirmed SQL injection via unsanitized string concatenation into a SQLAlchemy `text()` query.

## Source
Line 18 embeds the untrusted `date_filter` parameter directly into an SQL string literal:
```python
WHERE placed_at >= '{date_filter}'
```

The `date_filter` value originates from the HTTP query parameter `since` (line 32) and flows through `get_orders_since()` without validation or sanitization. An attacker can inject SQL metacharacters—for example, `2024-01-01' OR '1'='1`—to break out of the string literal and append arbitrary SQL.

## Fix
Replace the f-string concatenation with SQLAlchemy's parameterized query mechanism. Use a named parameter placeholder (`:date_filter`) and bind the value separately:

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
    """).bindparams(date_filter=date_filter)

    with engine.connect() as connection:
        result = connection.execute(sql)
        rows = [dict(row._mapping) for row in result]

    return rows
```

Alternatively, pass the parameters dict directly to `execute()`:
```python
sql = text("""
    SELECT order_id, customer_id, total_cents, placed_at
    FROM orders
    WHERE placed_at >= :date_filter
    ORDER BY placed_at DESC
""")
result = connection.execute(sql, {"date_filter": date_filter})
```

## Explanation
SQLAlchemy's `text()` construct accepts parameterized queries using `:name` placeholders. When you bind parameters—either through `.bindparams()` or by passing a dict to `execute()`—the database driver handles escaping and quoting, ensuring that the value is treated as data, not SQL syntax. This prevents an attacker from injecting metacharacters or additional SQL commands.

The fix separates the query structure (fixed string) from the data (bound parameter), which is the core principle of SQL injection prevention. The database engine will never interpret the bound value as executable code.
