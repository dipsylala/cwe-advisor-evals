## Verdict
SQL Injection vulnerability confirmed. The `date_filter` parameter is directly concatenated into the SQL query via an f-string without parameterization, allowing an attacker to inject arbitrary SQL code through the query parameter.

## Source
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
        result = connection.execute(text(sql))
        rows = [dict(row._mapping) for row in result]

    return rows
```

## Fix
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
The vulnerability occurs because the user-supplied `date_filter` is directly concatenated into the SQL query string via an f-string. An attacker could inject SQL code by providing a value like `' OR '1'='1' --` to alter the query logic.

The fix replaces string concatenation with parameterized queries using SQLAlchemy's `text()` construct with named parameter placeholders (`:date_filter`). The parameter value is then passed separately to `connection.execute()` via a dictionary, ensuring the value is treated as data rather than SQL code. This cleanly separates SQL structure from user input and is the standard SQLAlchemy Core defense against SQL injection.
