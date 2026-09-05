## Verdict

Exploitable. Untrusted user input from the HTTP request parameter flows directly into the SQL query via f-string concatenation on line 18, and is executed without parameterization on line 24.

## Source

Line 32, `request.args.get("since", "1970-01-01")` - untrusted HTTP query parameter passed to `get_orders_since()` as the `date_filter` argument.

## Fix

**Vulnerable code (line 15-20):**
```python
sql = f"""
    SELECT order_id, customer_id, total_cents, placed_at
    FROM orders
    WHERE placed_at >= '{date_filter}'
    ORDER BY placed_at DESC
"""
```

**Fixed code:**
```python
sql = text("""
    SELECT order_id, customer_id, total_cents, placed_at
    FROM orders
    WHERE placed_at >= :date_filter
    ORDER BY placed_at DESC
""")
```

**Fixed execution (line 24):**
```python
result = connection.execute(sql, {"date_filter": date_filter})
```

## Explanation

The fix replaces f-string interpolation with SQLAlchemy's parameterized query mechanism. The `text()` construct accepts a SQL string with named placeholders (`:date_filter`), and the untrusted `date_filter` value is passed separately to `execute()` as a parameter dictionary. SQLAlchemy's driver handles escaping and binding the value to the placeholder, ensuring it is always treated as data rather than executable SQL structure. This closes the SQL injection vulnerability because the database will never interpret the parameter value as part of the query syntax.

## Behaviour changes

None. The sink contract is preserved: `connection.execute()` returns the same result object, `_mapping` conversion produces the same dict structure, and the return value to the caller remains `list[dict]`. Parameter binding does not alter what the query returns when executed with a valid date value.
