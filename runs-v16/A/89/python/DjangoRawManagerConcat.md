## Verdict

**Confirmed SQL Injection (CWE-89)**: The email parameter from an untrusted request source is directly interpolated into a SQL query string using an f-string, then executed via Django's `raw()` method without parameterization.

## Source

Line 16-18 in `views.py`:

```python
sql = f"SELECT id, placed_at, total_cents, status FROM shop_order WHERE customer_email = '{email}'"
# Line 18:
orders = Order.objects.raw(sql)
```

The `email` parameter originates from `request.GET.get("email")` on line 12, which is user-controlled HTTP input.

## Fix

Replace the string interpolation with parameterized query syntax:

```python
sql = "SELECT id, placed_at, total_cents, status FROM shop_order WHERE customer_email = %s"
orders = Order.objects.raw(sql, [email])
```

## Explanation

Django's `raw()` method supports parameterized queries using `%s` placeholders and a params list. The database driver escapes and sanitizes parameter values before constructing the final SQL statement, preventing injection.

The vulnerable code concatenates the user-supplied `email` directly into the SQL string. An attacker can inject SQL metacharacters—for example, passing `' OR '1'='1` closes the string and injects a true condition that bypasses the WHERE clause entirely.

The fix separates the SQL structure (the query template with `%s` markers) from the data (the `[email]` parameter list). Django handles escaping automatically, treating the email value as literal data, not SQL syntax.
