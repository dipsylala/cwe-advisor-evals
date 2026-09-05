## Verdict

Exploitable

## Source

`request.GET.get("email")` on line 12 — untrusted user input from query parameter, passed directly into SQL query construction without parameterization.

## Fix

**Vulnerable code (lines 16-18):**
```python
sql = f"SELECT id, placed_at, total_cents, status FROM shop_order WHERE customer_email = '{email}'"
# SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
orders = Order.objects.raw(sql)
```

**Fixed code (lines 16-18):**
```python
sql = "SELECT id, placed_at, total_cents, status FROM shop_order WHERE customer_email = %s"
orders = Order.objects.raw(sql, [email])
```

## Explanation

The fix replaces the f-string interpolation with a parameterized query. Instead of embedding the email directly into the SQL string, `%s` is used as a placeholder, and the email value is passed as a separate parameter to the `raw()` method. This ensures the database driver treats the email as data only, never as executable SQL code, closing the injection vector. An attacker cannot manipulate the query structure through the email parameter because the parameter is bound after the SQL is parsed.

## Behaviour changes

None. The query executes identically, returning the same result set with the same fields and in the same order. Django's `.raw()` method accepts both the SQL string and a list of parameters; the return type remains a QuerySet that the subsequent loop consumes without modification.
