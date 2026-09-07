## Verdict

VULNERABLE

The application builds an SQL query by concatenating untrusted user input from `request.GET.get("email")` into an f-string and passes it directly to Django's `.raw()` method. This is a textbook SQL injection vulnerability - an attacker can inject arbitrary SQL by providing an email like `' OR '1'='1` in the query parameter, causing the query to return all orders regardless of email address.

## Source

User-controlled input: `request.GET.get("email")` at line 12, which is never validated or sanitized before use.

## Fix

Replace the vulnerable raw SQL concatenation with Django ORM's parameterized query method:

**Vulnerable code (lines 16–18):**
```python
sql = f"SELECT id, placed_at, total_cents, status FROM shop_order WHERE customer_email = '{email}'"
# SAST FINDING: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')) reported here. Sink is the next statement.
orders = Order.objects.raw(sql)
```

**Fixed code:**
```python
orders = Order.objects.filter(customer_email=email)
```

## Explanation

The fix replaces direct SQL string concatenation with Django ORM's `.filter()` method, which automatically uses parameterized queries internally. Django's ORM treats the `customer_email` parameter as a value, not query structure, preventing any injected SQL from being interpreted as code. This aligns with the CWE-89 remediation guidance: "Employ ORM frameworks - Use SQLAlchemy, Django ORM, or similar frameworks that handle parameterization." The `.filter()` method maintains the same QuerySet return type, so iteration behavior in the downstream code remains unchanged.

## Behaviour changes

- The query now uses parameterized queries instead of string concatenation, completely eliminating SQL injection as a vector for this code path.
- No functional or output changes: `.filter()` returns a QuerySet of Order objects, which iterates and accesses attributes identically to the original `.raw()` result.
- Minor side effect: all Order model fields are selected rather than just the four in the original SELECT list. This is not a security issue and has negligible performance impact for typical order objects.
