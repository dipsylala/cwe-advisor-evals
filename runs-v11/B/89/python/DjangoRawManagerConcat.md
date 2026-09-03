## Verdict

Exploitable. An attacker can inject SQL by providing an email parameter containing SQL metacharacters (e.g., `' OR '1'='1' --`), which would alter the query logic and return all orders regardless of email match, or extract unauthorized data.

## Source

The `email` parameter originates from untrusted user input via `request.GET.get("email")` on line 12. This value flows directly into the SQL query string via f-string concatenation on line 16.

## Fix

**Vulnerable code (lines 16-18):**
```python
sql = f"SELECT id, placed_at, total_cents, status FROM shop_order WHERE customer_email = '{email}'"
orders = Order.objects.raw(sql)
```

**Fixed code:**
```python
sql = "SELECT id, placed_at, total_cents, status FROM shop_order WHERE customer_email = %s"
orders = Order.objects.raw(sql, [email])
```

## Explanation

The vulnerable code concatenates untrusted email input directly into the SQL query string using an f-string, allowing an attacker to inject SQL metacharacters that alter the query logic. The fix uses Django's parameterized query support in the `.raw()` method: the query string uses `%s` as a placeholder for the email value, and the email is passed separately as a parameter in a list. This ensures the email value is always treated as data, never as executable SQL code, eliminating the injection vector.

## Behaviour changes

None. The `.raw()` method's contract is fully preserved. The method continues to accept a query string and optional parameter list, returns a RawQuerySet of Order objects, and the returned queryset is iterated over in the list comprehension identically to the original code.
