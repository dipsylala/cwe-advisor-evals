## Verdict

SQL Injection vulnerability confirmed at line 16-18 in `views.py`. The `email` parameter from user input is concatenated directly into the SQL query string without parameterization or escaping.

## Source

Line 12: `email = request.GET.get("email")` retrieves untrusted input from the HTTP request.

Lines 16-18: The `email` value is interpolated into a raw SQL query using an f-string and passed to `Order.objects.raw()`, allowing an attacker to inject arbitrary SQL.

## Fix

Replace the string concatenation approach with Django's parameterized query support. Use either the ORM's `filter()` method (preferred) or parameterized placeholders with `raw()`:

**Option 1 (Preferred - uses Django ORM):**
```python
def orders_by_email(request):
    """Return the order history for a customer, looked up by email address.

    Called from the account portal's "order history" page with the email
    the customer entered into a search box on that page.
    """
    email = request.GET.get("email")
    if not email:
        return HttpResponseBadRequest("email is required")

    orders = Order.objects.filter(customer_email=email)

    results = [
        {
            "id": order.id,
            "placed_at": order.placed_at.isoformat(),
            "total_cents": order.total_cents,
            "status": order.status,
        }
        for order in orders
    ]
    return JsonResponse({"orders": results})
```

**Option 2 (Parameterized raw query):**
```python
    sql = "SELECT id, placed_at, total_cents, status FROM shop_order WHERE customer_email = %s"
    orders = Order.objects.raw(sql, [email])
```

## Explanation

The vulnerability exists because user-controlled input (`email` from `request.GET`) is directly embedded into a SQL string without any escaping or parameter binding. An attacker can inject SQL metacharacters (e.g., `' OR '1'='1`) to modify the query logic.

Django's ORM methods like `filter()` automatically handle parameter binding and escaping. The `%s` placeholders in `raw()` followed by a parameter list achieve the same protection by separating query structure from data.

Using either approach ensures the database driver treats the `email` value as data, not as executable SQL code, preventing injection attacks.
