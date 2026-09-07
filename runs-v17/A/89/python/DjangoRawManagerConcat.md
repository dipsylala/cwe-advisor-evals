## Verdict

SQL injection vulnerability confirmed. The `email` parameter from `request.GET` is directly interpolated into a SQL string and passed to `Order.objects.raw()` without parameterization, allowing an attacker to inject arbitrary SQL.

## Source

Line 16 constructs a raw SQL query using an f-string with untrusted user input:
```python
email = request.GET.get("email")  # untrusted input
sql = f"SELECT id, placed_at, total_cents, status FROM shop_order WHERE customer_email = '{email}'"
```

An attacker could pass `email="' OR '1'='1"` or similar payloads to alter the query logic. The resulting SQL is then executed at line 18 via `Order.objects.raw(sql)`.

## Fix

### File: views.py

```python
from django.http import JsonResponse, HttpResponseBadRequest

from .models import Order


def orders_by_email(request):
    """Return the order history for a customer, looked up by email address.

    Called from the account portal's "order history" page with the email
    the customer entered into a search box on that page.
    """
    email = request.GET.get("email")
    if not email:
        return HttpResponseBadRequest("email is required")

    sql = "SELECT id, placed_at, total_cents, status FROM shop_order WHERE customer_email = %s"
    orders = Order.objects.raw(sql, params=[email])

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

## Explanation

The fix replaces the unsafe f-string SQL construction with a parameterized query using Django's `raw()` method. The SQL string now contains a `%s` placeholder instead of directly embedding the email variable, and the email value is passed separately via the `params` argument. Django's database driver handles proper escaping and prevents the email value from being interpreted as SQL syntax, eliminating the injection vector.
