## Verdict
SQL Injection via Django raw query with unsanitized user input. The email parameter is concatenated directly into the SQL query string using an f-string, allowing an attacker to inject arbitrary SQL through the `email` GET parameter. Severity: High.

## Source
File: views.py, lines 16-18

The vulnerability occurs when constructing a raw SQL query using string interpolation:
```python
sql = f"SELECT id, placed_at, total_cents, status FROM shop_order WHERE customer_email = '{email}'"
orders = Order.objects.raw(sql)
```

The `email` variable comes from untrusted user input (`request.GET.get("email")`), and is concatenated directly into the SQL string without escaping or parameterization. An attacker could inject SQL by providing a value like `' OR '1'='1` to bypass authentication or exfiltrate data.

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
    orders = Order.objects.raw(sql, [email])

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
Django's `.raw()` method supports parameterized queries to prevent SQL injection. The fix replaces the f-string construction with a SQL query containing a `%s` placeholder, and passes the parameter value as a second argument to `.raw()` in a list: `Order.objects.raw(sql, [email])`.

Django's database adapter will properly escape and bind the email parameter, ensuring that special characters and SQL metacharacters in the email value are treated as data rather than executable SQL. This eliminates the injection vector while preserving the intended query logic.
