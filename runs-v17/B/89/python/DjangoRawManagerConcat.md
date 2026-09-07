## Verdict

exploitable

## Source

`request.GET.get("email")` at line 12, user-supplied HTTP query parameter

## Sink

`Order.objects.raw(sql)` at line 18, executes raw SQL with interpolated query string

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

The original code interpolated the user-supplied `email` parameter directly into the SQL query using an f-string, allowing SQL injection. An attacker could input `' OR '1'='1` to bypass the WHERE clause and retrieve all orders regardless of email.

The fix replaces the f-string interpolation with Django's parameterized query syntax. The SQL query now uses `%s` placeholders (Django's parameter marker), and the email value is passed separately as the second argument to `.raw()`. This ensures the parameter is always treated as data, never as executable SQL code, closing the injection vector.

## Behaviour changes

The call signature to `.raw()` changes from a single argument (raw query string) to two arguments (parameterized query string and parameter list). The underlying database driver handles the escaping and quoting of the parameter, not the Python code. The returned `QuerySet` from `.raw()` behaves identically - iteration, serialization, and all subsequent operations remain unchanged. The query logic is identical, with the WHERE clause still matching on `customer_email`.
