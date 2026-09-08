## Verdict

**Confirmed SQL Injection via Django `.raw()` with f-string concatenation.** The untrusted `email` parameter is concatenated directly into a SQL query string at line 16 and executed at line 18 via `Order.objects.raw()`. An attacker can inject arbitrary SQL using payloads like `' OR '1'='1` to extract or modify data.

**Fix applied:** Replace `.raw()` with parameterized Django ORM `.filter()` method, which automatically handles parameter binding.

## Source

**File:** `views.py`  
**Lines:** 12 (source), 16 (concatenation), 18 (sink)  
**Vulnerable pattern:** User-supplied `email` from `request.GET` is concatenated into an f-string SQL query and executed via `Order.objects.raw()`.

```
Line 12: email = request.GET.get("email")
Line 16: sql = f"SELECT id, placed_at, total_cents, status FROM shop_order WHERE customer_email = '{email}'"
Line 18: orders = Order.objects.raw(sql)
```

The `email` variable is untrusted and directly embedded in the SQL query string without parameterization.

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

## Explanation

The fix replaces the vulnerable raw SQL construction with Django's ORM `.filter()` method. The `.filter(customer_email=email)` call automatically parameterizes the `email` value, ensuring it is treated as data rather than executable SQL code. This eliminates the SQL injection vulnerability while preserving the exact same query logic and result set.

Django ORM handles parameterization transparently, passing the `email` value as a bound parameter to the database driver rather than interpolating it into the SQL string. This is the idiomatic Django approach for simple queries like this one and requires no additional imports or configuration.

## Behaviour changes

**None.** The fix produces identical database query results and response JSON as the original vulnerable code when given valid input. Malicious SQL payloads that would have been executed in the vulnerable version are now treated as literal string values and safely rejected by the database query (no matching customer email addresses contain SQL syntax). The function signature, return type, response structure, and HTTP status codes remain unchanged.
