## Verdict

Confirmed. The `email` query parameter is concatenated directly into a raw SQL string that is executed via `Order.objects.raw()`, letting an attacker break out of the string literal and alter the query (e.g. tautologies, `UNION`-based extraction of other tables).

## Source

`request.GET.get("email")` in `orders_by_email` (views.py, line 12) - user-controlled input from the account portal's order-history search box, with no encoding or parameterization before reaching the query.

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

`Order.objects.raw()` accepts a second `params` argument specifically so callers can keep parameterized raw SQL: the query string uses the database driver's `%s` placeholder, and the actual value is passed separately in the `params` list. Django's raw-query executor forwards the SQL and params straight to the DB-API cursor as a parameterized statement, so the driver sends `email` to the database as pure data rather than as part of the SQL text - it can never be interpreted as a quote-closing character, a boolean tautology, or a `UNION` clause. This preserves the exact same query semantics and return shape (still an `Order` `RawQuerySet` with `id`, `placed_at`, `total_cents`, `status`), so no other code changes are required, while eliminating the string-interpolation sink entirely. Verification: submitting a normal email (`alice@example.com`) still returns her order history unchanged; submitting an injection payload such as `' OR '1'='1` or `' UNION SELECT ...--` now matches zero rows (or raises no error) instead of returning all orders or attacker-chosen data, because the apostrophe is sent as a literal character inside the bound parameter rather than terminating the string literal.
