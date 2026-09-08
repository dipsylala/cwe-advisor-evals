## Verdict

exploitable

- cwe_id: CWE-89
- location: views.py, line 18 (`Order.objects.raw(sql)`), built from line 16
- confidence: high

## Source

`request.GET.get("email")` at line 12 - the `email` query-string parameter submitted from the account portal's order-history search box. It is attacker-controlled and reaches the sink with no validation or escaping: the only check on it (line 13-14) is a not-empty guard, which does not constrain its content.

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

The vulnerable code built the SQL string with an f-string, splicing `email` directly inside the quoted literal (`customer_email = '{email}'`), so a value such as `' OR '1'='1` or a stacked/UNION payload changes the query's logic or exfiltrates other customers' orders. The fix keeps the same `Order.objects.raw()` sink and the same query shape but replaces the interpolated value with the driver placeholder `%s` and passes `email` as a separate element of the `params` list, per Django's documented `Manager.raw(raw_query, params=None, ...)` signature. Django forwards `params` to the underlying DB-API cursor as bound parameters, so the value is always treated as data for the `customer_email` column and can no longer alter the query's structure, regardless of what characters it contains.

## Behaviour changes

none - `Order.objects.raw()` still returns the same `RawQuerySet` of `Order` model instances constructed from the same four selected columns, iterated the same way to build `results`, and the empty/missing-`email` short-circuit (`HttpResponseBadRequest`) is unchanged. The only difference is that the value is now bound as a parameter instead of being spliced into the query text, which changes how the value reaches the database but not what the endpoint returns for legitimate input.

Verification: copied the fixed file to a scratch directory and ran `python -m py_compile views.py` - compiled with no errors. `Order.objects.raw(raw_query, params)` is Django's own documented API (no new import introduced); the `%s` placeholder is the Django/DB-API form named in the loaded Python CWE-89 guidance for non-sqlite3 drivers and is also the form Django's `raw()` itself expects.
