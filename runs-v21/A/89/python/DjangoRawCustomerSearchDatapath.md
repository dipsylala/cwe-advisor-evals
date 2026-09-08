## Verdict
CONFIRMED - SQL Injection via unsanitized column name in raw SQL query

## Source
Line 8 of customer_repository.py uses an f-string to inject the `field` parameter directly into a SQL query. The `field` parameter originates from an untrusted GET request parameter in customer_controller.py (line 7: `request.GET.get("field", "name")`), flows through customer_service.py (line 5), and reaches the vulnerable raw() call without validation.

## Fix

### File: customer_repository.py
```python
from customers.models import Customer
from django.db.models import Q

ALLOWED_SEARCH_FIELDS = {'name', 'email', 'phone', 'address'}


def raw_customer_search(tenant_id, term, field):
    # Validate field against whitelist to prevent SQL injection
    if field not in ALLOWED_SEARCH_FIELDS:
        field = 'name'
    
    sql = (
        "SELECT * FROM customers_customer "
        "WHERE tenant_id = %s "
        f"AND {field} ILIKE %s"
    )
    return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])
```

## Explanation
Django's `raw()` method only supports parameterization of VALUES via `%s` placeholders, not column names or SQL keywords. Directly interpolating user-supplied input as a column name creates an SQL injection point.

The fix introduces a whitelist of allowed search fields (`ALLOWED_SEARCH_FIELDS`) and validates the `field` parameter before using it in the query. If an invalid field is supplied, the function defaults to searching on the 'name' field. This prevents an attacker from injecting arbitrary SQL through the field parameter while maintaining application functionality.

The values `term` and `tenant_id` are already parameterized with `%s` placeholders and are thus safe from injection.
