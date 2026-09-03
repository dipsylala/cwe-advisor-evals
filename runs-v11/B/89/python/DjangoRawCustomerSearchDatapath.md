## Verdict

True Positive - SQL Injection via unparameterized field column name at line 8.

## Source

HTTP GET parameter `field` passed from `customer_controller.py` → `customer_service.py` → `customer_repository.py` line 4.

## Fix

```python
from customers.models import Customer

# Define allowed field names to prevent SQL injection
ALLOWED_SEARCH_FIELDS = {'name', 'email', 'phone', 'address'}

def raw_customer_search(tenant_id, term, field):
    # Validate field against allowlist of permitted column names
    if field not in ALLOWED_SEARCH_FIELDS:
        field = 'name'  # Default to 'name' if invalid field provided
    
    sql = (
        "SELECT * FROM customers_customer "
        "WHERE tenant_id = %s "
        f"AND {field} ILIKE %s"
    )
    return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])
```

## Explanation

The vulnerability exists at line 8 where the `field` parameter is directly interpolated into the SQL query via an f-string (`f"AND {field} ILIKE %s"`). An attacker can inject arbitrary SQL through the HTTP `field` GET parameter. 

Column and table names cannot be parameterized in SQL (only values can), so the fix applies an allowlist validation. The `field` parameter is checked against `ALLOWED_SEARCH_FIELDS`, a fixed set of permitted column names. If the provided field is not in the allowlist, it defaults to `'name'`, ensuring only legitimate columns reach the query. The `term` parameter remains properly parameterized using `%s` placeholder syntax, which Django's `.raw()` method handles correctly.

## Behaviour changes

- **Input validation added**: The `field` parameter is now validated against a predefined allowlist before use. Invalid field names default to `'name'` rather than being injected directly.
- **Attack surface eliminated**: An attacker cannot inject SQL through the `field` parameter; only allowlisted column names can be used.
- **Default behavior**: When an invalid field is provided, the query silently defaults to searching by `'name'` instead of executing injected SQL.
