## Verdict

The vulnerability is confirmed. Line 10 of `customer_repository.py` directly interpolates the `field` parameter into the SQL query using an f-string, allowing SQL injection. The `field` parameter originates from untrusted user input (`request.GET.get("field")` in `customer_controller.py`) and flows through `customer_service.py` unchecked before reaching the vulnerable SQL construction.

## Source

The taint source is user-controlled input from `customer_controller.py`:
- **Line 6**: `field = request.GET.get("field", "name")` receives untrusted HTTP query parameter

The taint flows through the call chain:
- **customer_controller.py:7** → calls `search_customers(tenant_id, term, field)`
- **customer_service.py:5** → calls `raw_customer_search(tenant_id, term, field)`
- **customer_repository.py:10** → uses `field` directly in f-string: `f"AND {field} ILIKE %s"`

The sink is the raw SQL query construction at line 10, which uses the unsanitized `field` value to build the WHERE clause.

## Fix

### File: customer_repository.py

```python
from customers.models import Customer


ALLOWED_FIELDS = {'name', 'email', 'phone'}


def raw_customer_search(tenant_id, term, field):
    if field not in ALLOWED_FIELDS:
        raise ValueError(f"Invalid field: {field}")
    
    sql = (
        "SELECT * FROM customers_customer "
        "WHERE tenant_id = %s "
        f"AND {field} ILIKE %s"
    )
    return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])
```

## Explanation

Django's `raw()` method cannot parameterize column/field names—only values can use the `%s` parameter placeholder. Therefore, direct string interpolation of field names is inevitable, making input validation the primary defence.

The fix adds a whitelist (`ALLOWED_FIELDS`) containing the specific column names the search feature supports. Before constructing the SQL query, the code validates that the `field` parameter matches one of these allowed values. If an attacker attempts to inject SQL through the `field` parameter (e.g., `name OR 1=1`), the validation rejects it and raises a `ValueError`.

This approach:
- Ensures only known columns can be searched
- Prevents column enumeration and data exfiltration attacks
- Remains safe even if the field value reaches the f-string interpolation
- Fails fast and explicitly rather than silently accepting malicious input

The whitelist should be adjusted to match the actual searchable columns in the `customers_customer` table; `name`, `email`, and `phone` are shown as examples.
