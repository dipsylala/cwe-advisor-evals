## Verdict

Real vulnerability confirmed. The `field` parameter is user-controlled and directly interpolated into the SQL query via f-string, enabling SQL injection despite `term` being properly parameterized.

## Source

`customer_controller.py` line 7: `field = request.GET.get("field", "name")` passes untrusted user input through `search_customers()` to `raw_customer_search()`.

## Fix

Define an allowlist of permitted column names in `customer_repository.py` and validate the `field` parameter against it before building the query:

```python
from customers.models import Customer


# Whitelist of allowed column names for search
ALLOWED_SEARCH_FIELDS = {"name", "email", "phone", "company"}


def raw_customer_search(tenant_id, term, field):
    # Validate field against allowlist
    if field not in ALLOWED_SEARCH_FIELDS:
        raise ValueError(f"Invalid search field: {field}")
    
    sql = (
        "SELECT * FROM customers_customer "
        "WHERE tenant_id = %s "
        f"AND {field} ILIKE %s"
    )
    return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])
```

## Explanation

The vulnerability stems from directly interpolating the user-supplied `field` parameter into the SQL query string via f-string on line 7. While the `term` parameter is correctly parameterized using Django's `%s` placeholder, the column name (`field`) cannot be parameterized—SQL does not allow binding identifiers as parameters. The fix validates `field` against a predefined allowlist of safe column names (`ALLOWED_SEARCH_FIELDS`). Only if the value matches one of the permitted columns is it used in the query. Any value outside this set raises a `ValueError`, preventing SQL injection. The allowlist acts as the control boundary: the attacker's input must match exactly one of the known, application-controlled identifiers to proceed.

## Behaviour changes

- Requests with a `field` parameter not in the allowlist (`ALLOWED_SEARCH_FIELDS`) now raise a `ValueError` instead of executing an injected query. The caller (controller) should catch this exception and return a 400 Bad Request response to indicate invalid input.
- Only valid column names can be searched: `name`, `email`, `phone`, `company`. The default fallback of `"name"` remains valid and backward-compatible for callers that omit the parameter.
- The SQL query structure and parameterization of `term` remain unchanged; only the injection vector (column name) is now restricted to a known safe set.
