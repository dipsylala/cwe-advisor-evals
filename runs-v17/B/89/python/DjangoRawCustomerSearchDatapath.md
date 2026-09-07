## Verdict

The vulnerability is confirmed. Line 10 uses an f-string to interpolate the `field` parameter (a dynamic identifier / column name) directly into the SQL query. This allows attackers to manipulate the query structure through the request parameter.

## Source

User-controlled `field` parameter from `request.GET.get("field", "name")` in `customer_controller.py` flows through `customer_service.py` and reaches the SQL query construction in `customer_repository.py` where it is interpolated into the query using an f-string on line 8.

## Fix

Validate the `field` parameter against an allowlist of permitted column names before using it in the SQL query. Dynamic identifiers (column names, table names) cannot be bound as parameters and must be validated against a fixed set of safe values.

### File: customer_repository.py

```python
from customers.models import Customer


# Define allowed searchable fields
ALLOWED_SEARCH_FIELDS = {'name', 'email', 'phone', 'address'}


def raw_customer_search(tenant_id, term, field):
    # Validate field against allowlist to prevent SQL injection
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

The vulnerability occurs because `field` is a dynamic identifier (column name) that is directly interpolated into the SQL query. Unlike parameter binding which treats values as data, dynamic identifiers cannot be parameterized—they must be structural parts of the query.

The fix implements allowlist validation: only a predefined set of column names (`name`, `email`, `phone`, `address`) are permitted. The `field` parameter is checked against this allowlist before being used in the query. If an invalid field is provided, a `ValueError` is raised rather than allowing the malicious input to reach the database query.

This prevents an attacker from injecting SQL logic through the `field` parameter. For example, attempting to pass `field="name OR 1=1 --"` now raises an exception instead of executing a manipulated query.

The `term` parameter remains safely parameterized using Django's `.raw()` method, which binds it as a separate parameter to prevent SQL injection there as well.

## Behaviour changes

- The function now validates the `field` parameter against an allowlist on every call
- Invalid field values raise a `ValueError` instead of executing a modified query
- Permitted field values proceed normally without performance impact
- Error messages inform developers and monitoring systems of invalid search attempts
