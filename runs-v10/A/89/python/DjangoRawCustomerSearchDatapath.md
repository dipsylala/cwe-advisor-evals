## Verdict

The finding is correct. The `field` parameter is directly interpolated into the SQL query using an f-string on line 8, creating an SQL injection vulnerability. An attacker controlling this parameter can inject arbitrary SQL code.

## Source

Line 10 passes user-controlled `field` directly into the query:

```python
sql = (
    "SELECT * FROM customers_customer "
    "WHERE tenant_id = %s "
    f"AND {field} ILIKE %s"  # field is unsanitized f-string interpolation
)
return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])
```

The `field` parameter flows directly into the SQL query via f-string interpolation without validation.

## Fix

Validate the `field` parameter against a whitelist of allowed column names before interpolation:

```python
from customers.models import Customer

ALLOWED_SEARCH_FIELDS = {'first_name', 'last_name', 'email', 'phone'}

def raw_customer_search(tenant_id, term, field):
    if field not in ALLOWED_SEARCH_FIELDS:
        raise ValueError(f"Invalid search field: {field}")
    
    sql = (
        "SELECT * FROM customers_customer "
        "WHERE tenant_id = %s "
        f"AND {field} ILIKE %s"
    )
    return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])
```

Alternatively, use Django ORM to avoid raw SQL entirely:

```python
from customers.models import Customer

def raw_customer_search(tenant_id, term, field):
    allowed_fields = {'first_name', 'last_name', 'email', 'phone'}
    if field not in allowed_fields:
        raise ValueError(f"Invalid search field: {field}")
    
    filter_kwargs = {f"{field}__icontains": term}
    return Customer.objects.filter(tenant_id=tenant_id, **filter_kwargs)
```

## Explanation

SQL column names cannot be parameterized using standard parameter placeholders like `%s`—they must be identifiers in the query text. The fix enforces a whitelist of allowed field names, validating user input before interpolation. Only the search `term` value remains safely parameterized. The ORM alternative is preferred because it eliminates raw SQL and delegates column resolution to the framework.
