## Verdict
SQL injection vulnerability confirmed. The `field` parameter from user input flows unsafely into the SQL query via f-string interpolation without validation or parameterization.

## Source
```python
def raw_customer_search(tenant_id, term, field):
    sql = (
        "SELECT * FROM customers_customer "
        "WHERE tenant_id = %s "
        f"AND {field} ILIKE %s"  # Vulnerable: field is interpolated directly
    )
    return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])
```

The `field` parameter originates from untrusted user input via `request.GET.get("field", "name")` in `customer_controller.py` and flows through `customer_service.py` into `raw_customer_search()` where it is directly embedded into the SQL query using an f-string on line 8. This allows an attacker to inject arbitrary SQL by controlling the `field` parameter.

## Fix
```python
def raw_customer_search(tenant_id, term, field):
    # Whitelist allowed column names
    allowed_fields = {"name", "email", "phone"}
    if field not in allowed_fields:
        raise ValueError(f"Invalid field: {field}")
    
    sql = (
        "SELECT * FROM customers_customer "
        "WHERE tenant_id = %s "
        f"AND {field} ILIKE %s"
    )
    return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])
```

## Explanation
Column names cannot be parameterized in SQL (Django's `%s` placeholder only works for values), so the `field` parameter must be validated against a whitelist of allowed columns before interpolation. The fix defines a set of permitted field names and raises a `ValueError` if the user provides an unrecognized field. This prevents SQL injection while maintaining the query's functionality. The `term` parameter remains safely parameterized using Django's `%s` placeholder.
