## Verdict
This is a valid SQL injection vulnerability. The `field` parameter originates from untrusted user input (`request.GET.get("field", "name")` in customer_controller.py) and flows through customer_service.py to customer_repository.py, where it is directly interpolated into the SQL query string at line 8 using an f-string. SQL parameter binding is applied only to `tenant_id` and `term`, not to the column name.

## Source
The vulnerability originates in customer_controller.py line 7, where `field` is read from the query string without validation and passed through the call chain to the vulnerable function. In customer_repository.py line 8, the untrusted `field` value is interpolated directly into the SQL string: `f"AND {field} ILIKE %s"`.

## Fix
```python
from customers.models import Customer


# Whitelist of allowed column names
ALLOWED_SEARCH_FIELDS = {'name', 'email', 'phone', 'address'}


def raw_customer_search(tenant_id, term, field):
    # Validate field against whitelist to prevent SQL injection
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
Column names and table identifiers cannot be parameterized in SQL the way values can. The fix uses a whitelist approach: define an explicit set of allowed column names (`ALLOWED_SEARCH_FIELDS`) and validate the user-supplied `field` against this list. If the field is not in the whitelist, it defaults to 'name'. This prevents an attacker from injecting arbitrary SQL syntax through the field parameter. The `%s` placeholders for `tenant_id` and `term` remain parameterized, protecting against value-based injection.
