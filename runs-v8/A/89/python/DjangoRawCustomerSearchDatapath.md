## Verdict
SQL Injection via unparameterized column name. The `field` parameter is directly interpolated into the SQL query using an f-string on line 8, bypassing parameterization and allowing an attacker to inject arbitrary SQL clauses.

## Source
```python
def raw_customer_search(tenant_id, term, field):
    sql = (
        "SELECT * FROM customers_customer "
        "WHERE tenant_id = %s "
        f"AND {field} ILIKE %s"
    )
    return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])
```

The vulnerability: `field` is user-controlled and appears directly in the SQL query string via f-string interpolation, not as a parameterized placeholder.

## Fix
```python
from customers.models import Customer
from django.db.models import Q

def raw_customer_search(tenant_id, term, field):
    allowed_fields = {'name', 'email', 'phone', 'address'}
    if field not in allowed_fields:
        raise ValueError(f"Invalid search field: {field}")
    
    query = Q(tenant_id=tenant_id)
    query &= Q(**{f'{field}__icontains': term})
    return Customer.objects.filter(query)
```

## Explanation
Column names cannot be parameterized in SQL (they are identifiers, not values), so they must be validated against an allowlist. The fix replaces the raw SQL with Django's ORM query builder, which eliminates the injection surface entirely. The `__icontains` lookup provides case-insensitive substring matching equivalent to `ILIKE %term%`. The field name is validated against an explicit allowlist before being used in the query, and the term value remains properly parameterized by Django's ORM.
