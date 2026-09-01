## Verdict

Exploitable.

## Source

The `field` parameter passed to `raw_customer_search()` at line 4 is untrusted, caller-controlled input.

## Fix

**Vulnerable code:**
```python
def raw_customer_search(tenant_id, term, field):
    sql = (
        "SELECT * FROM customers_customer "
        "WHERE tenant_id = %s "
        f"AND {field} ILIKE %s"  # Unparameterized field name
    )
    return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])
```

**Fixed code:**
```python
from customers.models import Customer

# Allowlist of searchable fields
ALLOWED_SEARCH_FIELDS = {'email', 'name', 'phone', 'address'}

def raw_customer_search(tenant_id, term, field):
    # Validate field against allowlist before using in query
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

SQL Injection via dynamic column names cannot be prevented by parameterization alone—SQL placeholders bind data values, not query structure. Column names must be restricted to a predefined allowlist of safe identifiers. The fix defines `ALLOWED_SEARCH_FIELDS` as a server-controlled set of permitted field names, validates the caller-supplied `field` parameter against this allowlist at the entry point, and raises an exception if an invalid field is requested. Once validated, the value is guaranteed to be one of the known-safe identifiers and is safe to interpolate into the query. The `term` parameter remains correctly parameterized (passed as a separate argument to `.raw()`), preserving that layer of defense.

## Behaviour changes

None. The function signature and return type remain unchanged. Callers passing invalid field names will now receive a `ValueError` instead of executing an injected query, which is the correct security-oriented behaviour. Callers passing valid field names experience no change.
