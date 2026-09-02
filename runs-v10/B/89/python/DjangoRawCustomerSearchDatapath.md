## Verdict

Confirmed: SQL Injection via dynamic column name. User-controlled `field` parameter is directly interpolated into SQL query without validation.

## Source

**customer_controller.py, line 7:**

```python
field = request.GET.get("field", "name")
```

Untrusted user input passed through `search_customers()` to `raw_customer_search()`.

**customer_repository.py, line 8:**

```python
f"AND {field} ILIKE %s"
```

Field is interpolated via f-string directly into SQL statement, bypassing parameterization.

## Fix

Validate `field` against an allowlist of permitted column names before use:

```python
from customers.models import Customer

# Allowlist of permitted search fields
ALLOWED_SEARCH_FIELDS = {"name", "email", "phone"}

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

SQL injection via dynamic identifiers (column names) cannot be prevented by parameterization alone—identifiers are structural, not data values. The original code allowed an attacker to inject SQL through the `field` parameter by constructing a query like `... AND name) OR 1=1 -- ILIKE %s`, which succeeds regardless of parameterization.

The fix validates `field` against a hardcoded allowlist before using it in the query. Only known-safe column names are permitted; any invalid request raises `ValueError`. The `term` parameter was already properly parameterized and requires no change.

## Behaviour changes

- **New**: Invalid `field` values now raise `ValueError` instead of being incorporated into the query.
- **Query execution**: Only valid field names in the allowlist produce results; others fail with an error.
- **Attack surface**: Injection through `field` is eliminated by constraining the value to a fixed set of known-safe identifiers.
