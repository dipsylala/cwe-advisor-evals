## Verdict

Exploitable. The `field` parameter from the HTTP request is interpolated directly into the SQL query without validation or parameterization.

## Source

User input: `request.GET.get("field", "name")` in `customer_controller.py`, line 7, flows through `customer_service.py` to `customer_repository.py`.

## Fix

**Vulnerable code:**

```python
def raw_customer_search(tenant_id, term, field):
    sql = (
        "SELECT * FROM customers_customer "
        "WHERE tenant_id = %s "
        f"AND {field} ILIKE %s"  # <-- VULNERABLE: field is interpolated directly
    )
    return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])
```

**Fixed code:**

```python
from customers.models import Customer

# Define allowed column names - server-controlled, not user-supplied
ALLOWED_FIELDS = {
    'name': 'name',
    'email': 'email',
    'phone': 'phone',
    'address': 'address'
}

def raw_customer_search(tenant_id, term, field):
    # Map user input to allowlist; use safe default if unknown field
    validated_field = ALLOWED_FIELDS.get(field, 'name')
    
    sql = (
        "SELECT * FROM customers_customer "
        "WHERE tenant_id = %s "
        f"AND {validated_field} ILIKE %s"
    )
    return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])
```

## Explanation

The fix introduces an allowlist of permitted column names. Instead of using the user-supplied `field` parameter directly in the SQL string, the code now maps it to a canonical value from a server-controlled dictionary. An unknown field defaults to `'name'` rather than reaching the query. This approach prevents column-name injection because the query is constructed only from values the application defines, not from untrusted input. The `term` parameter remains safely parameterized via Django's `.raw()` method, which treats the list elements as data values, not SQL structure. The `f"%{term}%"` construction is safe because the percent signs are literal characters for the SQL `ILIKE` pattern, and the actual `term` value is passed to the database driver as a parameter.

## Behaviour changes

The function now returns only results matching fields in the `ALLOWED_FIELDS` dictionary. Any caller passing an undefined field name will receive results for the `name` field instead. This is a defensive change that prevents both injection and out-of-scope column access. To preserve caller control over field selection, the allowlist can be expanded to include additional safe columns, or the default fallback behavior can be changed to raise an exception for unknown fields - either approach keeps the injection surface closed.
