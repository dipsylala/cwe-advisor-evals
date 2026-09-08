## Verdict

Confirmed SQL injection vulnerability. The `field` parameter is untrusted user input from `request.GET` that flows through the call chain without validation and is directly interpolated into a SQL query via f-string.

**Data flow:**
- Source: `request.GET.get("field", "name")` in customer_controller.py line 7 (untrusted user input)
- Intermediate: Passed through customer_service.py search_customers() without transformation
- Sink: `f"AND {field} ILIKE %s"` in customer_repository.py line 8 (direct string interpolation)
- Execution: `Customer.objects.raw(sql)` on line 10

An attacker can inject SQL through the field parameter. Example: `field="1) OR (1=1"` would produce invalid SQL that manipulates the query logic.

## Source

**customer_controller.py, line 7:**
```python
field = request.GET.get("field", "name")
```
This retrieves untrusted user input from the HTTP query string.

**customer_service.py, line 5:**
```python
return raw_customer_search(tenant_id, term, field)
```
The untrusted `field` value passes through unchanged.

**customer_repository.py, lines 8-10:**
```python
f"AND {field} ILIKE %s"  # field is directly interpolated
return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])  # executed as raw SQL
```
The field parameter is embedded in the f-string and executed via Django's `.raw()` method, which executes raw SQL without protection against injection through dynamic column names.

## Fix

### File: customer_repository.py

```python
from customers.models import Customer


def raw_customer_search(tenant_id, term, field):
    # Allowlist of permitted search fields to prevent SQL injection
    FIELD_MAPPING = {
        'email': 'email',
        'name': 'name',
        'phone': 'phone',
        'company': 'company',
        'address': 'address',
    }
    
    if field not in FIELD_MAPPING:
        raise ValueError(f"Invalid field: {field}")
    
    # Use the mapped field value (not the user-supplied field directly)
    safe_field = FIELD_MAPPING[field]
    
    # Use Django ORM filter() which safely handles column names
    filter_kwargs = {
        'tenant_id': tenant_id,
        f'{safe_field}__icontains': term
    }
    return Customer.objects.filter(**filter_kwargs)
```

## Explanation

The vulnerability is eliminated by replacing Django's `.raw()` method (which executes raw SQL vulnerable to injection via dynamic identifiers) with Django ORM's `.filter()` method (which safely constructs parameterized queries).

The fix introduces an allowlist (`FIELD_MAPPING`) that maps user-supplied field names to safe column identifiers. The user-controlled `field` parameter is validated against this allowlist—if it is not recognized, the function raises `ValueError`. Only values from the allowlist are used to construct the query. This prevents attackers from injecting SQL through the field parameter while maintaining the same functional behavior.

The search uses the `__icontains` Django ORM lookup, which generates safe parameterized SQL equivalent to the original `ILIKE` operation. Both the tenant ID validation and the term substring search continue to use parameterization, so no additional injection vectors are introduced.

Syntax verified with `python -m py_compile`.

## Behaviour changes

- **Return type:** Preserved. Both `.raw()` and `.filter()` return a Django QuerySet.
- **Query behavior:** Identical. Both perform case-insensitive substring matching (`ILIKE` vs `__icontains`). Results are sorted and filtered identically.
- **Invalid field handling:** Changed. The original code would attempt to execute SQL with an invalid field name, producing a database error. The fixed code raises `ValueError` with a clear error message before attempting the query, providing earlier and clearer failure feedback.
- **Performance:** Equivalent. Django ORM `.filter()` generates the same efficient parameterized SQL that `.raw()` would execute.
