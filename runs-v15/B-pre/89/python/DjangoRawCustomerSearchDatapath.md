## Verdict
Exploitable. Untrusted user input (`field` from `request.GET`) flows directly into the SQL query via f-string interpolation, allowing an attacker to inject SQL operators and manipulate query logic.

## Source
`customer_controller.py` line 7: `field = request.GET.get("field", "name")` - attacker-controlled via query parameter.

## Fix

**customer_repository.py:**

```python
from customers.models import Customer


# Define a whitelist of safe column names that can be searched
SEARCHABLE_FIELDS = {"name", "email", "phone"}


def raw_customer_search(tenant_id, term, field):
    # Validate field against allowlist; default to 'name' if invalid
    safe_field = field if field in SEARCHABLE_FIELDS else "name"
    
    sql = (
        "SELECT * FROM customers_customer "
        "WHERE tenant_id = %s "
        f"AND {safe_field} ILIKE %s"
    )
    return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])
```

**customer_controller.py:**

```python
from customer_service import search_customers


# Define allowlist of permitted search fields
SEARCHABLE_FIELDS = {"name", "email", "phone"}


def customer_search_endpoint(request):
    tenant_id = request.user.tenant_id
    term = request.GET.get("q", "")
    field = request.GET.get("field", "name")
    
    # Validate field against allowlist before passing downstream
    if field not in SEARCHABLE_FIELDS:
        field = "name"
    
    return {"customers": list(search_customers(tenant_id, term, field))}
```

## Explanation

The fix establishes an allowlist of permitted column names (`name`, `email`, `phone`) and validates the untrusted `field` parameter against it before interpolating into the SQL query. When the input does not match any safe value, it defaults to `name`. Since column names cannot be parameterized in SQL, validation against a server-controlled allowlist is the required defence. The allowlist is maintained at both the entry point (controller) and the sink (repository) to ensure consistent enforcement. The parameterized `%s` placeholders continue to protect the `term` parameter from injection.

## Behaviour changes

- Requests with `field` values outside the allowlist now default to searching the `name` column instead of executing a potentially malicious query.
- The search behavior is otherwise identical: same query structure, same parameter binding, same return type.
- A client explicitly passing an invalid field value receives results for the default field rather than an error or bypassed validation.
