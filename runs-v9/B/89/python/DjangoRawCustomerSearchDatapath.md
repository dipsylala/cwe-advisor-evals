## Verdict

Exploitable. CWE-89 (SQL Injection), confidence high.

- Location: `customer_repository.py:8-9`, sink at `customer_repository.py:10`
- Assumption: the `Customer` model's exact column list is not available in this call chain, so the allowlist below assumes `name`, `email`, and `phone` are legitimate searchable columns (matching the existing `field="name"` default). The repository owner should adjust the mapping to the model's real field set.

## Source

- Source: `request.GET.get("field", "name")` in `customer_search_endpoint` (`customer_controller.py:7`) - fully attacker-controlled query string parameter, no validation applied at the boundary.
- Flow: `field` passes unchanged through `customer_search_endpoint` -> `search_customers` (`customer_service.py:5`, pure passthrough) -> `raw_customer_search(tenant_id, term, field)` (`customer_repository.py:4`).
- Sink: `customer_repository.py:8`, where `field` is interpolated directly into the SQL text via an f-string (`f"AND {field} ILIKE %s"`), then executed by `Customer.objects.raw(sql, [...])` at line 10 - a documented Django raw-SQL taint sink.
- Note: `tenant_id` and `term` are already bound correctly as `%s` placeholders passed through the `raw()` params list; they are not part of this finding. `field` is used as a column identifier, which placeholders cannot bind - it requires allowlist validation, not parameterization.

## Fix

Vulnerable code (`customer_repository.py`):

```python
from customers.models import Customer


def raw_customer_search(tenant_id, term, field):
    sql = (
        "SELECT * FROM customers_customer "
        "WHERE tenant_id = %s "
        f"AND {field} ILIKE %s"  # field is attacker-controlled and unvalidated
    )
    return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])
```

Fixed code:

```python
from customers.models import Customer

SEARCHABLE_FIELDS = {
    "name": "name",
    "email": "email",
    "phone": "phone",
}


def raw_customer_search(tenant_id, term, field):
    column = SEARCHABLE_FIELDS.get(field, SEARCHABLE_FIELDS["name"])
    sql = (
        "SELECT * FROM customers_customer "
        "WHERE tenant_id = %s "
        f"AND {column} ILIKE %s"
    )
    return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])
```

## Explanation

`field` selects which column the search runs against, and a column name cannot be bound as a query parameter - only the primary defence (parameterization) already correctly applied to `tenant_id` and `term` does not cover it. The fix adds a server-side allowlist (`SEARCHABLE_FIELDS`) that maps each accepted request value to its own literal column name; the SQL is then built from the map's value, never from the caller's string, so no request input reaches the query text unvalidated. An unrecognized or malicious `field` value (e.g. `id=1 OR 1=1--`, or a subquery) falls through to the safe `"name"` default instead of being interpolated. `term` and `tenant_id` are untouched, preserving the existing parameter binding and the `Customer.objects.raw()` return contract (a `RawQuerySet`, consumed unchanged by `search_customers` and `customer_search_endpoint`).

## Behaviour changes

- Request values for `field` outside `{name, email, phone}` no longer raise a database error or execute arbitrary SQL - they silently fall back to searching `name`. This is a deliberate narrowing to close the injection; if the API contract requires rejecting unknown `field` values with a 4xx response instead of silently defaulting, add that check in `customer_controller.py` before calling `search_customers`.
- The concrete set of allowed columns (`name`, `email`, `phone`) is an assumption (see Verdict) - it must be reconciled with the real `Customer` model fields before this fix is merged.
- No change to `tenant_id`/`term` handling, return type, or error behaviour otherwise; the sink contract (a `RawQuerySet` over `customers_customer`) is preserved.
