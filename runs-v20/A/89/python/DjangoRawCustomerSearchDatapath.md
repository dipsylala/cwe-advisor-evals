## Verdict

Confirmed. `raw_customer_search` builds a raw SQL string with Django's `Customer.objects.raw()` and binds `tenant_id` and the search term correctly as `%s` parameters, but the `field` argument — which selects which column to search — is interpolated directly into the SQL text via an f-string (`f"AND {field} ILIKE %s"`). A column name cannot be passed as a bound parameter, so this identifier position is unescaped. Since `field` traces back to `request.GET.get("field", "name")` in `customer_controller.py`, a caller can supply any string as `field` and inject arbitrary SQL into the query (e.g. closing the identifier position and appending additional clauses, subqueries, or `UNION SELECT` statements), fully bypassing the `tenant_id` scoping.

## Source

`request.GET.get("field", "name")` in `customer_controller.py`, passed unchanged through `search_customers()` in `customer_service.py` into `raw_customer_search(tenant_id, term, field)` in `customer_repository.py`, where it reaches the SQL sink at the `f"AND {field} ILIKE %s"` line.

## Fix

### File: customer_repository.py
```python
from customers.models import Customer

# Server-owned allowlist: maps the external "field" key to the actual
# database column it is permitted to search. Only these keys may ever
# reach the SQL text; anything else falls back to the default column.
ALLOWED_SEARCH_FIELDS = {
    "name": "name",
    "email": "email",
    "phone": "phone",
}


def raw_customer_search(tenant_id, term, field):
    column = ALLOWED_SEARCH_FIELDS.get(field, ALLOWED_SEARCH_FIELDS["name"])
    sql = (
        "SELECT * FROM customers_customer "
        "WHERE tenant_id = %s "
        f"AND {column} ILIKE %s"
    )
    return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])
```

## Explanation

The vulnerability is not in the two already-bound values (`tenant_id`, the LIKE term) — it is that a column/identifier cannot be parameterized with `%s` at all, so whatever string reaches that position becomes literal SQL text. Escaping quotes in `field` or trying to bind it as another `%s` argument (the documented trap) would not help: `%s` binding only produces safely-quoted string *literals*, and a literal can never stand in for a column name syntactically, while quote-escaping does nothing to stop an attacker from injecting unquoted SQL keywords, operators, or a closing paren followed by additional clauses.

The correct fix is to stop treating `field` as data that flows into the query text at all. Instead, `field` is used only as a *key* to look up a column name from `ALLOWED_SEARCH_FIELDS`, a fixed, server-owned dictionary. Only the literal column names the application itself defined (`name`, `email`, `phone`) can ever be substituted into the SQL string; any external value that isn't a known key silently falls back to the default `name` column rather than being rejected with an error that could leak information or be used to probe valid keys. This preserves every required behavior: `tenant_id` stays bound as a parameter, the search term stays a bound LIKE value, the default `name` field continues to work when no `field` is supplied, and the approved alternate fields (`email`, `phone`) search the same `customers_customer` table without any raw identifier ever being accepted from the request. Because the map is closed and defined in code, no scanner-visible regex or allowlist pattern is needed — the set of reachable column names is fixed at author time, not computed from input.
