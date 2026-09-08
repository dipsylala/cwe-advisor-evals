## Verdict

Confirmed - exploitable SQL injection via unvalidated column-name interpolation.

## Source

`request.GET.get("field", "name")` in `customer_controller.py` (`customer_search_endpoint`). This is a fully attacker-controlled query-string parameter.

Data flow:
1. `customer_controller.py`: `field = request.GET.get("field", "name")`, passed to `search_customers(tenant_id, term, field)`.
2. `customer_service.py`: `search_customers` forwards `field` unchanged to `raw_customer_search(tenant_id, term, field)`.
3. `customer_repository.py` (sink, line 10): `field` is spliced into the SQL text with an f-string - `f"AND {field} ILIKE %s"` - then executed via `Customer.objects.raw(sql, [tenant_id, f"%{term}%"])`.

`term` reaches the database safely, as a bound `%s` parameter. `field` does not: it occupies an identifier position (a column name in the `WHERE` clause), which the DB-API placeholder mechanism cannot bind - a placeholder stands in for a value, not for query structure. Because `field` is concatenated into the SQL text with no allowlist or escaping, a request such as `?field=1;DROP TABLE customers_customer--` (or a boolean/UNION-based payload) is executed as written. This is CWE-89 in its identifier-injection form.

**Sink contract** (`Customer.objects.raw()`):
- Returns: a `RawQuerySet`, iterated by the controller via `list(...)`.
- Discards: nothing beyond what the original code already discards.
- Implicit arguments: none - only `sql` and the bound params list are passed.
- Failure behaviour: raises `django.db.utils.DatabaseError` (or a subclass) on invalid SQL; nothing downstream currently expects or handles that.

## Fix

### File: customer_repository.py

```python
from customers.models import Customer

# Map of caller-supplied search field names to the actual database columns
# they are permitted to search. Only these columns are ever interpolated
# into the SQL text; the raw `field` value from the request is never used
# directly. Adjust the keys/values to match the real searchable columns on
# Customer if they differ from this starting set.
ALLOWED_SEARCH_FIELDS = {
    "name": "name",
    "email": "email",
    "phone": "phone",
}


def raw_customer_search(tenant_id, term, field):
    column = ALLOWED_SEARCH_FIELDS.get(field)
    if column is None:
        raise ValueError(f"Unsupported search field: {field}")
    sql = (
        "SELECT * FROM customers_customer "
        "WHERE tenant_id = %s "
        f"AND {column} ILIKE %s"
    )
    return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])
```

## Explanation

`field` selects a column name, not a value, so it can never be passed as a bound `%s` parameter - the fix already in place for `term` does not apply to it. The remediation is an allowlist substitution rather than escaping or validation-then-reuse: `field` is looked up in `ALLOWED_SEARCH_FIELDS`, a fixed, server-controlled map, and the SQL is built from the map's value (`column`), never from the caller's original string. An unrecognized `field` fails closed with `ValueError` before any SQL is built, rather than being passed through to the database. This removes the injection point entirely: whatever the request sends for `field`, only one of the three hardcoded column names (or a rejection) ever reaches the query text.

`ALLOWED_SEARCH_FIELDS`'s three entries (`name`, `email`, `phone`) are an assumption - the `Customer` model's actual searchable columns are not visible in this call chain (`customers.models` is not included among the traced files). The set should be adjusted to the model's real fields before this ships; using an allowlist narrower than the true set only rejects otherwise-valid searches, while using one wider than the true set reproduces the original `DatabaseError`-on-bad-column failure mode for a request against a non-existent field.

## Behaviour changes

- A `field` value outside the allowlist now raises `ValueError` immediately, instead of being concatenated into the SQL and either causing a `DatabaseError` (unknown column) or executing as injected SQL (malicious payload). `customer_controller.py` does not currently catch this; it should be updated to translate `ValueError` into a 400-style response, but that change is outside this file's scope since `customer_controller.py` was not part of the vulnerable data flow.
- The default (`field` omitted, defaulting to `"name"`) and any request for `email` or `phone` behave exactly as before: same SQL shape, same bound `term` parameter, same `RawQuerySet` return value.
- `ALLOWED_SEARCH_FIELDS`'s contents are an assumption (see Explanation) and should be reconciled with the real `Customer` model fields.
- Check performed: `python -m py_compile` on the fixed file in isolation - no syntax errors. `Customer.objects.raw`, `ALLOWED_SEARCH_FIELDS.get`, and dict literal usage are all either unchanged from the original or standard-library/Django-ORM constructs already in use; no new external names were introduced.
