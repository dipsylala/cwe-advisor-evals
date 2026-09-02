## Verdict

Confirmed. `raw_customer_search` builds a raw SQL string where the `field` parameter is spliced directly into the query text via an f-string (`f"AND {field} ILIKE %s"`), rather than being passed as a bound parameter. `tenant_id` and `term` are correctly parameterized through `%s` placeholders and the `params` list, but `field` is not — it is used as a column name, and Django's `raw()` parameter binding cannot bind identifiers (column/table names), only value literals. An attacker who controls the `field` query string argument controls a fragment of SQL syntax placed directly into the `WHERE` clause.

## Source

`request.GET.get("field", "name")` in `customer_controller.py` (`customer_search_endpoint`), line 7. This is unauthenticated, attacker-controlled HTTP query-string input. It flows unmodified through `search_customers(tenant_id, term, field)` in `customer_service.py` (a pure pass-through) into `raw_customer_search(tenant_id, term, field)` in `customer_repository.py`, where it reaches the sink at line 8: `f"AND {field} ILIKE %s"` inside the raw SQL string passed to `Customer.objects.raw(sql, [tenant_id, f"%{term}%"])`.

Example exploit: a request to `?field=1=1;DROP TABLE customers_customer;--&q=x` (or, more realistically for a UNION/boolean-based read, `?field=name)) UNION SELECT ... --`) is interpolated verbatim into the SQL text before it reaches the database, giving the attacker query structure control — not just data control.

## Fix

Since `field` selects a column name rather than a value, it cannot be parameterized with `%s` — the correct remediation is to validate it against an explicit allowlist of the columns the search is actually meant to support, and reject anything else before the SQL string is built.

Replace the body of `raw_customer_search` in `customer_repository.py`:

```python
from customers.models import Customer

ALLOWED_SEARCH_FIELDS = {"name", "email", "phone", "company"}


def raw_customer_search(tenant_id, term, field):
    if field not in ALLOWED_SEARCH_FIELDS:
        raise ValueError(f"Unsupported search field: {field!r}")

    sql = (
        "SELECT * FROM customers_customer "
        "WHERE tenant_id = %s "
        f"AND {field} ILIKE %s"
    )
    return Customer.objects.raw(sql, [tenant_id, f"%{term}%"])
```

`ALLOWED_SEARCH_FIELDS` should be set to the actual set of `customers_customer` columns the UI exposes as searchable — adjust the membership to match the real schema. Because the set is a fixed, hardcoded allowlist checked with `in` before the f-string interpolation runs, `field` can no longer carry attacker-chosen SQL syntax into the query: any value outside the allowlist is rejected with a `ValueError` before `sql` is constructed.

Prefer raising on an invalid field (as above) over silently substituting a default — silently falling back to `"name"` would mask a client bug or a probing attack as a normal, empty-looking search result. If the caller (`customer_service.py` / `customer_controller.py`) needs a friendlier HTTP response than an unhandled 500, catch `ValueError` in `customer_search_endpoint` and return a 400 with a validation message; that is a UX choice layered on top of the fix, not a substitute for the allowlist check itself.

Do not attempt to "sanitize" `field` by stripping characters or using a regex allowlist pattern (e.g. `^[a-zA-Z_]+$`) instead of an explicit set — a pattern still accepts any syntactically valid identifier, including real column names the application never intended to expose for searching (password hashes, internal flags, other tenants' foreign keys), which is a narrower but still real information-disclosure risk. An explicit, closed set of expected values is the correct control for a column-name parameter.

## Explanation

Parameterized queries close SQL injection for *values* because the database driver sends the parameter separately from the query text and never interprets its contents as SQL syntax. That mechanism does not extend to *identifiers* — column names, table names, `ORDER BY` directions — because the SQL standard has no placeholder syntax for those positions; a driver-level bind parameter can only ever represent a literal value in an expression, not a piece of query structure. This is why `tenant_id = %s` and `ILIKE %s` are safe as written, while `f"AND {field} ILIKE %s"` is not: `field` occupies an identifier position, so parameter binding was never available to it in the first place, regardless of how carefully the rest of the query uses `%s`.

The allowlist works because it converts an open-ended attacker-controlled string into a closed choice between values the application author already trusts to be safe column names. Checking membership before string interpolation, rather than after, ensures the untrusted value never reaches the point where it is treated as code — the `ValueError` is raised while `field` is still just a string being compared, not yet part of a SQL statement handed to the database.
