## Verdict

Exploitable. CWE-89 (SQL Injection), high confidence.

- **Source**: `report_controller.py:7` - `sort = request.args.get("sort", "created_at")`, an attacker-controlled query-string parameter with no default fallback protection once a value is supplied.
- **Sink**: `report_repository.py:9` - `f"ORDER BY {sort}"`, interpolated directly into the SQL text passed to `session.execute()`.
- **Call chain**: `report_controller.report_endpoint()` -> `report_service.run_report()` -> `report_repository.fetch_report_rows()`. `run_report` passes `sort` through unchanged; it performs no validation of its own.

## Source

`request.args.get("sort", "created_at")` in `report_controller.py:7`. `account_id` and `status` follow the same path but are bound as SQLAlchemy `text()` parameters (`:account_id`, `:status`) at the sink, so they are not vulnerable. `sort` is the only value that reaches the query unbound.

## Fix

Vulnerable code (`report_repository.py`):

```python
from sqlalchemy import text


def fetch_report_rows(session, account_id, status, sort):
    statement = text(
        "SELECT id, status, total_cents, created_at "
        "FROM invoices "
        "WHERE account_id = :account_id AND status = :status "
        f"ORDER BY {sort}"  # sort is attacker-controlled, interpolated unbound
    )
    return session.execute(statement, {"account_id": account_id, "status": status})
```

Fixed code (`report_repository.py`):

```python
from sqlalchemy import text

# ORDER BY targets cannot be bound as query parameters, so the sort key is
# resolved through a server-side allowlist keyed on the columns this query
# actually exposes. The value used downstream is always the map's canonical
# fragment, never the caller-supplied string.
ALLOWED_SORTS = {
    "id": "id ASC",
    "id_desc": "id DESC",
    "status": "status ASC",
    "status_desc": "status DESC",
    "total_cents": "total_cents ASC",
    "total_cents_desc": "total_cents DESC",
    "created_at": "created_at ASC",
    "created_at_desc": "created_at DESC",
}


def fetch_report_rows(session, account_id, status, sort):
    try:
        sort_clause = ALLOWED_SORTS[sort]
    except KeyError:
        raise ValueError(f"unsupported sort value: {sort!r}")

    statement = text(
        "SELECT id, status, total_cents, created_at "
        "FROM invoices "
        "WHERE account_id = :account_id AND status = :status "
        f"ORDER BY {sort_clause}"
    )
    return session.execute(statement, {"account_id": account_id, "status": status})
```

## Explanation

`ORDER BY` targets are structure, not data, so SQLAlchemy's `text()` bind parameters cannot cover them - the fix has to close this gap with allowlisting rather than parameterization. `ALLOWED_SORTS` enumerates the only sort expressions the query supports, built from the columns the `SELECT` list actually exposes. The lookup treats `sort` as a key into that fixed map rather than as input to sanitize and reuse: the string that reaches the f-string and the SQL text is always one of the map's own canonical fragments, never the caller's value, so no attacker-controlled substring can reach the query regardless of what `sort` contains. A value outside the map raises before any SQL is built, so an unrecognized sort key can no longer be forwarded to the database in any form. `account_id` and `status` were already safe (bound via `:account_id`/`:status`) and are unchanged.

## Behaviour changes

- An unrecognized `sort` value now raises `ValueError` before the query is built, where previously it was forwarded straight into the SQL text (producing either an attacker-controlled query or a database-level syntax error depending on the payload). Callers that relied on arbitrary or malformed sort strings silently reaching the database will now see this exception instead; `report_service.run_report` and `report_controller.report_endpoint` do not currently catch it, so an invalid `sort` query-string value will surface as an unhandled exception at the controller boundary rather than a 200 response - the calling layer should translate `ValueError` to a 400 response if that behavior is not desired.
- The allowlisted values (`id`, `status`, `total_cents`, `created_at`, and their `_desc` variants) were inferred from the columns already present in the `SELECT` list, since neither the controller nor service layer documents the supported sort keys. If the API previously accepted other sort keys or compound expressions (e.g. multi-column sort), those are no longer accepted and will need to be added to `ALLOWED_SORTS` explicitly.
- Default behavior for `sort="created_at"` (the controller's default) is functionally unchanged: `ORDER BY created_at` and `ORDER BY created_at ASC` are equivalent, since `ASC` is SQL's default sort direction.
