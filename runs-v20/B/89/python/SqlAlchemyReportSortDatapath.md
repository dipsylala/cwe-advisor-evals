## Verdict

Confirmed - exploitable SQL injection via an unvalidated `ORDER BY` column identifier.

## Source

`report_controller.py`, `report_endpoint()`: `sort = request.args.get("sort", "created_at")` reads an attacker-controlled query-string parameter with no validation. It is passed unchanged through `run_report(session, account_id, status, sort)` in `report_service.py`, which forwards it unchanged to `fetch_report_rows(session, account_id, status, sort)` in `report_repository.py`.

Sink: `report_repository.py`, `fetch_report_rows()` - the `sort` value is spliced into the SQL text via an f-string, `f"ORDER BY {sort}"`, and that string becomes part of the `sqlalchemy.text()` statement executed by `session.execute()`. `account_id` and `status` are already bound as `:account_id`/`:status` parameters and are not affected. `sort` is never parameterized, so an attacker can submit `?sort=1;DROP TABLE invoices;--` or a UNION/boolean payload and have it execute as SQL structure rather than data.

Sink contract (`session.execute(statement, params)`):
- **Returns**: a SQLAlchemy `CursorResult`; the controller iterates it as `[dict(row) for row in rows]`.
- **Discards**: nothing beyond what the original code already discards.
- **Implicit arguments**: none - only the two bound parameters are passed, matching the original.
- **Failure behaviour**: today, a `sort` value that is not a valid column name reaches the database and raises at execute time (e.g. `ProgrammingError`/syntax error), propagating to the caller.

## Fix

A bind parameter cannot stand in for an identifier position (`ORDER BY <column>`), so this is not fixable by adding another `:param` placeholder - per the CWE-89 Python guidance, a dynamic identifier must be resolved through a server-side allowlist map, and the value used in the query must be the map's canonical value, never the caller-supplied string. `sort` selects among the four columns the query already selects (`id`, `status`, `total_cents`, `created_at`), so the fix maps the incoming value to one of those exact names and falls back to the existing default (`created_at`) for anything else.

### File: report_repository.py

```python
from sqlalchemy import text

ALLOWED_SORT_COLUMNS = {
    "id": "id",
    "status": "status",
    "total_cents": "total_cents",
    "created_at": "created_at",
}


def fetch_report_rows(session, account_id, status, sort):
    sort_column = ALLOWED_SORT_COLUMNS.get(sort, "created_at")
    statement = text(
        "SELECT id, status, total_cents, created_at "
        "FROM invoices "
        "WHERE account_id = :account_id AND status = :status "
        f"ORDER BY {sort_column}"
    )
    return session.execute(statement, {"account_id": account_id, "status": status})
```

## Explanation

`ALLOWED_SORT_COLUMNS` is a fixed, server-defined map from the permitted external names to the exact column identifiers already present in the `SELECT` list. `fetch_report_rows` looks the incoming `sort` value up in that map and uses the map's value (`sort_column`), not the caller's string, when building the `ORDER BY` clause - an unrecognized value can no longer reach the SQL text at all, it is replaced by the same `created_at` default the controller already used for a missing parameter. `account_id` and `status` were already correctly bound and are untouched. This closes the injection while keeping the query's shape, return value, and parameter binding identical to the original.

Verification performed: the fixed file was copied to a scratch location and checked with `python -m py_compile`, which completed with no errors (no separate SQLAlchemy/DB runtime was reachable in this environment). By hand: `ALLOWED_SORT_COLUMNS` and `sort_column` are the only new names, both defined in this file; `.get()` is a standard `dict` method; the call sites in `report_service.py` and `report_controller.py` pass `sort` positionally and are unchanged, since the function's signature and return value are unchanged.

## Behaviour changes

- A `sort` value outside `{id, status, total_cents, created_at}` (whether malicious or simply a typo/unsupported column) now silently falls back to sorting by `created_at` instead of reaching the database. Previously such a value either produced an SQL syntax/execution error (if not a valid identifier) or - if it happened to name a real, unintended column in the `invoices` table or another table-qualified identifier - silently sorted by that column. The allowlist removes both of those behaviors: no error propagates for a bad value, and only the four listed columns are reachable as sort targets. If the application needs an error surfaced for an invalid `sort` value (e.g. to return a 400 to the client) rather than a silent default, add that check in `report_controller.py` before calling `run_report`, since `report_repository.py` cannot distinguish "missing" from "invalid" once it only sees the final string.
- No other observable behavior (query results, column selection, parameter binding for `account_id`/`status`, return type) changes.
