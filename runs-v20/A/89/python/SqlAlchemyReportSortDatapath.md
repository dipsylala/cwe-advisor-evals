## Verdict

Confirmed. `fetch_report_rows` builds its SQL with SQLAlchemy `text()` and correctly binds `account_id` and `status` as parameters, but the `sort` value is spliced into the `ORDER BY` clause with an f-string before the statement is built. Any value reaching `sort` is interpreted as raw SQL syntax rather than data.

## Source

`report_controller.py`, `report_endpoint`: `sort = request.args.get("sort", "created_at")` takes the sort key directly from the request's query string, defaulted but otherwise unvalidated. It is passed unchanged through `report_service.run_report` into `report_repository.fetch_report_rows`, where it is interpolated into the SQL text at line 11 (`f"ORDER BY {sort}"`). A request such as `?sort=id;--` or `?sort=(SELECT ...)` or a boolean/time-based subquery in place of a column name reaches the database verbatim, since bind parameters cannot represent identifiers like column names or the `ASC`/`DESC` keyword, so the taint is never neutralized.

## Fix

### File: report_repository.py
```python
from sqlalchemy import text

_SORTABLE_COLUMNS = {
    "id": "id",
    "status": "status",
    "total_cents": "total_cents",
    "created_at": "created_at",
}

_SORT_DIRECTIONS = {
    "asc": "ASC",
    "desc": "DESC",
}


def _resolve_sort(sort):
    parts = (sort or "").split()
    column_key = parts[0].lower() if parts else "created_at"
    direction_key = parts[1].lower() if len(parts) > 1 else "asc"

    column = _SORTABLE_COLUMNS.get(column_key, _SORTABLE_COLUMNS["created_at"])
    direction = _SORT_DIRECTIONS.get(direction_key, "ASC")

    return f"{column} {direction}"


def fetch_report_rows(session, account_id, status, sort):
    order_by = _resolve_sort(sort)
    statement = text(
        "SELECT id, status, total_cents, created_at "
        "FROM invoices "
        "WHERE account_id = :account_id AND status = :status "
        f"ORDER BY {order_by}"
    )
    return session.execute(statement, {"account_id": account_id, "status": status})
```

## Explanation

SQL bind parameters can only stand in for literal values, never for identifiers such as column names or for keywords such as `ASC`/`DESC`, so the `ORDER BY` clause can never be fully parameterized the way `account_id` and `status` are. The fix keeps the interpolation but removes the attacker's ability to control what gets interpolated: `_resolve_sort` splits the incoming `sort` string into an optional column and direction, and looks each half up in a fixed dictionary of the only column names actually exposed by this report (`id`, `status`, `total_cents`, `created_at`) and the only two valid directions. Any input that doesn't match a known key - extra SQL, a comment sequence, a subquery, an unlisted column - falls back to the safe default (`created_at ASC`) rather than being echoed into the statement. Only the resulting fixed, known-safe string (e.g. `"created_at DESC"`) is ever placed into the f-string, so the value that reaches the database's `ORDER BY` clause is always one of the eight literal strings the application itself defines, never attacker-supplied text. This is an identifier allowlist scoped to a closed, application-defined set (the report's own selectable columns), not a general input-shape restriction, so it does not reject any legitimate value the caller could have meant.
