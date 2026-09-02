## Verdict

Confirmed. SQL injection via the `sort` parameter in the `ORDER BY` clause.

## Source

`report_controller.py` line 7: `sort = request.args.get("sort", "created_at")` — the `sort` value comes directly from the HTTP request's query string, fully attacker-controlled, and passed unchanged through `report_service.run_report` into `report_repository.fetch_report_rows`.

## Fix

```python
from sqlalchemy import text

_ALLOWED_SORT_COLUMNS = {
    "id",
    "status",
    "total_cents",
    "created_at",
}

_DEFAULT_SORT_COLUMN = "created_at"


def _resolve_sort_clause(sort):
    """Map a user-supplied sort token to a safe, literal ORDER BY clause.

    Only ever returns a value drawn from _ALLOWED_SORT_COLUMNS; never
    echoes attacker input back into the SQL string.
    """
    if sort is None:
        return _DEFAULT_SORT_COLUMN

    column = sort.strip()
    direction = ""
    if column.lower().endswith(" asc"):
        column, direction = column[:-4].strip(), " ASC"
    elif column.lower().endswith(" desc"):
        column, direction = column[:-5].strip(), " DESC"

    if column not in _ALLOWED_SORT_COLUMNS:
        column, direction = _DEFAULT_SORT_COLUMN, ""

    return f"{column}{direction}"


def fetch_report_rows(session, account_id, status, sort):
    order_by = _resolve_sort_clause(sort)
    statement = text(
        "SELECT id, status, total_cents, created_at "
        "FROM invoices "
        "WHERE account_id = :account_id AND status = :status "
        f"ORDER BY {order_by}"
    )
    return session.execute(statement, {"account_id": account_id, "status": status})
```

## Explanation

`account_id` and `status` are already safe: they are passed as bound parameters (`:account_id`, `:status`) via SQLAlchemy's `text()` construct, so the driver escapes them correctly. `sort`, however, is spliced straight into the SQL text with an f-string on line 9 (`f"ORDER BY {sort}"`), because SQL does not allow column/direction identifiers to be supplied as bind parameters — they have to appear as literal SQL text. Since `sort` originates unchanged from `request.args.get("sort", ...)` in the controller, an attacker can set the `sort` query parameter to arbitrary SQL (e.g. a subquery, `UNION`, or a boolean/time-based blind-injection payload appended after a valid column name) and have it executed verbatim as part of the statement.

The fix keeps the parameterized `WHERE` clause untouched and instead closes the gap the only way ORDER BY safely can be closed: never let request-controlled text reach the SQL string. `_resolve_sort_clause` treats `sort` purely as a *lookup key*, not as text to embed — it strips an optional trailing `asc`/`desc` direction token, checks the remaining column name against a fixed allowlist (`_ALLOWED_SORT_COLUMNS`, drawn from the columns already selected by the query), and falls back to a safe default column with no direction whenever the input doesn't match. The string that is ultimately interpolated into the SQL is always one of the hardcoded allowlist values or the default — never a transformation or substring of the original attacker input — so no attacker-supplied character sequence can reach the query text, regardless of how the value is mangled or encoded.
