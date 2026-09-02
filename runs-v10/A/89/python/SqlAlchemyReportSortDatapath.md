## Verdict

**Confirmed**: SQL injection via unsanitized ORDER BY clause.

## Source

The vulnerability is in `report_repository.py`, line 9:

```python
f"ORDER BY {sort}"
```

The `sort` parameter originates from untrusted user input (`request.args.get("sort", ...)` in the controller) and flows through the service layer unchanged. It is directly interpolated into the SQL query string via an f-string, allowing an attacker to inject arbitrary SQL.

The preceding WHERE clause parameters (`account_id`, `status`) are safely parameterized using named placeholders (`:account_id`, `:status`), but the ORDER BY clause bypasses parameterization.

## Fix

Validate the `sort` parameter against a whitelist of allowed column names before using it in the query. In `report_repository.py`:

```python
from sqlalchemy import text


ALLOWED_SORT_COLUMNS = {"id", "status", "total_cents", "created_at"}


def fetch_report_rows(session, account_id, status, sort):
    if sort not in ALLOWED_SORT_COLUMNS:
        sort = "created_at"  # or raise an exception for strict validation
    
    statement = text(
        "SELECT id, status, total_cents, created_at "
        "FROM invoices "
        "WHERE account_id = :account_id AND status = :status "
        f"ORDER BY {sort}"
    )
    return session.execute(statement, {"account_id": account_id, "status": status})
```

## Explanation

ORDER BY expressions in SQL cannot be parameterized in the standard way that WHERE clause values are. The fix is to validate that the `sort` parameter matches one of the columns the application allows sorting by. The whitelist must contain only column names that are safe to use in ORDER BY (typically the columns returned in the SELECT list).

This ensures the attacker cannot inject SQL operators, subqueries, or other malicious syntax through the sort parameter, even though the value is still interpolated into the query string — it can only be one of the predetermined safe column names.
