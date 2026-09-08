## Verdict

Exploitable. The `sort` parameter from user input (report_controller.py line 7) flows through report_service.py to report_repository.py, where it is interpolated directly into an SQL query string at line 9 without validation. An attacker can inject SQL by supplying a malicious sort parameter, e.g., `created_at DESC; DROP TABLE invoices; --`.

## Source

User input: `request.args.get("sort", "created_at")` in report_controller.py (line 7)

Call chain:
1. report_controller.py line 7: `sort = request.args.get("sort", "created_at")`
2. report_controller.py line 8: passes `sort` to `run_report()`
3. report_service.py line 5: passes `sort` to `fetch_report_rows()`
4. report_repository.py line 9: interpolates `sort` into SQL via f-string: `f"ORDER BY {sort}"`

Sink: `text()` with f-string interpolation of untrusted `sort` parameter (line 9), executed at line 11 via `session.execute()`.

## Fix

### File: report_repository.py

```python
from sqlalchemy import text


def fetch_report_rows(session, account_id, status, sort):
    # Map of permitted sort columns - the query uses the map's value, not the caller's input
    ALLOWED_SORT_COLUMNS = {
        "id": "id",
        "status": "status", 
        "total_cents": "total_cents",
        "created_at": "created_at"
    }
    
    # Validate sort parameter and use the map's value
    safe_sort = ALLOWED_SORT_COLUMNS.get(sort, "created_at")
    
    statement = text(
        "SELECT id, status, total_cents, created_at "
        "FROM invoices "
        "WHERE account_id = :account_id AND status = :status "
        f"ORDER BY {safe_sort}"
    )
    return session.execute(statement, {"account_id": account_id, "status": status})
```

## Explanation

The fix validates the `sort` parameter against a server-controlled allowlist of permitted column names before interpolating it into the SQL query. Instead of using the untrusted user input directly, the code looks up the value in an ALLOWED_SORT_COLUMNS map and uses the map's value—ensuring only known, safe column identifiers can appear in the ORDER BY clause. Invalid sort parameters default to "created_at", preventing injection attacks while maintaining functionality. This follows the guidance principle that dynamic identifiers must be treated as keys into a server-side map of permitted names, not as input to validate and then use.

## Behaviour changes

1. Invalid sort parameters now default to "created_at" instead of being interpolated directly into the query. Previously, any string value would be used; now only the four permitted columns (id, status, total_cents, created_at) are allowed. This is an intentional restriction to prevent SQL injection.

2. The query execution and return value remain unchanged; only the sort column is now validated. The function still returns the same result set, and the database operation is identical when valid column names are provided.

3. No additional parameters are added to `session.execute()`. The function signature and call semantics are preserved; only the variable passed to the query changes from untrusted `sort` to validated `safe_sort`.
