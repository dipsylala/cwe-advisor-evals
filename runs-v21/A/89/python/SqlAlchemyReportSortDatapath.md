## Verdict
VULNERABLE. The `sort` parameter from user input is directly interpolated into the SQL query without validation, allowing SQL injection.

## Source
User input enters via `request.args.get("sort")` in report_controller.py (line 7), flows through report_service.py to report_repository.py, and is unsafely embedded in the SQL query at line 9 using an f-string: `f"ORDER BY {sort}"`.

## Fix

### File: report_repository.py
```python
from sqlalchemy import text


def fetch_report_rows(session, account_id, status, sort):
    # Whitelist allowed sort columns to prevent SQL injection
    allowed_columns = {"id", "status", "total_cents", "created_at"}
    
    # Parse sort parameter to extract column name and direction
    sort_parts = sort.split()
    column_name = sort_parts[0]
    direction = sort_parts[1].lower() if len(sort_parts) > 1 else "asc"
    
    # Validate column name and sort direction against whitelist
    if column_name not in allowed_columns or direction not in {"asc", "desc"}:
        raise ValueError("Invalid sort parameter")
    
    statement = text(
        "SELECT id, status, total_cents, created_at "
        "FROM invoices "
        "WHERE account_id = :account_id AND status = :status "
        f"ORDER BY {column_name} {direction.upper()}"
    )
    return session.execute(statement, {"account_id": account_id, "status": status})
```

## Explanation
The fix implements input validation by maintaining a whitelist of allowed column names from the SELECT clause and allowing only "asc" or "desc" for the sort direction. The `sort` parameter is parsed and validated against these whitelists before being used in the SQL query. This prevents SQL injection because only known-safe column identifiers and directions can reach the query string. While the f-string remains, it is now safe because the values are guaranteed to be from the whitelist. This approach is the standard remediation for ORDER BY clauses, where SQL does not support parameterized column names, making input validation the appropriate defense.
