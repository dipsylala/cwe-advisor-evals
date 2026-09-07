## Verdict

Exploitable. Untrusted user input from `request.args.get("sort")` in the controller flows directly to the SQL query via an f-string in the repository's `fetch_report_rows()` function at line 11, allowing SQL injection.

## Source

`request.args.get("sort", "created_at")` in `report_controller.py` - HTTP request parameter, untrusted.

## Fix

### File: report_repository.py

```python
from sqlalchemy import text


def fetch_report_rows(session, account_id, status, sort):
    # Allowlist of permitted sort columns to prevent SQL injection
    permitted_sorts = {"created_at", "id", "status", "total_cents"}
    
    # Validate sort parameter against allowlist
    if sort not in permitted_sorts:
        raise ValueError(f"Invalid sort column: {sort}")
    
    statement = text(
        "SELECT id, status, total_cents, created_at "
        "FROM invoices "
        "WHERE account_id = :account_id AND status = :status "
        f"ORDER BY {sort}"
    )
    return session.execute(statement, {"account_id": account_id, "status": status})
```

## Explanation

The vulnerability occurs because the `sort` parameter is directly interpolated into the SQL query using an f-string (`f"ORDER BY {sort}"`). Since `ORDER BY` clause identifiers cannot be parameterized (only values can be), an allowlist validation is the appropriate defence. The fix adds a set of permitted column names (`{"created_at", "id", "status", "total_cents"}`) and validates the input against it before use. If the sort parameter is not in the allowlist, a `ValueError` is raised with a clear message, preventing the query execution with untrusted input. This ensures only pre-approved column names reach the SQL query, eliminating the SQL injection path while preserving legitimate functionality for valid sort requests.

## Behaviour changes

The fix introduces a validation check that may raise `ValueError` if an invalid sort column is requested. The original code would have silently accepted any sort value and injected it into the SQL. 

- **New exception**: Invalid sort values now raise `ValueError("Invalid sort column: {sort}")` instead of executing a potentially malicious query.
- **Allowlist scope**: Only columns in the predefined set (`created_at`, `id`, `status`, `total_cents`) are now accepted.
- **Default value handling**: The default value `"created_at"` from `request.args.get("sort", "created_at")` is in the allowlist, so normal operation with no sort parameter is unaffected.

The caller (report_service.py and report_controller.py) will need to handle the `ValueError` if they wish to provide user-friendly error messages for invalid sort parameters, or the exception will propagate to the framework's error handler.
