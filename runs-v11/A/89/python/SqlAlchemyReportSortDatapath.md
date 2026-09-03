## Verdict

Vulnerable. The `sort` parameter is user-controlled (from `request.args` in the controller) and flows unvalidated into the SQL ORDER BY clause via f-string interpolation on line 9.

## Source

- **report_controller.py line 7**: `sort = request.args.get("sort", "created_at")` - untrusted user input
- **report_repository.py line 9**: `f"ORDER BY {sort}"` - direct interpolation into SQL query

The data flows from user input → controller → service → repository without validation.

## Fix

Add whitelist validation in `report_repository.py` before using the `sort` value:

```python
from sqlalchemy import text


def fetch_report_rows(session, account_id, status, sort):
    # Whitelist allowed columns for sorting to prevent SQL injection
    allowed_columns = {"id", "status", "total_cents", "created_at"}
    
    if sort not in allowed_columns:
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

SQL ORDER BY clauses cannot use bind parameters—the column name must be part of the query structure, not a value. The only safe approach is to validate that the sort parameter matches a known, safe column name before including it in the query string.

The fix defines a set of allowed columns that match the SELECT list and the table schema. Any input that doesn't match this whitelist is rejected with a ValueError. This prevents attackers from injecting SQL commands (e.g., `created_at; DROP TABLE invoices; --`) into the ORDER BY clause.

The bound parameters for `account_id` and `status` remain unchanged and continue to protect those columns from injection.
