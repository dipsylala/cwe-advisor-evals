## Verdict
Exploitable.

## Source
`request.args.get("sort", "created_at")` in report_controller.py, line 6. Untrusted user input from the HTTP request.

## Fix

**Vulnerable code** (report_repository.py, lines 5-11):
```python
def fetch_report_rows(session, account_id, status, sort):
    statement = text(
        "SELECT id, status, total_cents, created_at "
        "FROM invoices "
        "WHERE account_id = :account_id AND status = :status "
        f"ORDER BY {sort}"  # VULNERABLE: sort is interpolated directly
    )
    return session.execute(statement, {"account_id": account_id, "status": status})
```

**Fixed code** (report_repository.py, entire file):
```python
from sqlalchemy import text

# Define allowed sort columns
ALLOWED_SORT_COLUMNS = {"id", "status", "total_cents", "created_at"}


def fetch_report_rows(session, account_id, status, sort):
    if sort not in ALLOWED_SORT_COLUMNS:
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
The vulnerability stems from using an f-string to interpolate the `sort` parameter directly into the SQL query. Column names and identifiers cannot be bound as parameterized placeholders in SQL, so they require allowlist validation. The fix adds a predefined set of permitted column names and validates the `sort` parameter against this allowlist before use. An attacker attempting to inject SQL code (e.g., `created_at; DROP TABLE invoices; --`) will trigger a `ValueError` instead of executing arbitrary SQL. The allowlist is defined at module scope and enforced at the single sink that consumes the `sort` parameter.

## Behaviour changes
- Raises `ValueError` if `sort` is not in the allowlist, instead of allowing the query to execute with an invalid column name. This is a new constraint that prevents SQL injection, replacing the previous implicit acceptance of any input.
- No changes to query execution, parameter binding, or return values when the sort parameter is valid.
