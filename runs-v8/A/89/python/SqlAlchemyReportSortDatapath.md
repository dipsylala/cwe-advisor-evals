## Verdict
SQL injection via unsanitized ORDER BY clause.

## Source
`report_repository.py` line 9: The `sort` parameter from the function argument is directly interpolated into the SQL query using an f-string without validation, allowing an attacker to inject arbitrary SQL code through the ORDER BY clause.

## Fix
```python
from sqlalchemy import text


def fetch_report_rows(session, account_id, status, sort):
    # Whitelist of allowed columns for sorting
    allowed_sort_columns = {"id", "status", "total_cents", "created_at"}
    
    # Validate sort parameter; default to "created_at" if invalid
    if sort not in allowed_sort_columns:
        sort = "created_at"
    
    statement = text(
        "SELECT id, status, total_cents, created_at "
        "FROM invoices "
        "WHERE account_id = :account_id AND status = :status "
        f"ORDER BY {sort}"
    )
    return session.execute(statement, {"account_id": account_id, "status": status})
```

## Explanation
ORDER BY clauses cannot be parameterized as bound parameters in SQL; the column name must be part of the query structure. The fix implements a whitelist of allowed sort columns and validates the user-supplied `sort` parameter against this list before interpolating it into the query. If an invalid or malicious value is provided, it defaults to a safe column name. This prevents SQL injection by ensuring only known, safe column names can be used in the ORDER BY clause, regardless of what the attacker supplies.
