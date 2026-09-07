## Verdict
SQL injection through unsanitized `sort` parameter interpolated into ORDER BY clause.

## Source
The vulnerability is in `report_repository.py` line 9, where the `sort` parameter received from user input (via `report_controller.py` line 7) is directly interpolated into the SQL query using an f-string:

```python
f"ORDER BY {sort}"
```

An attacker can supply malicious SQL in the `sort` query parameter, such as:
- `created_at; DROP TABLE invoices; --`
- `id UNION SELECT * FROM users --`
- `(SELECT password FROM users LIMIT 1) --`

## Fix
Validate the `sort` parameter against an allowlist of permitted column names before interpolating it into the SQL query:

```python
from sqlalchemy import text


def fetch_report_rows(session, account_id, status, sort):
    # Allowlist of columns permitted for sorting
    ALLOWED_SORT_COLUMNS = {"id", "status", "total_cents", "created_at"}
    
    # Validate sort parameter
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

The fix defines a set of allowed column names (`ALLOWED_SORT_COLUMNS`) and validates the `sort` parameter against it before use. Any value not in the allowlist raises a `ValueError`.

## Explanation
ORDER BY clauses cannot be parameterized in SQL — the column name must be part of the query structure, not a bound parameter value. An allowlist of permitted sort columns is the standard mitigation for this class of injection.

The allowlist includes only the columns that are selected in the query (`id`, `status`, `total_cents`, `created_at`), preventing both SQL injection and invalid column errors. The validation occurs before the value reaches the SQL text, stopping any malicious input from reaching the database.

This pattern is language-agnostic and applies to all SQL injection variants in ORDER BY context across Python, Java, PHP, and other ecosystems.
