## Verdict

Exploitable. The `sort` parameter flows directly from untrusted HTTP request input through the call chain into SQL string interpolation without validation, allowing an attacker to inject arbitrary SQL commands.

## Source

`request.args.get("sort", "created_at")` in `report_controller.py` line 7. The parameter is passed through `run_report()` in the service layer and reaches `fetch_report_rows()` in `report_repository.py`.

## Fix

**Vulnerable code:**
```python
def fetch_report_rows(session, account_id, status, sort):
    statement = text(
        "SELECT id, status, total_cents, created_at "
        "FROM invoices "
        "WHERE account_id = :account_id AND status = :status "
        f"ORDER BY {sort}"  # SQL injection: sort interpolated without validation
    )
    return session.execute(statement, {"account_id": account_id, "status": status})
```

**Fixed code:**
```python
from sqlalchemy import text

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

The vulnerability occurs because the `sort` parameter—sourced from untrusted user input via HTTP request arguments—is directly interpolated into the SQL query string using an f-string without any validation. SQLAlchemy's `text()` function treats the entire string as executable SQL code, allowing an attacker to inject arbitrary SQL commands such as `id; DROP TABLE invoices; --`. The fix implements an allowlist of permitted column names matching the columns returned by the query. Before the `sort` parameter is used in the SQL string, it is validated against this allowlist; if it does not match a permitted value, a `ValueError` is raised. This prevents SQL injection because only pre-approved identifiers can reach the query string. Column names cannot be parameterized in SQL, so allowlist validation is the appropriate defence for dynamic identifiers in this position of the query.

## Behaviour changes

A new module-level constant `ALLOWED_SORT_COLUMNS` is added to enumerate safe column names. A validation check is introduced that raises `ValueError` when the `sort` parameter does not match an allowlisted value. This prevents previously unchecked invalid inputs from reaching the database. The check is a breaking change for requests that supply unrecognized sort columns—the application now explicitly rejects them instead of attempting to execute the malformed query. This is the intended behaviour: valid sort columns should be restricted to a fixed, server-controlled set. The query execution, return type, and data output remain unchanged for valid inputs.
