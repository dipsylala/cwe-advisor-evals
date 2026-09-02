## Verdict

**Exploitable SQL injection via unsanitized ORDER BY clause.**

The `sort` parameter flows from user-controlled HTTP query input (`request.args.get("sort")` in `report_controller.py` line 7) through the service layer to `fetch_report_rows()` in `report_repository.py`, where it is directly interpolated into the SQL query using an f-string on line 9 (`f"ORDER BY {sort}"`). This allows an attacker to inject arbitrary SQL fragments into the ORDER BY clause.

## Source

User-supplied `sort` query parameter from HTTP request:
- **Location**: `report_controller.py`, line 7: `sort = request.args.get("sort", "created_at")`
- **Taint flow**: `report_service.py` line 5 → `report_repository.py` line 4 parameter → line 9 f-string interpolation
- **Sink**: `session.execute()` with `text()` statement containing unsanitized f-string

An attacker can control the `sort` parameter by sending a request like `GET /report?sort=id; DROP TABLE invoices;--` to execute arbitrary SQL.

## Fix

Replace the unsanitized f-string with an allowlist of permitted sort columns:

```python
from sqlalchemy import text


ALLOWED_SORT_COLUMNS = {"id", "status", "total_cents", "created_at"}


def fetch_report_rows(session, account_id, status, sort):
    # Validate sort parameter against allowlist of permitted columns
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

The vulnerability exists because the `ORDER BY` clause uses an f-string with the untrusted `sort` parameter, allowing SQL injection. ORDER BY expressions cannot be parameterized in SQLAlchemy (or any SQL dialect) because they control query structure, not data values.

The fix implements an allowlist of safe column names. The `sort` parameter is validated against this fixed set before being used in the query. Only values that match the allowlist are permitted—any other input raises a `ValueError`. This transforms the dynamic parameter from untrusted user input into a validated, safe identifier.

The WHERE clause parameters (`:account_id` and `:status`) remain properly parameterized, preventing injection in those positions.

## Behaviour changes

- **Valid inputs**: Requests with `sort=created_at`, `sort=id`, `sort=status`, or `sort=total_cents` work as before.
- **Invalid inputs**: Requests with any sort parameter not in the allowlist now raise `ValueError` and return an error instead of executing injected SQL.
- **Default behaviour**: The controller's default of `created_at` (line 7) remains valid and passes the allowlist.
- **Error handling**: The application must handle the `ValueError` raised by the validation and return an appropriate HTTP error response (e.g., 400 Bad Request).
