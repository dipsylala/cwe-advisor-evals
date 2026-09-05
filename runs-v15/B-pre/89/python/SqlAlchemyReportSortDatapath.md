## Verdict

Exploitable

## Source

HTTP request parameter `sort` from `request.args.get("sort", "created_at")` in report_controller.py, passed through report_service.py to report_repository.py

## Fix

**Vulnerable code (report_repository.py):**

```python
def fetch_report_rows(session, account_id, status, sort):
    statement = text(
        "SELECT id, status, total_cents, created_at "
        "FROM invoices "
        "WHERE account_id = :account_id AND status = :status "
        f"ORDER BY {sort}"  # SQL injection: sort is interpolated directly
    )
    return session.execute(statement, {"account_id": account_id, "status": status})
```

**Fixed code:**

```python
def fetch_report_rows(session, account_id, status, sort):
    # Allowlist of permitted sort columns
    ALLOWED_SORT_COLUMNS = {"id", "status", "total_cents", "created_at"}
    
    # Validate and select the canonical sort value from the allowlist
    if sort not in ALLOWED_SORT_COLUMNS:
        sort = "created_at"  # Fall back to default if invalid
    
    statement = text(
        "SELECT id, status, total_cents, created_at "
        "FROM invoices "
        "WHERE account_id = :account_id AND status = :status "
        f"ORDER BY {sort}"  # Now using allowlist-validated value
    )
    return session.execute(statement, {"account_id": account_id, "status": status})
```

## Explanation

The vulnerability occurs because the `sort` parameter—an untrusted HTTP request parameter—is interpolated directly into the SQL query via an f-string before being passed to SQLAlchemy's `text()` function. Since ORDER BY accepts structural elements (column names) rather than values, it cannot use bind parameters, making allowlist validation the required defence. The fix defines a set of permitted column names that match those available in the SELECT clause, validates the incoming sort parameter against this allowlist, and uses only the canonical value (either the validated input or the safe default) in the query. This eliminates the SQL injection risk while preserving the original functionality.

## Behaviour changes

None. The fix maintains the same return type and query behaviour. The default fallback to "created_at" matches the existing parameter default in the controller (`request.args.get("sort", "created_at")`), so callers passing invalid sort values now receive sorted results using the default order instead of a potential SQL injection in the query.
