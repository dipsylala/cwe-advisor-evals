## Verdict

Exploitable. The `sort` parameter is user-controlled input from `request.args.get("sort")` in the controller, passed through the service to the repository, and directly interpolated into a SQL query string via f-string before execution. This allows an attacker to inject arbitrary SQL fragments into the `ORDER BY` clause.

## Source

`report_controller.py` line 7: `sort = request.args.get("sort", "created_at")` receives untrusted user input from the HTTP request query parameters.

## Fix

**Vulnerable code (report_repository.py, lines 4-11):**

```python
def fetch_report_rows(session, account_id, status, sort):
    statement = text(
        "SELECT id, status, total_cents, created_at "
        "FROM invoices "
        "WHERE account_id = :account_id AND status = :status "
        f"ORDER BY {sort}"
    )
    return session.execute(statement, {"account_id": account_id, "status": status})
```

**Fixed code (report_repository.py, lines 4-14):**

```python
def fetch_report_rows(session, account_id, status, sort):
    # Allowlist of permitted sort columns
    permitted_sorts = {
        "id": "id",
        "status": "status",
        "total_cents": "total_cents",
        "created_at": "created_at",
    }
    
    # Validate sort parameter against allowlist
    if sort not in permitted_sorts:
        sort = "created_at"  # Use safe default if invalid
    
    sort_col = permitted_sorts[sort]  # Use the allowlisted value
    
    statement = text(
        "SELECT id, status, total_cents, created_at "
        "FROM invoices "
        "WHERE account_id = :account_id AND status = :status "
        f"ORDER BY {sort_col}"
    )
    return session.execute(statement, {"account_id": account_id, "status": status})
```

## Explanation

SQL injection in this case occurs because `sort` is a dynamic identifier (a column name) that cannot be bound as a parameterized query parameter. Per the CWE-89 Python guidance, dynamic identifiers must be validated against a predefined allowlist of permitted values, and the query must use the value from that allowlist, not the original user input. The fix creates a dictionary mapping user-supplied values to the canonical database column names, validates the `sort` parameter against this allowlist, and uses the safe value from the allowlist in the f-string. If the user provides an invalid sort value, the code defaults to `"created_at"`, rejecting the injection attempt. The `account_id` and `status` parameters remain properly parameterized using SQLAlchemy's `:` placeholder syntax and bound separately to prevent injection in those numeric/string contexts.

## Behaviour changes

The fixed code introduces input validation that rejects unexpected sort column names by defaulting to `"created_at"` instead. This is an intentional security hardening that prevents attackers from sorting by arbitrary columns. Applications that currently accept any column name will now silently use the default sort; to expose this as an explicit error, the code could raise a `ValueError` instead of using the default, but this changes the application's behaviour and requires coordination with all callers. The parameterized binding of `account_id` and `status` remains unchanged. All existing legitimate requests with sort values matching the allowlist (`id`, `status`, `total_cents`, `created_at`) continue to work identically.
