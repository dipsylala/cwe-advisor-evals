## Verdict
Exploitable. The `sort` parameter is directly interpolated into a SQLAlchemy `text()` query via an f-string at line 9 of report_repository.py. This allows SQL injection: an attacker controlling the query parameter can inject arbitrary SQL, such as modifying the WHERE clause or injecting UNION-based queries. The parameter originates from untrusted user input in the request query string (report_controller.py line 7).

## Source
- **Input source**: `request.args.get("sort", "created_at")` in report_controller.py, line 7
- **Attack vector**: Query string parameter `sort` passed by HTTP client, untrusted and user-controlled
- **Call chain**: report_controller.py:7 → report_service.py:5 → report_repository.py:4-11

## Fix

**Vulnerable code:**
```python
def fetch_report_rows(session, account_id, status, sort):
    statement = text(
        "SELECT id, status, total_cents, created_at "
        "FROM invoices "
        "WHERE account_id = :account_id AND status = :status "
        f"ORDER BY {sort}"  # INJECTION: sort is user-controlled
    )
    return session.execute(statement, {"account_id": account_id, "status": status})
```

**Fixed code:**
```python
def fetch_report_rows(session, account_id, status, sort):
    # Allowlist of permitted sort columns
    permitted_sorts = {"id", "status", "total_cents", "created_at"}
    if sort not in permitted_sorts:
        sort = "created_at"  # Default to safe value on invalid input
    
    statement = text(
        "SELECT id, status, total_cents, created_at "
        "FROM invoices "
        "WHERE account_id = :account_id AND status = :status "
        f"ORDER BY {sort}"  # Now uses allowlist-validated value
    )
    return session.execute(statement, {"account_id": account_id, "status": status})
```

## Explanation
The `ORDER BY` clause in SQL cannot be parameterized (it is structural, not a data value), so it cannot use the `:param` placeholder syntax that SQLAlchemy provides for values. The fix validates the `sort` parameter against a whitelist of permitted column names before constructing the query. Only the canonical values from the allowlist—not the raw user input—are used in the query string. An attacker attempting to inject SQL through the sort parameter will fail validation and the query will default to sorting by `created_at`. This approach follows CWE-89 guidance that dynamic identifiers must be validated against a fixed set of permitted names, with the selected value drawn from the server-controlled set rather than echoing the user's input.

## Behaviour changes
None. The query returns the same result set with the same column order when sort is a valid column name. When sort is invalid or malicious, the original code would either fail at execution (if the injection produces invalid SQL) or execute injected SQL (if the injection is syntactically valid). The fixed code substitutes a safe default and completes successfully. The calling code must decide whether to reject the request (e.g., HTTP 400) or silently apply the default; this change assumes accepting the default is acceptable.
