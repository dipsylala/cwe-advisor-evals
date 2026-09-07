## Verdict

Real SQL injection vulnerability. The `sort` parameter from `report_controller.py` flows untrusted through the call chain and is interpolated directly into the SQL string via f-string on line 9 of `report_repository.py`, bypassing parameterization.

## Source

- `report_controller.py` line 7: User-controlled `sort` from `request.args.get("sort", "created_at")`
- `report_service.py` line 4: Passes through without validation
- `report_repository.py` line 9: `f"ORDER BY {sort}"` concatenates the untrusted value directly into SQL

An attacker can supply `sort=id; DROP TABLE invoices--` or any other SQL expression.

## Fix

### File: report_repository.py

```python
from sqlalchemy import text


def fetch_report_rows(session, account_id, status, sort):
    # Whitelist allowed columns to prevent SQL injection
    allowed_columns = {"id", "status", "total_cents", "created_at"}
    if sort not in allowed_columns:
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

SQL ORDER BY clauses cannot use bind parameters for column names—only for values. The fix validates the `sort` parameter against a whitelist of known safe column names before interpolation. Only columns that exist in the query and are safe to sort by are permitted; any other input defaults to `"created_at"`. This prevents injection because the f-string only expands to a known column name, not arbitrary SQL syntax.
