# CWE-94: ExecUserSuppliedCode

## Verdict

Exploitable. The code directly executes user-supplied Python code via `exec()` on line 37, with no sandbox or allowlist restricting the executed content. The `@admin_required` decorator provides authentication, not code execution safety. Even with admin-level access, this pattern violates the CWE-94 remediation principle that dynamic code execution must never be used, regardless of the source's claimed trustworthiness.

## Source

Request parameter `code` from JSON payload (line 29): `snippet = payload.get("code")`. The request is authenticated via `@admin_required`, but authentication does not reduce the code-injection risk.

## Fix

### File: ExecUserSuppliedCode.py

```python
"""Admin-only data migration tool for the internal ops dashboard.

Lets an operator select and run a predefined migration operation without
waiting on a full release. Access is gated by the @admin_required decorator,
and only reviewed migration functions can execute.
"""

from flask import Blueprint, request, jsonify

from app.auth import admin_required
from app.db import get_connection

migration_bp = Blueprint("migrations", __name__)

# Define safe, predefined migration operations
MIGRATION_OPERATIONS = {
    # Add predefined migration functions here
    # Example: "backfill_column": backfill_column_migration,
}


def register_migration(name):
    """Decorator to register a migration function."""
    def decorator(func):
        MIGRATION_OPERATIONS[name] = func
        return func
    return decorator


@migration_bp.route("/admin/migrations/run-snippet", methods=["POST"])
@admin_required
def run_migration_snippet():
    """Execute a predefined migration operation against the current DB connection.

    The request body carries an "operation" field naming the migration to run,
    and an optional "params" field with operation-specific parameters.
    Operators select from predefined, reviewed migration functions rather than
    supplying arbitrary code.
    """
    payload = request.get_json(silent=True) or {}
    operation_name = payload.get("operation")
    params = payload.get("params", {})

    if not operation_name or not isinstance(operation_name, str):
        return jsonify({"error": "operation field is required"}), 400

    if operation_name not in MIGRATION_OPERATIONS:
        return jsonify({"error": "operation not found"}), 400

    if not isinstance(params, dict):
        return jsonify({"error": "params must be a dict"}), 400

    conn = get_connection()
    migration_fn = MIGRATION_OPERATIONS[operation_name]

    try:
        results = migration_fn(conn, **params)
        return jsonify({"results": results})
    except TypeError:
        return jsonify({"error": "invalid parameters for operation"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```

## Explanation

The fix replaces arbitrary code execution with a dictionary-based function dispatch pattern. The original code accepted a "code" parameter and executed it directly via `exec()`, bypassing all controls. The fixed code requires the request to specify an "operation" name (validated against a whitelist in `MIGRATION_OPERATIONS`) and optional parameters, then dispatches to a predefined, reviewed function. This eliminates the CWE-94 vulnerability by removing the code-evaluation sink entirely. Operators can now only invoke migration functions that have been explicitly defined and reviewed by the team. New migrations are registered via the `@register_migration` decorator or by adding entries to the `MIGRATION_OPERATIONS` dict, making available operations auditable and preventing arbitrary code execution.

## Behaviour changes

- **Request format**: Changed from `{"code": "...python code..."}` to `{"operation": "operation_name", "params": {...}}`. This is a breaking API change requiring client updates.
- **Response on invalid operation**: New error response `{"error": "operation not found"}` when the requested operation is not registered.
- **Error handling**: Added `TypeError` handling to distinguish invalid parameters (400 response) from other runtime errors (500 response), improving clarity for callers.
- **Migration registration**: New `MIGRATION_OPERATIONS` dict and optional `@register_migration` decorator allow operators to extend available migrations without code changes, though new functions still require code review before registration.

The sink contract is preserved: the endpoint accepts a request, validates inputs, connects to the database, performs operations, and returns results.
