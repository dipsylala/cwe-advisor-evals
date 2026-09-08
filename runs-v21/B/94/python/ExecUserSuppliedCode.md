## Verdict
exploitable

## Source
HTTP POST request body, `code` field (line 29: `snippet = payload.get("code")`)

## Fix

### File: ExecUserSuppliedCode.py

```python
"""Admin-only data migration tool for the internal ops dashboard.

Lets an operator select from predefined migration operations to backfill or 
transform records without waiting on a full release. Access is gated by the
@admin_required decorator, and operations are restricted to a known set of safe
operations rather than executing arbitrary code.
"""

from flask import Blueprint, request, jsonify

from app.auth import admin_required
from app.db import get_connection


migration_bp = Blueprint("migrations", __name__)


def transform_column(conn, table, column, transformation):
    """Apply a predefined transformation to a column."""
    # Implementation of safe column transformation
    # This would be a specific, non-arbitrary operation
    pass


def backfill_column(conn, table, column, value):
    """Backfill a column with a specific value."""
    # Implementation of safe backfill operation
    pass


# Dictionary of allowed migration operations, replacing dynamic code execution
MIGRATION_OPERATIONS = {
    "transform_column": transform_column,
    "backfill_column": backfill_column,
}


@migration_bp.route("/admin/migrations/run-snippet", methods=["POST"])
@admin_required
def run_migration_snippet():
    """Execute a predefined migration operation against the current DB connection.

    The request body carries an "operation" field specifying which migration
    to run, and a "params" field with operation-specific parameters. Only
    operations in MIGRATION_OPERATIONS are allowed.
    """
    payload = request.get_json(silent=True) or {}
    operation_name = payload.get("operation")
    operation_params = payload.get("params", {})
    
    if not operation_name or not isinstance(operation_name, str):
        return jsonify({"error": "operation field is required"}), 400
    
    if operation_name not in MIGRATION_OPERATIONS:
        return jsonify({"error": f"Unknown operation: {operation_name}"}), 400

    try:
        conn = get_connection()
        operation = MIGRATION_OPERATIONS[operation_name]
        results = operation(conn, **operation_params)
        return jsonify({"results": results or []})
    except TypeError as e:
        return jsonify({"error": f"Invalid parameters: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": f"Migration failed: {str(e)}"}), 500
```

## Explanation

The original code at line 37 executed user-supplied Python code directly via `exec(snippet, migration_globals)`, allowing arbitrary code execution despite the `@admin_required` decorator. The decorator controls *who* can call the endpoint but not *what code they run*. Even an authorized admin user's account can be compromised, and a malicious admin could exploit this to access sensitive data, modify the database, or perform other unauthorized operations with full application privileges.

The fix replaces dynamic code execution with a safe dictionary-based dispatch pattern. Instead of accepting raw Python code, the endpoint now accepts an `operation` field that selects from a predefined set of named migration functions stored in `MIGRATION_OPERATIONS`. Each operation is implemented as a separate, auditable function that handles only its specific use case. Parameters are passed as data through `operation_params` rather than as executable code. This eliminates the code injection vector entirely: attackers cannot inject arbitrary Python code because the application never evaluates untrusted strings as code.

## Behaviour changes

1. **Request schema change**: The endpoint now expects `{"operation": "operation_name", "params": {...}}` instead of `{"code": "python_code"}`. This is a breaking change to the API contract that moves from code execution to operation dispatch.

2. **New validation**: The fix adds validation that the operation name exists in `MIGRATION_OPERATIONS` before attempting execution (line 56-57). The original code did not validate operation types.

3. **Error handling**: The fix adds explicit error handling for `TypeError` (invalid parameters to the operation function) and a generic `Exception` handler for operation-specific failures (lines 62-65), whereas the original code would have propagated any exception raised by `exec()`.

4. **Return value handling**: The fix explicitly handles cases where an operation returns `None` by defaulting to an empty list (line 61: `results or []`), matching the original code's expectation of a results list.

5. **Placeholder function implementations**: The fix defines two example operations (`transform_column`, `backfill_column`) as stubs with `pass`. These must be implemented with the actual migration logic that was previously embedded in user-supplied code snippets.

Reason for each: The operation dispatch eliminates the injection vector while preserving the admin-controlled migration capability. Validation prevents incorrect operation names from being silently accepted. Error handling makes migration failures explicit and debuggable. The return value handling maintains backward compatibility with the JSON response format. The placeholder functions show how concrete operations should be defined.

