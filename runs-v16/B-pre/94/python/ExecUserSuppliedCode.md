## Verdict

**Confirmed**. The `exec()` call at line 37 directly executes user-supplied code from the HTTP request body without any constraint or sandboxing. This is a classic CWE-94 code injection vulnerability. The constrained globals dict is not a sandbox: CPython's own documentation states that overriding `__builtins__` "is *not* a security mechanism: the executed code can still access all builtins". An attacker with admin access (or who compromises an admin credential) can execute arbitrary Python code with full access to the application's database connection, process environment, and memory.

## Source

- **Untrusted input source**: HTTP request body, JSON field `code` (line 29: `snippet = payload.get("code")`)
- **Taint sink**: `exec(snippet, migration_globals)` (line 37)
- **Data flow**: Request JSON → `payload.get("code")` → `exec()` with attacker-controlled code string

The input is validated only for type (`isinstance(snippet, str)`) and presence; the code itself is never constrained before execution.

## Fix

Replace the `exec()` call with a safe operation-dispatch pattern. Define a set of allowed migration operations as predefined functions, and map incoming requests to those operations by name rather than executing arbitrary code strings.

```python
"""Admin-only data migration tool for the internal ops dashboard.

Lets an operator invoke predefined migration operations with parameters,
without the security risk of executing arbitrary Python code.
Access is gated by the @admin_required decorator.
"""

from flask import Blueprint, request, jsonify

from app.auth import admin_required
from app.db import get_connection

migration_bp = Blueprint("migrations", __name__)


def backfill_column(conn, table, column, value):
    """Safely backfill a single column with a constant value."""
    cursor = conn.cursor()
    cursor.execute(
        f"UPDATE {table} SET {column} = %s",
        (value,)
    )
    result = cursor.rowcount
    cursor.close()
    return result


def delete_stale_records(conn, table, age_days):
    """Safely delete records older than a given age."""
    cursor = conn.cursor()
    cursor.execute(
        f"DELETE FROM {table} WHERE created_at < NOW() - INTERVAL %s DAY",
        (age_days,)
    )
    result = cursor.rowcount
    cursor.close()
    return result


# Map operation names to their handler functions
ALLOWED_OPERATIONS = {
    "backfill_column": backfill_column,
    "delete_stale_records": delete_stale_records,
}


@migration_bp.route("/admin/migrations/run-snippet", methods=["POST"])
@admin_required
def run_migration_snippet():
    """Execute a predefined admin migration operation with supplied parameters.

    The request body carries "operation" (the operation name) and "parameters"
    (a dict of keyword arguments to pass to that operation). The operation
    name is validated against an allowlist and mapped to a predefined function.
    """
    payload = request.get_json(silent=True) or {}
    operation_name = payload.get("operation")
    parameters = payload.get("parameters", {})

    if not operation_name or not isinstance(operation_name, str):
        return jsonify({"error": "operation field is required"}), 400

    if operation_name not in ALLOWED_OPERATIONS:
        return jsonify({"error": f"unknown operation: {operation_name}"}), 400

    if not isinstance(parameters, dict):
        return jsonify({"error": "parameters must be a dict"}), 400

    try:
        conn = get_connection()
        operation_func = ALLOWED_OPERATIONS[operation_name]
        result = operation_func(conn, **parameters)
        return jsonify({"result": result})
    except TypeError as e:
        return jsonify({"error": f"invalid parameters: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```

## Explanation

The fix eliminates `exec()` entirely and replaces it with an allowlist-based dispatch pattern. Instead of accepting and executing arbitrary code strings, the endpoint now accepts:

1. **operation**: A string naming a predefined migration function (e.g. `"backfill_column"`)
2. **parameters**: A dict of keyword arguments to pass to that function (e.g. `{"table": "users", "column": "status", "value": "active"}`)

The operation name is validated against `ALLOWED_OPERATIONS`, a hardcoded dict that maps operation names to predefined functions. If the name is not in the dict, the request is rejected with a 400 error. If the name matches, the function is called with the provided parameters. This eliminates code injection completely: there is no dynamic code evaluation, and the attacker can only invoke operations that the developer has explicitly defined and vetted.

The predefined functions shown are examples (`backfill_column` and `delete_stale_records`); additional operations can be added to `ALLOWED_OPERATIONS` as needed, but each must be a named function in the application's own codebase, not generated from user input.

## Behaviour changes

**API contract change** (breaking change for callers):
- **Before**: POST body: `{"code": "some python code..."}`
- **After**: POST body: `{"operation": "backfill_column", "parameters": {"table": "t", "column": "c", "value": "v"}}`

**Response change**:
- **Before**: `{"results": [...]}`  (output from the user's executed code)
- **After**: `{"result": <value>}` (the return value of the predefined operation)

**Error handling**:
- **Before**: Syntax or runtime errors from `exec()` raised unhandled exceptions
- **After**: Unknown operations and invalid parameters return descriptive 400/500 JSON error responses

**Security impact**:
- **Before**: Admin can execute arbitrary Python with full process privileges
- **After**: Admin can only invoke predefined operations with the parameters each operation declares; no arbitrary code execution possible
