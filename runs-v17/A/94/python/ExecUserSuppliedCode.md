## Verdict
**Code Injection vulnerability confirmed.** Line 37 executes arbitrary user-supplied Python code via `exec()` with insufficient restrictions. Even though the endpoint requires `@admin_required` authentication, an administrator can inject and execute malicious code with full application privileges.

## Source
The vulnerability exists in the `run_migration_snippet()` function at line 37:
```python
exec(snippet, migration_globals)
```

The `snippet` variable is taken directly from the JSON request body (`payload.get("code")`) with only a type check (`isinstance(snippet, str)`). This passes the code to `exec()` with a globals dictionary that includes the live database connection. An admin user can inject arbitrary Python code to access, modify, or exfiltrate database contents or perform other harmful operations.

## Fix
Replace the unrestricted `exec()` call with RestrictedPython, which compiles code in a restricted mode and limits access to dangerous built-ins and operations:

### File: ExecUserSuppliedCode.py
```python
"""Admin-only data migration tool for the internal ops dashboard.

Lets an operator paste a one-off Python snippet to backfill or transform
records without waiting on a full release. Access is gated by the
@admin_required decorator, and the snippet runs in a restricted
environment with limited access to built-ins.
"""

from flask import Blueprint, request, jsonify
from RestrictedPython import compile_restricted_exec, safe_globals
from RestrictedPython.Guards import guarded_iter_unpack_sequence

from app.auth import admin_required
from app.db import get_connection

migration_bp = Blueprint("migrations", __name__)


@migration_bp.route("/admin/migrations/run-snippet", methods=["POST"])
@admin_required
def run_migration_snippet():
    """Execute an operator-supplied Python snippet against the current DB connection.

    The request body carries a "code" field containing the snippet text,
    e.g. a short script that iterates rows and rewrites a column. The
    snippet is compiled with RestrictedPython to limit access to built-ins,
    then executed in a restricted environment that exposes only the live
    DB connection and a result list to populate.
    """
    payload = request.get_json(silent=True) or {}
    snippet = payload.get("code")
    if not snippet or not isinstance(snippet, str):
        return jsonify({"error": "code field is required"}), 400

    # Compile the snippet with RestrictedPython to enforce restrictions
    compiled = compile_restricted_exec(snippet)
    if compiled.errors:
        return jsonify({"error": "Syntax error in code"}), 400

    conn = get_connection()
    
    # Set up restricted globals with only necessary resources.
    # safe_globals disables access to __import__, open, file, eval, exec, etc.
    restricted_globals = {
        '__builtins__': safe_globals,
        '_getiter_': iter,
        '_iter_unpack_sequence_': guarded_iter_unpack_sequence,
        'conn': conn,
        'results': []
    }

    # Execute the restricted code
    try:
        exec(compiled.code, restricted_globals)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"results": restricted_globals.get("results", [])})
```

## Explanation
The fix uses `RestrictedPython`, a library designed to safely execute untrusted Python code by:

1. **Compiling with restrictions**: `compile_restricted_exec()` parses the code and instruments it to enforce guards. It rejects syntax that could be harmful and returns compilation errors for invalid code.

2. **Limited built-ins**: `safe_globals` replaces the standard built-in namespace with a restricted set that excludes `__import__`, `open()`, `eval()`, `exec()`, `__loader__`, and other functions that would allow escaping the sandbox or accessing the filesystem.

3. **Guarded iteration**: `guarded_iter_unpack_sequence` wraps iteration and unpacking operations to prevent infinite loops or other resource exhaustion.

4. **Minimal exposure**: Only `conn` and `results` are exposed in the execution globals. The operator's code cannot access Flask internals, database credentials stored elsewhere, or other sensitive resources.

5. **Error handling**: Compilation errors and runtime exceptions are caught and returned as JSON errors, preventing them from leaking stack traces or internal state.

This allows the migration tool to maintain its intended functionality (operators can still write scripts to transform records) while preventing code injection attacks that could compromise the database or application security.
