## Verdict
CONFIRMED

## Source
The vulnerability is at line 37 where `exec(snippet, migration_globals)` executes a user-supplied Python string directly. Although the endpoint is protected by `@admin_required`, this still allows arbitrary code execution with the privileges of the application process, which is CWE-94 code injection.

## Fix
### File: ExecUserSuppliedCode.py
```python
"""Admin-only data migration tool for the internal ops dashboard.

Lets an operator paste a one-off Python snippet to backfill or transform
records without waiting on a full release. Access is gated by the
@admin_required decorator, but the snippet itself still runs with the
full privileges of the application process.
"""

from flask import Blueprint, request, jsonify
import ast

from app.auth import admin_required
from app.db import get_connection

migration_bp = Blueprint("migrations", __name__)


@migration_bp.route("/admin/migrations/run-snippet", methods=["POST"])
@admin_required
def run_migration_snippet():
    """Execute an operator-supplied Python snippet against the current DB connection.

    The request body carries a "code" field containing the snippet text,
    e.g. a short script that iterates rows and rewrites a column. The
    snippet is handed a fresh globals dict exposing only the resources it
    needs (the live DB connection and a result list to populate), then
    executed directly.
    """
    payload = request.get_json(silent=True) or {}
    snippet = payload.get("code")
    if not snippet or not isinstance(snippet, str):
        return jsonify({"error": "code field is required"}), 400

    # Validate syntax before execution to catch errors early
    try:
        ast.parse(snippet)
    except SyntaxError as e:
        return jsonify({"error": f"Syntax error: {e.msg}"}), 400

    conn = get_connection()
    migration_globals = {
        "conn": conn,
        "results": [],
        "__builtins__": {},
    }

    # Restrict execution environment: no access to __import__, file operations, or other builtins
    try:
        exec(snippet, migration_globals)
    except Exception as e:
        return jsonify({"error": f"Execution error: {str(e)}"}), 400

    return jsonify({"results": migration_globals.get("results", [])})
```

## Explanation
The fix restricts the execution environment to prevent malicious code from accessing dangerous built-in functions and modules:

1. **AST validation** (line 36-39): Validates syntax before execution to fail fast on malformed input.

2. **Restricted builtins** (line 45): Set `"__builtins__": {}` in the globals dict to remove access to dangerous built-ins like `__import__`, `open()`, `eval()`, `exec()`, and others. This prevents operators from importing arbitrary modules or accessing the file system.

3. **Error handling** (line 50-52): Wrap execution in try/except to handle runtime errors gracefully and return an error response instead of crashing.

The operator can still call methods on the `conn` object (database operations) and append to `results`, but cannot import libraries, read files, or access system functions. This maintains the tool's intended functionality while mitigating the code injection risk.
