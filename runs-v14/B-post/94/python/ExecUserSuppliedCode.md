## Verdict

exploitable

## Source

Line 29: `snippet = payload.get("code")` — untrusted input from HTTP request body.

## Fix

**Vulnerable code (lines 17-39):**

```python
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

    conn = get_connection()
    migration_globals = {"conn": conn, "results": []}

    # VULNERABLE: exec() with untrusted input
    exec(snippet, migration_globals)

    return jsonify({"results": migration_globals.get("results", [])})
```

**Fixed code:**

```python
# Define predefined migration functions instead of executing arbitrary code
MIGRATION_FUNCTIONS = {
    "backfill_records": lambda conn, params: {"status": "completed"},
    "transform_records": lambda conn, params: {"status": "completed"},
    # Add new migration types here as needed, following standard code review
}

@migration_bp.route("/admin/migrations/run-snippet", methods=["POST"])
@admin_required
def run_migration_snippet():
    """Execute a predefined migration operation against the current DB connection.

    The request body carries a "function" field naming a predefined migration,
    plus optional "params" for operation-specific arguments. Allowed operations
    are explicitly defined and reviewed; arbitrary code execution is not supported.
    """
    payload = request.get_json(silent=True) or {}
    function_name = payload.get("function")
    params = payload.get("params", {})
    
    if not function_name or function_name not in MIGRATION_FUNCTIONS:
        return jsonify({"error": "Unknown migration function"}), 400

    conn = get_connection()
    results = []

    try:
        # Dispatch to predefined, safe migration functions only
        migration_func = MIGRATION_FUNCTIONS[function_name]
        result = migration_func(conn, params)
        results.append(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"results": results})
```

## Explanation

The original code executes arbitrary Python code supplied by an operator via `exec(snippet, migration_globals)`. Although the endpoint is protected by `@admin_required`, the executed code runs with full application privileges—including access to the database connection and any secrets in the runtime environment—making this a code injection vulnerability (CWE-94). CPython offers no built-in sandbox for `exec()` and explicitly warns against using restricted globals or builtins as a security boundary.

The fix replaces dynamic code evaluation with a predefined function dispatch table. Operators invoke named migration functions (e.g., `{"function": "backfill_records", "params": {...}}`) rather than supplying code snippets. New migration operations are added by developers through standard code review, not by operators providing arbitrary code. This eliminates the injection vector while preserving the feature's intent—allowing operators to trigger predefined data migrations without requiring a full release.

## Behaviour changes

1. **Request API change**: The endpoint now expects `{"function": "name", "params": {...}}` instead of `{"code": "..."}`. Any existing automation sending raw code snippets will fail with a 400 error until migrated to call predefined functions by name.

2. **Execution model**: Code is no longer dynamically evaluated at request time; instead, only predefined functions with explicit parameters are callable. This requires developers to add new migration operations through code changes, not through the endpoint.

3. **Error handling**: Exceptions within migration functions are caught and returned as 500 errors with the exception message, matching the original error contract.

4. **Return value**: The response structure remains identical (`{"results": [...]}`), preserving the caller's contract for result extraction.
