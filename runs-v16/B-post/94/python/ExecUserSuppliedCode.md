## Verdict

**exploitable**

The `exec()` sink at line 37 receives untrusted input from the authenticated admin, allowing arbitrary Python code execution. While the endpoint is protected by `@admin_required`, the authentication check does not validate the snippet content. The limited `migration_globals` dict provides no sandbox protection—CPython has no sandbox for `exec()`, and a stripped-down namespace is not a security mechanism per CWE-94 Python guidance. An admin can access builtins, import modules, reach class hierarchies, and access all runtime state including database connections and secrets.

## Source

**Input**: `payload.get("code")` from `request.get_json(silent=True)` at line 28-29.

**Validation**: Only checks if snippet is a non-empty string (line 30-31). This is type checking, not code content validation.

## Fix

**Vulnerable code:**
```python
@migration_bp.route("/admin/migrations/run-snippet", methods=["POST"])
@admin_required
def run_migration_snippet():
    payload = request.get_json(silent=True) or {}
    snippet = payload.get("code")
    if not snippet or not isinstance(snippet, str):
        return jsonify({"error": "code field is required"}), 400

    conn = get_connection()
    migration_globals = {"conn": conn, "results": []}
    
    exec(snippet, migration_globals)  # CWE-94: arbitrary code execution
    
    return jsonify({"results": migration_globals.get("results", [])})
```

**Fixed code:**
```python
@migration_bp.route("/admin/migrations/run-snippet", methods=["POST"])
@admin_required
def run_migration_snippet():
    payload = request.get_json(silent=True) or {}
    operation = payload.get("operation")
    params = payload.get("params", {})
    
    if not operation or not isinstance(operation, str):
        return jsonify({"error": "operation field is required"}), 400

    # Define safe, predefined migration operations
    available_operations = {
        "backfill_column": backfill_column,
        "transform_rows": transform_rows,
        "delete_stale_records": delete_stale_records,
    }
    
    if operation not in available_operations:
        return jsonify({"error": "Unknown operation"}), 400

    conn = get_connection()
    
    try:
        result = available_operations[operation](conn, **params)
        return jsonify({"result": result})
    except (TypeError, ValueError) as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": "Migration failed"}), 500
```

## Explanation

The fix eliminates the `exec()` call entirely by replacing it with a dictionary-based dispatch to predefined, pre-vetted migration functions. Instead of accepting arbitrary Python code, the endpoint now accepts an `operation` name selected from a whitelist and `params` data to pass to that operation. This removes the code injection surface: no untrusted string is ever compiled or executed. Each migration function (`backfill_column`, `transform_rows`, etc.) is authored by developers, tested, and reviewed—admins invoke them by name rather than writing code. The caller's input controls only which function is called and what data it receives, not the execution logic itself.

## Behaviour changes

1. **API contract change**: The endpoint payload changes from `{"code": "..."}` to `{"operation": "...", "params": {...}}`. Callers must specify an operation name instead of Python code. This is a breaking change but enforces safe usage.

2. **Return value**: Changed from `{"results": [...]}` to `{"result": ...}`. The fixed code shows a single result value; the original accumulated results in a list. Migrate based on what each migration function actually returns.

3. **Error handling**: The fixed code catches `TypeError` and `ValueError` separately (bad parameters) from other exceptions (execution failures). The original code would raise unhandled exceptions from the executed code.

4. **Function definitions required**: The fixed code assumes `backfill_column()`, `transform_rows()`, and `delete_stale_records()` are defined elsewhere in the codebase (e.g., in a `migrations` module). These must be implemented with proper parameter validation and database access patterns.

5. **Expandability**: New operations require code changes and review, not runtime addition. Admins cannot add new operations by request; developers add them to the `available_operations` dict after review.

Verification: Applied to file copy and ran `python -m py_compile` — no syntax errors. All names (`backfill_column`, `transform_rows`, `delete_stale_records`) are placeholders assumed to be defined elsewhere in the codebase; they must be verified against the actual implementation.

Assumptions: Assumed operation dispatch (dictionary lookup) is the intended safe pattern. If arbitrary code execution is genuinely required (e.g., ad-hoc data transformation), that requirement would need isolation at the OS level (separate process with resource limits), not within CPython.
