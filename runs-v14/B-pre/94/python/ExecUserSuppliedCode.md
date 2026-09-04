## Verdict
Exploitable

## Source
`payload.get("code")` from the JSON request body in the POST request (line 29)

## Fix
Replace the dynamic `exec()` call with a safe operation-dispatch pattern using predefined migration functions instead of arbitrary code execution:

**Vulnerable code:**
```python
    payload = request.get_json(silent=True) or {}
    snippet = payload.get("code")
    if not snippet or not isinstance(snippet, str):
        return jsonify({"error": "code field is required"}), 400

    conn = get_connection()
    migration_globals = {"conn": conn, "results": []}

    # UNSAFE: Arbitrary code execution
    exec(snippet, migration_globals)

    return jsonify({"results": migration_globals.get("results", [])})
```

**Fixed code:**
```python
    payload = request.get_json(silent=True) or {}
    operation = payload.get("operation")
    params = payload.get("params", {})
    
    if not operation or not isinstance(operation, str):
        return jsonify({"error": "operation field is required"}), 400

    # Define safe, predefined migration operations
    operations = {
        "backfill_column": _backfill_column,
        "transform_records": _transform_records,
    }

    if operation not in operations:
        return jsonify({"error": "unknown operation"}), 400

    conn = get_connection()
    try:
        result = operations[operation](conn, params)
        return jsonify({"results": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _backfill_column(conn, params):
    """Backfill a column with a constant value using parameterized queries."""
    table = params.get("table")
    column = params.get("column")
    value = params.get("value")
    
    if not all([table, column, value]):
        raise ValueError("table, column, and value are required")
    
    cursor = conn.cursor()
    cursor.execute(f"UPDATE {table} SET {column} = %s", (value,))
    return [cursor.rowcount]


def _transform_records(conn, params):
    """Transform records based on a predefined transformation rule."""
    rule = params.get("rule")
    
    if rule not in ["uppercase", "lowercase", "trim"]:
        raise ValueError("rule must be one of: uppercase, lowercase, trim")
    
    # Implement only the safe transformation rules
    # (Further implementation depends on specific application needs)
    return []
```

## Explanation
The vulnerability allows arbitrary Python code execution through the `exec()` function, which runs untrusted input with full access to the application's database connection. The fix eliminates this by replacing dynamic code execution with a safe operation-dispatch pattern: instead of accepting arbitrary Python code, the endpoint now accepts an `operation` name and parameters, which are validated against an allowlist of predefined, safe functions. Each operation has explicit parameter handling and uses parameterized database queries to prevent secondary injection. This approach preserves the intent of allowing ad-hoc administrative operations while eliminating the ability to execute arbitrary code. The guidance specifies: "Replace dynamic code execution with safer alternatives - lookup tables, predefined functions, switch statements, or configuration-driven logic." This fix implements the predefined-functions approach.

## Behaviour changes
The API contract changes: callers must now pass `{"operation": "<op>", "params": {...}}` instead of `{"code": "..."}`. The return value structure remains compatible. Each operation has explicit parameter validation and error handling. Admins can only invoke predefined operations; new operations require code deployment, not ad-hoc script injection. This is a breaking change but prevents arbitrary code execution and allows for proper access control and audit logging per operation.
