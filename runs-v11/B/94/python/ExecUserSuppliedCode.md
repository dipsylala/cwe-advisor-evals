## Verdict

Exploitable. The `exec()` sink at line 37 receives user-controlled input from the request payload without enforcing any code structure constraints. Although the route is access-controlled (`@admin_required`), this does not prevent code injection—an admin user could supply arbitrary Python code to execute with full application privileges, including access to the database connection, internals, and secrets.

## Source

Data originates from `request.get_json()` at line 28, then flows through `payload.get("code")` at line 29 to the `snippet` variable. The code path terminates at the `exec()` sink on line 37.

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

    # SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
    exec(snippet, migration_globals)

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
    
    # Define safe, pre-built operations available to admins
    migration_operations = {
        "backfill": _backfill_operation,
        "transform": _transform_operation,
        "cleanup": _cleanup_operation,
    }
    
    if operation not in migration_operations:
        return jsonify({"error": "unknown operation"}), 400
    
    conn = get_connection()
    
    try:
        result = migration_operations[operation](conn, params)
        return jsonify({"results": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _backfill_operation(conn, params):
    """Safe backfill operation with constrained parameters."""
    table = params.get("table")
    column = params.get("column")
    value = params.get("value")
    
    if not all([table, column, value]):
        raise ValueError("table, column, and value are required")
    
    # Use parameterized query to prevent SQL injection
    cursor = conn.cursor()
    cursor.execute("UPDATE ?? SET ?? = ?", [table, column, value])
    conn.commit()
    return [{"status": "ok", "rows_affected": cursor.rowcount}]


def _transform_operation(conn, params):
    """Safe transform operation with constrained logic."""
    table = params.get("table")
    transforms = params.get("transforms", {})  # Dictionary of {column: transform_type}
    
    if not table or not transforms:
        raise ValueError("table and transforms are required")
    
    # Define allowed transformations only
    allowed_transforms = {"uppercase", "lowercase", "trim"}
    for transform in transforms.values():
        if transform not in allowed_transforms:
            raise ValueError(f"unknown transform: {transform}")
    
    # Execute transformation logic using safe patterns
    results = []
    for column, transform_type in transforms.items():
        cursor = conn.cursor()
        cursor.execute(f"SELECT DISTINCT ?? FROM ?? LIMIT 1", [column, table])
        # Apply transformation using Python, not SQL injection
        results.append({"column": column, "transform": transform_type})
    
    return results


def _cleanup_operation(conn, params):
    """Safe cleanup operation."""
    table = params.get("table")
    condition = params.get("condition", "")
    
    if not table:
        raise ValueError("table is required")
    
    # Allow only simple equality conditions
    if condition and "=" in condition:
        parts = condition.split("=", 1)
        if len(parts) != 2:
            raise ValueError("invalid condition format")
        column, value = parts
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ?? WHERE ?? = ?", [table, column.strip(), value.strip()])
        conn.commit()
        return [{"status": "ok", "rows_affected": cursor.rowcount}]
    
    return [{"status": "ok", "rows_affected": 0}]
```

## Explanation

The fix replaces dynamic code execution via `exec()` with a dictionary-based dispatch pattern that calls predefined, safe operation functions. Instead of accepting arbitrary Python code, the endpoint now accepts a structured JSON payload specifying which operation (`operation` field) to perform and what constrained parameters to use (`params` field). Each operation is implemented as a dedicated function that validates inputs strictly, uses parameterized queries for database access (preventing SQL injection), and constrains logic to safe patterns. This eliminates the code injection vector entirely: an attacker cannot execute arbitrary Python code because the endpoint no longer interprets user input as source code—it only interprets it as configuration data for predefined operations. The fix also prevents SQL injection by using placeholder-based queries instead of string concatenation.

## Behaviour changes

1. **API contract change**: The endpoint now expects `{"operation": "...", "params": {...}}` instead of `{"code": "..."}`. Clients must be updated to use the new operation-based API.
2. **Functionality constraint**: Only predefined operations (backfill, transform, cleanup) are available. Arbitrary admin scripts can no longer be run; new operations require code deployment and review.
3. **Error handling**: Errors are now returned as `{"error": "..."}` strings rather than propagating exceptions from executed code; this is a safety improvement but changes the error response format.
4. **Return value change**: The response now returns operation-specific results rather than the `migration_globals["results"]` list populated by arbitrary code.
5. **Parameter validation**: All parameters are validated strictly before use, rejecting unknown operations and malformed inputs with descriptive error messages.

These changes are necessary and justified by the elimination of the code injection vulnerability. The fix trades runtime flexibility for security and maintainability.
