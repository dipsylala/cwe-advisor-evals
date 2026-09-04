## Verdict

**Confirmed.** The code executes arbitrary user-supplied Python strings via `exec()` without restriction. Although gated by an `@admin_required` decorator, this creates a code injection vulnerability because an admin's account compromise, credential leakage, or social engineering can lead to arbitrary code execution with the application's full privileges.

## Source

```python
# Line 37 in evals/cases/94/python/ExecUserSuppliedCode/ExecUserSuppliedCode.py
exec(snippet, migration_globals)
```

The `snippet` parameter originates from user input (`payload.get("code")`) at line 29 and is passed directly to `exec()` with minimal validation (only a type and presence check at line 30).

## Fix

Replace the unrestricted `exec()` call with a restricted execution environment that prevents access to dangerous built-in functions:

```python
import types

@migration_bp.route("/admin/migrations/run-snippet", methods=["POST"])
@admin_required
def run_migration_snippet():
    """Execute an operator-supplied Python snippet against the current DB connection."""
    payload = request.get_json(silent=True) or {}
    snippet = payload.get("code")
    if not snippet or not isinstance(snippet, str):
        return jsonify({"error": "code field is required"}), 400

    conn = get_connection()
    migration_globals = {"conn": conn, "results": []}
    
    # Restrict access to dangerous built-ins
    restricted_builtins = {
        "len": len,
        "range": range,
        "enumerate": enumerate,
        "zip": zip,
        "sorted": sorted,
        "reversed": reversed,
        "sum": sum,
        "min": min,
        "max": max,
        "abs": abs,
        "round": round,
        "str": str,
        "int": int,
        "float": float,
        "list": list,
        "dict": dict,
        "set": set,
        "tuple": tuple,
        "bool": bool,
        "type": type,
        "isinstance": isinstance,
        "issubclass": issubclass,
        "hasattr": hasattr,
        "getattr": getattr,
        "setattr": setattr,
        "delattr": delattr,
        "callable": callable,
        "print": print,
        "None": None,
        "True": True,
        "False": False,
        "Exception": Exception,
        "ValueError": ValueError,
        "TypeError": TypeError,
        "KeyError": KeyError,
        "IndexError": IndexError,
    }
    
    migration_globals["__builtins__"] = restricted_builtins
    
    try:
        exec(snippet, migration_globals)
    except Exception as e:
        return jsonify({"error": f"Execution failed: {str(e)}"}), 400

    return jsonify({"results": migration_globals.get("results", [])})
```

## Explanation

This fix addresses CWE-94 by preventing access to dangerous built-in functions and modules that could compromise the system:

1. **Restricted `__builtins__`**: By explicitly setting `__builtins__` to a controlled dictionary, the executed code cannot access functions like `__import__`, `open`, `eval`, `compile`, `exec`, or `__loader__`, which would allow file access, subprocess execution, or further code injection.

2. **Preserves Required Functionality**: The allowlist includes safe functions needed for typical data manipulation (iteration, type conversion, collections, attribute access) while the snippet still has access to the passed `conn` and `results` objects for database operations.

3. **Error Handling**: Added a try-except block to catch and report execution errors gracefully, preventing uncaught exceptions from exposing internal details.

4. **Defense in Depth**: While the `@admin_required` decorator provides access control, restricting the execution environment ensures that even a compromised admin account cannot escalate privileges beyond what the restricted environment permits.

The fix maintains the intended functionality (allowing an admin to execute data migration logic) while eliminating the ability to execute arbitrary system operations.
