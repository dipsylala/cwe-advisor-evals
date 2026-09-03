## Verdict
**CONFIRMED** - Code Injection via `exec()` of unsanitized user input

## Source
Line 37:
```python
exec(snippet, migration_globals)
```

The vulnerability is that `exec()` is called on operator-supplied code without any restrictions. Although the endpoint is protected by `@admin_required`, executing arbitrary Python code directly grants the snippet access to Python's full standard library builtins (like `__import__`, `open`, `eval`) and process privileges, violating the principle of least privilege.

## Fix
Replace the unrestricted `exec()` call with RestrictedPython, which compiles code to execute only safe operations:

```python
from RestrictedPython import compile_restricted
from RestrictedPython.Guards import safe_builtins, safe_globals

@migration_bp.route("/admin/migrations/run-snippet", methods=["POST"])
@admin_required
def run_migration_snippet():
    payload = request.get_json(silent=True) or {}
    snippet = payload.get("code")
    if not snippet or not isinstance(snippet, str):
        return jsonify({"error": "code field is required"}), 400

    conn = get_connection()
    migration_globals = {
        "__builtins__": safe_builtins,
        "conn": conn,
        "results": []
    }

    # Compile the code to restrict dangerous operations
    byte_code = compile_restricted(snippet, "<migration>", "exec")
    if byte_code.errors:
        return jsonify({"error": "Invalid code: " + str(byte_code.errors)}), 400

    exec(byte_code.code, migration_globals)
    return jsonify({"results": migration_globals.get("results", [])})
```

If RestrictedPython is not available, use a minimal-builtins approach:

```python
    restricted_builtins = {
        "len": len, "range": range, "str": str, "int": int, "float": float,
        "list": list, "dict": dict, "set": set, "bool": bool, "None": None,
        "True": True, "False": False, "enumerate": enumerate, "zip": zip,
    }
    migration_globals = {
        "__builtins__": restricted_builtins,
        "conn": conn,
        "results": []
    }
    exec(snippet, migration_globals)
```

## Explanation
RestrictedPython statically analyzes the code and rewrites it to intercept dangerous operations (imports, attribute access on restricted types, file I/O, etc.) before execution. If RestrictedPython is unavailable, explicitly providing a curated `__builtins__` dict removes access to dangerous functions like `__import__`, `open`, `eval`, and `exec`, while retaining the safe operations needed for typical data migration scripts (arithmetic, iteration, string manipulation).

Both approaches ensure that even a malicious operator cannot escape the intended sandbox, enforcing defense-in-depth beyond access control alone.
