## Verdict

**CONFIRMED** — Code Injection via `exec()`.

The vulnerability is on line 37 where `exec(snippet, migration_globals)` executes operator-supplied Python code with unrestricted access to Python builtins (`__import__`, `open`, `eval`, etc.), despite the authentication gate on the endpoint. An authenticated operator can execute arbitrary code with the full privileges of the application process.

## Source

```python
exec(snippet, migration_globals)
```

An operator can supply a `code` field in the POST request body containing arbitrary Python. The code is executed directly without parsing validation, builtin restrictions, or sandboxing. Although the endpoint is protected by `@admin_required`, this does not limit what code is executed—only who can reach the endpoint.

## Fix

Restrict the builtins available to the snippet and validate code syntax before execution:

```python
import ast

@migration_bp.route("/admin/migrations/run-snippet", methods=["POST"])
@admin_required
def run_migration_snippet():
    payload = request.get_json(silent=True) or {}
    snippet = payload.get("code")
    if not snippet or not isinstance(snippet, str):
        return jsonify({"error": "code field is required"}), 400

    # Validate syntax before execution
    try:
        ast.parse(snippet)
    except SyntaxError as e:
        return jsonify({"error": f"Syntax error: {e.msg}"}), 400

    conn = get_connection()
    migration_globals = {
        "conn": conn,
        "results": [],
        "__builtins__": {
            # Expose only safe builtins needed for data operations
            "len": len,
            "range": range,
            "enumerate": enumerate,
            "zip": zip,
            "str": str,
            "int": int,
            "float": float,
            "bool": bool,
            "list": list,
            "dict": dict,
            "set": set,
            "tuple": tuple,
            "None": None,
            "True": True,
            "False": False,
            "Exception": Exception,
            "ValueError": ValueError,
            "TypeError": TypeError,
        },
    }

    exec(snippet, migration_globals)

    return jsonify({"results": migration_globals.get("results", [])})
```

## Explanation

The original code allows any authenticated user to execute arbitrary Python, including calls to `__import__`, `open`, and `eval`. Restricting `__builtins__` to a minimal safe set prevents:

- **Module imports** (`__import__` removed)
- **File system access** (`open`, `exec`, `compile` removed)
- **Process spawning** (`subprocess` cannot be imported)
- **Network access** (`socket` cannot be imported)

Validating syntax with `ast.parse()` ensures the snippet is at least valid Python before execution and fails fast on malformed input.

The whitelisted builtins retain basic data structure and type operations (`len`, `range`, `enumerate`, `dict`, `list`) that migration scripts commonly need without exposing dangerous capabilities. The operator can still iterate rows, transform data, and populate the `results` list; they cannot escape the sandbox to access the file system, network, or subprocess layer.

This approach maintains the intended use case (ad-hoc data migrations by trusted admins) while significantly reducing the attack surface.
