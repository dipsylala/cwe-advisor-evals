## Verdict

exploitable

## Source

Line 22: `plugin_name = payload["plugin"]` — untrusted user-supplied JSON parameter

## Sink

Line 25: `plugin_module = importlib.import_module(plugin_name)` — dynamically loads and executes the named module's top-level code with full application privileges

## Fix

**Vulnerable code:**

```python
@app.route("/plugins/run", methods=["POST"])
def run_plugin():
    payload = request.get_json(force=True)
    plugin_name = payload["plugin"]

    # SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
    plugin_module = importlib.import_module(plugin_name)

    context = _build_plugin_context(payload)
    result = plugin_module.run(context)
    return jsonify({"status": "ok", "result": result})
```

**Fixed code:**

```python
# Map allowed plugin names to their modules (pre-loaded, not user-controlled)
AVAILABLE_PLUGINS = {
    "csv_export": importlib.import_module("csv_export"),
    "pdf_export": importlib.import_module("pdf_export"),
}


@app.route("/plugins/run", methods=["POST"])
def run_plugin():
    payload = request.get_json(force=True)
    plugin_name = payload["plugin"]

    # Validate plugin name against allowlist before loading
    if plugin_name not in AVAILABLE_PLUGINS:
        return jsonify({"status": "error", "message": "Unknown plugin"}), 400

    plugin_module = AVAILABLE_PLUGINS[plugin_name]

    context = _build_plugin_context(payload)
    result = plugin_module.run(context)
    return jsonify({"status": "ok", "result": result})
```

## Explanation

The vulnerability allowed arbitrary code execution by mapping any user-supplied module name through `importlib.import_module()`, which loads and executes that module's top-level code. An attacker could request any installed package (e.g., `os`, `subprocess`, or a malicious package in the Python path) to execute arbitrary code with full application privileges.

The fix replaces dynamic module loading with a fixed allowlist dictionary (`AVAILABLE_PLUGINS`) that pre-loads only known, trusted plugins at application startup time using hardcoded module names. User input is validated against this allowlist and mapped to the pre-loaded module object, eliminating the ability to inject arbitrary module names. Unknown plugins return a 400 error instead of attempting to load them.

## Behaviour changes

- **Added error response:** The endpoint now returns HTTP 400 with an error message when an unknown plugin name is requested, instead of raising `ModuleNotFoundError`. This is a breaking change for clients that sent invalid plugin names and expected a 500 error, but it improves API semantics and security. The proper fix for callers is to use one of the known plugin names documented in the API.
- **Module loading moved to startup:** Plugins are now loaded once at application startup rather than on each request. This reduces runtime overhead and ensures that plugin availability is determined before serving any requests. If a plugin cannot be imported (e.g., not installed), the application fails to start with a clear error, rather than silently accepting the plugin name at request time only to fail later.
- **No change to returned values or context:** The `plugin_module.run(context)` contract remains identical; the result object and response structure are unchanged.

