## Verdict

Exploitable.

## Source

User-supplied JSON parameter `plugin_name = payload["plugin"]` (line 22) directly from HTTP POST request, with no validation or sanitization.

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
# Define allowed plugins as a fixed dictionary mapping
ALLOWED_PLUGINS = {
    "csv_export": "plugins.csv_export",
    "pdf_export": "plugins.pdf_export",
    # Add other approved plugins here as needed
}

@app.route("/plugins/run", methods=["POST"])
def run_plugin():
    payload = request.get_json(force=True)
    plugin_name = payload["plugin"]

    # Validate against allowlist of approved plugins
    if plugin_name not in ALLOWED_PLUGINS:
        return jsonify({"status": "error", "message": "Unknown plugin"}), 400
    
    # Use the canonical module name from the allowlist, not user input
    module_name = ALLOWED_PLUGINS[plugin_name]
    plugin_module = importlib.import_module(module_name)

    context = _build_plugin_context(payload)
    result = plugin_module.run(context)
    return jsonify({"status": "ok", "result": result})
```

## Explanation

The original code passes user input directly to `importlib.import_module()`, which executes the target module's top-level code. An attacker can inject arbitrary module names (e.g., `"os"`, `"sys"`) to execute any module available in the Python environment, gaining full access to the application's runtime, variables, and secrets. The fix implements an allowlist of approved plugin modules and validates the user input against it before import. Only canonical module names from the allowlist dictionary are used; the original user input is discarded. If the input does not match an allowlist entry, an error response is returned immediately, preventing any import attempt. This eliminates the code injection vector entirely by removing the ability to dynamically specify arbitrary module names.

## Behaviour changes

1. **Error handling**: The endpoint now returns an HTTP 400 error with `{"status": "error", "message": "Unknown plugin"}` if the requested plugin is not in the allowlist. The original code would attempt the import and return a 500 error if the module was not found. Callers must now handle 400 responses in addition to 200.
2. **Module resolution**: The canonical module name from `ALLOWED_PLUGINS` is used instead of the user-supplied name. If approved plugins are nested under a package (e.g., `plugins.csv_export`), callers request by short name (e.g., `"csv_export"`) while the actual import uses the full path. This decouples the public API from internal package structure.
3. **Scope reduction**: Only pre-registered plugins can be loaded; arbitrary modules cannot be imported. This is the intended security boundary and removes unintended extensibility.
