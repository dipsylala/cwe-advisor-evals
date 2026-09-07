## Verdict

exploitable

## Source

Line 22: `plugin_name = payload["plugin"]` — untrusted user input from Flask JSON request body.

## Fix

**Vulnerable code:**
```python
@app.route("/plugins/run", methods=["POST"])
def run_plugin():
    payload = request.get_json(force=True)
    plugin_name = payload["plugin"]

    # Untrusted input passed directly to importlib.import_module
    plugin_module = importlib.import_module(plugin_name)

    context = _build_plugin_context(payload)
    result = plugin_module.run(context)
    return jsonify({"status": "ok", "result": result})
```

**Fixed code:**
```python
# Define the allowlist of permitted plugins
ALLOWED_PLUGINS = {
    "csv_export": "plugins.csv_export",
    "pdf_export": "plugins.pdf_export",
    # Add other legitimate plugins here
}

@app.route("/plugins/run", methods=["POST"])
def run_plugin():
    payload = request.get_json(force=True)
    plugin_name = payload["plugin"]

    # Validate against allowlist before importing
    if plugin_name not in ALLOWED_PLUGINS:
        return jsonify({"status": "error", "message": "Unknown plugin"}), 400

    plugin_module = importlib.import_module(ALLOWED_PLUGINS[plugin_name])

    context = _build_plugin_context(payload)
    result = plugin_module.run(context)
    return jsonify({"status": "ok", "result": result})
```

## Explanation

The fix replaces the dangerous dynamic module loading with an allowlist-based dispatcher. The user-supplied `plugin_name` is validated against a fixed dictionary `ALLOWED_PLUGINS` before any import occurs. Only whitelisted plugin names are accepted; any other value returns an error. The actual module path is resolved through the dictionary, so the attacker cannot control which module is imported. This prevents attackers from importing arbitrary system modules (os, sys, subprocess, etc.) whose top-level code would execute immediately upon import.

## Behaviour changes

The route now rejects requests with unknown plugin names by returning a 400 error with an error message. Previously, such requests would attempt to import any Python module and either succeed (exposing arbitrary modules) or fail with an ImportError. The fixed code ensures only pre-approved plugins can be loaded.
