## Verdict
CWE-94 confirmed: user-supplied plugin name passed directly to `importlib.import_module()` without validation, allowing arbitrary module imports and code execution.

## Source
Line 25 of `plugin_loader.py`:
```python
plugin_module = importlib.import_module(plugin_name)
```

The `plugin_name` originates from untrusted JSON payload (line 22: `plugin_name = payload["plugin"]`) with no prior validation.

## Fix
Define an allowlist of permitted plugin modules and validate the input against it before importing:

```python
ALLOWED_PLUGINS = {"csv_export", "pdf_export"}

@app.route("/plugins/run", methods=["POST"])
def run_plugin():
    payload = request.get_json(force=True)
    plugin_name = payload["plugin"]
    
    if plugin_name not in ALLOWED_PLUGINS:
        return jsonify({"error": "Plugin not found"}), 404
    
    plugin_module = importlib.import_module(plugin_name)
    
    context = _build_plugin_context(payload)
    result = plugin_module.run(context)
    return jsonify({"status": "ok", "result": result})
```

## Explanation
Dynamically importing modules by user-provided names is dangerous because `importlib.import_module()` will load and execute code from any installed or discoverable module. An attacker can supply names like `os`, `subprocess`, or custom malicious modules to gain arbitrary code execution.

The fix restricts imports to a static allowlist of known, safe plugin modules. The allowlist is defined at module level and checked before any import attempt. This prevents the attacker from injecting arbitrary module names while preserving the plugin system's core functionality.
