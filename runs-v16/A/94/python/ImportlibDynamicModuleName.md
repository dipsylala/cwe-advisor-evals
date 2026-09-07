## Verdict

The code injection vulnerability is confirmed. Line 25 passes an untrusted request parameter directly to `importlib.import_module()` without validation, allowing an attacker to load arbitrary Python modules.

## Source

Line 25 in `plugin_loader.py`:
```python
plugin_module = importlib.import_module(plugin_name)
```

The `plugin_name` is sourced from the JSON request payload (`payload["plugin"]`) with no allowlist or validation applied before being passed to the dynamic import function.

## Fix

Replace line 25 with a validation step that checks the plugin name against a whitelist of allowed plugins before importing:

```python
ALLOWED_PLUGINS = {"csv_export", "pdf_export"}

@app.route("/plugins/run", methods=["POST"])
def run_plugin():
    payload = request.get_json(force=True)
    plugin_name = payload["plugin"]
    
    if plugin_name not in ALLOWED_PLUGINS:
        return jsonify({"status": "error", "message": "Plugin not allowed"}), 403
    
    plugin_module = importlib.import_module(plugin_name)
    context = _build_plugin_context(payload)
    result = plugin_module.run(context)
    return jsonify({"status": "ok", "result": result})
```

## Explanation

CWE-94 code injection through dynamic module loading occurs when attacker-controlled input is passed to functions like `importlib.import_module()`. An attacker can craft a malicious module name to load unintended modules, potentially triggering import hooks or side effects in unrelated code.

The fix establishes an explicit allowlist of permitted plugin names. This restricts `importlib.import_module()` to load only pre-approved modules, closing the injection vector entirely. The whitelist is the primary defense; the 403 response signals that the requested plugin is not authorized.

This approach assumes plugins are known in advance and managed by the application owner. If plugins must be dynamically discovered, use a plugin registry pattern instead: maintain an explicit registry of installed plugins, validate the request name against that registry, and reject unknown names outright.
