## Verdict

exploitable

## Source

`plugin_name = payload["plugin"]` at line 22, where `payload` is untrusted JSON from `request.get_json(force=True)` on line 21. The user-supplied plugin name flows directly from the POST request to the dynamic import sink.

## Fix

### File: plugin_loader.py

```python
"""Plugin loading endpoint for the reporting service.

Installed report plugins (e.g. ``csv_export``, ``pdf_export``) are ordinary
importable Python modules, each exposing a module-level ``run(context)`` entry
point that the loader invokes once the module has been imported.
"""

import importlib

from flask import Flask, jsonify, request

app = Flask(__name__)

# Whitelist of allowed plugin modules
ALLOWED_PLUGINS = {
    "csv_export",
    "pdf_export",
}


def _build_plugin_context(payload):
    return {"requested_by": payload.get("user"), "options": payload.get("options", {})}


@app.route("/plugins/run", methods=["POST"])
def run_plugin():
    payload = request.get_json(force=True)
    plugin_name = payload["plugin"]

    # Validate plugin_name against whitelist before importing
    if plugin_name not in ALLOWED_PLUGINS:
        return jsonify({"status": "error", "message": "Plugin not found"}), 404

    plugin_module = importlib.import_module(plugin_name)

    context = _build_plugin_context(payload)
    result = plugin_module.run(context)
    return jsonify({"status": "ok", "result": result})
```

## Explanation

The vulnerability exists because `importlib.import_module()` dynamically loads and executes any Python module by name. When given a user-supplied plugin name without validation, an attacker can import arbitrary installed modules or modules on the Python path, executing their top-level code with the application's privileges.

The fix introduces an `ALLOWED_PLUGINS` whitelist containing only the known safe plugin module names. Before importing, the code validates that `plugin_name` is in this whitelist. If the request specifies a module not in the whitelist, the endpoint returns a 404 error response instead of importing the module. This eliminates the code injection risk by ensuring only pre-approved modules can be loaded, preventing attackers from reaching dangerous modules through dynamic import.

## Behaviour changes

The endpoint now rejects requests for plugins not in the `ALLOWED_PLUGINS` whitelist, returning `{"status": "error", "message": "Plugin not found"}` with HTTP 404 status. Previously, any installed Python module name could be imported. This is an intentional restriction that prevents code injection and requires the calling client to know which plugins are available. No changes to the sink contract (`importlib.import_module()` still receives a valid module name, still returns the same module object, still executes top-level code when called). The modified return paths add a new 404 response for disallowed plugins, which is a necessary behaviour change to implement the security fix.
