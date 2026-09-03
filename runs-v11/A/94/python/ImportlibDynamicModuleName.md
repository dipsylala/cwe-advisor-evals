## Verdict

The vulnerability is confirmed. Line 25 uses user-supplied input directly as a module name to `importlib.import_module()` without any validation, allowing arbitrary module loading and code execution.

## Source

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

An attacker can request any Python module (e.g., `os`, `subprocess`, `pickle`) and trigger arbitrary code execution at module import time.

## Fix

```python
import importlib
import importlib.util

from flask import Flask, jsonify, request

app = Flask(__name__)

# Whitelist of allowed plugins
ALLOWED_PLUGINS = {
    "csv_export",
    "pdf_export",
    "json_export",
}


def _build_plugin_context(payload):
    return {"requested_by": payload.get("user"), "options": payload.get("options", {})}


@app.route("/plugins/run", methods=["POST"])
def run_plugin():
    payload = request.get_json(force=True)
    plugin_name = payload["plugin"]

    # Validate plugin name against whitelist
    if plugin_name not in ALLOWED_PLUGINS:
        return jsonify({"status": "error", "message": "Unknown plugin"}), 400

    # Safe to import only whitelisted plugins
    plugin_module = importlib.import_module(plugin_name)

    context = _build_plugin_context(payload)
    result = plugin_module.run(context)
    return jsonify({"status": "ok", "result": result})
```

## Explanation

The vulnerability occurs because `plugin_name` from user input is passed directly to `importlib.import_module()` without validation. An attacker can request any module available in the Python path, including standard library modules, to execute arbitrary code at import time.

The fix implements a whitelist of allowed plugin names. Only modules in `ALLOWED_PLUGINS` are permitted to load. The validation rejects any plugin name not in the whitelist with a 400 error response, preventing loading of unauthorized modules.

This approach:
- Explicitly defines the attack surface by listing allowed plugins
- Rejects unknown plugins early, before any import attempt
- Returns a clear error message to the client
- Maintains the intended plugin architecture while eliminating the injection vector
