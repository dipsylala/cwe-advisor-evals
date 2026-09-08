## Verdict

The code is vulnerable to CWE-94 code injection. The `plugin_name` parameter is read directly from untrusted user input (JSON payload) and passed to `importlib.import_module()` without any validation or restriction. An attacker can supply an arbitrary module name to load any Python module accessible in the Python path, potentially executing malicious code.

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

    # Validate plugin name against whitelist before importing
    if plugin_name not in ALLOWED_PLUGINS:
        return jsonify({"status": "error", "message": "Plugin not allowed"}), 400

    # SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
    plugin_module = importlib.import_module(plugin_name)

    context = _build_plugin_context(payload)
    result = plugin_module.run(context)
    return jsonify({"status": "ok", "result": result})
```

## Explanation

The vulnerability arises because `importlib.import_module()` executes module-level code when a module is imported. Without validation, an attacker can supply any module name in the `plugin` field to load and execute arbitrary Python code.

The remediation adds a whitelist (`ALLOWED_PLUGINS`) containing only the legitimate plugin modules the application is designed to support. Before calling `import_module()`, the code now validates that the requested `plugin_name` is in the whitelist. If it is not, the endpoint returns a 400 error with an appropriate message instead of attempting the import.

This approach follows the principle of least privilege by explicitly enumerating what is allowed rather than trying to block what is dangerous. Only known, legitimate plugins can be loaded, closing the injection vector entirely.
