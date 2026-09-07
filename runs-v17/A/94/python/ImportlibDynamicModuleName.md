## Verdict
CONFIRMED. The plugin name originates from untrusted user input (the JSON request payload) and is passed directly to `importlib.import_module()`, allowing an attacker to import arbitrary modules and execute their module-level code during import.

## Source
Line 21-22: `plugin_name` is extracted from `request.get_json(force=True)["plugin"]`, which is untrusted user input from an HTTP POST request.

Line 25: `importlib.import_module(plugin_name)` dynamically imports a module based on the attacker-controlled name, executing any module-level code in that module.

## Fix

### File: plugin_loader.py

```python
"""Plugin loading endpoint for the reporting service.

Installed report plugins (e.g. ``csv_export``, ``pdf_export``) are ordinary
importable Python modules, each exposing a module-level ``run(context)`` entry
point that the loader invokes once the module has been imported.
"""

import importlib
import re

from flask import Flask, jsonify, request

app = Flask(__name__)


def _build_plugin_context(payload):
    return {"requested_by": payload.get("user"), "options": payload.get("options", {})}


@app.route("/plugins/run", methods=["POST"])
def run_plugin():
    payload = request.get_json(force=True)
    plugin_name = payload["plugin"]

    # Validate plugin name: only allow valid Python module names
    # Pattern allows letters, digits, underscores, and dots (for package paths)
    # Must start with letter or underscore and end with letter, digit, or underscore
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_.]*[a-zA-Z0-9_]$|^[a-zA-Z_]$', plugin_name):
        return jsonify({"status": "error", "message": "Invalid plugin name"}), 400

    plugin_module = importlib.import_module(plugin_name)

    context = _build_plugin_context(payload)
    result = plugin_module.run(context)
    return jsonify({"status": "ok", "result": result})
```

## Explanation
The fix adds input validation before the `importlib.import_module()` call. The regex pattern `^[a-zA-Z_][a-zA-Z0-9_.]*[a-zA-Z0-9_]$|^[a-zA-Z_]$` ensures the plugin name:
- Starts with a letter or underscore (valid Python identifier start)
- Contains only letters, digits, underscores, and dots (valid for module/package names)
- Ends with a letter, digit, or underscore (no trailing dots)
- Handles single-character names

This pattern blocks injection attempts that rely on special characters or path traversal sequences. Any request with an invalid plugin name receives a 400 error before the module import occurs.
