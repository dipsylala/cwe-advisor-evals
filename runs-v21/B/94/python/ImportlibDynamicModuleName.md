## Verdict

CONFIRMED - CWE-94 code injection via untrusted module import

## Source

Line 22: `plugin_name = payload["plugin"]` — untrusted attacker-controlled input from JSON POST request

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

# Allowlist of permitted plugins - maps user-supplied names to actual module names
PERMITTED_PLUGINS = {
    "csv_export": "plugins.csv_export",
    "pdf_export": "plugins.pdf_export",
}


def _build_plugin_context(payload):
    return {"requested_by": payload.get("user"), "options": payload.get("options", {})}


@app.route("/plugins/run", methods=["POST"])
def run_plugin():
    payload = request.get_json(force=True)
    plugin_name = payload["plugin"]

    # Validate input against allowlist before importing
    if plugin_name not in PERMITTED_PLUGINS:
        return jsonify({"status": "error", "message": "Unknown plugin"}), 400

    # Use the allowlist-selected canonical module name, never the untrusted input
    module_name = PERMITTED_PLUGINS[plugin_name]
    plugin_module = importlib.import_module(module_name)

    context = _build_plugin_context(payload)
    result = plugin_module.run(context)
    return jsonify({"status": "ok", "result": result})
```

## Explanation

The original code passes attacker-controlled input directly to `importlib.import_module()`, which executes the imported module's top-level code. This allows an attacker to import and execute arbitrary installed Python modules with full access to the application's runtime environment, secrets, and data.

The fix replaces dynamic module name resolution with an allowlist dictionary (`PERMITTED_PLUGINS`) that maps user-supplied plugin names to pre-approved module paths. The input is validated against this allowlist before import, and only the canonical module name from the allowlist is passed to `importlib.import_module()`. This ensures that only explicitly permitted modules can be loaded, regardless of what names an attacker supplies in requests. If an unknown plugin is requested, the endpoint returns a 400 error instead of attempting to load it.

## Behaviour changes

- **Breaking change**: The endpoint now rejects requests for any plugin not in the `PERMITTED_PLUGINS` dictionary, returning a 400 error with message "Unknown plugin". Any client code calling with undefined plugin names will receive an error instead of a 500 exception. This is intentional and correct — the application should only load known-safe plugins.
- **New dict constant**: `PERMITTED_PLUGINS` at module level defines the complete set of loadable plugins. The application maintainer must populate this dictionary with all plugins that should be available.
- **Error response format**: Changed from a 500 exception to a structured 400 JSON response for unknown plugins, improving client error handling and security transparency.

The endpoint's success path and context building are unchanged when a valid plugin is supplied.
