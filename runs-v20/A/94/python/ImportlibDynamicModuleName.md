## Verdict

Confirmed. `run_plugin()` passes the client-supplied `plugin` field straight into `importlib.import_module()` with no validation. `import_module` will import any dotted path importable on `sys.path` - not just the intended `csv_export`/`pdf_export` plugins - and importing a module executes that module's top-level code. An attacker can supply the name of any installed package (third-party or stdlib) to trigger its import-time side effects, probe for installed packages, or reach an unintended module whose import (or subsequent `.run()` call, via `AttributeError`/duck-typing tricks) causes unwanted behavior. This is attacker-controlled selection of code to execute, i.e. CWE-94.

## Source

`payload["plugin"]` in `run_plugin()` (`plugin_loader.py:22`), taken directly from the untrusted, force-parsed JSON request body (`request.get_json(force=True)`, line 21), flows unchanged into `importlib.import_module(plugin_name)` at line 25.

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

# Explicit allowlist mapping the public plugin name accepted from clients to
# the actual importable module. Only names listed here can ever reach
# importlib.import_module, so client input never selects the module path
# directly - it only selects a key into this fixed, developer-controlled map.
ALLOWED_PLUGINS = {
    "csv_export": "plugins.csv_export",
    "pdf_export": "plugins.pdf_export",
}


def _build_plugin_context(payload):
    return {"requested_by": payload.get("user"), "options": payload.get("options", {})}


@app.route("/plugins/run", methods=["POST"])
def run_plugin():
    payload = request.get_json(force=True)
    plugin_name = payload["plugin"]

    module_path = ALLOWED_PLUGINS.get(plugin_name)
    if module_path is None:
        return jsonify({"status": "error", "message": "unknown plugin"}), 400

    plugin_module = importlib.import_module(module_path)

    context = _build_plugin_context(payload)
    result = plugin_module.run(context)
    return jsonify({"status": "ok", "result": result})
```

## Explanation

`importlib.import_module()` treats its argument as a dotted module path to import, not as data - whatever string reaches it selects arbitrary code (any importable module's top-level statements) to run in-process. The endpoint's contract is that only a small, known set of report plugins are valid, so the value's format is entirely defined by the application, not by the user: fixing this means resolving the request's `plugin` field against a fixed, developer-maintained mapping (`ALLOWED_PLUGINS`) of accepted names to real module paths, and only ever calling `import_module()` with a value taken from that mapping. An unrecognized name is rejected with a 400 before any import happens, so the client can never cause an import of a module the developer did not explicitly register. This preserves the original behavior for every legitimate plugin name - `csv_export` and `pdf_export` continue to resolve and run exactly as before - while closing off every other importable module (stdlib, third-party, or internal) as an injection target. A regex or prefix check on `plugin_name` alone would not be sufficient, since any syntactically valid identifier still names a real, importable module; only constraining the set of reachable modules to ones the developer chose closes the sink.
