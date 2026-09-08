## Verdict

Exploitable. `plugin_name` comes straight from the untrusted JSON request body (`payload["plugin"]`, no validation) and is passed unmodified into `importlib.import_module()`, which imports and runs that module's top-level code. A client can supply any importable dotted path reachable on `sys.path` - including a module already present in the environment whose import-time side effects are attacker-usable, or, on a deployment where the app process can write to a directory on `sys.path` (e.g. an upload/tmp directory, a writable working directory), a module the attacker placed there themselves, giving arbitrary code execution at import time before `plugin_module.run()` is ever reached.

## Source

`payload["plugin"]` in `run_plugin()`, taken from `request.get_json(force=True)` on the `POST /plugins/run` endpoint - fully attacker-controlled, no allowlist or type/format check applied before use.

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

# Fixed allowlist mapping a request-supplied plugin name to the module that
# actually gets imported. importlib.import_module() only ever sees one of
# these hard-coded dotted paths - the request value is used solely as a
# lookup key into this dict, never concatenated into or passed as the
# module name itself.
_ALLOWED_PLUGINS = {
    "csv_export": "plugins.csv_export",
    "pdf_export": "plugins.pdf_export",
}


def _build_plugin_context(payload):
    return {"requested_by": payload.get("user"), "options": payload.get("options", {})}


@app.route("/plugins/run", methods=["POST"])
def run_plugin():
    payload = request.get_json(force=True)
    plugin_name = payload["plugin"]

    module_path = _ALLOWED_PLUGINS.get(plugin_name)
    if module_path is None:
        return jsonify({"status": "error", "message": "unknown plugin"}), 400

    plugin_module = importlib.import_module(module_path)

    context = _build_plugin_context(payload)
    result = plugin_module.run(context)
    return jsonify({"status": "ok", "result": result})
```

## Explanation

The sink itself (`importlib.import_module()`) is unchanged - it still resolves and imports a module, and `plugin_module.run(context)` still runs it the same way. What changed is what value reaches that call: `plugin_name` is now used only as a lookup key into a fixed, server-defined dictionary (`_ALLOWED_PLUGINS`) that maps each recognised request-facing name to the real dotted module path the application ships. If the requested name isn't a key in that dictionary, the lookup returns `None` and the handler rejects the request before `import_module()` ever runs. Because the string handed to `import_module()` is always one of the two literal paths written into the source - never the client's string, not even after a "successful" match - there is no way for request input to select an arbitrary module, closing the code-injection path while leaving the plugin-dispatch behaviour (import, then call `run(context)`) identical to before for every legitimate plugin name.

## Behaviour changes

- **New failure mode for unrecognised plugin names**: the original code let an unknown name propagate into `importlib.import_module()`, which raises `ModuleNotFoundError` (uncaught here, so Flask would turn it into a 500). The fix instead returns a `400` with `{"status": "error", "message": "unknown plugin"}` before the import is attempted. This is a direct consequence of the allowlist gate the fix requires (Step 4's allowlist-fix-point guidance: reject up front rather than let a bad value continue toward the sink) and is a strict narrowing, not a widening, of what the endpoint accepts - it does not affect any request that names a plugin the deployment actually ships.
- **Assumption**: the two allowlist entries (`csv_export` -> `plugins.csv_export`, `pdf_export` -> `plugins.pdf_export`) are illustrative, taken from the module docstring's own examples, since this single file does not enumerate the full set of installed plugins or the package they live in. A real deployment must populate `_ALLOWED_PLUGINS` with its actual plugin names and dotted module paths; the mechanism (fixed dictionary, lookup-then-import) is the load-bearing part of the fix, not the two sample entries. Confidence is lowered accordingly on the exact dictionary contents, not on the fix pattern itself.
- No other argument, return value, or control flow changed: `_build_plugin_context`, the response shape on success, and the `run(context)` call signature are all identical to the original.

## Verification

Ran `python -m py_compile` (via the local uv-managed CPython 3.13.12 interpreter) against the fixed file in isolation - compiled with no errors or warnings. No test suite or Flask app fixture was available in the case directory to exercise the route end-to-end, so behaviour was additionally checked by hand: `_ALLOWED_PLUGINS.get()` and `jsonify` are both used per their standard signatures, `importlib` and `flask` imports are unchanged from the original file, and the only new name introduced (`_ALLOWED_PLUGINS`) is a plain module-level dict literal with no external dependency.
