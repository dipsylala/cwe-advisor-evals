## Verdict

CONFIRMED - The vulnerability is real and exploitable. The application imports Python modules based on untrusted user input without validation, allowing an attacker to load and execute arbitrary Python code.

## Source

HTTP POST request parameter `plugin` in the JSON payload (line 22): `plugin_name = payload["plugin"]`

This value comes directly from untrusted user input via `request.get_json(force=True)` with no validation or sanitization.

## Fix

Replace the dynamic import with allowlist-based module selection. Define a mapping of allowed plugin names to their canonical module names, validate the input against this allowlist, and only import modules that are explicitly approved.

**Vulnerable code (line 25):**
```python
plugin_module = importlib.import_module(plugin_name)
```

**Fixed code:**
```python
# Define the allowlist of permitted plugins at module level
ALLOWED_PLUGINS = {
    "csv_export": "csv_export",
    "pdf_export": "pdf_export",
}

# In run_plugin() function:
@app.route("/plugins/run", methods=["POST"])
def run_plugin():
    payload = request.get_json(force=True)
    plugin_name = payload["plugin"]
    
    # Validate against allowlist
    if plugin_name not in ALLOWED_PLUGINS:
        return jsonify({"status": "error", "message": "Plugin not allowed"}), 403
    
    # Use the canonical module name from the allowlist
    canonical_module_name = ALLOWED_PLUGINS[plugin_name]
    plugin_module = importlib.import_module(canonical_module_name)
    
    context = _build_plugin_context(payload)
    result = plugin_module.run(context)
    return jsonify({"status": "ok", "result": result})
```

## Explanation

The original code passes untrusted user input directly to `importlib.import_module()`, which executes the target module's top-level code. An attacker can specify any importable Python module name to achieve arbitrary code execution.

The fix implements an allowlist: a dictionary mapping allowed plugin names to their corresponding module names. Before importing, the code validates that the requested plugin exists in the allowlist. Only canonical module names from this allowlist can be imported. This prevents attackers from importing unexpected modules while preserving the original functionality for approved plugins.

The allowlist serves as the single source of truth about which plugins the application permits. The validation is enforced before the import operation, making it impossible to bypass. Using a separate `canonical_module_name` variable ensures the import receives only values explicitly approved by the developer, not the original tainted input.

## Behaviour changes

- Requests with a `plugin` value not in the `ALLOWED_PLUGINS` dictionary will receive a 403 Forbidden response instead of attempting to import the module.
- Only the explicitly listed plugins can be loaded; any attempt to import unlisted modules fails safely.
- Error responses now include a descriptive message indicating the plugin is not allowed.
- The application's functionality for approved plugins remains unchanged.
