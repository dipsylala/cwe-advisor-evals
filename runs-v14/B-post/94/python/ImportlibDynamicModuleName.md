## Verdict

Exploitable. The plugin name is read directly from user-controlled JSON input and passed to `importlib.import_module()`, which executes that module's top-level code, allowing arbitrary code injection.

## Source

The plugin name comes from `payload["plugin"]` (line 22), which is obtained from `request.get_json(force=True)` - untrusted data from the HTTP POST body. This value is used directly as the argument to `importlib.import_module()` at line 25 without validation or restriction.

## Fix

**Vulnerable code (line 22-25):**
```python
plugin_name = payload["plugin"]

# SAST FINDING: CWE-94 (Improper Control of Generation of Code ('Code Injection')) reported here. Sink is the next statement.
plugin_module = importlib.import_module(plugin_name)
```

**Fixed code:**
```python
# Define a whitelist of allowed plugins
ALLOWED_PLUGINS = {
    "csv_export": "reporting.plugins.csv_export",
    "pdf_export": "reporting.plugins.pdf_export",
}

plugin_name = payload["plugin"]

# Map the request to an allowed module name
if plugin_name not in ALLOWED_PLUGINS:
    return jsonify({"status": "error", "message": "Unknown plugin"}), 400

plugin_module = importlib.import_module(ALLOWED_PLUGINS[plugin_name])
```

## Explanation

The fix replaces dynamic module resolution with an allowlist-based dispatch. Instead of allowing arbitrary module names to be imported, the application maintains a dictionary of known, safe plugins and maps user-supplied names to their actual module paths. The untrusted input is used only as a key to look up the safe value. This eliminates the code injection vector because an attacker cannot cause arbitrary modules to be imported - only whitelisted ones can be loaded. If the requested plugin name does not match a key in the allowlist, the request is rejected with an HTTP 400 error rather than attempting to import an unknown module.

## Behaviour changes

- The endpoint now rejects requests for plugin names not in the `ALLOWED_PLUGINS` whitelist with HTTP 400 and an error message, where previously any installed Python module name would be attempted.
- The plugin paths can now be controlled independently of the request parameter - you can internally organize plugins in a package structure (e.g., `reporting.plugins.csv_export`) while accepting short names from clients (e.g., `"csv_export"`), or update the mapping without changing the API contract.
- No changes to return values, error handling, or the context passed to `plugin_module.run()`.
