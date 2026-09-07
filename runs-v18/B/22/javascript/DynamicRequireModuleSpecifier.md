## Verdict

CONFIRMED - CWE-22 Path Traversal vulnerability in dynamic `require()` call.

Vulnerability permits arbitrary module loading by passing path traversal sequences in the `name` query parameter. An attacker can supply `name=../../sensitive.js` to load and execute modules outside the intended `./plugins/` directory.

## Source

**File:** DynamicRequireModuleSpecifier.js  
**Line:** 26  
**Vulnerable code:** `plugin = require('./plugins/' + pluginName);`

**Data flow:**
- Source: `req.query.name` (untrusted user input from HTTP query parameter)
- Intermediate: `pluginName = req.query.name`
- Sink: `require('./plugins/' + pluginName)` - the require() call executes the loaded module

The vulnerability is a **dynamic require with unvalidated path construction**. The JavaScript guidance for CWE-22 specifically flags this pattern: "Treat a built module specifier as a path sink too - `require('./plugins/' + name)` and dynamic `import()` traverse out of the intended directory and execute what they load; resolve the name through a lookup map instead."

## Fix

The fix uses an allowlist (indirect reference mapping) to constrain which plugins can be loaded. Only pre-approved plugin names are permitted; any request for a name outside this list is rejected before the require() call.

### File: DynamicRequireModuleSpecifier.js

```javascript
'use strict';

const express = require('express');
const router = express.Router();

// Registry of plugin instances that have been loaded this session, keyed by
// plugin name, so a repeated request for the same plugin doesn't reload it.
const loadedPlugins = new Map();

// Allowlist of approved plugin names that are safe to load
const approvedPlugins = new Set(['reporting', 'analytics', 'export']);

// GET /plugins/run?name=reporting
// Loads a plugin module by name and invokes its exported `run()` entry point.
// Plugins are simple CommonJS modules that live under ./plugins/*.js and each
// export a single `run(req)` function.
router.get('/plugins/run', (req, res) => {
  const pluginName = req.query.name;

  if (!pluginName) {
    return res.status(400).json({ error: 'Missing required "name" query parameter' });
  }

  // Validate the plugin name is in the allowlist
  if (!approvedPlugins.has(pluginName)) {
    return res.status(400).json({ error: `Plugin "${pluginName}" is not approved` });
  }

  try {
    let plugin = loadedPlugins.get(pluginName);

    if (!plugin) {
      // Safe to use pluginName now - it has been validated against the allowlist
      plugin = require('./plugins/' + pluginName);
      loadedPlugins.set(pluginName, plugin);
    }

    if (typeof plugin.run !== 'function') {
      return res.status(500).json({ error: `Plugin "${pluginName}" does not export a run() function` });
    }

    const result = plugin.run(req);
    res.json({ plugin: pluginName, result });
  } catch (err) {
    res.status(500).json({ error: `Failed to load plugin "${pluginName}": ${err.message}` });
  }
});

module.exports = router;
```

## Explanation

The fix implements indirect reference mapping via an allowlist, which is the primary defence recommended by the CWE-22 JavaScript guidance. A `Set` named `approvedPlugins` defines the exact plugin names that are permitted to load. Before attempting to load any plugin, the code validates that the requested `pluginName` appears in this allowlist. If the name is not approved, the request is rejected with a 400 error.

This eliminates the path traversal vulnerability because:

1. **Attack vectors are blocked**: An attacker supplying `name=../../sensitive`, `name=../malicious`, or any other traversal sequence is rejected before reaching the require() call.
2. **Only canonical names work**: The allowlist contains only the exact names of legitimate plugins (e.g., `reporting`, `analytics`, `export`). Any transformation or variant of these names is rejected.
3. **The require() sink is now safe**: By the time `require('./plugins/' + pluginName)` executes, `pluginName` is guaranteed to be one of the approved values, so the constructed path cannot traverse outside `./plugins/`.

The fix aligns with CWE-22 guidance: "Use indirect reference mapping with IDs/tokens instead of accepting file paths from users" and "Replace direct file path parameters with indirect references."

## Behaviour changes

**API contract changes:**
- Requests with an unapproved plugin name now return HTTP 400 (Bad Request) with error message instead of attempting to load and potentially succeeding or returning a 500 error.
- Requests for approved plugins (`reporting`, `analytics`, `export`) behave identically to before - the plugin is loaded, cached, invoked, and the result returned.

**Security boundary:**
- The application now enforces that only explicitly approved plugins can be loaded, preventing accidental or malicious attempts to load plugins outside the approved set.
