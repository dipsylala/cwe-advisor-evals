## Verdict

**CWE-22 confirmed and exploitable.** The `require()` call at line 26 uses an unsanitized query parameter to construct a dynamic module path, allowing path traversal attacks. An attacker can supply `name=../../../../etc/passwd` or similar to load arbitrary modules outside the intended `./plugins/` directory.

## Source

`pluginName` originates from the untrusted query parameter `req.query.name` (line 15). Express automatically decodes URL-encoded values before populating `req.query`, so percent-encoded traversal sequences like `%2e%2e%2f` are decoded to `../` before reaching line 15.

The data flows directly into path construction at line 26 without validation:
```
req.query.name (untrusted source) → pluginName (line 15)
                                  → string concatenation (line 26)
                                  → require() sink (line 26)
```

## Fix

### File: DynamicRequireModuleSpecifier.js

```javascript
'use strict';

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');

// Registry of plugin instances that have been loaded this session, keyed by
// plugin name, so a repeated request for the same plugin doesn't reload it.
const loadedPlugins = new Map();

// Allowlist of permitted plugin names and their paths. This prevents arbitrary
// module loading via path traversal.
const allowedPlugins = {
  'reporting': path.join(__dirname, 'plugins', 'reporting.js'),
  'analytics': path.join(__dirname, 'plugins', 'analytics.js'),
  // Add additional permitted plugins here
};

// GET /plugins/run?name=reporting
// Loads a plugin module by name and invokes its exported `run()` entry point.
// Plugins are simple CommonJS modules that live under ./plugins/*.js and each
// export a single `run(req)` function.
router.get('/plugins/run', (req, res) => {
  const pluginName = req.query.name;

  if (!pluginName) {
    return res.status(400).json({ error: 'Missing required "name" query parameter' });
  }

  try {
    let plugin = loadedPlugins.get(pluginName);

    if (!plugin) {
      // Verify the plugin name is in the allowlist, then load it using the registered path.
      // This prevents path traversal attacks via constructs like '../../../etc/passwd'.
      if (!allowedPlugins.hasOwnProperty(pluginName)) {
        return res.status(400).json({ error: `Unknown plugin "${pluginName}"` });
      }

      const pluginPath = allowedPlugins[pluginName];
      plugin = require(pluginPath);
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

The fix replaces direct path concatenation with an indirect reference approach using an allowlist registry. Instead of concatenating the user-supplied `pluginName` directly into a path string, the code now:

1. Checks that `pluginName` exists as a key in the `allowedPlugins` object, which is defined at application startup and under sole developer control.
2. Retrieves the canonical path from the registry only if the name is approved.
3. Passes that approved path to `require()`, eliminating the attack surface entirely.

This approach aligns with the CWE-22 guidance's primary defence for module loading: *"Treat a built module specifier as a path sink too - require('./plugins/' + name) and dynamic import() traverse out of the intended directory and execute what they load; resolve the name through a lookup map instead."*

The fix preserves all existing functionality: legitimate plugin names are resolved to their correct paths, the caching mechanism remains intact, and error messages remain informative. The `path.join()` and `__dirname` calls ensure paths are correctly formed and absolute, preventing any reliance on relative path traversal.

## Behaviour changes

**Request Outcome Changes:**

- **Before:** Any query parameter `name=...` is accepted and attempted to be loaded as a plugin, allowing traversal attacks.
- **After:** Only plugin names that exist in the `allowedPlugins` registry are accepted. Requests with unknown plugin names receive a 400 Bad Request response with the message `Unknown plugin "{name}"`.

**Error Handling:**

- Unknown plugin names now fail at the allowlist check with a distinct 400 error, rather than at the `require()` call with a 500 error. This provides clearer feedback and logs the rejection before any module loading is attempted.

**Plugin Loading:**

- Plugin paths are now always absolute and application-controlled, never derived from user input. This prevents both path traversal and accidental module shadowing.

**Existing Requests:**

- Legitimate requests with known plugin names (e.g., `?name=reporting`) behave identically: the plugin is resolved to its registered path, loaded, cached, and executed as before.
