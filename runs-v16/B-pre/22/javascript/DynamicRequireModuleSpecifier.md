## Verdict

VULNERABLE. The `pluginName` parameter from `req.query.name` flows unsanitized into a dynamic `require()` call, allowing an attacker to traverse the filesystem with sequences like `../` and load arbitrary modules from outside the intended `./plugins/` directory.

## Source

**Input location:** Line 15, `const pluginName = req.query.name`

The `pluginName` is extracted from the untrusted user-supplied query parameter `name` in a GET request to `/plugins/run?name=...`

**Taint flow:** 
- `req.query.name` (untrusted, user-controlled)
- Used directly in string concatenation on line 26
- Passed to `require()` sink

## Fix

Replace the vulnerable dynamic require with validation and path containment checks:

```javascript
'use strict';

const express = require('express');
const path = require('path');
const router = express.Router();

// Registry of plugin instances that have been loaded this session, keyed by
// plugin name, so a repeated request for the same plugin doesn't reload it.
const loadedPlugins = new Map();

// GET /plugins/run?name=reporting
// Loads a plugin module by name and invokes its exported `run()` entry point.
// Plugins are simple CommonJS modules that live under ./plugins/*.js and each
// export a single `run(req)` function.
router.get('/plugins/run', (req, res) => {
  const pluginName = req.query.name;

  if (!pluginName) {
    return res.status(400).json({ error: 'Missing required "name" query parameter' });
  }

  // Validate plugin name: alphanumeric, underscore, hyphen only
  if (!/^[a-zA-Z0-9_-]+$/.test(pluginName)) {
    return res.status(400).json({ error: 'Invalid plugin name: only alphanumeric, underscore, and hyphen characters allowed' });
  }

  try {
    let plugin = loadedPlugins.get(pluginName);

    if (!plugin) {
      // Construct the plugin path and verify it stays within ./plugins directory
      const pluginsDir = path.resolve(__dirname, 'plugins');
      const pluginPath = path.resolve(pluginsDir, pluginName + '.js');

      // Ensure the resolved path is inside the plugins directory
      if (!pluginPath.startsWith(pluginsDir + path.sep) && pluginPath !== pluginsDir) {
        return res.status(400).json({ error: `Plugin path traversal attempted` });
      }

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

The fix implements two layers of defence:

1. **Input validation** (line 32): A strict allowlist pattern `^[a-zA-Z0-9_-]+$` restricts the plugin name to only alphanumeric characters, underscores, and hyphens. This rejects path traversal sequences like `../` and absolute paths outright before they reach the filesystem.

2. **Path containment verification** (lines 40-45): 
   - `path.resolve(__dirname, 'plugins')` produces the absolute path to the plugins directory
   - `path.resolve(pluginsDir, pluginName + '.js')` resolves the requested plugin against that base directory
   - The check `!pluginPath.startsWith(pluginsDir + path.sep)` verifies the resolved path is actually inside the plugins directory
   - This prevents escape even if the validation regex were bypassed, because `path.resolve()` normalizes `..` and symlinks before containment is checked

The fix preserves the existing behaviour: cache hits work as before, and successful loads populate the same `loadedPlugins` map. Error handling remains unchanged.

## Behaviour changes

- **Request validation:** Requests with plugin names containing characters outside `[a-zA-Z0-9_-]` now return HTTP 400 instead of attempting to load.
- **Path resolution:** The plugin path is resolved to an absolute path and verified to stay within `./plugins/` before `require()` is invoked.
- **Traversal attempts:** Payloads like `../../../config`, `../../etc/passwd`, or `/etc/passwd` are rejected at the validation stage.
- **Cache key:** The cache still uses the validated `pluginName` as the key, so repeated requests for the same plugin reuse the cached instance.
