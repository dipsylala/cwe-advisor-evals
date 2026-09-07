## Verdict

Exploitable. The vulnerability is confirmed. An attacker can supply `../` sequences in the `name` query parameter to traverse out of the intended `./plugins/` directory and require arbitrary Node.js modules from anywhere in the filesystem.

## Source

`pluginName` originates from `req.query.name` (line 15), user-supplied untrusted input from the HTTP request query string.

## Fix

### File: DynamicRequireModuleSpecifier.js

```javascript
'use strict';

const express = require('express');
const router = express.Router();

// Allowlist of valid plugin names mapped to their module paths.
// This prevents path traversal attacks via directory escape sequences.
const validPlugins = {
  reporting: './plugins/reporting',
  analytics: './plugins/analytics',
};

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

  try {
    let plugin = loadedPlugins.get(pluginName);

    if (!plugin) {
      // Validate that the requested plugin name is in the allowlist.
      // This prevents path traversal via directory escape sequences like '../'.
      if (!validPlugins.hasOwnProperty(pluginName)) {
        return res.status(400).json({ error: `Unknown plugin: "${pluginName}"` });
      }

      // Load the plugin using the mapped path from the allowlist, not the raw input.
      plugin = require(validPlugins[pluginName]);
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

The original code constructed module paths by string concatenation: `require('./plugins/' + pluginName)`. An attacker could supply `pluginName = '../../../etc/passwd'` or any other path traversal sequence to load arbitrary modules outside the intended plugins directory.

The fix implements indirect reference mapping via an allowlist (`validPlugins` object). The request handler now:
1. Validates that the requested plugin name is a key in the allowlist
2. Rejects unknown plugin names with a 400 error
3. Uses only the mapped path from the allowlist to construct the require statement

This ensures that only explicitly permitted plugins can be loaded, and the actual filesystem path is controlled by the application, not the attacker. The allowlist should be populated with the actual valid plugin names and their corresponding module paths; `reporting` and `analytics` are shown as examples.

## Behaviour changes

- **Input validation added**: Requests for unknown plugins now receive a 400 error response instead of attempting to load an arbitrary module.
- **Response message changed**: Invalid plugin requests return `{ error: "Unknown plugin: ..." }` instead of potentially attempting a require and later returning a 500 error.
- **Security boundary enforced**: Only plugins explicitly listed in `validPlugins` can be loaded, eliminating path traversal possibilities.
- **No change to successful path**: Valid plugin names work exactly as before—they are loaded once, cached, and their `run()` function is invoked with the same contract.
