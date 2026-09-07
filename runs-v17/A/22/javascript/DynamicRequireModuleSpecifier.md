## Verdict
The vulnerability is confirmed. Line 26 directly concatenates an unsanitized query parameter into a require path, allowing directory traversal.

## Source
The vulnerability originates at line 15 where `pluginName` is extracted from `req.query.name` without validation. This tainted value flows directly to line 26 where it is concatenated into the require path: `require('./plugins/' + pluginName)`. An attacker can pass values like `../../../etc/passwd` to escape the intended `./plugins/` directory.

## Fix

### File: DynamicRequireModuleSpecifier.js

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

  try {
    let plugin = loadedPlugins.get(pluginName);

    if (!plugin) {
      // Use path.basename() to extract only the filename component, preventing directory traversal
      const safeName = path.basename(pluginName);
      plugin = require('./plugins/' + safeName);
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
The fix uses Node's `path.basename()` function to extract only the filename component from the user-supplied plugin name. This prevents directory traversal because `path.basename()` strips away any leading directory components. For example, `path.basename('../../../etc/passwd')` returns `'passwd'`, and `path.basename('../../plugins/admin')` returns `'admin'`. This ensures the require path can only load files from the intended `./plugins/` directory, not from arbitrary locations in the filesystem.
