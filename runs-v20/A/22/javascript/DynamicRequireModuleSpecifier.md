## Verdict

Confirmed. The `name` query parameter reaches `require('./plugins/' + pluginName)` unvalidated, so a value such as `../../../../etc/passwd` or an absolute path lets an attacker load and execute an arbitrary module from outside the `plugins` directory.

## Source

`req.query.name` (the `name` query parameter on `GET /plugins/run`), read at line 15 into `pluginName`.

## Fix

### File: DynamicRequireModuleSpecifier.js

```javascript
'use strict';

const path = require('path');
const express = require('express');
const router = express.Router();

// Registry of plugin instances that have been loaded this session, keyed by
// plugin name, so a repeated request for the same plugin doesn't reload it.
const loadedPlugins = new Map();

const PLUGINS_DIR = path.join(__dirname, 'plugins');

// GET /plugins/run?name=reporting
// Loads a plugin module by name and invokes its exported `run()` entry point.
// Plugins are simple CommonJS modules that live under ./plugins/*.js and each
// export a single `run(req)` function.
router.get('/plugins/run', (req, res) => {
  const pluginName = req.query.name;

  if (!pluginName) {
    return res.status(400).json({ error: 'Missing required "name" query parameter' });
  }

  // Plugin names must be a single, safe path segment - letters, digits,
  // underscore and hyphen only. This rejects "../" sequences, absolute
  // paths, and null bytes before the value ever reaches require().
  if (!/^[A-Za-z0-9_-]+$/.test(pluginName)) {
    return res.status(400).json({ error: `Invalid plugin name "${pluginName}"` });
  }

  try {
    let plugin = loadedPlugins.get(pluginName);

    if (!plugin) {
      const pluginPath = path.join(PLUGINS_DIR, pluginName);

      // Defense in depth: confirm the resolved path still lives under the
      // plugins directory before requiring it.
      const relative = path.relative(PLUGINS_DIR, pluginPath);
      if (relative.startsWith('..') || path.isAbsolute(relative)) {
        return res.status(400).json({ error: `Invalid plugin name "${pluginName}"` });
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

`pluginName` comes straight from the query string and is concatenated into a module specifier passed to `require()`. Node resolves `require()` paths the same way it resolves any filesystem path, so `../`, an absolute path, or a null byte in `pluginName` lets the request load and execute any `.js` file reachable from the process, not just a file under `plugins/` - a full path traversal into arbitrary code execution, since `require()` runs the target module's top-level code as a side effect of loading it.

The fix applies an allowlist regex (`^[A-Za-z0-9_-]+$`) before doing anything else. This is appropriate here because a plugin name is not free-form user data - it is meant to identify one of a fixed set of module files, so restricting it to safe filename characters does not reject any legitimate value the application's own contract allows. The regex alone also stops traversal, since it excludes `/`, `\`, and `.` entirely.

As defense in depth, the code also builds the path with `path.join()` and checks with `path.relative()` that the resolved path still resides inside `PLUGINS_DIR` before calling `require()`. This second check protects against any edge case the regex might miss (for example on platforms with alternate separators) and keeps the containment guarantee independent of the character allowlist, so a future relaxation of the regex does not reopen the traversal on its own.
