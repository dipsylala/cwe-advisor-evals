## Verdict

- **cwe_id**: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal'))
- **location**: `DynamicRequireModuleSpecifier.js`, line 26
- **verdict**: exploitable
- **confidence**: high

## Source

`req.query.name` (the `name` query-string parameter on `GET /plugins/run`) flows unmodified into `pluginName` (line 15), is used as-is to build a module specifier at `'./plugins/' + pluginName` (line 26), and is passed directly to `require()`. There is no validation, canonicalization, or containment check anywhere between source and sink. Because `require()` resolves `..` segments and accepts absolute-looking specifiers, a value such as `../../../../etc/passwd` or an absolute path walks the resolved specifier outside `./plugins` and loads whatever module is found there, and because `require()` also executes the target file's top-level code, this is both a path-traversal read and an arbitrary-module-execution primitive.

## Fix

### File: DynamicRequireModuleSpecifier.js

```javascript
'use strict';

const fs = require('fs');
const path = require('path');
const express = require('express');
const router = express.Router();

// Registry of plugin instances that have been loaded this session, keyed by
// plugin name, so a repeated request for the same plugin doesn't reload it.
const loadedPlugins = new Map();

// Indirect reference map: built once from the actual contents of ./plugins,
// so an incoming request name is only ever resolved to a path that already
// exists on disk in the plugins directory, never derived from user input.
const pluginsDir = path.join(__dirname, 'plugins');
const availablePlugins = new Map(
  fs.readdirSync(pluginsDir)
    .filter((file) => file.endsWith('.js'))
    .map((file) => [path.basename(file, '.js'), path.join(pluginsDir, file)])
);

// GET /plugins/run?name=reporting
// Loads a plugin module by name and invokes its exported `run()` entry point.
// Plugins are simple CommonJS modules that live under ./plugins/*.js and each
// export a single `run(req)` function.
router.get('/plugins/run', (req, res) => {
  const pluginName = req.query.name;

  if (!pluginName) {
    return res.status(400).json({ error: 'Missing required "name" query parameter' });
  }

  const pluginPath = availablePlugins.get(pluginName);
  if (!pluginPath) {
    return res.status(404).json({ error: `Unknown plugin "${pluginName}"` });
  }

  try {
    let plugin = loadedPlugins.get(pluginName);

    if (!plugin) {
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

The fix replaces the tainted string concatenation with the indirect-reference pattern the knowledge base names specifically for this sink: build a lookup map from the actual files present in `./plugins` (name -> absolute path), keyed by each file's basename with the `.js` extension stripped, at module load. The request's `name` parameter is then only ever used as a lookup key into that map (`availablePlugins.get(pluginName)`); the value passed to `require()` is the map's resolved absolute path, never the raw input, so the canonical-value substitution rule is satisfied. A `name` that doesn't correspond to an existing plugin - including any value containing `../`, an absolute path, or an encoded traversal sequence - simply misses the map and gets a 404, closing the weakness. `fs.readdirSync` and `path.join`/`path.basename` are Node's built-in `fs`/`path` modules, already implicitly available in this Node/Express codebase.

## Behaviour changes

- Requests whose `name` does not match an existing file in `./plugins` now receive `404 { error: 'Unknown plugin "<name>"' }` instead of falling through to the original `require()` call's `MODULE_NOT_FOUND` exception, which the original code's `catch` block turned into `500 { error: 'Failed to load plugin "<name>": ...' }`. This is a status-code change (404 vs 500) for the not-found case, which is a closer match to the actual condition (unknown plugin) but is a visible difference for any caller that branches on status code.
- The plugin directory is now enumerated once at module load (`fs.readdirSync`) rather than never; if `./plugins` does not exist or is unreadable at load time, the module now throws at require-time instead of lazily at first request. This trades a lazy failure for an eager one but does not change behavior for the normal case where `./plugins` exists.
- All other behavior - caching in `loadedPlugins`, the `run()`-export check, the success response shape, and error handling for a plugin whose own code throws - is unchanged from the original.

## Verification

Ran `node --check` against the fixed file at a scratch location (Node v24.3.0): passed with no diagnostics. Additionally exercised the new lookup logic standalone (same `fs.readdirSync`/`path.join`/`path.basename` construction, against a real file with a sibling `plugins/reporting.js`): a legitimate name (`reporting`) resolved to the correct absolute path and `require()` of that path returned a working module whose `run()` executed; traversal-shaped names (`../../../../etc/passwd`, `../evil`) both returned `undefined` from the map lookup, confirming they hit the new 404 branch rather than reaching `require()`.

## Assumptions

- The `./plugins` directory and its contents are not part of the provided case file; the fix assumes it exists relative to this module (as the existing code's own `'./plugins/' + pluginName` construction and its doc comment already assume) and contains only legitimate, trusted plugin modules dropped there by the application owner - the map is built from that directory's actual contents, not from a hardcoded name list, per the language guidance's instruction to use indirect reference mapping rather than a hand-authored allowlist.
- Changing the not-found response from 500 to 404 is treated as an acceptable, more-accurate behavior change rather than a regression; if strict response-shape parity with the original error path is required, the 404 branch could instead be folded into the existing `catch` block by throwing an error there and letting the existing 500 handler catch it, at the cost of no longer distinguishing "unknown plugin" from "plugin file failed to load."
