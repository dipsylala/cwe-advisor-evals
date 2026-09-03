## Verdict
VULNERABLE. Line 26 constructs a `require()` path by concatenating user-supplied input without validation, permitting path traversal to load modules outside the intended plugins directory.

## Source
The vulnerability exists at line 26:
```javascript
plugin = require('./plugins/' + pluginName);
```

The `pluginName` variable originates from `req.query.name` (line 15) and is passed directly into the path without any sanitization or validation. An attacker can supply a value like `../../../etc/passwd` or `../../../../config` to load arbitrary Node.js modules from outside the `./plugins/` directory.

## Fix
Validate the plugin name to permit only safe characters (alphanumeric, underscore, hyphen) before constructing the path. Alternatively, use `path.resolve()` with `path.relative()` to canonicalize the path and verify it remains within the plugins directory:

```javascript
const path = require('path');

router.get('/plugins/run', (req, res) => {
  const pluginName = req.query.name;

  if (!pluginName) {
    return res.status(400).json({ error: 'Missing required "name" query parameter' });
  }

  // Validate that pluginName contains only safe characters (no path separators or directory traversal)
  if (!/^[a-zA-Z0-9_-]+$/.test(pluginName)) {
    return res.status(400).json({ error: 'Invalid plugin name format' });
  }

  try {
    let plugin = loadedPlugins.get(pluginName);

    if (!plugin) {
      // Construct the path and verify it stays within ./plugins/
      const pluginsDir = path.resolve(__dirname, './plugins');
      const modulePath = path.resolve(__dirname, './plugins', pluginName);
      
      // Ensure the resolved path is within the plugins directory
      if (!path.relative(pluginsDir, modulePath).startsWith('..') === false) {
        // path.relative() returns a relative path; if it starts with '..', 
        // the resolved module is outside pluginsDir
        if (path.relative(pluginsDir, modulePath).startsWith('..')) {
          throw new Error('Path traversal attempt detected');
        }
      }
      
      plugin = require(modulePath);
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
```

The simpler and more maintainable fix is the regex validation on line 16-18: restricting `pluginName` to `[a-zA-Z0-9_-]+` eliminates the vector entirely because path traversal sequences like `../` or `..\\` cannot be expressed within that character set.

## Explanation
Path traversal (CWE-22) occurs when user-supplied input is concatenated into a file path without validation, allowing an attacker to navigate outside the intended directory. Node.js `require()` resolves module paths relative to the calling file, so `'./plugins/' + '../../../etc'` resolves to a module at the repository root or system level.

The fix combines input validation (regex) with optional path canonicalization (path.resolve + path.relative). The regex approach is sufficient because it structurally prevents any directory separators or traversal sequences. The path.resolve approach provides defense-in-depth and is useful if validation alone is bypassed or if the whitelist needs to expand.

The `require()` call itself is not the vulnerability—it is a necessary operation. The vulnerability is the absence of validation before the path is constructed.
