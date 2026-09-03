## Verdict

Confirmed path traversal vulnerability via dynamic `require()` statement.

## Source

`req.query.name` parameter from line 15, passed unsanitized into `require()` via string concatenation on line 26.

## Fix

Replace the dynamic require with an allowlist-based lookup:

```javascript
// Define an allowlist of trusted plugins
const allowedPlugins = {
  'reporting': './plugins/reporting',
  'analytics': './plugins/analytics',
  // Add other approved plugins here
};

router.get('/plugins/run', (req, res) => {
  const pluginName = req.query.name;

  if (!pluginName) {
    return res.status(400).json({ error: 'Missing required "name" query parameter' });
  }

  try {
    let plugin = loadedPlugins.get(pluginName);

    if (!plugin) {
      // Validate against allowlist before requiring
      if (!allowedPlugins.hasOwnProperty(pluginName)) {
        return res.status(400).json({ error: `Unknown plugin: "${pluginName}"` });
      }
      plugin = require(allowedPlugins[pluginName]);
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

## Explanation

The vulnerability exists because `pluginName` from `req.query.name` is directly concatenated into the module path passed to `require()`, allowing path traversal sequences like `../` to escape the intended `./plugins/` directory and load arbitrary modules from anywhere on the filesystem, potentially executing attacker-controlled code.

The fix implements an allowlist-based indirect reference mapping. Instead of allowing users to supply arbitrary paths, they can only request plugins by a whitelisted name. Each name is mapped to a specific, hardcoded module path controlled by the developer. The allowlist is checked before any module loading occurs, ensuring only approved plugins can be loaded regardless of the input provided. This follows CWE-22 guidance: "use indirect reference mapping with IDs/tokens instead of accepting file paths from users."

Attacking with traversal sequences like `name=../../../etc/passwd` now returns a 400 error because `../../../etc/passwd` is not a key in `allowedPlugins`, rather than attempting to load `/etc/passwd` as a Node module.

## Behaviour changes

- **Validation added**: Unknown plugin names now return an error (400 status) instead of attempting to load them
- **Request handling**: Valid requests behave identically - approved plugins still load and their `run()` function executes
- **Caching preserved**: The loaded plugins map still functions, so repeated requests for the same plugin avoid re-loading
- **Error messages**: Failed loads now produce the same error structure (500 status) but only occur for whitelisted plugins that fail to load
