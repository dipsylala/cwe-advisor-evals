## Verdict

Exploitable.

## Source

`req.query.name` at line 15, user-supplied query parameter.

## Fix

Vulnerable code (line 26):
```javascript
plugin = require('./plugins/' + pluginName);
```

Fixed code:
```javascript
// Registry mapping allowed plugin names to their module paths
const pluginRegistry = {
  'reporting': './plugins/reporting.js',
  'analytics': './plugins/analytics.js',
  // Register additional plugins here
};

// In the route handler (replacing the direct require):
const pluginPath = pluginRegistry[pluginName];
if (!pluginPath) {
  return res.status(400).json({ error: 'Unknown plugin' });
}

let plugin = loadedPlugins.get(pluginName);
if (!plugin) {
  plugin = require(pluginPath);
  loadedPlugins.set(pluginName, plugin);
}
```

## Explanation

The vulnerability occurs because `pluginName` flows directly from user input (`req.query.name`) into the module path construction without any validation. An attacker can inject path traversal sequences (e.g., `../../../any/module` or encoded variants) to load arbitrary Node.js modules outside the intended `./plugins/` directory, potentially leading to arbitrary code execution.

The fix implements indirect reference mapping: instead of accepting a direct file path from the user, the application maintains a registry that maps allowed plugin names to their actual module paths. The user-supplied name is validated against this registry, and only registered plugins can be loaded. This approach:

1. Eliminates the path traversal vector entirely by preventing any path construction from user input
2. Makes the set of loadable plugins explicit and configurable
3. Provides fail-safe behavior: unknown plugins are rejected rather than silently bypassed

## Behaviour changes

1. **Unknown plugin handling**: The original code would attempt to load any require() path and catch errors generically. The fixed code explicitly rejects unknown plugins with a 400 error before attempting to load, making the error semantics clearer.
2. **Plugin registry requirement**: The application must maintain an explicit registry mapping plugin names to paths. Plugins must be pre-registered; dynamic or ad-hoc plugin names are no longer supported. This is intentional: it restricts the attack surface to administrator-configured plugins only.
3. **Plugin initialization**: Plugin paths are now server-controlled constants rather than user-controlled strings, eliminating the require() path argument uncertainty.

All legitimate functionality for registered plugins is preserved: the caching mechanism via `loadedPlugins` works unchanged, and the `run()` function invocation proceeds normally.
