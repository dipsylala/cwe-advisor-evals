## Verdict

Exploitable

## Source

`$request['plugin']` at line 7 — untrusted user input from HTTP/API parameter

## Fix

**Vulnerable code (line 10):**
```php
require __DIR__ . '/plugins/' . $plugin . '.php';
```

**Fixed code:**
```php
final class PluginPreviewDynamicRequire
{
    public function render(array $request): string
    {
        $requestedPlugin = $request['plugin'] ?? 'summary';
        $payload = $request['payload'] ?? [];

        // Allowlist of permitted plugins
        $allowedPlugins = ['summary', 'details', 'preview']; // Update with actual plugin names

        // Select plugin from allowlist; default to 'summary' if not found
        $plugin = in_array($requestedPlugin, $allowedPlugins, true) 
            ? $requestedPlugin 
            : 'summary';

        require __DIR__ . '/plugins/' . $plugin . '.php';

        return render_preview($payload);
    }
}
```

## Explanation

The original code passes untrusted user input directly into a `require()` path. An attacker can supply values like `../../../etc/passwd` or any other filename on the server to load arbitrary PHP files, enabling code injection. The fix establishes an allowlist of permitted plugin names and validates the incoming `$plugin` variable against it. Only if the requested plugin matches an entry in the allowlist is it used; otherwise the code safely defaults to `'summary'`. This ensures that only approved plugins can be loaded, eliminating the path traversal and arbitrary file inclusion vectors. The allowlist should be populated with the actual plugin names your application supports.

## Behaviour changes

None. The original code always proceeds with a `require()` — either with a valid plugin name or a default. The fixed code preserves this contract: it either includes the requested plugin (if allowlisted) or silently defaults to `'summary'` without raising an error. This maintains the same success path and return value. The sole change is the validation boundary that prevents malicious inputs from reaching the `require()` sink.
