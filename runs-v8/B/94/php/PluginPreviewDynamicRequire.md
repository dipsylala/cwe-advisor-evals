## Verdict

Confirmed. CWE-94 code injection via unsafe file inclusion. User-controlled `$plugin` parameter is concatenated directly into a `require` path without validation, allowing path traversal to arbitrary files.

## Source

`$request['plugin']` parameter, assigned to `$plugin` variable with a default of `'summary'`. The parameter is untrusted user input from the HTTP request.

## Fix

```php
<?php

final class PluginPreviewDynamicRequire
{
    private const ALLOWED_PLUGINS = ['summary', 'details', 'preview'];

    public function render(array $request): string
    {
        $plugin = $request['plugin'] ?? 'summary';
        $payload = $request['payload'] ?? [];

        // Validate plugin identifier against allowlist before including
        if (!in_array($plugin, self::ALLOWED_PLUGINS, true)) {
            throw new \InvalidArgumentException('Invalid plugin identifier: ' . $plugin);
        }

        require __DIR__ . '/plugins/' . $plugin . '.php';

        return render_preview($payload);
    }
}
```

## Explanation

The vulnerability occurs because `$plugin` is directly concatenated into the file path with no validation. An attacker can supply values like `../../sensitive` or `../config` to include arbitrary files outside the intended `plugins/` directory.

The fix introduces an allowlist of permitted plugin identifiers (`ALLOWED_PLUGINS`). Before constructing the path, the code validates that `$plugin` is one of the known safe values using `in_array()` with strict type checking (`true` parameter). If the plugin is not in the allowlist, an `InvalidArgumentException` is thrown, preventing the unsafe include.

This ensures only predefined, trusted plugins can be loaded, eliminating the path traversal attack vector while preserving the original functionality for valid plugin names.

## Behaviour changes

**Before fix**: Any string value in the `plugin` request parameter is passed directly to `require`, allowing inclusion of unintended files such as configuration files, uploaded content, or files outside the plugins directory.

**After fix**: Only plugin names in the `ALLOWED_PLUGINS` list can be included. Requests with invalid plugin names now throw `InvalidArgumentException` instead of loading arbitrary files or failing with a generic "file not found" error. This provides explicit control over which files are executable and fails safely with an application error rather than silently including the wrong content.
