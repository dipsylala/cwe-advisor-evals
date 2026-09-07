## Verdict

Confirmed exploitable. The `$plugin` parameter is attacker-controlled and concatenated directly into the `require` statement, permitting path traversal and arbitrary file inclusion.

## Source

Line 7: `$plugin = $request['plugin'] ?? 'summary';`

The attacker controls `$request['plugin']` via HTTP request parameters.

## Fix

```php
<?php

final class PluginPreviewDynamicRequire
{
    public function render(array $request): string
    {
        $plugin = $request['plugin'] ?? 'summary';
        $payload = $request['payload'] ?? [];

        // Allowlist of permitted plugins
        $allowed = ['summary', 'details', 'preview'];
        if (!in_array($plugin, $allowed, true)) {
            throw new InvalidArgumentException('Plugin not permitted');
        }

        require __DIR__ . '/plugins/' . $plugin . '.php';

        return render_preview($payload);
    }
}
```

## Explanation

The fix introduces an allowlist of permitted plugin names and validates the input against it using `in_array()` with strict type checking (`true` parameter). If the supplied `$plugin` value is not in the allowlist, an exception is thrown before the value reaches the `require` statement. This prevents path traversal attacks (e.g., `../../../etc/passwd`) and arbitrary file inclusion. The fix uses only the user-supplied value for validation but keeps it as-is for the require since it has already been constrained to a known set; the fix does not select a replacement value from the allowlist because the original value itself is permitted if it passes validation.

## Behaviour changes

- Requests with a `plugin` parameter not in the allowlist now throw `InvalidArgumentException` instead of silently attempting to include a nonexistent file
- The default plugin (`summary`) must be present in the allowlist for the fallback to work
- The list of allowed plugins must be maintained in code; adding new plugins requires a code change, not a filesystem addition
