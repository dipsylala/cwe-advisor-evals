## Verdict
True Positive - CWE-94 confirmed.

## Source
Line 10 contains a `require` statement that loads a PHP file using a user-controlled path component. The `$plugin` parameter from `$request['plugin']` is directly concatenated into the file path without any validation, allowing a path traversal attack to load arbitrary files from the filesystem.

## Fix
Validate the `$plugin` parameter to allow only safe characters:

```php
<?php

final class PluginPreviewDynamicRequire
{
    public function render(array $request): string
    {
        $plugin = $request['plugin'] ?? 'summary';
        $payload = $request['payload'] ?? [];

        // Validate plugin name contains only alphanumeric, underscore, and hyphen
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $plugin)) {
            throw new InvalidArgumentException('Invalid plugin name');
        }

        require __DIR__ . '/plugins/' . $plugin . '.php';

        return render_preview($payload);
    }
}
```

## Explanation
The vulnerability allows an attacker to use path traversal sequences (e.g., `../../../etc/passwd`, `../../config`) to load arbitrary PHP files from anywhere on the filesystem. The fix adds a strict allowlist validation using `preg_match()` that permits only alphanumeric characters, underscores, and hyphens in the plugin name. This prevents directory traversal while allowing legitimate plugin names. The validation throws an exception immediately if an invalid name is supplied, ensuring no unsafe file loads occur.
