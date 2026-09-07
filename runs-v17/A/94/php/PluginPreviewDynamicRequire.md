## Verdict
Real vulnerability. The `$plugin` parameter is user-controlled input taken directly from `$request['plugin']` and used in a `require` statement without validation. An attacker can use path traversal sequences (e.g., `plugin=../../etc/passwd`) to include arbitrary PHP files from outside the intended `plugins/` directory, leading to arbitrary code execution.

## Source
```
File: PluginPreviewDynamicRequire.php
Line: 10
Vulnerability: require __DIR__ . '/plugins/' . $plugin . '.php';
```

The `$plugin` variable is derived from user input at line 7 with no sanitization:
```php
$plugin = $request['plugin'] ?? 'summary';
```

## Fix
### File: PluginPreviewDynamicRequire.php

```php
<?php

final class PluginPreviewDynamicRequire
{
    public function render(array $request): string
    {
        $plugin = $request['plugin'] ?? 'summary';
        $payload = $request['payload'] ?? [];

        // Validate plugin name: alphanumeric, underscore, hyphen only
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $plugin)) {
            throw new \InvalidArgumentException('Invalid plugin name');
        }

        require __DIR__ . '/plugins/' . $plugin . '.php';

        return render_preview($payload);
    }
}
```

## Explanation
The fix adds input validation using a regex pattern that permits only alphanumeric characters, underscores, and hyphens in the plugin name. This prevents path traversal attacks using sequences like `..`, `/`, `\`, or other special characters.

The pattern `^[a-zA-Z0-9_-]+$` ensures:
- Only safe characters are accepted
- Path traversal attempts with `..`, `/`, or `\` are rejected
- The plugin name must not be empty (the `+` quantifier requires at least one character)

If a plugin name doesn't match the safe pattern, an `InvalidArgumentException` is thrown, stopping execution before the unsafe `require` statement executes. This is the primary defense against arbitrary file inclusion.

An attacker attempting `plugin=../../etc/passwd%00` or similar payloads will now trigger an exception instead of including unintended files.
