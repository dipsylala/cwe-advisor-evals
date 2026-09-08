## Verdict

Confirmed. The code at line 10 uses user-supplied input in a `require` statement without validation, allowing arbitrary PHP files to be loaded from the filesystem.

## Source

```php
<?php

final class PluginPreviewDynamicRequire
{
    public function render(array $request): string
    {
        $plugin = $request['plugin'] ?? 'summary';
        $payload = $request['payload'] ?? [];

        require __DIR__ . '/plugins/' . $plugin . '.php';

        return render_preview($payload);
    }
}
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

        // Validate that plugin name contains only safe characters (alphanumeric, dash, underscore)
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $plugin)) {
            throw new InvalidArgumentException('Invalid plugin name');
        }

        $pluginPath = __DIR__ . '/plugins/' . $plugin . '.php';

        // Verify the resolved path stays within the plugins directory
        $realPluginPath = realpath($pluginPath);
        $pluginDir = realpath(__DIR__ . '/plugins');

        if ($realPluginPath === false || strpos($realPluginPath, $pluginDir) !== 0) {
            throw new InvalidArgumentException('Plugin file not found');
        }

        require $pluginPath;

        return render_preview($payload);
    }
}
```

## Explanation

The vulnerability allows arbitrary file inclusion through the `$plugin` parameter. The fix implements two layers of control:

1. **Pattern validation**: `preg_match('/^[a-zA-Z0-9_-]+$/', $plugin)` restricts the plugin name to alphanumeric characters, dashes, and underscores, eliminating path traversal sequences like `../` that could escape the plugins directory.

2. **Path containment check**: `realpath()` resolves the final path to its canonical form, then verifies it stays within the intended `plugins` directory using `strpos()`. This catches any remaining path traversal attempts and confirms the file exists before requiring it. If the resolved path is outside the plugins directory or the file doesn't exist, an exception is thrown.

These controls ensure that only legitimately named plugin files within the designated directory can be loaded.
