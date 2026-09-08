## Verdict
exploitable

## Source
`$request['plugin']` at line 7, user-controlled array input passed to the `render()` method.

## Sink
`require` statement at line 10 using an unsanitized path constructed from the untrusted `$plugin` value: `require __DIR__ . '/plugins/' . $plugin . '.php';`

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

        // Allowlist of permitted plugin names
        $allowedPlugins = ['summary', 'details', 'preview'];
        
        if (!in_array($plugin, $allowedPlugins, true)) {
            throw new InvalidArgumentException('Invalid plugin requested');
        }

        require __DIR__ . '/plugins/' . $plugin . '.php';

        return render_preview($payload);
    }
}
```

## Explanation

The vulnerability is a path traversal attack via dynamic file inclusion. An attacker could supply `plugin = "../../../etc/passwd"` or `plugin = "php://filter/resource=..."` to execute arbitrary files outside the intended `plugins/` directory, achieving remote code execution.

The fix introduces an allowlist of permitted plugin names and validates the user input against it using `in_array($plugin, $allowedPlugins, true)`. The strict type check (third parameter `true`) ensures the plugin name matches exactly by type. If the plugin is not in the allowlist, an `InvalidArgumentException` is thrown, preventing the execution of any non-whitelisted file. Only validated plugin names are then passed to the `require` statement, eliminating the path traversal attack vector.

## Behaviour changes

The fix adds validation logic that may throw an `InvalidArgumentException` if an invalid plugin name is supplied. The calling code must handle this exception. This is a behaviour change from the original code, which would attempt to include any file matching the constructed path (or fail silently with a warning). The new behavior is safer and rejects invalid input explicitly rather than attempting to execute potentially dangerous files. The return value and successful execution path remain unchanged when the plugin name is in the allowlist.
