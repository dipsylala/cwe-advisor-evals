## Verdict

Confirmed. `render()` builds a filesystem path for `require` by concatenating an attacker-controlled request field (`$request['plugin']`) directly into the path, with no validation of its contents. A caller can supply a path-traversal sequence (`../../../../var/www/uploads/shell`), a null byte, or a PHP stream wrapper value to make `require` execute arbitrary PHP code instead of one of the intended plugin files - classic PHP Local File Inclusion / Remote Code Execution via dynamic `require`.

## Source

`$request['plugin']` (falls back to `'summary'` only when the key is absent) - attacker-controlled input from the HTTP request, flowing unmodified into the `require` path expression at line 10.

## Fix

### File: PluginPreviewDynamicRequire.php

```php
<?php

final class PluginPreviewDynamicRequire
{
    private const PLUGIN_DIR = __DIR__ . '/plugins';

    public function render(array $request): string
    {
        $plugin = $request['plugin'] ?? 'summary';
        $payload = $request['payload'] ?? [];

        if (!is_string($plugin) || !preg_match('/^[A-Za-z0-9_-]+$/', $plugin)) {
            throw new InvalidArgumentException('Invalid plugin identifier.');
        }

        $pluginDir = realpath(self::PLUGIN_DIR);
        if ($pluginDir === false) {
            throw new RuntimeException('Plugin directory is not available.');
        }

        $pluginFile = realpath($pluginDir . DIRECTORY_SEPARATOR . $plugin . '.php');
        if ($pluginFile === false
            || strncmp($pluginFile, $pluginDir . DIRECTORY_SEPARATOR, strlen($pluginDir) + 1) !== 0
        ) {
            throw new InvalidArgumentException('Unknown plugin: ' . $plugin);
        }

        require $pluginFile;

        return render_preview($payload);
    }
}
```

## Explanation

The fix stops the attacker-controlled value from ever reaching the filesystem path unconstrained:

- A strict allowlist pattern (`^[A-Za-z0-9_-]+$`) rejects the value outright if it contains `/`, `\`, `.`, a null byte, or a stream-wrapper prefix like `php://` or `data://` before it is ever used to build a path. Rejecting is used instead of stripping the bad characters, because stripping (e.g. removing `../`) can still leave a value that resolves somewhere unintended; rejecting guarantees the value is one of a small set of safe identifiers. This allowlist is appropriate here because `plugin` names an internal identifier defined by the application's own `plugins/` directory layout, not free-form user data with a legitimate need for special characters.
- After the character check, the code resolves both the plugins directory and the candidate file with `realpath()` and verifies the resolved file path is still contained inside the resolved plugins directory (`strncmp` prefix check on the real, symlink-resolved paths). This is the containment check that actually defeats traversal and symlink tricks - the character allowlist alone would not catch a symlink planted inside `plugins/` that points outside it.
- `realpath()` returning `false` (directory missing, or target file does not exist) is treated as an error rather than silently falling through to `require` a non-existent or attacker-influenced path.
- Only after both checks pass does the code `require` the fully-resolved, verified path, so the include target is always a real `.php` file that lives inside the intended `plugins/` directory.
