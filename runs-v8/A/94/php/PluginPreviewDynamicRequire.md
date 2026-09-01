## Verdict

The code constructs a file path for dynamic code inclusion using unsanitized user input. Line 10 directly concatenates the `$plugin` parameter from the request into a `require` statement, allowing an attacker to load arbitrary PHP files from the filesystem.

## Source

```php
$plugin = $request['plugin'] ?? 'summary';
// ...
require __DIR__ . '/plugins/' . $plugin . '.php';
```

An attacker can supply any value for `$plugin` to load unintended files (e.g., `$plugin = '../../../var/www/html/uploaded'` to include a user-uploaded file, or any existing PHP file on the server).

## Fix

Use an explicit allowlist of permitted plugin names and validate the input before including:

```php
final class PluginPreviewDynamicRequire
{
    private const ALLOWED_PLUGINS = ['summary', 'detail', 'compact'];

    public function render(array $request): string
    {
        $plugin = $request['plugin'] ?? 'summary';
        $payload = $request['payload'] ?? [];

        // Validate against allowlist
        if (!in_array($plugin, self::ALLOWED_PLUGINS, true)) {
            throw new InvalidArgumentException(
                'Invalid plugin: ' . $plugin
            );
        }

        require __DIR__ . '/plugins/' . $plugin . '.php';

        return render_preview($payload);
    }
}
```

## Explanation

The remediation uses an explicit allowlist of permitted plugin names defined as a class constant. The `$plugin` value is validated against this allowlist using strict comparison (`in_array()` with `true` as the third argument) before constructing the file path. This prevents dynamic code injection: even if an attacker supplies a malicious value, the code will either reject it or use only one of the known-safe plugin names. The allowlist should contain only the names of plugins that exist in the `/plugins/` directory and are safe to load.
