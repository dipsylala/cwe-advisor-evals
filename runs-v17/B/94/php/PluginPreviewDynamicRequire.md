## Verdict

Real. The vulnerability is confirmed: line 10 performs an unrestricted `require()` with a user-controlled path derived from the `$plugin` parameter, which is drawn from untrusted `$request` input without validation. An attacker can supply path traversal sequences or arbitrary filesystem paths to include unintended files.

## Source

```php
final class PluginPreviewDynamicRequire
{
    public function render(array $request): string
    {
        $plugin = $request['plugin'] ?? 'summary';
        $payload = $request['payload'] ?? [];

        require __DIR__ . '/plugins/' . $plugin . '.php';  // Line 10: unsafe include

        return render_preview($payload);
    }
}
```

The `$plugin` variable at line 7 is read directly from user input and concatenated into a `require()` path without allowlist validation. This permits path traversal attacks or arbitrary file inclusion.

## Fix

### File: PluginPreviewDynamicRequire.php

```php
<?php

final class PluginPreviewDynamicRequire
{
    private const ALLOWED_PLUGINS = ['summary', 'details', 'preview'];

    public function render(array $request): string
    {
        $plugin = $request['plugin'] ?? 'summary';
        $payload = $request['payload'] ?? [];

        if (!in_array($plugin, self::ALLOWED_PLUGINS, true)) {
            throw new \InvalidArgumentException(sprintf(
                'Plugin "%s" is not permitted',
                $plugin
            ));
        }

        require __DIR__ . '/plugins/' . $plugin . '.php';

        return render_preview($payload);
    }
}
```

## Explanation

The fix introduces an allowlist-based validation gate: a class constant `ALLOWED_PLUGINS` defines the only plugin names the application will load. Before the `require()` executes, the supplied `$plugin` is checked against this allowlist using `in_array()` with strict comparison (`true` as the third argument) to prevent type juggling bypasses.

If the plugin name is not in the allowlist, an `\InvalidArgumentException` is raised immediately, preventing the unsafe `require()` from executing. This follows the PHP guidance for CWE-94: "Never use `include`/`require` with user-controlled paths - use an allowlist of permitted filenames."

The allowlist is private and constant, preventing accidental modification. The error message is specific enough to aid debugging but does not leak the full path.

## Behaviour changes

- **Blocked paths**: Any attempt to load a plugin not in `ALLOWED_PLUGINS` now raises an exception instead of silently attempting to include a file at an attacker-supplied path.
- **Valid requests unchanged**: Requests for `plugin=summary`, `plugin=details`, or `plugin=preview` behave identically to before (assuming those files exist in the `plugins/` directory).
- **Default unchanged**: Requests omitting the `plugin` parameter still default to `'summary'`, which is in the allowlist.
- **Path traversal defeated**: Inputs like `plugin=../../config` or `plugin=../etc/passwd` are rejected with an exception instead of attempting to include filesystem paths outside the intended `plugins/` directory.
