## Verdict

Exploitable. The code directly concatenates user-controlled input into a `require` statement without validation, allowing an attacker to include arbitrary files from the filesystem.

## Source

User input enters via `$request['plugin']` (line 7), which comes from the HTTP request parameters or external caller. The value is used directly in the file path on line 10: `require __DIR__ . '/plugins/' . $plugin . '.php'`.

An attacker can supply `$request['plugin'] = '../../config'` or similar path traversal sequences to load files outside the intended `plugins/` directory, or use null bytes (in older PHP versions) to bypass the `.php` extension, or include other arbitrary files the server can read.

## Fix

Replace the dynamic `require` with an allowlist of permitted plugin names. Validate the requested plugin against the allowlist before including it, and use only the whitelisted value:

```php
<?php

final class PluginPreviewDynamicRequire
{
    // Define allowed plugins
    private const ALLOWED_PLUGINS = ['summary', 'dashboard', 'profile'];

    public function render(array $request): string
    {
        $plugin = $request['plugin'] ?? 'summary';
        $payload = $request['payload'] ?? [];

        // Validate against allowlist
        if (!in_array($plugin, self::ALLOWED_PLUGINS, true)) {
            throw new \InvalidArgumentException('Invalid plugin requested');
        }

        require __DIR__ . '/plugins/' . $plugin . '.php';

        return render_preview($payload);
    }
}
```

## Explanation

The fix eliminates the code injection vulnerability by removing the dynamic execution of untrusted input. Instead of permitting any plugin name, it defines a whitelist of safe, pre-approved plugin names in `ALLOWED_PLUGINS`. The `in_array()` check with strict type matching (`true` parameter) ensures the requested plugin is in the allowlist before the file is loaded. Only validated values are passed to `require`, ensuring that path traversal attempts, null bytes, or other injection techniques cannot load unintended files.

The use of `const` for the allowlist keeps the safe values server-controlled and immutable, preventing accidental modification at runtime. The exception provides clear feedback when an invalid plugin is requested, rather than silently failing or revealing filesystem paths.

## Behaviour changes

- Requests for plugins not in the `ALLOWED_PLUGINS` list will now raise an `InvalidArgumentException` instead of attempting to include a file.
- Previously, an attacker could traverse directories or include arbitrary files; now only whitelisted plugins can be loaded.
- The application's behavior is restricted to a known-safe set of plugins, eliminating the attack surface.
- Default behavior unchanged: requesting no plugin still loads the `summary` plugin.
