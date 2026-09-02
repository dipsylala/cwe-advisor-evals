## Verdict

Confirmed. `PluginPreviewDynamicRequire::render()` builds a filesystem path for `require` by concatenating an attacker-controlled request field directly into the path, with no allowlist, no character restriction, and no confinement to the intended directory. This is improper control of generation of code (CWE-94): the request can select and execute an arbitrary PHP file.

## Source

`$plugin = $request['plugin'] ?? 'summary';` on line 7. `$request` is the method's input parameter (the render request), so `plugin` is attacker-controlled. It flows unmodified into the `require` path built on line 10:

```
require __DIR__ . '/plugins/' . $plugin . '.php';
```

Because `$plugin` is concatenated verbatim, a value such as `../../../../var/www/uploads/evil` traverses out of the `plugins/` directory, and on hosts where an attacker can place or influence file content elsewhere on disk (upload directories, log files, session files, cache files), this turns into arbitrary PHP code execution when that file is `require`d. Even without traversal, `plugin` selects and executes any `.php` file already present under `plugins/`, which may include files never meant to be reachable this way.

## Fix

```php
<?php

final class PluginPreviewDynamicRequire
{
    private const ALLOWED_PLUGINS = [
        'summary',
        'gallery',
        'timeline',
        // ... every legitimate plugin name, enumerated explicitly
    ];

    public function render(array $request): string
    {
        $plugin = $request['plugin'] ?? 'summary';
        $payload = $request['payload'] ?? [];

        if (!in_array($plugin, self::ALLOWED_PLUGINS, true)) {
            throw new InvalidArgumentException('Unknown plugin requested.');
        }

        require __DIR__ . '/plugins/' . $plugin . '.php';

        return render_preview($payload);
    }
}
```

## Explanation

The fix replaces free-form path construction with a strict allowlist check (`in_array(..., true)` for strict, type-safe comparison) before the value ever reaches `require`. Only a name that exactly matches a pre-approved plugin identifier is allowed through; anything else — path traversal sequences, unexpected filenames, or plugin names that happen to exist on disk but were never intended to be reachable through this request — is rejected before the filesystem is touched.

An allowlist is the correct primary defense here rather than sanitization (stripping `../` or slashes) because sanitization only narrows the attack surface without closing it, and the set of legitimate plugin names is small, known, and rarely changes, making an explicit allowlist both safe and low-maintenance. `basename()` or regex filtering alone would still permit selection of any `.php` file already present in the directory, including ones not meant to be exposed via this preview path; the allowlist additionally constrains *which* files can be selected, not just how the filename is shaped.

Because the allowed values are hard-coded plugin identifiers rather than external input, `$plugin` is fully trusted by the time it is concatenated into the `require` path, and the rest of the path (`__DIR__ . '/plugins/' . ... . '.php'`) stays fixed and safe. To verify, add a test confirming that a request with `plugin` set to a traversal sequence (e.g. `../../etc/passwd%00` or `../secret`) or to a filename outside the allowlist throws `InvalidArgumentException` and never executes `require`, alongside a positive test confirming each legitimate plugin name in the allowlist still renders successfully.
