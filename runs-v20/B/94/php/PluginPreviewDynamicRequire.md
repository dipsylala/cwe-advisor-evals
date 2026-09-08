## Verdict

Exploitable. Confidence: high.

`PluginPreviewDynamicRequire::render()` builds a filesystem path for `require` by concatenating an attacker-controlled string directly onto a fixed directory, with no validation of the value in between.

## Source

`$request['plugin']` (line 7) - read from the `$request` array passed into `render()`, which represents attacker-controlled request data (e.g. an HTTP query/body parameter). No sanitization, allowlist check, or type constraint is applied between this read and the sink. `$request['payload']` is passed through unchanged to `render_preview()` and is not part of this finding.

**Sink:** `require __DIR__ . '/plugins/' . $plugin . '.php';` (line 10). `$plugin` is concatenated straight into the include path. A value such as `../../../../etc/passwd%00` (older PHP), a path-traversal sequence like `../../config`, or a wrapper string (`php://filter/...`, `data://...` where `allow_url_include`/`allow_url_fopen` permit it) lets an attacker cause the server to execute arbitrary local PHP code or to read/execute a file the developer never intended to expose - classic PHP dynamic-file-inclusion code injection (CWE-94/CWE-98).

**Sink contract established before fixing:**
- **Returns:** the file's top-level output becomes part of the script's output stream (buffered/inlined); the function `render_preview()` it's expected to define is then called and its return value is returned to `render()`'s caller.
- **Discards:** nothing beyond the normal return value; there's no captured output the fix needs to preserve.
- **Implicit arguments:** none - `require` takes only the path.
- **Failure behaviour:** if the target file doesn't exist, `require` emits a fatal error and halts the script (unlike `include`, which only warns). Any fix that changes "file missing" into a different failure mode should choose one at least as safe as this one.

## Fix

### File: PluginPreviewDynamicRequire.php

```php
<?php

final class PluginPreviewDynamicRequire
{
    private const PLUGINS_DIR = __DIR__ . '/plugins/';

    public function render(array $request): string
    {
        $plugin = $request['plugin'] ?? 'summary';
        $payload = $request['payload'] ?? [];

        $allowedPlugins = $this->getAllowedPlugins();

        if (!in_array($plugin, $allowedPlugins, true)) {
            throw new \InvalidArgumentException("Unknown plugin: {$plugin}");
        }

        require self::PLUGINS_DIR . $plugin . '.php';

        return render_preview($payload);
    }

    private function getAllowedPlugins(): array
    {
        $files = glob(self::PLUGINS_DIR . '*.php') ?: [];

        return array_map(
            static fn(string $path): string => basename($path, '.php'),
            $files
        );
    }
}
```

## Explanation

The fix follows the PHP CWE-94 guidance's prescribed pattern for `include`/`require` with a variable path: validate the requested name against an allowlist before it ever reaches the sink, rather than trying to sanitize the string. Since the concrete set of valid plugin names isn't defined anywhere in the class or visible to this fix, the allowlist is derived at request time from the actual `*.php` files present in the fixed `plugins/` directory (`getAllowedPlugins()`), which is a deploy-time set the caller has no way to influence - it can only ever contain names of files that were already deployed by whoever controls the filesystem. `$plugin` is checked with a strict (`in_array(..., true)`) membership test against that list before the `require`; because the allowlist is a set of exact basenames and `$plugin` must exactly equal one of them, the value used in the sink is already the canonical allowlisted string, so no separate substitution step is needed. Any value containing path traversal sequences, absolute paths, null bytes, or stream-wrapper prefixes (`php://`, `data://`, etc.) cannot match a basename produced by `glob()` and `basename()`, so it is rejected before the `require` executes, closing the code-injection path while leaving every legitimately deployed plugin reachable exactly as before.

## Behaviour changes

- An unrecognized `plugin` value now throws `\InvalidArgumentException` before any file access is attempted, instead of PHP's `require` emitting a fatal "failed to open stream" error when the concatenated path doesn't resolve to a real file. Both are fatal/terminating outcomes for the request; this is a deliberate, earlier and more explicit failure of the same kind the sink contract already produced, not a new success path. Reason: this is the allowlist gate itself, the mechanism the guidance requires.
- The allowlist is computed by scanning the `plugins/` directory (`glob`) rather than being hard-coded, because the actual list of valid plugin names is not present anywhere in the provided file. Reason (assumption): this preserves every plugin that was already deployed and working, without guessing names that don't exist in the given code; if the real codebase maintains an explicit registry of plugin names elsewhere, that registry should be used as the allowlist source instead of directory scanning.
- No change to `$payload` handling, the `render_preview()` call, or the default `'summary'` value.

**Assumptions:** the concrete list of valid plugin identifiers isn't visible in the provided file (only `plugins/` as a directory and `'summary'` as a default are known), so the allowlist source was assumed to be "whatever `.php` files exist in `plugins/` at request time" rather than a hard-coded list. This is recorded as it affects deployment: if plugin files can be written by a lower-trust process than the one deploying this class, the directory-scan allowlist would inherit that risk and a hard-coded/registry-based allowlist should be substituted.

**Verification:** `php -l` (PHP 8.5.8 CLI) against the fixed file, run from a scratch copy outside the case directory - "No syntax errors detected". `glob()`, `basename()`, `array_map()`, `in_array()`, and `\InvalidArgumentException` are all PHP core/SPL and require no new dependency.
