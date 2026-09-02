## Verdict

- **CWE-94** (Improper Control of Generation of Code / Code Injection via unrestricted `require`)
- **Location:** `PluginPreviewDynamicRequire.php:10`
- **Verdict:** exploitable
- **Confidence:** medium - the sink and taint path are unambiguous; confidence is not high only because the actual contents of `plugins/` (and therefore the correct allowlist values) are not visible in the provided file, per the Assumptions note below.

## Source

- **Source:** `$request['plugin']`, read at line 7 (`$request['plugin'] ?? 'summary'`). `$request` is the method's parameter and is treated as attacker-controlled HTTP request data (no sanitization or type constraint is applied before use).
- **Path:** the value flows unmodified from `$plugin` directly into a string-concatenated file path at line 10 - no validation, allowlist check, or canonicalization occurs between source and sink.
- **Sink:** `require __DIR__ . '/plugins/' . $plugin . '.php';` (line 10). This is a PHP file-inclusion sink: `require` compiles and executes whatever PHP file the resulting path resolves to, in the full runtime context of the application (same variable scope, same credentials, same privileges).
- **Impact:** supplying a path-traversal value for `plugin` (e.g. `../../../../tmp/uploaded` or an absolute-path-style payload, subject to PHP's path handling) can cause the `require` to execute an arbitrary PHP file elsewhere on the filesystem instead of one of the intended `plugins/*.php` files - full code execution in the application's context.

## Fix

No third-party library is needed; the fix is a code-level allowlist per `cwe/94/php/INDEX.md`.

**Vulnerable code:**

```php
final class PluginPreviewDynamicRequire
{
    public function render(array $request): string
    {
        $plugin = $request['plugin'] ?? 'summary';
        $payload = $request['payload'] ?? [];

        // Untrusted $plugin is concatenated directly into a require path - code injection / LFI.
        require __DIR__ . '/plugins/' . $plugin . '.php';

        return render_preview($payload);
    }
}
```

**Fixed code:**

```php
final class PluginPreviewDynamicRequire
{
    // Enumerate the actual filenames present under plugins/ (without the .php suffix).
    private const ALLOWED_PLUGINS = ['summary'];

    public function render(array $request): string
    {
        $requestedPlugin = $request['plugin'] ?? 'summary';
        $payload = $request['payload'] ?? [];

        if (!in_array($requestedPlugin, self::ALLOWED_PLUGINS, true)) {
            throw new \InvalidArgumentException('Unknown plugin requested');
        }

        // $requestedPlugin is now confirmed equal to one of the allowlisted, developer-controlled
        // strings above, so it is safe to use in the require path.
        require __DIR__ . '/plugins/' . $requestedPlugin . '.php';

        return render_preview($payload);
    }
}
```

## Explanation

The vulnerability is that `$plugin` - an HTTP-controlled value with no validation - is concatenated directly into a filesystem path passed to `require`, letting an attacker choose which PHP file the application executes. The fix adds an explicit allowlist (`ALLOWED_PLUGINS`) of the plugin identifiers the application is actually meant to serve, and rejects any request whose `plugin` value is not an exact (strict, type-safe `in_array(..., true)`) match against that list before the value ever reaches the `require`. Because the check is an exact-match membership test rather than a transformation, the value used at the sink is provably one of the fixed, developer-authored strings in the allowlist - not attacker-supplied data - which closes the code-injection path while preserving the existing dynamic-dispatch-by-name behavior for all legitimate plugins.

## Behaviour changes

- A request for a `plugin` value not present in `ALLOWED_PLUGINS` now throws `InvalidArgumentException` instead of attempting the `require`. Previously such a request would have either fatally errored (file not found) or, if a matching file happened to exist on disk, been included and executed - so this is a narrowing of behavior directly tied to closing the weakness, not an unrelated change. The `require`'s own return value, its use of `__DIR__`, and the call to `render_preview($payload)` on success are all unchanged.
- **Assumption:** `ALLOWED_PLUGINS` is populated with only `'summary'`, the one value visible in the provided file (the default fallback). The real list must be replaced with every plugin filename that actually exists under `plugins/`, since the contents of that directory were not part of the provided call chain - deploying this fix with an incomplete allowlist will functionally break any currently-supported plugin not listed.
