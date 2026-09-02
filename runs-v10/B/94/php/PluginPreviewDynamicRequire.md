## Verdict

Confirmed: CWE-94 code injection via unsanitized `require()` path. The `$plugin` parameter is taken directly from untrusted user input and concatenated into a file path passed to `require()`, allowing arbitrary PHP file inclusion and execution.

## Source

```php
public function render(array $request): string
{
    $plugin = $request['plugin'] ?? 'summary';  // User-controlled input
    $payload = $request['payload'] ?? [];

    require __DIR__ . '/plugins/' . $plugin . '.php';  // Taint sink: require with user-controlled path

    return render_preview($payload);
}
```

Data flow: `$request['plugin']` (untrusted HTTP parameter) → `$plugin` (no validation) → `require()` (dynamic execution).

## Fix

```php
public function render(array $request): string
{
    $plugin = $request['plugin'] ?? 'summary';
    $payload = $request['payload'] ?? [];

    // Allowlist of permitted plugin names
    $allowed_plugins = ['summary', 'detail', 'preview'];
    
    if (!in_array($plugin, $allowed_plugins, true)) {
        throw new InvalidArgumentException("Invalid plugin: {$plugin}");
    }

    require __DIR__ . '/plugins/' . $plugin . '.php';

    return render_preview($payload);
}
```

## Explanation

The fix introduces an allowlist of permitted plugin names before the `require()` call. The validation uses `in_array()` with strict type checking (`true` flag) to ensure an exact match against the whitelist. If the supplied `$plugin` value is not in the allowlist, an exception is thrown, preventing execution of arbitrary files.

This follows the PHP-specific guidance for CWE-94: "For `include`/`require` with variable paths, replace with an allowlist." The approach eliminates code injection by restricting which files can be loaded to only those explicitly permitted, eliminating path traversal and arbitrary file inclusion.

## Behaviour changes

**Before fix**: Any value in `$request['plugin']` is used to construct the file path. An attacker can supply paths like `../../config` or `../../../etc/passwd` to include and execute arbitrary files with access to the application's environment, variables, and secrets.

**After fix**: Only plugin names matching the whitelist ('summary', 'detail', 'preview') are accepted. Requests with other values throw an `InvalidArgumentException` and do not proceed to file inclusion. Calls with permitted plugin names behave identically to before (same file is included).

**Error handling change**: Code that previously encountered a missing file (fatal error from `require`) or arbitrary file inclusion now encounters an `InvalidArgumentException` on invalid plugin names. Callers must handle or allow this exception to propagate appropriately.
