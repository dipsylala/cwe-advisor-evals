## Verdict

exploitable

## Source

`$request['plugin']` (line 7) - user-controlled input passed from the request array without validation.

## Fix

**Vulnerable code:**
```php
public function render(array $request): string
{
    $plugin = $request['plugin'] ?? 'summary';
    $payload = $request['payload'] ?? [];

    require __DIR__ . '/plugins/' . $plugin . '.php';  // CWE-94: unsanitized path

    return render_preview($payload);
}
```

**Fixed code:**
```php
public function render(array $request): string
{
    $plugin = $request['plugin'] ?? 'summary';
    $payload = $request['payload'] ?? [];

    // Allowlist of permitted plugin names
    $allowedPlugins = ['summary', 'details', 'advanced'];
    
    // Validate against allowlist
    if (!in_array($plugin, $allowedPlugins, true)) {
        throw new InvalidArgumentException('Invalid plugin name');
    }

    require __DIR__ . '/plugins/' . $plugin . '.php';

    return render_preview($payload);
}
```

## Explanation

The original code concatenates user-supplied input directly into a file path passed to `require`, allowing an attacker to traverse directories (e.g., `../../config.php`) or include arbitrary PHP files from accessible directories, achieving remote code execution with the application's privilege level. The fix introduces an explicit allowlist of permitted plugin names and validates the input against it using strict comparison (`in_array(..., $allowedPlugins, true)`). Only values present in the allowlist proceed to inclusion, blocking path traversal and arbitrary file inclusion. The validated value from the allowlist ensures the correct plugin filename is used while preventing injection.

## Behaviour changes

- The fixed code throws `InvalidArgumentException` when an invalid plugin name is provided, instead of attempting to include a non-existent or unintended file. This requires the caller to handle the exception or validate input before calling `render()`.
- The allowlist must be maintained and kept synchronized with the actual plugin files available in `/plugins/`. This is a control constraint, not a bug - it establishes what is permitted and must be updated whenever plugins are added or removed.
