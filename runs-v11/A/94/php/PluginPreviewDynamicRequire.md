## Verdict

Code injection via unvalidated dynamic file inclusion.

## Source

Line 10 includes a file whose path is constructed from unsanitized user input:

```php
$plugin = $request['plugin'] ?? 'summary';
require __DIR__ . '/plugins/' . $plugin . '.php';
```

The `$plugin` parameter originates directly from `$request` without validation, allowing an attacker to inject path traversal sequences or absolute paths.

## Fix

Validate the `$plugin` parameter against a strict allowlist of safe characters before using it in a file path:

```php
public function render(array $request): string
{
    $plugin = $request['plugin'] ?? 'summary';
    $payload = $request['payload'] ?? [];

    // Validate plugin name: alphanumeric, underscore, hyphen only
    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $plugin)) {
        throw new InvalidArgumentException('Invalid plugin name');
    }

    $path = __DIR__ . '/plugins/' . $plugin . '.php';
    
    // Ensure the resolved path stays within the plugins directory
    $realPath = realpath($path);
    $pluginsDir = realpath(__DIR__ . '/plugins');
    
    if ($realPath === false || strpos($realPath, $pluginsDir) !== 0) {
        throw new InvalidArgumentException('Invalid plugin path');
    }

    require $realPath;

    return render_preview($payload);
}
```

## Explanation

The fix uses two layers of validation:

1. **Character validation**: `preg_match()` enforces that `$plugin` contains only alphanumeric characters, underscores, and hyphens. This blocks path traversal sequences like `../`, absolute paths, and stream wrapper schemes like `php://`.

2. **Path canonicalization**: `realpath()` resolves the final path to its absolute form and verifies it exists. Comparing against the plugins directory ensures the included file stays within the intended location, preventing directory traversal.

Together, these checks prevent an attacker from including arbitrary files while still allowing legitimate plugin names.
