## Verdict

The code is vulnerable to arbitrary file inclusion via path traversal in the `require` statement. Unsanitized user input from `$request['plugin']` is concatenated directly into the file path, allowing an attacker to include arbitrary PHP files from the filesystem by using sequences like `../` or absolute paths.

## Source

```php
public function render(array $request): string
{
    $plugin = $request['plugin'] ?? 'summary';
    $payload = $request['payload'] ?? [];

    require __DIR__ . '/plugins/' . $plugin . '.php';

    return render_preview($payload);
}
```

The vulnerability is on line 10 where `$plugin` is directly interpolated into the `require` path.

## Fix

```php
public function render(array $request): string
{
    $plugin = $request['plugin'] ?? 'summary';
    $payload = $request['payload'] ?? [];

    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $plugin)) {
        throw new InvalidArgumentException('Invalid plugin name');
    }

    require __DIR__ . '/plugins/' . $plugin . '.php';

    return render_preview($payload);
}
```

## Explanation

The fix validates the `$plugin` parameter using a whitelist pattern that only allows alphanumeric characters, underscores, and hyphens. This prevents path traversal attacks (sequences like `../`, `..\\`, or `/`) and ensures only legitimate plugin filenames can be included.

The validation is strict and intentional: it rejects any unexpected characters before the plugin file is loaded, failing fast with an `InvalidArgumentException` if the input is malicious or malformed. This prevents an attacker from manipulating the file path to access sensitive files outside the intended `plugins/` directory.
