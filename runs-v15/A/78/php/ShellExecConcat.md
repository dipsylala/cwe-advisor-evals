## Verdict

Real - confirmed OS command injection via unsanitized user input to shell_exec().

## Source

Line 27: User-supplied `$_GET['host']` is concatenated directly into a shell command string without escaping or validation.

```php
$host = $_GET['host'] ?? '';
// ...
$output = shell_exec('ping -c ' . $pingCount . ' ' . $host . ' 2>&1');
```

An attacker can inject shell metacharacters (`;`, `|`, `&`, `$(...)`, etc.) to execute arbitrary commands. For example, `?host=127.0.0.1; rm -rf /` would execute the ping followed by file deletion.

## Fix

Escape the `$host` parameter using `escapeshellarg()` before passing it to `shell_exec()`:

```php
$output = shell_exec('ping -c ' . $pingCount . ' ' . escapeshellarg($host) . ' 2>&1');
```

Alternatively, validate that `$host` matches a strict pattern (IPv4, IPv6, or FQDN) and reject anything else:

```php
if (!filter_var($host, FILTER_VALIDATE_IP) && !filter_var($host, FILTER_VALIDATE_DOMAIN)) {
    http_response_code(400);
    return 'Invalid host parameter.';
}
$output = shell_exec('ping -c ' . $pingCount . ' ' . escapeshellarg($host) . ' 2>&1');
```

## Explanation

`escapeshellarg()` wraps the argument in single quotes and escapes any existing single quotes within the value, making it safe to pass to shell_exec(). This preserves the intended behavior (ping executes with the host as an argument) while preventing injection.

The validation approach adds defense-in-depth by rejecting unexpected input shapes, reducing the attack surface. For a diagnostic endpoint, whitelist-based validation of the host format is preferred alongside escaping to ensure only legitimate reachability checks can be run.
