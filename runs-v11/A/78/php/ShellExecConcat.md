## Verdict
CONFIRMED

## Source
Line 17: `$host = $_GET['host'] ?? '';` - untrusted user input from the query parameter

## Fix
The vulnerable command on line 27 must be protected by either validating `$host` to a known-safe pattern or escaping it for shell consumption. The most direct fix combines both:

```php
function runReachabilityCheck(): string
{
    $host = $_GET['host'] ?? '';

    if ($host === '') {
        http_response_code(400);
        return 'Missing host parameter.';
    }

    // Validate host is a hostname or IP address (alphanumeric, dots, hyphens only)
    if (!preg_match('/^[a-zA-Z0-9.\-:]+$/', $host)) {
        http_response_code(400);
        return 'Invalid host parameter.';
    }

    $pingCount = 4;

    // Safe: validated input + escapeshellarg() as defense-in-depth
    $output = shell_exec('ping -c ' . $pingCount . ' ' . escapeshellarg($host) . ' 2>&1');

    if ($output === null) {
        return 'Diagnostic command failed to run.';
    }

    return $output;
}
```

## Explanation
The original code concatenates unsanitized user input (`$host`) directly into the shell string passed to `shell_exec()`. An attacker can inject shell metacharacters (e.g., `;`, `|`, `&`, `$()``) to execute arbitrary commands.

The fix applies two layers:

1. **Input validation**: The regex `^[a-zA-Z0-9.\-:]+$` restricts `$host` to characters valid in hostnames and IPv6 addresses, rejecting any input containing shell metacharacters or path traversal sequences upfront.

2. **Escaping**: `escapeshellarg()` quotes the remaining `$host` value as a single shell argument, ensuring any shell metacharacters within it are treated literally by the shell, not as command operators.

Together, these prevent both the obvious injection vectors (rejecting control characters outright) and provide a safety net for any unexpected input that passes validation.

An alternative approach using `proc_open()` with an argument array avoids the shell entirely, but `escapeshellarg()` is more concise for this use case and is idiomatic PHP for command injection defense.
