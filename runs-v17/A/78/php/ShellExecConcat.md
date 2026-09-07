## Verdict
Real OS command injection vulnerability. User-controlled input from `$_GET['host']` is concatenated directly into a shell command without sanitization, allowing arbitrary command execution.

## Source
Line 27 in ShellExecConcat.php:
```php
$output = shell_exec('ping -c ' . $pingCount . ' ' . $host . ' 2>&1');
```

The `$host` variable (assigned from `$_GET['host']` on line 17) is concatenated into the shell command as-is. An attacker can pass shell metacharacters or commands (e.g., `google.com; rm -rf /`) to execute arbitrary OS commands on the server.

## Fix
### File: ShellExecConcat.php
```php
<?php
/**
 * Network diagnostics endpoint for the internal admin panel.
 *
 * Lets an on-call engineer kick off a quick reachability check against a
 * host from the browser instead of shelling into the box directly.
 */

/**
 * Run a ping-based reachability check against the requested host and
 * return the raw command output for display.
 *
 * @return string Combined stdout/stderr from the diagnostic command.
 */
function runReachabilityCheck(): string
{
    $host = $_GET['host'] ?? '';

    if ($host === '') {
        http_response_code(400);
        return 'Missing host parameter.';
    }

    $pingCount = 4;

    // SAST FINDING: CWE-78 (Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')) reported here. Sink is the next statement.
    $output = shell_exec('ping -c ' . $pingCount . ' ' . escapeshellarg($host) . ' 2>&1');

    if ($output === null) {
        return 'Diagnostic command failed to run.';
    }

    return $output;
}

if (php_sapi_name() !== 'cli' && isset($_GET['host'])) {
    header('Content-Type: text/plain');
    echo runReachabilityCheck();
}
```

## Explanation
The fix uses PHP's `escapeshellarg()` function to safely escape the user-supplied `$host` parameter. This function wraps the argument in single quotes and escapes any single quotes within the value, ensuring the shell treats it as a single literal argument rather than allowing metacharacter interpretation or command chaining.

With `escapeshellarg()`, the input `google.com; rm -rf /` becomes the literal string `'google.com; rm -rf /'`, which ping will attempt to resolve as a hostname rather than executing as a separate command. This neutralizes the injection vector while preserving the legitimate functionality of passing the host to the ping command.
