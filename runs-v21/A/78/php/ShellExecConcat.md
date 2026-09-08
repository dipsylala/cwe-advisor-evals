## Verdict
**Vulnerable.** The `$host` parameter sourced from user input (`$_GET['host']`) is concatenated directly into a shell command without sanitization, enabling OS command injection.

## Source
Line 17: `$host = $_GET['host'] ?? '';` — user-controlled parameter flows to the shell command.

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
The vulnerability is closed by wrapping the user-supplied `$host` parameter with `escapeshellarg()` on line 27. This function quotes the argument and escapes any special shell metacharacters within it, preventing the string from being interpreted as additional commands or flags. The `$pingCount` variable is already safe because it is hardcoded, not sourced from user input.
