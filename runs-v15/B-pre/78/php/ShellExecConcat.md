## Verdict
CONFIRMED - OS Command Injection via unsanitized user input concatenated into shell_exec()

## Source
Line 27 in ShellExecConcat.php:
```php
$output = shell_exec('ping -c ' . $pingCount . ' ' . $host . ' 2>&1');
```

The `$host` parameter comes from `$_GET['host']` (line 17) with only an empty-string check (line 19). An attacker can inject shell metacharacters and commands.

Example payload: `; cat /etc/passwd #` would execute arbitrary commands on the system.

## Fix
Replace shell_exec() with fsockopen(), the native PHP alternative for network reachability checks:

```php
<?php
/**
 * Network diagnostics endpoint for the internal admin panel.
 *
 * Lets an on-call engineer kick off a quick reachability check against a
 * host from the browser instead of shelling into the box directly.
 */

/**
 * Run a connection-based reachability check against the requested host and
 * return the result for display.
 *
 * @return string Result message indicating reachability.
 */
function runReachabilityCheck(): string
{
    $host = $_GET['host'] ?? '';

    if ($host === '') {
        http_response_code(400);
        return 'Missing host parameter.';
    }

    // Validate host is a reasonable hostname/IP (allowlist approach)
    if (!preg_match('\A[a-zA-Z0-9.-]+\z', $host)) {
        http_response_code(400);
        return 'Invalid host parameter.';
    }

    $port = 80;
    $timeout = 5;

    // Use fsockopen() for native connection check instead of shell_exec()
    $connection = @fsockopen($host, $port, $errno, $errstr, $timeout);

    if ($connection) {
        fclose($connection);
        return "Host $host is reachable on port $port.";
    } else {
        return "Host $host is not reachable on port $port (Error: $errstr).";
    }
}

if (php_sapi_name() !== 'cli' && isset($_GET['host'])) {
    header('Content-Type: text/plain');
    echo runReachabilityCheck();
}
```

## Explanation
The original code used `shell_exec('ping ...')` to test reachability by executing an OS command. This is vulnerable because the `$host` parameter is concatenated into the command string without escaping, allowing shell metacharacter injection.

The fix eliminates shell execution entirely by using `fsockopen()`, which is PHP's native function for testing network connectivity. This approach:

1. **Removes the injection point** - No OS command is executed, so shell metacharacters cannot be injected
2. **Uses a language-native API** - Follows the primary remediation strategy from CWE-78 guidance
3. **Achieves the same goal** - Tests whether a host is reachable by attempting a TCP connection
4. **Adds input validation** - A regex allowlist restricts `$host` to characters that make sense in a hostname (letters, digits, dots, hyphens)

The output format differs slightly: instead of raw ping output, the endpoint returns a simple reachability status message, which is appropriate for an administrative diagnostic endpoint.

## Behaviour changes
- Command execution is eliminated entirely; the OS cannot execute injected shell commands through the `$host` parameter
- Output format changes from raw `ping` command output to a simple status message indicating whether the host is reachable on port 80
- Default port tested is 80 (HTTP); if a different port is needed, it would require additional parameter validation and input handling
- Response time is typically faster than ping, as it only attempts a TCP connection rather than sending ICMP packets
