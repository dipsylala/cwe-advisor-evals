## Verdict

**Confirmed exploitable.** The `$host` parameter is sourced from `$_GET['host']` without validation and concatenated directly into a shell command string passed to `shell_exec()` on line 27. An attacker can inject shell metacharacters to execute arbitrary commands (e.g., `127.0.0.1; rm -rf /` executes both ping and the rm command).

## Source

User input flows from `$_GET['host']` (line 17) with no validation checks, proceeding directly to the sink at line 27.

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
 * Run a connectivity check against the requested host and
 * return the result.
 *
 * @return string Connectivity status message.
 */
function runReachabilityCheck(): string
{
    $host = $_GET['host'] ?? '';

    if ($host === '') {
        http_response_code(400);
        return 'Missing host parameter.';
    }

    // Validate host format: allow only alphanumeric characters, dots, and hyphens
    if (!preg_match('/\A[a-zA-Z0-9.-]+\z/', $host)) {
        http_response_code(400);
        return 'Invalid host format.';
    }

    // Check connectivity using fsockopen instead of shell ping command
    $ports = [80, 443];
    foreach ($ports as $port) {
        $connection = @fsockopen($host, $port, $errno, $errstr, 2);
        if ($connection !== false) {
            fclose($connection);
            return "Host $host is reachable on port $port.";
        }
    }

    return "Host $host does not respond on ports 80 or 443.";
}

if (php_sapi_name() !== 'cli' && isset($_GET['host'])) {
    header('Content-Type: text/plain');
    echo runReachabilityCheck();
}
```

## Explanation

The fix eliminates the OS command injection entirely by replacing the `shell_exec('ping ...')` call with `fsockopen()`, a built-in PHP function for network connectivity checks. This removes the shell layer completely, preventing metacharacter injection.

The input validation regex `/\A[a-zA-Z0-9.-]+\z/` uses anchors `\A` and `\z` (as per CWE-78 guidance) to strictly match valid hostnames and IPv4 addresses, rejecting any input containing shell metacharacters or whitespace before it reaches the network function.

The fix preserves the core functionality—checking whether a host is reachable—while using PHP's native network API instead of spawning a system process. The function now checks connectivity on common ports (80, 443) and returns a status message indicating reachability.

## Behaviour changes

- **Output format**: Changed from raw ping command output (round-trip times, packet loss statistics) to simple connectivity status ("Host X is reachable on port Y" or "does not respond on ports 80 or 443")
- **Port checking**: Uses port-based connectivity (HTTP/HTTPS) instead of ICMP ping, which is more reliable through firewalls and requires no elevated privileges
- **Timeout**: Connection timeout fixed at 2 seconds (configurable via the fifth parameter to `fsockopen()`)
- **Invalid input handling**: Now explicitly rejects hosts with invalid characters with a 400 response, whereas the original silently passed invalid input to the shell
- **Error handling**: Network errors are silently suppressed (via `@`) and reported as "unreachable"; the original command's stderr was captured and returned
