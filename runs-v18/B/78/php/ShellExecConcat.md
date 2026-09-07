## Verdict

Remediation confirmed. The vulnerability is exploitable: `$_GET['host']` is unsanitized and concatenated directly into a shell_exec() command string, allowing arbitrary command injection. Fixed by replacing shell_exec() with fsockopen() for network reachability checks and adding hostname validation.

## Source

File: `ShellExecConcat.php`, line 27

```php
$output = shell_exec('ping -c ' . $pingCount . ' ' . $host . ' 2>&1');
```

The `$host` variable originates from `$_GET['host']` (line 17) with only an empty-string check, then flows directly into the shell_exec() sink where it is concatenated into the command string.

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
 * Run a fsockopen-based reachability check against the requested host and
 * return diagnostic output for display.
 *
 * @return string Diagnostic output from the reachability check.
 */
function runReachabilityCheck(): string
{
    $host = $_GET['host'] ?? '';

    if ($host === '') {
        http_response_code(400);
        return 'Missing host parameter.';
    }

    // Validate hostname/IP format to prevent injection via host parameter
    if (!filter_var($host, FILTER_VALIDATE_IP) && 
        !preg_match('/\A([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\z/', $host)) {
        http_response_code(400);
        return 'Invalid host format.';
    }

    // Use fsockopen to check reachability on common ports
    $ports = [80, 443, 22];
    $results = [];
    
    foreach ($ports as $port) {
        $startTime = microtime(true);
        $sock = @fsockopen($host, $port, $errno, $errstr, 2);
        $elapsed = (microtime(true) - $startTime) * 1000;
        
        if ($sock) {
            fclose($sock);
            $results[] = "Port $port: reachable ({$elapsed}ms)";
        } else {
            $results[] = "Port $port: unreachable";
        }
    }

    return implode("\n", $results);
}

if (php_sapi_name() !== 'cli' && isset($_GET['host'])) {
    header('Content-Type: text/plain');
    echo runReachabilityCheck();
}
```

## Explanation

The fix eliminates the OS command injection vulnerability by replacing `shell_exec()` with PHP's built-in `fsockopen()` function, per the CWE-78 PHP guidance which explicitly recommends "Use fsockopen() for network checks instead of ping command."

Three changes close the vulnerability:

1. **Remove shell execution**: Replace shell_exec() and string concatenation with fsockopen(), eliminating the shell metacharacter interpretation entirely. The `$host` parameter no longer reaches any command execution sink.

2. **Validate hostname/IP format**: Add an allowlist-style regex that accepts only valid FQDN labels and dot separators, plus filter_var() for IPv4/IPv6 detection. Reject the request if the host does not match these formats. The regex enforces that labels start and end with alphanumerics, contain only hyphens as separators, and follow valid domain naming rules. This is the application's expected input format - diagnostic checks are intended for real hosts, not arbitrary command strings.

3. **Use parameterized network API**: fsockopen() takes the host and port as separate parameters, not as a command string. The host cannot be misinterpreted as a command sequence or redirect.

The fix preserves the endpoint's purpose (host reachability checks) while replacing the unsafe ping command with TCP connectivity checks on standard ports. The response format changes from raw ping output to port-by-port reachability status, which is appropriate for the shift from ICMP-based diagnostics to TCP-based checks using native PHP APIs.

## Behaviour changes

- **Input validation**: Requests with invalid hostname/IP formats now return HTTP 400 and an error message instead of attempting execution.
- **Diagnostic output**: Changed from raw ping output (ICMP echo response times) to TCP port reachability checks on ports 80, 443, and 22. Each line reports whether a port is reachable and the connection time in milliseconds.
- **Error handling**: Connection failures now report "unreachable" instead of command error output.
- **Shell invocation**: Completely eliminated; no shell interpreter is spawned for this endpoint.
