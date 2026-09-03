## Verdict

**CONFIRMED**: OS Command Injection (CWE-78) via unvalidated `$_GET['host']` parameter in `shell_exec()` call.

## Source

Line 17: `$_GET['host']` (user-controlled, unauthenticated HTTP parameter)

## Fix

**Replace the vulnerable `shell_exec()` call with `fsockopen()` for native network reachability checking:**

```php
<?php
/**
 * Network diagnostics endpoint for the internal admin panel.
 *
 * Lets an on-call engineer kick off a quick reachability check against a
 * host from the browser instead of shelling into the box directly.
 */

/**
 * Run a reachability check against the requested host and
 * return the result for display.
 *
 * @return string Reachability status message.
 */
function runReachabilityCheck(): string
{
    $host = $_GET['host'] ?? '';

    if ($host === '') {
        http_response_code(400);
        return 'Missing host parameter.';
    }

    // Validate host to prevent DNS injection and limit input to alphanumeric, dots, and hyphens
    if (!preg_match('/\A(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\z/i', $host)) {
        http_response_code(400);
        return 'Invalid host format.';
    }

    // Perform reachability check using fsockopen() instead of shell_exec()
    $port = 80; // Default to HTTP port
    $timeout = 3; // 3 second timeout

    $socket = @fsockopen($host, $port, $errno, $errstr, $timeout);

    if ($socket === false) {
        return "Host unreachable on port $port (errno: $errno, error: $errstr)";
    }

    fclose($socket);
    return "Host $host is reachable on port $port";
}

if (php_sapi_name() !== 'cli' && isset($_GET['host'])) {
    header('Content-Type: text/plain');
    echo runReachabilityCheck();
}
```

## Explanation

The vulnerability exists because the user-supplied `$host` parameter is directly concatenated into a shell command and passed to `shell_exec()`, allowing attackers to inject arbitrary OS commands. For example, `?host=8.8.8.8; rm -rf /` would execute the destructive rm command.

The fix eliminates the shell execution entirely by replacing it with `fsockopen()`, which natively tests TCP connectivity to a host and port without spawning a shell or external process. This is the primary defence recommended by CWE-78 guidance: remove the need for OS command execution.

Input validation using a strict allowlist anchor (regex with `\A` and `\z`) is added as a secondary defence to reject malformed hostnames that could bypass DNS resolvers or introduce format-based attacks. The validation allows only valid domain name characters (alphanumeric, dots, hyphens), preventing special shell characters from reaching the network function.

The fixed code returns a status message indicating reachability (same return type as original), replacing the diagnostic output from the ping command. Developers who need more detailed network diagnostics (like packet loss or latency) would need to implement those calculations, but basic reachability is preserved through the boolean success/failure of socket connection.

## Behaviour changes

- **Output changes**: Returns a reachability status message instead of raw ping output (RTT, packet loss, etc.). Original returns ping command output if reachable or null on failure; fixed version returns descriptive text message in both cases.
- **Port-based check**: Checks TCP connectivity to port 80 by default instead of ICMP ping. Different services may require different ports (443 for HTTPS, 22 for SSH, etc.) - the port is hardcoded and would need to be parameterized or configurable if multiple protocols need testing.
- **No shell execution**: Process isolation is improved; no external process or shell spawned.
- **Timeout enforced**: 3-second timeout is set for the connection attempt; original ping has configurable timing based on `-c` flag.
- **Input validation applied**: Hostnames outside standard DNS format (domain names and IPs) are now rejected at entry point before reaching the network function.
