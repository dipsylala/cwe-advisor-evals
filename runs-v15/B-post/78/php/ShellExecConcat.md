## Verdict
exploitable

## Source
`$_GET['host']` at line 17 - attacker-controlled query parameter passed unsanitized into shell command

## Fix

**Vulnerable code (line 27):**
```php
$output = shell_exec('ping -c ' . $pingCount . ' ' . $host . ' 2>&1');
```

**Fixed code:**
```php
function runReachabilityCheck(): string
{
    $host = $_GET['host'] ?? '';

    if ($host === '') {
        http_response_code(400);
        return 'Missing host parameter.';
    }

    // Validate host format - allow alphanumeric, dots, hyphens (hostnames and IP addresses)
    if (!preg_match('/\A[a-zA-Z0-9.-]+\z/', $host)) {
        http_response_code(400);
        return 'Invalid host format.';
    }

    // Use fsockopen for reachability check instead of ping command
    $port = 80;
    $timeout = 2;
    $errno = null;
    $errstr = null;
    
    $fp = @fsockopen($host, $port, $errno, $errstr, $timeout);
    
    if ($fp === false) {
        return "Host unreachable: $errstr (errno: $errno)";
    }
    
    fclose($fp);
    return "Host $host is reachable on port $port.";
}
```

## Explanation
The vulnerability is eliminated by replacing `shell_exec()` with PHP's built-in `fsockopen()` function, which performs the same network reachability goal without invoking a shell or concatenating untrusted input into a command string. The fix adds input validation using an allowlist regex that restricts hostnames to alphanumeric characters, dots, and hyphens - this prevents injection payloads while accepting valid hostnames and dotted-decimal IP addresses. The fsockopen call attempts a TCP connection to port 80 on the specified host; connection success indicates reachability, eliminating the need for shell-based ping execution entirely.

## Behaviour changes
The reachability check changes from returning raw ping output (multiple lines with round-trip times) to returning a simple string indicating whether the host is reachable on port 80. The port is now fixed at 80 rather than all protocols that ping probes. The timeout is now 2 seconds (hardcoded) rather than determined by ping's defaults. If the host is unreachable, the error message includes the system error and errno for debugging. A stricter format validation now rejects hostnames with special characters that were previously passed through; this breaks backward compatibility for any host parameter containing `/`, `&`, `;`, or other shell metacharacters, which were exploitation vectors anyway.
