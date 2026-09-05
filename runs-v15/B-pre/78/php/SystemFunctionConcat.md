## Verdict

Exploitable. The `$host` parameter is sourced from untrusted user input (`$_GET['host']`) and directly concatenated into a system command without validation or escaping, allowing arbitrary OS command execution.

## Source

User-supplied `$host` parameter via `$_GET['host']` at line 16, which flows directly into the `system()` call at line 8 with no validation.

## Fix

**Vulnerable code (line 8):**
```php
system('ping -c 2 -W 2 ' . $host, $resultCode);
```

**Fixed code:**
```php
function check_host_reachability(string $host): array
{
    $resultCode = 0;

    // Use fsockopen for network reachability check instead of system command
    $handle = @fsockopen($host, 80, $errno, $errstr, 2);
    
    if ($handle) {
        fclose($handle);
        $resultCode = 0;
    } else {
        $resultCode = 1;
    }

    return [
        'host' => $host,
        'reachable' => $resultCode === 0,
    ];
}
```

## Explanation

The fix replaces the system `ping` command with PHP's native `fsockopen()` function, which performs a network-level reachability check by attempting a TCP connection to port 80 on the target host. This eliminates the OS command injection vulnerability entirely because no shell command is executed. The `fsockopen()` call requires only the hostname and port, does not interpret special shell characters or command separators, and is not vulnerable to argument injection. The function signature and return structure remain identical, preserving the original behavior contract. Error handling via `@` operator suppresses connection warnings and allows graceful false return on connection failure, which correctly maps to the original ping exit code behavior (0 for success, non-zero for failure).

## Behaviour changes

1. **Check mechanism**: Changed from ICMP ping (layer 3) to TCP connection attempt (layer 4) on port 80. A host reachable by ping may not have port 80 open and vice versa, but both indicate basic network connectivity for the typical use case of verifying a web-accessible host. This is the documented and recommended alternative in the PHP guidance.

2. **Timeout behavior**: The original ping used a 2-second timeout per packet with 2 packets. The `fsockopen()` call uses a single 2-second timeout for the initial connection attempt, which may be slightly faster in failure cases but provides adequate reachability confirmation.

3. **Command execution eliminated**: The original code executed a system command, discarding stderr and using only the exit code. The fixed code performs no external process execution, entirely removing the injection surface.
