## Verdict

exploitable

## Source

`$_GET['host']` on line 17, passed to `check_host_reachability()` function on line 17.

## Fix

### File: SystemFunctionConcat.php

```php
<?php

function check_host_reachability(string $host): array
{
    // Validate host input - reject empty and extremely long values
    if (empty($host) || strlen($host) > 255) {
        return [
            'host' => $host,
            'reachable' => false,
        ];
    }

    // Strict allowlist for hostname/IP - alphanumeric, dots, hyphens, colons (IPv6)
    if (!preg_match('/\A[a-zA-Z0-9:.\-]+\z/', $host)) {
        return [
            'host' => $host,
            'reachable' => false,
        ];
    }

    // Use fsockopen for network reachability check instead of system ping command
    $socket = @fsockopen($host, 80, $errno, $errstr, 2);
    $reachable = $socket !== false;
    if ($socket !== false) {
        fclose($socket);
    }

    return [
        'host' => $host,
        'reachable' => $reachable,
    ];
}

header('Content-Type: application/json');
$status = check_host_reachability($_GET['host'] ?? '');
echo json_encode($status);
```

## Explanation

The vulnerability arose from directly concatenating untrusted user input (`$host`) into a command string passed to `system()`, allowing arbitrary command execution. The fix eliminates the command execution entirely by replacing the `system('ping ...')` call with a native PHP alternative: `fsockopen()` performs a TCP connection attempt to port 80 on the target host, providing network reachability assessment without spawning an OS command. Input validation using a strict allowlist (`/\A[a-zA-Z0-9:.\-]+\z/`) rejects any input containing shell metacharacters or special characters, and length validation prevents excessively long inputs. The allowlist anchors use `\A` and `\z` to prevent bypass via trailing newlines. The function returns the same data structure as before (host and reachability status), preserving the original behavior.

## Behaviour changes

The reachability check method changed from ICMP ping (which tests network layer connectivity via the ping command) to TCP connection attempt on port 80 (which tests application-layer connectivity). This means:
- A host that responds to ICMP ping but does not have port 80 open will now report as unreachable.
- A host that has port 80 open but does not respond to ICMP will now report as reachable.
- The timeout changed from the ping command's `-W 2` (milliseconds) to fsockopen's 2 (seconds), making timeouts 1000x longer.
- Invalid input (containing special characters, exceeding 255 characters, or empty) now returns `false` instead of attempting execution and potentially executing arbitrary commands.

These are intentional changes required to eliminate the injection vulnerability; the trade-off is that TCP connectivity on port 80 is a different and possibly less reliable test than ICMP echo, but eliminates shell injection entirely. A reviewer should confirm this behavior is acceptable for the use case.
