## Verdict

Confirmed. The `$host` parameter from `$_GET['host']` is concatenated directly into the `system()` command string without validation or escaping, allowing OS command injection via shell metacharacters (e.g., `; command`, `| command`, `&& command`).

## Source

Untrusted input: `$_GET['host']` (line 17)

Entry point: `check_host_reachability($_GET['host'] ?? '')` (line 17)

Sink: `system('ping -c 2 -W 2 ' . $host, $resultCode)` (line 8)

Data flow: User-supplied `host` parameter flows directly to string concatenation in the `system()` call without validation.

## Fix

Replace the `system('ping')` call with native PHP socket operations (`fsockopen()`). This eliminates the command execution sink entirely and provides the same reachability check using TCP connectivity instead of ICMP:

```php
<?php

function check_host_reachability(string $host): array
{
    // Validate host to prevent port/host injection
    if (!preg_match('/\A(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\z/', $host)) {
        return [
            'host' => $host,
            'reachable' => false,
        ];
    }

    // Use fsockopen to check connectivity instead of system('ping')
    $connection = @fsockopen($host, 80, $errno, $errstr, 2);
    $reachable = $connection !== false;
    if ($connection) {
        fclose($connection);
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

The original code invokes `system('ping')` with string concatenation, which passes the untrusted `$host` directly to the shell. An attacker can inject shell metacharacters to execute arbitrary commands.

The fix replaces `system('ping')` with `fsockopen()`, a native PHP function that attempts a TCP connection to port 80 on the target host. This eliminates the OS command execution entirely (removing the injection sink). The hostname is also validated against a regex allowlist (RFC 1123 domain names) before use, preventing malformed input from reaching the socket function.

The fix preserves the return value structure: a boolean `reachable` field indicating connectivity. The method of checking reachability changes from ICMP ping to TCP port 80 availability, which is appropriate for web service health checks.

## Behaviour changes

- **Reachability check method**: Changes from ICMP ping (protocol 1) to TCP port 80 (protocol 6, port 80). A host that responds to ping but has port 80 closed will now report as unreachable.
- **Hostname validation**: Invalid hostnames now return `reachable: false` instead of executing a failed ping command.
- **Timeout handling**: `fsockopen()` uses a 2-second timeout (matching the ping timeout in the original), but applies only to TCP connection establishment rather than ICMP round-trip.
- **Output**: The original ping output is discarded via the `$resultCode` parameter; the fix produces no external output, only the return value.
