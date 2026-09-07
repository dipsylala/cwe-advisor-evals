## Verdict

The code is vulnerable to OS command injection. The `$host` parameter from untrusted user input (`$_GET['host']`) is concatenated directly into a `system()` command string without any validation or sanitization, allowing an attacker to inject arbitrary shell commands (e.g., `host=8.8.8.8; rm -rf /`).

## Source

**Taint source**: `$_GET['host']` (line 17)  
**Taint sink**: `system('ping -c 2 -W 2 ' . $host, $resultCode)` (line 8)  
**Data flow**: `$_GET['host']` → `check_host_reachability($host)` parameter → string concatenation into `system()` call

The `$host` variable reaches the sink unvalidated and is directly concatenated into the command string.

## Fix

Replace the dangerous `system()` call with PHP's native `fsockopen()` function for network connectivity checking, and add input validation as a secondary defense to restrict the host parameter to valid hostnames and IP addresses.

### File: SystemFunctionConcat.php

```php
<?php

function check_host_reachability(string $host): array
{
    // Validate the host is a valid IP address or hostname
    // Reject invalid formats to prevent bypass attempts
    if (!filter_var($host, FILTER_VALIDATE_IP) && 
        !preg_match('/\A(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\z/', $host)) {
        return [
            'host' => $host,
            'reachable' => false,
        ];
    }

    // Use fsockopen to check if the host is reachable on port 80
    // This is the PHP native alternative to the ping command and does not invoke a shell
    $timeout = 2;
    $connection = @fsockopen($host, 80, $errno, $errstr, $timeout);
    $reachable = is_resource($connection);
    
    if ($reachable) {
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

The fix eliminates the OS command injection vulnerability by:

1. **Removing the shell call**: Replacing `system('ping ...')` with `fsockopen()`, a PHP native function that does not invoke a shell interpreter. This eliminates the injection point entirely.

2. **Input validation**: Adding a validation layer that restricts `$host` to valid IPv4/IPv6 addresses or RFC-compliant hostnames. The validation uses `filter_var()` for robust IP detection and a regex pattern anchored with `\A` and `\z` (per CWE-78/php guidance) to match valid hostnames. Any value failing validation returns `reachable => false`.

3. **No shell parsing**: `fsockopen()` attempts to open a TCP connection to the specified host and port. It never parses shell metacharacters, command separators, or variable expansions because it is not a shell invocation.

The fix preserves the original return structure and semantics: it returns a JSON object with the host and reachability status. The reachability check now verifies TCP connectivity on port 80 rather than ICMP ping, which is a reasonable proxy for host availability in web service contexts.

## Behaviour changes

- **Original**: Executes `ping` command via shell with user input directly concatenated into the command string. Vulnerable to arbitrary command injection.
- **Fixed**: Uses `fsockopen()` to check TCP port 80 connectivity. No shell invocation. Invalid hostnames are rejected with `reachable: false`.
- **Semantic change**: The reachability check mechanism changes from ICMP ping (original) to TCP port 80 connectivity (fixed). Both serve as network reachability indicators but have different characteristics (ICMP is lower-level, TCP is application-layer). The fixed approach is more reliable in practice for web service availability monitoring and cannot be exploited for command injection.
- **Input validation change**: Invalid hostnames now cause the function to return false for reachability rather than passing through to a potentially errant ping command.
